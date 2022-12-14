/**
 * Copyright 2020-2022 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "test_ctx.h"

#include <memory>
#include <openssl/rand.h>

std::string g_log_output;

static void variable_logger(const char* fmt, ...) { // NOLINT
    static pthread_mutex_t _log_mutex = PTHREAD_MUTEX_INITIALIZER;

    pthread_mutex_lock(&_log_mutex);

    va_list args;
    va_start(args, fmt);

    char tmp[65536];
    memset(tmp, 0, sizeof(tmp));
    vsnprintf(tmp, sizeof(tmp) - 1, fmt, args); // NOLINT

    va_end(args);

    g_log_output += std::string(tmp);

    pthread_mutex_unlock(&_log_mutex);
}

void Logger::init() {
    g_log_output.clear();
    Sec_SetLogger(variable_logger);
}

void Logger::shutdown() {
    Sec_SetLogger(Sec_DefaultLoggerCb);
}

const char* Logger::output() {
    return g_log_output.c_str();
}

std::vector<int> SuiteCtx::getFailed() const {
    std::vector<int> res;

    for (int i = 0; i < tests_.size(); ++i) {
        if (tests_[i].second == TESTRESULT_FAILED) {
            res.push_back(i + 1);
        }
    }

    return res;
}

std::vector<int> SuiteCtx::getSucceeded() const {
    std::vector<int> res;

    for (int i = 0; i < tests_.size(); ++i) {
        if (tests_[i].second == TESTRESULT_SUCCEEDED) {
            res.push_back(i + 1);
        }
    }

    return res;
}

std::vector<int> SuiteCtx::getSkipped() const {
    std::vector<int> res;

    for (int i = 0; i < tests_.size(); ++i) {
        if (tests_[i].second == TESTRESULT_SKIPPED) {
            res.push_back(i + 1);
        }
    }

    return res;
}

std::vector<int> SuiteCtx::getAttempted() const {
    std::vector<int> res;

    for (int i = 0; i < tests_.size(); ++i) {
        if (tests_[i].second == TESTRESULT_SUCCEEDED || tests_[i].second == TESTRESULT_FAILED) {
            res.push_back(i + 1);
        }
    }

    return res;
}

std::vector<int> SuiteCtx::getAll() const {
    std::vector<int> res;

    for (int i = 0; i < tests_.size(); ++i) {
        res.push_back(i + 1); // NOLINT
    }

    return res;
}

Sec_Result TestCtx::init(const char* global_dir, const char* app_dir) {
    if (SecProcessor_GetInstance_Directories(&proc_, global_dir, app_dir) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecProcessor_GetInstance failed");
        return SEC_RESULT_FAILURE;
    }

    if (TestCreds::preprovisionSoc(this) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCreds::preprovisionSoc failed");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

TestCtx::~TestCtx() {
    while (!macs_.empty()) {
        SEC_BYTE mac[SEC_MAC_MAX_LEN];
        SEC_SIZE mac_len;

        SecMac_Release(macs_.back(), mac, &mac_len);
        macs_.pop_back();
    }

    while (!ciphers_.empty()) {
        releaseCipher(ciphers_.back());
    }

    while (!sigs_.empty()) {
        releaseSignature(sigs_.back());
    }

    while (!digests_.empty()) {
        releaseDigest(digests_.back());
    }

    while (!randoms_.empty()) {
        releaseRandom(randoms_.back());
    }

    while (!keys_.empty()) {
        releaseKey(keys_.back());
    }

    while (!provisionedKeys_.empty()) {
        deleteKey(provisionedKeys_.back());
    }

    while (!certs_.empty()) {
        releaseCert(certs_.back());
    }

    while (!provisionedCerts_.empty()) {
        deleteCert(provisionedCerts_.back());
    }

    while (!bundles_.empty()) {
        releaseBundle(bundles_.back());
    }

    while (!provisionedBundles_.empty()) {
        deleteBundle(provisionedBundles_.back());
    }

    if (proc_ != nullptr) {
        SecProcessor_Release(proc_);
        proc_ = nullptr;
    }
}

Sec_KeyHandle* TestCtx::provisionKey(SEC_OBJECTID id, Sec_StorageLoc loc, const SEC_BYTE* data, SEC_SIZE len,
        Sec_KeyContainer kc, bool softWrap) {
    Sec_StorageLoc locToUse = loc;

    if (softWrap) {
        if (loc == SEC_STORAGELOC_RAM) {
            locToUse = SEC_STORAGELOC_RAM_SOFT_WRAPPED;
        } else {
            locToUse = SEC_STORAGELOC_FILE_SOFT_WRAPPED;
        }
    }

    if (SecKey_Provision(proc_, id, locToUse, kc, const_cast<SEC_BYTE*>(data), len) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecKey_Provision failed");
        return nullptr;
    }

    provisionedKeys_.push_back(id);

    return getKey(id);
}

Sec_KeyHandle* TestCtx::provisionKey(SEC_OBJECTID id, Sec_StorageLoc loc, TestKey key, TestKc kc, bool softWrap) {
    if (kc == TESTKC_GENERATED) {
        Sec_StorageLoc locToUse = loc;

        //generate key with same key type as the known key
        if (SecKey_Generate(proc_, id, TestCreds::getKeyType(key), locToUse) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecKey_Generate failed");
            return nullptr;
        }

        provisionedKeys_.push_back(id);

        return getKey(id);
    }

    if (kc == TESTKC_EXPORTED) {
        std::shared_ptr<ProvKey> prov(TestCreds::getKey(key, TESTKC_CONDITIONAL, id));
        if (!prov) {
            SEC_LOG_ERROR("TestCreds::getKey failed");
            return nullptr;
        }

        Sec_KeyHandle* keyHandle = provisionKey(id, loc, &prov->key[0], prov->key.size(), prov->kc, softWrap);
        std::vector<SEC_BYTE> derivation_input = TestCtx::random(SEC_AES_BLOCK_SIZE);
        std::vector<SEC_BYTE> exported_key;
        exported_key.resize(SEC_KEYCONTAINER_MAX_LEN);
        SEC_SIZE exported_len;

        if (SecKey_ExportKey(keyHandle, derivation_input.data(), exported_key.data(), exported_key.size(),
                    &exported_len) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecKey_ExportKey failed");
            return nullptr;
        }
        exported_key.resize(exported_len);

        return provisionKey(id, loc, exported_key.data(), exported_key.size(), SEC_KEYCONTAINER_EXPORTED, SEC_FALSE);
    }

    std::shared_ptr<ProvKey> prov(TestCreds::getKey(key, kc, id));
    if (!prov) {
        SEC_LOG_ERROR("TestCreds::getKey failed");
        return nullptr;
    }

    return provisionKey(id, loc, &prov->key[0], prov->key.size(), prov->kc, softWrap);
}

Sec_KeyHandle* TestCtx::getKey(SEC_OBJECTID id) {
    Sec_KeyHandle* keyHandle = nullptr;

    if (SecKey_GetInstance(proc_, id, &keyHandle) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecKey_GetInstance failed");
        return nullptr;
    }

    keys_.push_back(keyHandle);

    return keyHandle;
}

void TestCtx::releaseKey(Sec_KeyHandle* keyHandle) {
    keys_.remove(keyHandle);
    SecKey_Release(keyHandle);
}

void TestCtx::deleteKey(SEC_OBJECTID id) {
    provisionedKeys_.remove(id);
    SecKey_Delete(proc_, id);
}

void TestCtx::releaseCert(Sec_CertificateHandle* certificateHandle) {
    certs_.remove(certificateHandle);
    SecCertificate_Release(certificateHandle);
}

Sec_CertificateHandle* TestCtx::provisionCert(SEC_OBJECTID id, Sec_StorageLoc loc, TestCert cert) {
    std::shared_ptr<ProvCert> prov(TestCreds::getCert(cert));
    if (!prov) {
        SEC_LOG_ERROR("TestCreds::getCert failed");
        return nullptr;
    }

    if (SecCertificate_Provision(proc_, id, loc, prov->cc, &prov->cert[0], prov->cert.size()) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecCertificate_Provision failed");
        return nullptr;
    }

    provisionedCerts_.push_back(id);

    return getCert(id);
}

Sec_CertificateHandle* TestCtx::getCert(SEC_OBJECTID id) {
    Sec_CertificateHandle* certificateHandle = nullptr;

    if (SecCertificate_GetInstance(proc_, id, &certificateHandle) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecCertificate_GetInstance failed");
        return nullptr;
    }

    certs_.push_back(certificateHandle);

    return certificateHandle;
}

void TestCtx::deleteCert(SEC_OBJECTID id) {
    provisionedCerts_.remove(id);
    SecCertificate_Delete(proc_, id);
}

Sec_BundleHandle* TestCtx::provisionBundle(SEC_OBJECTID id, Sec_StorageLoc location,
        const std::vector<SEC_BYTE>& bundle) {
    if (SecBundle_Provision(proc_, id, location, const_cast<SEC_BYTE*>(bundle.data()), bundle.size()) !=
            SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecBundle_Provision failed");
        return nullptr;
    }

    provisionedBundles_.push_back(id);

    return getBundle(id);
}

Sec_BundleHandle* TestCtx::getBundle(SEC_OBJECTID id) {
    Sec_BundleHandle* bundleHandle = nullptr;

    if (SecBundle_GetInstance(proc_, id, &bundleHandle) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecBundle_GetInstance failed");
        return nullptr;
    }

    bundles_.push_back(bundleHandle);

    return bundleHandle;
}

void TestCtx::releaseBundle(Sec_BundleHandle* bundleHandle) {
    bundles_.remove(bundleHandle);
    SecBundle_Release(bundleHandle);
}

void TestCtx::deleteBundle(SEC_OBJECTID id) {
    provisionedBundles_.remove(id);
    SecBundle_Delete(proc_, id);
}

Sec_CipherHandle* TestCtx::acquireCipher(Sec_CipherAlgorithm algorithm, Sec_CipherMode mode, Sec_KeyHandle* keyHandle,
        SEC_BYTE* iv) {
    Sec_CipherHandle* cipherHandle = nullptr;

    if (SecCipher_GetInstance(proc_, algorithm, mode, keyHandle, iv, &cipherHandle) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecCipher_GetInstance failed");
        return nullptr;
    }

    ciphers_.push_back(cipherHandle);

    return cipherHandle;
}

void TestCtx::releaseCipher(Sec_CipherHandle* cipherHandle) {
    ciphers_.remove(cipherHandle);
    SecCipher_Release(cipherHandle);
}

Sec_RandomHandle* TestCtx::acquireRandom(Sec_RandomAlgorithm algorithm) {
    Sec_RandomHandle* randomHandle = nullptr;

    if (SecRandom_GetInstance(proc_, algorithm, &randomHandle) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecRandom_GetInstance failed");
        return nullptr;
    }

    randoms_.push_back(randomHandle);

    return randomHandle;
}

void TestCtx::releaseRandom(Sec_RandomHandle* randomHandle) {
    randoms_.remove(randomHandle);
    SecRandom_Release(randomHandle);
}

Sec_SignatureHandle* TestCtx::acquireSignature(Sec_SignatureAlgorithm algorithm, Sec_SignatureMode mode,
        Sec_KeyHandle* keyHandle) {
    Sec_SignatureHandle* signatureHandle = nullptr;

    if (SecSignature_GetInstance(proc_, algorithm, mode, keyHandle, &signatureHandle) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecSignature_GetInstance failed");
        return nullptr;
    }

    sigs_.push_back(signatureHandle);

    return signatureHandle;
}

void TestCtx::releaseSignature(Sec_SignatureHandle* signatureHandle) {
    sigs_.remove(signatureHandle);
    SecSignature_Release(signatureHandle);
}

Sec_MacHandle* TestCtx::acquireMac(Sec_MacAlgorithm algorithm, Sec_KeyHandle* keyHandle) {
    Sec_MacHandle* macHandle = nullptr;

    if (SecMac_GetInstance(proc_, algorithm, keyHandle, &macHandle) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecMac_GetInstance failed");
        return nullptr;
    }

    macs_.push_back(macHandle);

    return macHandle;
}

Sec_Result TestCtx::releaseMac(Sec_MacHandle* macHandle, SEC_BYTE* macBuffer, SEC_SIZE* macSize) {
    macs_.remove(macHandle);
    return SecMac_Release(macHandle, macBuffer, macSize);
}

void TestCtx::releaseMac(Sec_MacHandle* macHandle) {
    SEC_BYTE macBuffer[SEC_DIGEST_MAX_LEN];
    SEC_SIZE macSize;

    releaseMac(macHandle, macBuffer, &macSize);
}

Sec_DigestHandle* TestCtx::acquireDigest(Sec_DigestAlgorithm algorithm) {
    Sec_DigestHandle* digestHandle = nullptr;

    if (SecDigest_GetInstance(proc_, algorithm, &digestHandle) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecDigest_GetInstance failed");
        return nullptr;
    }

    digests_.push_back(digestHandle);

    return digestHandle;
}

Sec_Result TestCtx::releaseDigest(Sec_DigestHandle* digestHandle, SEC_BYTE* digestOutput, SEC_SIZE* digestSize) {
    digests_.remove(digestHandle);
    return SecDigest_Release(digestHandle, digestOutput, digestSize);
}

void TestCtx::releaseDigest(Sec_DigestHandle* digestHandle) {
    SEC_BYTE digestOutput[SEC_DIGEST_MAX_LEN];
    SEC_SIZE digestSize;

    releaseDigest(digestHandle, digestOutput, &digestSize);
}

void TestCtx::printHex(const char* label, const std::vector<SEC_BYTE>& data) {
    SEC_PRINT("%s[%d]: ", label, data.size());
    Sec_PrintHex((void*) data.data(), data.size()); // NOLINT
    SEC_PRINT("\n");
}

std::vector<SEC_BYTE> TestCtx::random(SEC_SIZE len) {
    std::vector<SEC_BYTE> output;

    output.resize(len);

    RAND_bytes(output.data(), static_cast<int>(output.size()));

    return output;
}

std::vector<SEC_BYTE> TestCtx::coalesceInputs(const std::vector<std::vector<SEC_BYTE>>& inputs) {
    std::vector<SEC_BYTE> input;

    for (const auto& i : inputs) {
        input.insert(input.end(), i.begin(), i.end());
    }

    return input;
}

SEC_SIZE TestCtx::coalesceInputSizes(const std::vector<SEC_SIZE>& inputSizes) {
    SEC_SIZE out = 0;

    for (unsigned int inputSize : inputSizes) {
        out += inputSize;
    }

    return out;
}
