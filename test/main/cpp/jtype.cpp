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

#include "jtype.h" // NOLINT
#include "cipher.h"
#include "mac.h"
#include "sec_adapter_utils.h"
#include "sec_security_comcastids.h"
#include "test_ctx.h"
#include <openssl/aes.h>

#define BUFFER_SIZE 4096

std::string toB64(const SEC_BYTE* data, SEC_SIZE len) {
    std::string res;
    SEC_SIZE res_len;
    res.resize(SEC_KEYCONTAINER_MAX_LEN);

    if (SecUtils_Base64Encode(data, len, (SEC_BYTE*) res.data(), res.size(), &res_len) != // NOLINT
            SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecSrv_B64Encode failed");
        return "";
    }

    res.resize(res_len);

    return res;
}

std::string createJTypeHeader(const char* kid, const char* alg) {
    std::string res;

    res += R"({"kid":")";
    res += kid;
    res += R"(","alg":")";
    res += alg;
    res += "\"}";

    return toB64((SEC_BYTE*) res.c_str(), res.size()); // NOLINT
}

std::string createJTypeBodyV1(const char* contentKey, const char* contentKeyId, const char* contentKeyRights,
        SEC_BOOL cacheable, int contentKeyUsage, const char* contentKeyNotBefore, const char* contentKeyNotOnOrAfter) {
    std::string res;
    char tmp[BUFFER_SIZE];

    res += R"({"contentKeyNotOnOrAfter":")";
    res += contentKeyNotOnOrAfter;

    res += R"(","contentKey":")";
    res += contentKey;

    res += R"(","contentKeyId":")";
    res += contentKeyId;

    res += R"(","contentKeyRights":")";
    res += contentKeyRights;

    res += R"(","contentKeyCacheable":)";
    res += (cacheable == SEC_TRUE ? "true" : "false");

    sprintf(tmp, "%d", contentKeyUsage);

    res += ",\"contentKeyUsage\":";
    res += tmp;

    res += R"(,"contentKeyNotBefore":")";
    res += contentKeyNotBefore;

    res += "\"}";

    return toB64((SEC_BYTE*) res.c_str(), res.size()); // NOLINT
}

std::string createJTypeBodyV2(const char* contentKey, const char* contentKeyId, const char* contentKeyRights,
        SEC_BOOL cacheable, int contentKeyUsage, const char* contentKeyNotBefore, const char* contentKeyNotOnOrAfter,
        int cklen, const char* alg, const char* iv) {
    std::string res;
    char tmp[BUFFER_SIZE];

    res += "{";

    res += "\"contentKeyContainerVersion\":2";

    res += R"(,"contentKeyNotOnOrAfter":")";
    res += contentKeyNotOnOrAfter;

    res += R"(","contentKey":")";
    res += contentKey;

    res += R"(","contentKeyId":")";
    res += contentKeyId;

    res += R"(","contentKeyRights":")";
    res += contentKeyRights;

    res += R"(","contentKeyCacheable":)";
    res += (cacheable == SEC_TRUE ? "true" : "false");

    sprintf(tmp, "%d", contentKeyUsage);

    res += ",\"contentKeyUsage\":";
    res += tmp;

    res += R"(,"contentKeyNotBefore":")";
    res += contentKeyNotBefore;

    res += R"(","contentKeyLength":)";
    sprintf(tmp, "%d", cklen);
    res += tmp;
    res += "";

    res += R"(,"contentKeyTransportAlgorithm":")";
    res += alg;

    if (iv != nullptr) {
        res += R"(","contentKeyTransportIv":")";
        res += iv;
    }

    res += "\"}";

    return toB64((SEC_BYTE*) res.c_str(), res.size()); // NOLINT
}

std::string createContentKeyV1(TestKey contentKey, TestKey encryptionKey) {
    std::vector<SEC_BYTE> conK = TestCreds::asOpenSslAes(contentKey);
    if (conK.empty()) {
        SEC_LOG_ERROR("TestCreds::asOpenSslAes failed");
        return {};
    }

    if (conK.size() != 16) {
        SEC_LOG_ERROR("V1 Jtype cannot support keys that are not 128 bits");
        return {};
    }

    std::vector<SEC_BYTE> encK = TestCreds::asOpenSslAes(encryptionKey);
    if (encK.empty()) {
        SEC_LOG_ERROR("TestCreds::asOpenSslAes failed");
        return {};
    }

    std::vector<SEC_BYTE> encConK = opensslAesEcb(encryptionKey, SEC_CIPHERMODE_ENCRYPT, SEC_FALSE, nullptr, conK);
    if (encConK.empty()) {
        SEC_LOG_ERROR("OpensslAesEcb failed");
        return {};
    }

    return toB64(encConK.data(), encConK.size());
}

std::string createContentKeyV2(TestKey contentKey, TestKey encryptionKey, Sec_CipherAlgorithm alg, SEC_BYTE* iv) {
    std::vector<SEC_BYTE> conK = TestCreds::asOpenSslAes(contentKey);
    if (conK.empty()) {
        SEC_LOG_ERROR("TestCreds::asOpenSslAes failed");
        return {};
    }

    std::vector<SEC_BYTE> encK = TestCreds::asOpenSslAes(encryptionKey);
    if (encK.empty()) {
        SEC_LOG_ERROR("TestCreds::asOpenSslAes failed");
        return {};
    }

    std::vector<SEC_BYTE> encConK;

    if (alg == SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING) {
        encConK = opensslAesEcb(encryptionKey, SEC_CIPHERMODE_ENCRYPT, SEC_FALSE, iv, conK);
        if (encConK.empty()) {
            SEC_LOG_ERROR("OpensslAesEcb failed");
            return {};
        }
    } else if (alg == SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING) {
        encConK = opensslAesEcb(encryptionKey, SEC_CIPHERMODE_ENCRYPT, SEC_TRUE, iv, conK);
        if (encConK.empty()) {
            SEC_LOG_ERROR("OpensslAesEcb failed");
            return {};
        }
    } else {
        SEC_LOG_ERROR("Unexpected algorithm encountered: %d", alg);
    }

    return toB64(encConK.data(), encConK.size());
}

std::string createJTypeMac(const std::string& header, const std::string& body, TestKey macKey) {
    std::string data = header + "." + body;
    std::vector<SEC_BYTE> input((SEC_BYTE*) data.data(), (SEC_BYTE*) (data.data() + data.size())); // NOLINT
    std::vector<SEC_BYTE> mac = macOpenSSL(SEC_MACALGORITHM_HMAC_SHA256, macKey, input);
    return toB64(mac.data(), mac.size());
}

std::string createJTypeContainer(const char* kid, const char* macalg, TestKey contentKey, TestKey encryptionKey,
        const char* contentKeyId, const char* contentKeyRights, SEC_BOOL cacheable, int contentKeyUsage,
        const char* contentKeyNotBefore, const char* contentKeyNotOnOrAfter, TestKey macKey, int version,
        const char* alg) {

    std::string header_b64 = createJTypeHeader(kid, macalg);
    if (header_b64.empty()) {
        SEC_LOG_ERROR("CreateJTypeHeader failed");
        return {};
    }

    std::string body_b64;
    if (version == 1) {
        std::string encConK = createContentKeyV1(contentKey, encryptionKey);
        if (encConK.empty()) {
            SEC_LOG_ERROR("CreateContentKeyV1 failed");
            return {};
        }

        body_b64 = createJTypeBodyV1(encConK.c_str(), contentKeyId, contentKeyRights, cacheable, contentKeyUsage,
                contentKeyNotBefore, contentKeyNotOnOrAfter);
        if (body_b64.empty()) {
            SEC_LOG_ERROR("CreateJTypeBody failed");
            return {};
        }
    } else if (version == 2) {
        Sec_CipherAlgorithm salg;
        if (strcmp(alg, "aesEcbNone") == 0) {
            salg = SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING;
        } else if (strcmp(alg, "aesEcbPkcs5") == 0) {
            salg = SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING;
        } else {
            SEC_LOG_ERROR("Unknown algorithm encountered: %s", alg);
            return {};
        }

        std::string encConK = createContentKeyV2(contentKey, encryptionKey, salg, nullptr);
        if (encConK.empty()) {
            SEC_LOG_ERROR("CreateContentKeyV2 failed");
            return {};
        }

        std::vector<SEC_BYTE> conK = TestCreds::asOpenSslAes(contentKey);
        if (conK.empty()) {
            SEC_LOG_ERROR("TestCreds::asOpenSslAes failed");
            return {};
        }

        body_b64 = createJTypeBodyV2(encConK.c_str(), contentKeyId, contentKeyRights, cacheable, contentKeyUsage,
                contentKeyNotBefore, contentKeyNotOnOrAfter, static_cast<int>(conK.size()), alg, nullptr);
        if (body_b64.empty()) {
            SEC_LOG_ERROR("CreateJTypeBody failed");
            return {};
        }
    } else {
        SEC_LOG_ERROR("Unknown version encountered: %d", version);
        return {};
    }

    std::string mac_b64 = createJTypeMac(header_b64, body_b64, macKey);
    if (mac_b64.empty()) {
        SEC_LOG_ERROR("CreateJTypeMac failed");
        return {};
    }

    return header_b64 + "." + body_b64 + "." + mac_b64;
}

Sec_Result testProvisionJType(TestKey contentKey, TestKey encryptionKey, TestKc encKc, TestKey macKey, TestKc macKc,
        int version, const char* alg) {
    TestCtx ctx;
    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    std::string jtype = createJTypeContainer("1WXQ46EYW65SENER", "HS256", contentKey, encryptionKey,
            "9c621060-3a17-4813-8dcb-2e9187aaa903", createDefaultRights(TestCreds::getKeyType(contentKey)).c_str(),
            SEC_FALSE, 1, "2010-12-09T19:53:06Z", "2037-12-09T19:53:06Z", macKey, version, alg);
    if (jtype.empty()) {
        SEC_LOG_ERROR("CreateJTypeContainer failed");
        return SEC_RESULT_FAILURE;
    }

    //provision encryption key
    if (ctx.provisionKey(SEC_OBJECTID_COMCAST_XCALSESSIONENCKEY, SEC_STORAGELOC_RAM, encryptionKey, encKc) == nullptr) {
        SEC_LOG_ERROR("ProvisionKey failed");
        return SEC_RESULT_FAILURE;
    }

    //provision maccing key
    if (ctx.provisionKey(SEC_OBJECTID_COMCAST_XCALSESSIONMACKEY, SEC_STORAGELOC_RAM, macKey, macKc) == nullptr) {
        SEC_LOG_ERROR("ProvisionKey failed");
        return SEC_RESULT_FAILURE;
    }

    //provsion j-type key
    Sec_Result result = SecKey_Provision(ctx.proc(), SEC_OBJECTID_USER_BASE, SEC_STORAGELOC_RAM, SEC_KEYCONTAINER_JTYPE,
            reinterpret_cast<SEC_BYTE*>(&jtype[0]), jtype.size());
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecKey_Provision failed");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result testExportKey(TestKey contentKey, TestKey encryptionKey, TestKc encKc, TestKey macKey, TestKc macKc,
        Sec_CipherAlgorithm alg, SEC_SIZE input_len, int version, const char* calg) {
    TestCtx ctx;
    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    std::string jtype = createJTypeContainer("1WXQ46EYW65SENER", "HS256", contentKey, encryptionKey,
            "9c621060-3a17-4813-8dcb-2e9187aaa903", createDefaultRights(TestCreds::getKeyType(contentKey)).c_str(),
            SEC_TRUE, 1, "2010-12-09T19:53:06Z", "2037-12-09T19:53:06Z",
            macKey, version, calg);
    if (jtype.empty()) {
        SEC_LOG_ERROR("CreateJTypeContainer failed");
        return SEC_RESULT_FAILURE;
    }

    //provision encryption key
    if (ctx.provisionKey(SEC_OBJECTID_COMCAST_XCALSESSIONENCKEY, SEC_STORAGELOC_RAM, encryptionKey, encKc) == nullptr) {
        SEC_LOG_ERROR("ProvisionKey failed");
        return SEC_RESULT_FAILURE;
    }

    //provision maccing key
    if (ctx.provisionKey(SEC_OBJECTID_COMCAST_XCALSESSIONMACKEY, SEC_STORAGELOC_RAM, macKey, macKc) == nullptr) {
        SEC_LOG_ERROR("ProvisionKey failed");
        return SEC_RESULT_FAILURE;
    }

    //provsion j-type key
    Sec_Result result = SecKey_Provision(ctx.proc(), SEC_OBJECTID_USER_BASE, SEC_STORAGELOC_RAM, SEC_KEYCONTAINER_JTYPE,
            reinterpret_cast<SEC_BYTE*>(&jtype[0]), jtype.size());
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecKey_Provision failed");
        return SEC_RESULT_FAILURE;
    }

    Sec_KeyHandle* keyHandle;
    if (SecKey_GetInstance(ctx.proc(), SEC_OBJECTID_USER_BASE, &keyHandle) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecKey_GetInstance failed");
        return SEC_RESULT_FAILURE;
    }

    //get properties from j-type
    Sec_KeyProperties jtype_props;
    if (SecKey_GetProperties(keyHandle, &jtype_props) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecKey_GetProperties failed");
        return SEC_RESULT_FAILURE;
    }

    //export j-type key
    std::vector<SEC_BYTE> derivation_input = TestCtx::random(SEC_AES_BLOCK_SIZE);
    std::vector<SEC_BYTE> exported_key;
    exported_key.resize(SEC_KEYCONTAINER_MAX_LEN);
    SEC_SIZE exported_len;

    if (SecKey_ExportKey(keyHandle, &derivation_input[0], &exported_key[0], exported_key.size(), &exported_len) !=
            SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecKey_ExportKey failed");
        return SEC_RESULT_FAILURE;
    }
    exported_key.resize(exported_len);

    //provision exported
    if (SecKey_Provision(ctx.proc(), SEC_OBJECTID_USER_BASE, SEC_STORAGELOC_RAM, SEC_KEYCONTAINER_EXPORTED,
                &exported_key[0], exported_key.size()) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecKey_Provision failed");
        return SEC_RESULT_FAILURE;
    }

    Sec_KeyHandle* exportedKeyHandle;
    if (SecKey_GetInstance(ctx.proc(), SEC_OBJECTID_USER_BASE, &exportedKeyHandle) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecKey_GetInstance failed");
        return SEC_RESULT_FAILURE;
    }

    //grab properties from exported
    Sec_KeyProperties exported_props;
    if (SecKey_GetProperties(exportedKeyHandle, &exported_props) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecKey_GetProperties failed");
        return SEC_RESULT_FAILURE;
    }

    if (memcmp(&jtype_props, &exported_props, sizeof(Sec_KeyProperties)) != 0) {
        SEC_LOG_ERROR("Key properties on jtype and exported container do not match");
        return SEC_RESULT_FAILURE;
    }

    //test exported encryption
    if (cipherEncDecSingle(&ctx, SEC_OBJECTID_USER_BASE, alg, input_len) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("CipherEncDecSingle failed");
        return SEC_RESULT_FAILURE;
    }

    SecKey_Release(keyHandle);
    SecKey_Release(exportedKeyHandle);
    return SEC_RESULT_SUCCESS;
}

std::string createDefaultRights(Sec_KeyType kt) {
    SEC_BYTE allow_all_rights[] = {
            SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_DTCP_ALLOWED,
            SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_1_4_ALLOWED,
            SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_2_2_ALLOWED,
            SEC_KEYOUTPUTRIGHT_ANALOG_OUTPUT_ALLOWED};
    return toB64(allow_all_rights, sizeof(allow_all_rights));
}

Sec_Result testDecryptJType(TestKey contentKey, TestKey encryptionKey, TestKc encKc, TestKey macKey, TestKc macKc,
        Sec_CipherAlgorithm alg, SEC_SIZE input_len, int version, const char* calg) {
    TestCtx ctx;
    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    std::string jtype = createJTypeContainer("1WXQ46EYW65SENER", "HS256", contentKey, encryptionKey,
            "9c621060-3a17-4813-8dcb-2e9187aaa903",
            createDefaultRights(TestCreds::getKeyType(contentKey)).c_str(),
            SEC_FALSE, 1, "2010-12-09T19:53:06Z", "2037-12-09T19:53:06Z", macKey,
            version, calg);
    if (jtype.empty()) {
        SEC_LOG_ERROR("CreateJTypeContainer failed");
        return SEC_RESULT_FAILURE;
    }

    Sec_StorageLoc loc = SEC_STORAGELOC_RAM;

    //provision encryption key
    if (ctx.provisionKey(SEC_OBJECTID_COMCAST_XCALSESSIONENCKEY, loc, encryptionKey, encKc) == nullptr) {
        SEC_LOG_ERROR("ProvisionKey failed");
        return SEC_RESULT_FAILURE;
    }

    //provision maccing key
    if (ctx.provisionKey(SEC_OBJECTID_COMCAST_XCALSESSIONMACKEY, loc, macKey, macKc) == nullptr) {
        SEC_LOG_ERROR("ProvisionKey failed");
        return SEC_RESULT_FAILURE;
    }

    //provision jtype key
    Sec_Result result = SecKey_Provision(ctx.proc(), SEC_OBJECTID_USER_BASE, SEC_STORAGELOC_RAM, SEC_KEYCONTAINER_JTYPE,
            reinterpret_cast<SEC_BYTE*>(&jtype[0]), jtype.size());
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecKey_Provision failed");
        return SEC_RESULT_FAILURE;
    }

    //test encryption
    if (cipherEncDecSingle(&ctx, SEC_OBJECTID_USER_BASE, alg, input_len) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("CipherEncDecSingle failed");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}
