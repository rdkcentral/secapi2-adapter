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

#include "mac.h"
#include "test_ctx.h"
#include <openssl/cmac.h>
#include <openssl/hmac.h>

std::vector<SEC_BYTE> macOpenSSL(Sec_MacAlgorithm alg, const std::vector<SEC_BYTE>& openssl_key,
        const std::vector<SEC_BYTE>& input) {
    std::vector<SEC_BYTE> mac;
    SEC_SIZE mac_len;
    CMAC_CTX* cmac_ctx;

    switch (alg) {
        case SEC_MACALGORITHM_HMAC_SHA1:
            mac.resize(20);
            HMAC(EVP_sha1(), &openssl_key[0], static_cast<int>(openssl_key.size()), &input[0], input.size(), &mac[0],
                    &mac_len);
            return mac;

        case SEC_MACALGORITHM_HMAC_SHA256:
            mac.resize(32);
            HMAC(EVP_sha256(), &openssl_key[0], static_cast<int>(openssl_key.size()), &input[0], input.size(), &mac[0],
                    &mac_len);
            return mac;

        case SEC_MACALGORITHM_CMAC_AES_128: {
            mac.resize(SEC_AES_BLOCK_SIZE);
            cmac_ctx = CMAC_CTX_new();
            if (CMAC_Init(cmac_ctx, &openssl_key[0], openssl_key.size(),
                        openssl_key.size() == SEC_AES_BLOCK_SIZE ? EVP_aes_128_cbc() : EVP_aes_256_cbc(), nullptr) !=
                    OPENSSL_SUCCESS) {
                SEC_LOG_ERROR("Comcast_CMAC_Init failed");
                return {};
            }
            CMAC_Update(cmac_ctx, &input[0], input.size());
            size_t outl;
            CMAC_Final(cmac_ctx, &mac[0], &outl);
            mac_len = outl;
            CMAC_CTX_free(cmac_ctx);
            return mac;
        }
        default:
            break;
    }

    SEC_LOG_ERROR("Unimplemented");
    return {};
}

std::vector<SEC_BYTE> macOpenSSL(Sec_MacAlgorithm alg, TestKey key, const std::vector<SEC_BYTE>& input) {
    std::vector<SEC_BYTE> mac;
    SEC_SIZE mac_len;
    CMAC_CTX* cmac_ctx;

    std::vector<SEC_BYTE> openssl_key = TestCreds::asOpenSslAes(key);
    if (openssl_key.empty()) {
        SEC_LOG_ERROR("TestCreds::asOpenSslAes failed");
        return {};
    }

    switch (alg) {
        case SEC_MACALGORITHM_HMAC_SHA1:
            mac.resize(20);
            HMAC(EVP_sha1(), &openssl_key[0], static_cast<int>(openssl_key.size()), &input[0], input.size(), &mac[0],
                    &mac_len);
            return mac;

        case SEC_MACALGORITHM_HMAC_SHA256:
            mac.resize(32);
            HMAC(EVP_sha256(), &openssl_key[0], static_cast<int>(openssl_key.size()), &input[0], input.size(), &mac[0],
                    &mac_len);
            return mac;

        case SEC_MACALGORITHM_CMAC_AES_128: {
            mac.resize(SEC_AES_BLOCK_SIZE);
            cmac_ctx = CMAC_CTX_new();
            if (CMAC_Init(cmac_ctx, &openssl_key[0], openssl_key.size(),
                        openssl_key.size() == SEC_AES_BLOCK_SIZE ? EVP_aes_128_cbc() : EVP_aes_256_cbc(), nullptr) !=
                    OPENSSL_SUCCESS) {
                SEC_LOG_ERROR("Comcast_CMAC_Init failed");
                return {};
            }
            CMAC_Update(cmac_ctx, &input[0], input.size());
            size_t outl;
            CMAC_Final(cmac_ctx, &mac[0], &outl);
            mac_len = outl;
            CMAC_CTX_free(cmac_ctx);
            return mac;
        }
        default:
            break;
    }

    SEC_LOG_ERROR("Unimplemented");
    return {};
}

std::vector<SEC_BYTE> macSecApi(TestCtx* ctx, Sec_MacAlgorithm alg, Sec_KeyHandle* keyHandle,
        const std::vector<SEC_BYTE>& input, const std::vector<SEC_SIZE>& inputSizes) {

    std::vector<SEC_BYTE> output;
    output.resize(SEC_MAC_MAX_LEN);

    SEC_SIZE inputProcessed = 0;
    SEC_SIZE written = 0;

    Sec_MacHandle* macHandle = ctx->acquireMac(alg, keyHandle);
    if (macHandle == nullptr) {
        SEC_LOG_ERROR("TestCtx::acquireMac failed");
        return {};
    }

    for (unsigned int inputSize : inputSizes) {
        if (inputSize > 0) {
            if (SecMac_Update(macHandle, const_cast<SEC_BYTE*>(&input[inputProcessed]), inputSize) !=
                    SEC_RESULT_SUCCESS) {
                SEC_LOG_ERROR("SecMac_Update failed");
                return {};
            }
        }

        inputProcessed += inputSize;
    }

    if (ctx->releaseMac(macHandle, &output[0], &written) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecCipher_Process failed");
        return {};
    }

    output.resize(written);

    return output;
}

std::vector<SEC_BYTE> macSecApi(TestCtx* ctx, Sec_MacAlgorithm alg, Sec_KeyHandle* keyHandle,
        Sec_KeyHandle* paylodKeyHandle) {

    std::vector<SEC_BYTE> output;
    output.resize(SEC_MAC_MAX_LEN);

    SEC_SIZE written = 0;

    Sec_MacHandle* macHandle = ctx->acquireMac(alg, keyHandle);
    if (macHandle == nullptr) {
        SEC_LOG_ERROR("TestCtx::acquireMac failed");
        return {};
    }

    if (SecMac_UpdateWithKey(macHandle, paylodKeyHandle) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecDigest_Update failed");
        return {};
    }

    if (ctx->releaseMac(macHandle, &output[0], &written) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecCipher_Process failed");
        return {};
    }

    output.resize(written);

    return output;
}

Sec_Result testMacOverKey(Sec_MacAlgorithm alg, SEC_OBJECTID id_mac, TestKey keyMac,
        TestKc kc, SEC_OBJECTID id_payload, TestKey keyPayload,
        Sec_StorageLoc loc) {
    TestCtx ctx;

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    Sec_KeyHandle* keyHandleMac;
    if ((keyHandleMac = ctx.provisionKey(id_mac, loc, keyMac, kc)) == nullptr) {
        SEC_LOG_ERROR("ctx.provisionKey failed");
        return SEC_RESULT_FAILURE;
    }

    Sec_KeyHandle* keyHandlePayload;
    if ((TestCreds::supports(CAPABILITY_HMAC_OVER_HWKEY) && alg != SEC_MACALGORITHM_CMAC_AES_128) ||
            (TestCreds::supports(CAPABILITY_CMAC_OVER_HWKEY) && alg == SEC_MACALGORITHM_CMAC_AES_128)) {
        if ((keyHandlePayload = ctx.provisionKey(id_payload, loc, keyPayload, TESTKC_RAW)) == nullptr) {
            SEC_LOG_ERROR("ctx.provisionKey failed");
            return SEC_RESULT_FAILURE;
        }
    } else {
        if ((keyHandlePayload = ctx.provisionKey(id_payload, loc, keyPayload, TESTKC_RAW, SEC_TRUE)) == nullptr) {
            SEC_LOG_ERROR("ctx.provisionKey failed");
            return SEC_RESULT_FAILURE;
        }
    }

    //gen clear input
    std::vector<SEC_BYTE> clear = TestCreds::asOpenSslAes(keyPayload);
    TestCtx::printHex("key", clear);

    //mac
    std::vector<SEC_BYTE> macSA = macSecApi(&ctx, alg, keyHandleMac, keyHandlePayload);
    TestCtx::printHex("macSecApi", macSA);

    std::vector<SEC_BYTE> macOS = macOpenSSL(alg, keyMac, clear);
    TestCtx::printHex("macOpenssl", macOS);

    //check if results match
    if (macSA != macOS || macSA.empty()) {
        SEC_LOG_ERROR("Results do not match");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result testMacSingle(SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc, Sec_MacAlgorithm alg,
        SEC_SIZE inputSize) {
    std::vector<SEC_SIZE> inputSizes;
    inputSizes.resize(1);
    inputSizes[0] = inputSize;

    return testMacMult(id, key, kc, loc, alg, inputSizes);
}

Sec_Result testMacMult(SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc, Sec_MacAlgorithm alg,
        const std::vector<SEC_SIZE>& inputSizes) {

    TestCtx ctx;

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    Sec_KeyHandle* keyHandle;
    if ((keyHandle = ctx.provisionKey(id, loc, key, kc)) == nullptr) {
        SEC_LOG_ERROR("ctx.provisionKey failed");
        return SEC_RESULT_FAILURE;
    }

    //gen clear input
    std::vector<SEC_BYTE> clear = TestCtx::random(TestCtx::coalesceInputSizes(inputSizes));
    TestCtx::printHex("clear", clear);

    //mac
    std::vector<SEC_BYTE> macSA = macSecApi(&ctx, alg, keyHandle, clear, inputSizes);
    TestCtx::printHex("macSecApi", macSA);

    std::vector<SEC_BYTE> macOS = macOpenSSL(alg, key, clear);
    TestCtx::printHex("macOpenssl", macOS);

    //check if results match
    if (macSA != macOS) {
        SEC_LOG_ERROR("Results do not match");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result macCheck(Sec_ProcessorHandle* processorHandle, Sec_MacAlgorithm alg, SEC_OBJECTID id, SEC_BYTE* key,
        SEC_SIZE key_len) {
    std::vector<SEC_BYTE> mac_secapi;
    mac_secapi.resize(SEC_MAC_MAX_LEN);
    SEC_SIZE mac_len;

    std::vector<SEC_BYTE> clear = TestCtx::random(256);
    TestCtx::printHex("clear", clear);

    if (SecMac_SingleInputId(processorHandle, alg, id, &clear[0], clear.size(), &mac_secapi[0], &mac_len) !=
            SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecMac_SingleInputId failed");
        return SEC_RESULT_FAILURE;
    }

    mac_secapi.resize(mac_len);
    TestCtx::printHex("macSecApi", mac_secapi);

    std::vector<SEC_BYTE> openssl_key = std::vector<SEC_BYTE>(key, key + key_len);

    std::vector<SEC_BYTE> macOS = macOpenSSL(alg, openssl_key, clear);
    TestCtx::printHex("macOpenssl", macOS);

    //check if results match
    if (mac_secapi != macOS) {
        SEC_LOG_ERROR("Results do not match");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}
