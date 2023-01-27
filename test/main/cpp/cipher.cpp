/**
 * Copyright 2020-2023 Comcast Cable Communications Management, LLC
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

#include "cipher.h"
#include "digest.h"
#include "test_ctx.h"
#include <memory>
#include <openssl/aes.h>
#include <openssl/err.h>

#define BUFFER_SIZE 4096
#define SUBSAMPLE_SIZE 256

static std::vector<SEC_BYTE> opensslAesCbc(TestKey key, Sec_CipherMode mode, bool padding, SEC_BYTE* iv,
        const std::vector<SEC_BYTE>& input) {

    std::vector<SEC_BYTE> openssl_key = TestCreds::asOpenSslAes(key);
    if (openssl_key.empty()) {
        SEC_LOG_ERROR("TestCreds::asOpenSslAes failed");
        return {};
    }
    const EVP_CIPHER* evp_cipher;
    if (openssl_key.size() == 16)
        evp_cipher = EVP_aes_128_cbc();
    else
        evp_cipher = EVP_aes_256_cbc();

    std::shared_ptr<EVP_CIPHER_CTX> p_evp_ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);

    if (EVP_CipherInit_ex(p_evp_ctx.get(), evp_cipher, nullptr, nullptr, nullptr,
                (mode == SEC_CIPHERMODE_ENCRYPT || mode == SEC_CIPHERMODE_ENCRYPT_NATIVEMEM) ? 1 : 0) !=
            OPENSSL_SUCCESS) {
        SEC_LOG_ERROR("EVP_CipherInit failed");
        return {};
    }

    if (EVP_CIPHER_CTX_set_padding(p_evp_ctx.get(), padding ? 1 : 0) != OPENSSL_SUCCESS) {
        SEC_LOG_ERROR("EVP_CIPHER_CTX_set_padding failed");
        return {};
    }

    if (EVP_CipherInit_ex(p_evp_ctx.get(), nullptr, nullptr, openssl_key.data(), iv,
                (mode == SEC_CIPHERMODE_ENCRYPT || mode == SEC_CIPHERMODE_ENCRYPT_NATIVEMEM) ? 1 : 0) !=
            OPENSSL_SUCCESS) {
        SEC_LOG_ERROR("EVP_CipherInit failed");
        return {};
    }

    std::vector<SEC_BYTE> output;
    output.resize(input.size() + SEC_AES_BLOCK_SIZE);

    SEC_SIZE written = 0;
    int outlen = 0;

    if (EVP_CipherUpdate(p_evp_ctx.get(), output.data(), &outlen, input.data(), static_cast<int>(input.size())) !=
            OPENSSL_SUCCESS) {
        SEC_LOG_ERROR("EVP_CipherUpdate failed");
        return {};
    }
    written += outlen;
    outlen = 0;

    if (EVP_CipherFinal_ex(p_evp_ctx.get(), &output[written], &outlen) != OPENSSL_SUCCESS) {
        SEC_LOG_ERROR("EVP_CipherFinal failed");
        return {};
    }

    written += outlen;
    output.resize(written);
    return output;
}

std::vector<SEC_BYTE> opensslAesEcb(const std::vector<SEC_BYTE>& openssl_key, Sec_CipherMode mode, SEC_BOOL padding,
        SEC_BYTE* iv, const std::vector<SEC_BYTE>& input) {
    std::vector<SEC_BYTE> output;
    const EVP_CIPHER* evp_cipher;

    if (openssl_key.size() == 16) {
        evp_cipher = EVP_aes_128_ecb();
    } else {
        evp_cipher = EVP_aes_256_ecb();
    }

    std::shared_ptr<EVP_CIPHER_CTX> p_evp_ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (EVP_CipherInit_ex(p_evp_ctx.get(), evp_cipher, nullptr, nullptr, nullptr,
                (mode == SEC_CIPHERMODE_ENCRYPT || mode == SEC_CIPHERMODE_ENCRYPT_NATIVEMEM) ? 1 : 0) !=
            OPENSSL_SUCCESS) {
        SEC_LOG_ERROR("EVP_CipherInit failed");
        return {};
    }

    if (EVP_CIPHER_CTX_set_padding(p_evp_ctx.get(), padding) != OPENSSL_SUCCESS) {
        SEC_LOG_ERROR("EVP_CIPHER_CTX_set_padding failed");
        return {};
    }

    if (EVP_CipherInit_ex(p_evp_ctx.get(), nullptr, nullptr, openssl_key.data(), iv,
                (mode == SEC_CIPHERMODE_ENCRYPT || mode == SEC_CIPHERMODE_ENCRYPT_NATIVEMEM) ? 1 : 0) !=
            OPENSSL_SUCCESS) {
        SEC_LOG_ERROR("EVP_CipherInit failed");
        return {};
    }

    output.resize(input.size() + SEC_AES_BLOCK_SIZE);

    SEC_SIZE written = 0;
    int outlen = 0;
    if (EVP_CipherUpdate(p_evp_ctx.get(), output.data(), &outlen, input.data(), static_cast<int>(input.size())) !=
            OPENSSL_SUCCESS) {
        SEC_LOG_ERROR("EVP_CipherUpdate failed");
        return {};
    }
    written += outlen;
    outlen = 0;

    if (EVP_CipherFinal_ex(p_evp_ctx.get(), &output[written], &outlen) != OPENSSL_SUCCESS) {
        SEC_LOG_ERROR("EVP_CipherFinal failed");
        return {};
    }

    written += outlen;
    output.resize(written);

    return output;
}

std::vector<SEC_BYTE> opensslAesEcb(TestKey key, Sec_CipherMode mode, bool padding, SEC_BYTE* iv,
        const std::vector<SEC_BYTE>& input) {
    std::vector<SEC_BYTE> output;
    std::vector<SEC_BYTE> openssl_key = TestCreds::asOpenSslAes(key);
    const EVP_CIPHER* evp_cipher;

    if (openssl_key.size() == 16) {
        evp_cipher = EVP_aes_128_ecb();
    } else {
        evp_cipher = EVP_aes_256_ecb();
    }

    std::shared_ptr<EVP_CIPHER_CTX> p_evp_ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (EVP_CipherInit_ex(p_evp_ctx.get(), evp_cipher, nullptr, nullptr, nullptr,
                (mode == SEC_CIPHERMODE_ENCRYPT || mode == SEC_CIPHERMODE_ENCRYPT_NATIVEMEM) ? 1 : 0) !=
            OPENSSL_SUCCESS) {
        SEC_LOG_ERROR("EVP_CipherInit failed");
        return {};
    }

    if (EVP_CIPHER_CTX_set_padding(p_evp_ctx.get(), padding ? 1 : 0) != OPENSSL_SUCCESS) {
        SEC_LOG_ERROR("EVP_CIPHER_CTX_set_padding failed");
        return {};
    }

    if (EVP_CipherInit_ex(p_evp_ctx.get(), nullptr, nullptr, openssl_key.data(), iv,
                (mode == SEC_CIPHERMODE_ENCRYPT || mode == SEC_CIPHERMODE_ENCRYPT_NATIVEMEM) ? 1 : 0) !=
            OPENSSL_SUCCESS) {
        SEC_LOG_ERROR("EVP_CipherInit failed");
        return {};
    }

    output.resize(input.size() + SEC_AES_BLOCK_SIZE);

    SEC_SIZE written = 0;
    int outlen = 0;
    if (EVP_CipherUpdate(p_evp_ctx.get(), output.data(), &outlen, input.data(), static_cast<int>(input.size())) !=
            OPENSSL_SUCCESS) {
        SEC_LOG_ERROR("EVP_CipherUpdate failed");
        return {};
    }
    written += outlen;
    outlen = 0;

    if (EVP_CipherFinal_ex(p_evp_ctx.get(), &output[written], &outlen) != OPENSSL_SUCCESS) {
        SEC_LOG_ERROR("EVP_CipherFinal failed");
        return {};
    }

    written += outlen;
    output.resize(written);
    return output;
}

static std::vector<SEC_BYTE> opensslAesCtr(TestKey key, Sec_CipherMode mode, SEC_BYTE* iv,
        const std::vector<SEC_BYTE>& input) {

    std::vector<SEC_BYTE> openssl_key = TestCreds::asOpenSslAes(key);
    SEC_BYTE ivToUse[SEC_AES_BLOCK_SIZE];
    memcpy(ivToUse, iv, SEC_AES_BLOCK_SIZE);

    std::vector<SEC_BYTE> output;
    output.resize(input.size());

    std::shared_ptr<EVP_CIPHER_CTX> evp_ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    EVP_CIPHER_CTX_init(evp_ctx.get());
    if (EVP_CipherInit_ex(evp_ctx.get(), (openssl_key.size() == 16) ? EVP_aes_128_ctr() : EVP_aes_256_ctr(), nullptr,
                openssl_key.data(), ivToUse,
                (mode == SEC_CIPHERMODE_ENCRYPT || mode == SEC_CIPHERMODE_ENCRYPT_NATIVEMEM) ? 1 : 0) !=
            OPENSSL_SUCCESS) {
        SEC_LOG_ERROR("EVP_CipherInit_ex failed");
        return {};
    }

    int out_len = 0;
    if (EVP_CipherUpdate(evp_ctx.get(), output.data(), &out_len, input.data(), static_cast<int>(input.size())) !=
            OPENSSL_SUCCESS) {
        SEC_LOG_ERROR("EVP_CipherUpdate failed");
        return {};
    }

    if (EVP_CipherFinal_ex(evp_ctx.get(), &output[out_len], &out_len) != OPENSSL_SUCCESS) {
        SEC_LOG_ERROR("EVP_CipherFinal failed");
        return {};
    }

    return output;
}

std::vector<SEC_BYTE> opensslAesGcm(const std::vector<SEC_BYTE>& key, Sec_CipherMode mode, SEC_BYTE* iv, SEC_BYTE* aad,
        SEC_SIZE aad_length, SEC_BYTE* tag, SEC_SIZE tag_length, const std::vector<SEC_BYTE>& input) {

    SEC_BYTE ivToUse[SEC_AES_BLOCK_SIZE];
    memcpy(ivToUse, iv, SEC_AES_BLOCK_SIZE);

    std::vector<SEC_BYTE> output;
    output.resize(input.size());

    std::shared_ptr<EVP_CIPHER_CTX> evp_ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);

    // init cipher
    const EVP_CIPHER* cipher = (key.size() == 16) ? EVP_aes_128_gcm() : EVP_aes_256_gcm();
    if (EVP_EncryptInit_ex(evp_ctx.get(), cipher, nullptr, nullptr, nullptr) != OPENSSL_SUCCESS) {
        SEC_LOG_ERROR("EVP_EncryptInit_ex failed");
        return {};
    }

    // set iv length
    if (EVP_CIPHER_CTX_ctrl(evp_ctx.get(), EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != OPENSSL_SUCCESS) {
        SEC_LOG_ERROR("EVP_CIPHER_CTX_ctrl failed");
        return {};
    }

    // init key and iv
    if (EVP_EncryptInit_ex(evp_ctx.get(), cipher, nullptr, key.data(), iv) != OPENSSL_SUCCESS) {
        SEC_LOG_ERROR("EVP_EncryptInit_ex failed");
        return {};
    }

    // turn off padding
    if (EVP_CIPHER_CTX_set_padding(evp_ctx.get(), 0) != OPENSSL_SUCCESS) {
        SEC_LOG_ERROR("EVP_CIPHER_CTX_set_padding failed");
        return {};
    }

    int out_length = static_cast<int>(input.size());
    if (aad != nullptr) {
        if (EVP_EncryptUpdate(evp_ctx.get(), nullptr, &out_length, aad, static_cast<int>(aad_length)) !=
                OPENSSL_SUCCESS) {
            SEC_LOG_ERROR("EVP_EncryptUpdate failed");
            return {};
        }
    }

    if (EVP_CipherUpdate(evp_ctx.get(), output.data(), &out_length, input.data(), static_cast<int>(input.size())) !=
            OPENSSL_SUCCESS) {
        SEC_LOG_ERROR("EVP_CipherUpdate failed");
        return {};
    }

    if (tag != nullptr) {
        // get tag
        if (EVP_EncryptFinal_ex(evp_ctx.get(), nullptr, &out_length) != 1) {
            SEC_LOG_ERROR("EVP_EncryptFinal_ex failed");
            return {};
        }

        uint8_t local_tag[16];
        if (EVP_CIPHER_CTX_ctrl(evp_ctx.get(), EVP_CTRL_GCM_GET_TAG, sizeof(local_tag), local_tag) != 1) {
            return {};
        }

        memcpy(tag, local_tag, tag_length);
    }

    return output;
}

static std::vector<SEC_BYTE> opensslRsaCrypt(TestKey key, Sec_CipherAlgorithm algorithm, Sec_CipherMode mode,
        const std::vector<SEC_BYTE>& input) {

    std::shared_ptr<RSA> rsa(TestCreds::asOpenSslRsa(key), RSA_free);
    if (rsa == nullptr) {
        SEC_LOG_ERROR("TestCreds::asOpenSslRsa failed");
        return {};
    }

    int padding;
    if (algorithm == SEC_CIPHERALGORITHM_RSA_PKCS1_PADDING) {
        padding = RSA_PKCS1_PADDING;
    } else {
        padding = RSA_PKCS1_OAEP_PADDING;
    }

    int openssl_res;
    std::vector<SEC_BYTE> output;
    output.resize(RSA_size(rsa.get()));

    if (mode == SEC_CIPHERMODE_ENCRYPT || mode == SEC_CIPHERMODE_ENCRYPT_NATIVEMEM) {
        openssl_res = RSA_public_encrypt(static_cast<int>(input.size()), input.data(), output.data(), rsa.get(),
                padding);
    } else {
        openssl_res = RSA_private_decrypt(static_cast<int>(input.size()), input.data(), output.data(), rsa.get(),
                padding);
    }

    if (openssl_res < 0) {
        SEC_LOG_ERROR("%s", ERR_error_string(ERR_get_error(), nullptr));
        return {};
    }

    output.resize(openssl_res);

    return output;
}

std::vector<SEC_BYTE> cipherOpenSSL(TestKey key, Sec_CipherAlgorithm alg, Sec_CipherMode mode, SEC_BYTE* iv,
        const std::vector<SEC_BYTE>& input) {

    switch (alg) {
        case SEC_CIPHERALGORITHM_AES_CBC_NO_PADDING:
        case SEC_CIPHERALGORITHM_AES_CBC_PKCS7_PADDING:
            return opensslAesCbc(key, mode, alg == SEC_CIPHERALGORITHM_AES_CBC_PKCS7_PADDING, iv, input);

        case SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING:
        case SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING:
            return opensslAesEcb(key, mode, alg == SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING, iv, input);

        case SEC_CIPHERALGORITHM_AES_CTR:
            return opensslAesCtr(key, mode, iv, input);

        case SEC_CIPHERALGORITHM_RSA_PKCS1_PADDING:
        case SEC_CIPHERALGORITHM_RSA_OAEP_PADDING:
            return opensslRsaCrypt(key, alg, mode, input);

        default:
            break;
    }

    SEC_LOG_ERROR("Unimplemented");
    return {};
}

std::vector<SEC_BYTE> cipherSecApi(TestCtx* ctx, Sec_KeyHandle* keyHandle, Sec_CipherAlgorithm alg,
        Sec_CipherMode mode, const std::vector<SEC_BYTE>& iv, const std::vector<SEC_BYTE>& input,
        const std::vector<SEC_SIZE>& inputSizes, SEC_BOOL inplace) {

    std::vector<SEC_BYTE> output = input;
    output.resize(input.size() + BUFFER_SIZE);

    SEC_SIZE inputProcessed = 0;
    SEC_SIZE outputWritten = 0;
    SEC_SIZE written = 0;

    Sec_CipherHandle* cipherHandle = ctx->acquireCipher(alg, mode, keyHandle, const_cast<SEC_BYTE*>(iv.data()));
    if (cipherHandle == nullptr) {
        SEC_LOG_ERROR("TestCtx::acquireCipher failed");
        return {};
    }

    for (unsigned int i = 0; i < inputSizes.size() - 1; ++i) {
        if (inputSizes[i] > 0) {
            Sec_Result result = SecCipher_Process(cipherHandle,
                    const_cast<SEC_BYTE*>(inplace == SEC_TRUE ? &output[inputProcessed] : &input[inputProcessed]),
                    inputSizes[i], SEC_FALSE, &output[outputWritten], output.size() - outputWritten, &written);
            if (result != SEC_RESULT_SUCCESS) {
                SEC_LOG_ERROR("SecCipher_Process failed");
                return {};
            }

            outputWritten += written;
        }

        inputProcessed += inputSizes[i];
    }

    //last input
    Sec_Result result = SecCipher_Process(cipherHandle,
            const_cast<SEC_BYTE*>(inplace == SEC_TRUE ? &output[inputProcessed] : &input[inputProcessed]),
            input.size() - inputProcessed, SEC_TRUE, &output[outputWritten], output.size() - outputWritten, &written);
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecCipher_Process failed");
        return {};
    }

    outputWritten += written;
    output.resize(outputWritten);
    ctx->releaseCipher(cipherHandle);
    return output;
}

std::vector<SEC_BYTE> cipherSecApiSingle(TestCtx* ctx, Sec_KeyHandle* keyHandle, Sec_CipherAlgorithm alg,
        Sec_CipherMode mode, const std::vector<SEC_BYTE>& iv, const std::vector<SEC_BYTE>& input, SEC_BOOL inplace) {

    std::vector<SEC_BYTE> output = input;
    output.resize(input.size() + BUFFER_SIZE);

    SEC_SIZE written = 0;

    Sec_CipherHandle* cipherHandle = ctx->acquireCipher(alg, mode, keyHandle, const_cast<SEC_BYTE*>(iv.data()));
    if (cipherHandle == nullptr) {
        SEC_LOG_ERROR("TestCtx::acquireCipher failed");
        return {};
    }

    if (SecCipher_Process(cipherHandle, const_cast<SEC_BYTE*>(inplace == SEC_TRUE ? output.data() : input.data()),
                input.size(), SEC_TRUE, output.data(), output.size(), &written) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecCipher_Process failed");
        return {};
    }

    output.resize(written);

    ctx->releaseCipher(cipherHandle);

    return output;
}

std::vector<SEC_BYTE> cipherSecApiSingle(TestCtx* ctx, Sec_CipherHandle* cipherHandle, const std::vector<SEC_BYTE>& iv,
        const std::vector<SEC_BYTE>& input, SEC_BOOL inplace) {

    std::vector<SEC_BYTE> output = input;
    output.resize(input.size() + BUFFER_SIZE);

    SEC_SIZE written = 0;

    if (!iv.empty()) {
        if (SecCipher_UpdateIV(cipherHandle, const_cast<SEC_BYTE*>(iv.data())) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecCipher_UpdateIV failed");
            return {};
        }
    }

    Sec_Result result = SecCipher_Process(cipherHandle,
            const_cast<SEC_BYTE*>(inplace == SEC_TRUE ? output.data() : input.data()), input.size(), SEC_FALSE,
            output.data(), output.size(), &written);
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecCipher_Process failed");
        return {};
    }

    output.resize(written);

    return output;
}

Sec_Result testCipherSingle(SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc, Sec_CipherAlgorithm alg,
        Sec_CipherMode mode, SEC_SIZE inputSize, SEC_BOOL inplace) {

    std::vector<SEC_SIZE> inputSizes;
    inputSizes.resize(1);
    inputSizes[0] = inputSize;

    return testCipherMult(id, key, kc, loc, alg, mode, inputSizes, inplace);
}

Sec_Result testCtrRollover(SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc, Sec_CipherMode mode,
        SEC_SIZE inputSize, SEC_BOOL inplace) {

    std::vector<SEC_SIZE> inputSizes;
    inputSizes.resize(3);
    inputSizes[0] = 16;
    inputSize -= inputSizes[0];
    inputSizes[1] = 16;
    inputSize -= inputSizes[1];
    inputSizes[2] = inputSize;

    return testCipherMult(id, key, kc, loc, SEC_CIPHERALGORITHM_AES_CTR, mode, inputSizes, inplace, SEC_TRUE);
}

Sec_Result testCipherSingle(SEC_OBJECTID id, TestKey pub, TestKey priv, TestKc kc, Sec_StorageLoc loc,
        Sec_CipherAlgorithm alg, Sec_CipherMode mode, SEC_SIZE inputSize, SEC_BOOL inplace) {

    std::vector<SEC_SIZE> inputSizes;
    inputSizes.resize(1);
    inputSizes[0] = inputSize;

    return testCipherMult(id, pub, priv, kc, loc, alg, mode, inputSizes, inplace);
}

Sec_Result testCipherMult(SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc, Sec_CipherAlgorithm alg,
        Sec_CipherMode mode, const std::vector<SEC_SIZE>& inputSizes, SEC_BOOL inplace,
        SEC_BOOL testCtrRollover) {

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

    std::vector<SEC_BYTE> openssl_key = TestCreds::asOpenSslAes(key);
    TestCtx::printHex("key", openssl_key);

    //gen iv
    std::vector<SEC_BYTE> iv = TestCtx::random(SEC_AES_BLOCK_SIZE);
    if (alg == SEC_CIPHERALGORITHM_AES_CTR && testCtrRollover == SEC_TRUE) {
        //set iv to rollover
        memset(&iv[8], 0xff, 8);
    }

    TestCtx::printHex("iv", iv);

    //mode
    bool testEncrypt = (mode == SEC_CIPHERMODE_ENCRYPT || mode == SEC_CIPHERMODE_ENCRYPT_NATIVEMEM);

    //gen clear input
    std::vector<SEC_BYTE> clear = TestCtx::random(TestCtx::coalesceInputSizes(inputSizes));
    TestCtx::printHex("clear", clear);

    //encrypt
    std::vector<SEC_BYTE> encrypted;
    if (testEncrypt) {
        encrypted = cipherSecApi(&ctx, keyHandle, alg, SEC_CIPHERMODE_ENCRYPT, iv, clear, inputSizes, inplace);
    } else {
        //use openssl to encrypt
        encrypted = cipherOpenSSL(key, alg, SEC_CIPHERMODE_ENCRYPT, iv.data(), clear);
    }

    TestCtx::printHex("encrypted", encrypted);

    //decrypt
    std::vector<SEC_BYTE> decrypted;
    if (testEncrypt) {
        //use openssl to decrypt
        decrypted = cipherOpenSSL(key, alg, SEC_CIPHERMODE_DECRYPT, iv.data(), encrypted);
    } else {
        //use sec api to decrypt
        decrypted = cipherSecApi(&ctx, keyHandle, alg, SEC_CIPHERMODE_DECRYPT, iv, encrypted, inputSizes, inplace);
    }

    TestCtx::printHex("decrypted", decrypted);

    //check if results match
    if (clear != decrypted) {
        SEC_LOG_ERROR("Results do not match");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result testCipherMult(SEC_OBJECTID id, TestKey pub, TestKey priv, TestKc kc, Sec_StorageLoc loc,
        Sec_CipherAlgorithm alg, Sec_CipherMode mode, const std::vector<SEC_SIZE>& inputSizes, SEC_BOOL inplace) {

    TestCtx ctx;

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    //mode
    bool testEncrypt = (mode == SEC_CIPHERMODE_ENCRYPT || mode == SEC_CIPHERMODE_ENCRYPT_NATIVEMEM);

    Sec_KeyHandle* keyHandle;
    if (testEncrypt) {
        if ((keyHandle = ctx.provisionKey(id, loc, pub, kc)) == nullptr) {
            SEC_LOG_ERROR("ctx.provisionKey failed");
            return SEC_RESULT_FAILURE;
        }
    } else {
        if ((keyHandle = ctx.provisionKey(id, loc, priv, kc)) == nullptr) {
            SEC_LOG_ERROR("ctx.provisionKey failed");
            return SEC_RESULT_FAILURE;
        }
    }

    //gen iv
    std::vector<SEC_BYTE> iv = TestCtx::random(SEC_AES_BLOCK_SIZE);
    TestCtx::printHex("iv", iv);

    //gen clear input
    std::vector<SEC_BYTE> clear = TestCtx::random(TestCtx::coalesceInputSizes(inputSizes));
    TestCtx::printHex("clear", clear);

    //encrypt
    std::vector<SEC_BYTE> encrypted;
    if (testEncrypt) {
        encrypted = cipherSecApi(&ctx, keyHandle, alg, SEC_CIPHERMODE_ENCRYPT, iv, clear, inputSizes, inplace);
    } else {
        //use openssl to encrypt
        encrypted = cipherOpenSSL(pub, alg, SEC_CIPHERMODE_ENCRYPT, iv.data(), clear);
    }

    TestCtx::printHex("encrypted", encrypted);

    //decrypt
    std::vector<SEC_BYTE> decrypted;
    if (testEncrypt) {
        //use openssl to decrypt
        decrypted = cipherOpenSSL(priv, alg, SEC_CIPHERMODE_DECRYPT, iv.data(), encrypted);
    } else {
        //use sec api to decrypt
        decrypted = cipherSecApi(&ctx, keyHandle, alg, SEC_CIPHERMODE_DECRYPT, iv, encrypted, inputSizes, inplace);
    }

    TestCtx::printHex("decrypted", decrypted);

    //check if results match
    if (clear != decrypted) {
        SEC_LOG_ERROR("Results do not match");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result cipherEncDecSingle(TestCtx* ctx, SEC_OBJECTID id, Sec_CipherAlgorithm alg, SEC_SIZE inputSize,
        SEC_BOOL inplace) {

    std::vector<SEC_SIZE> inputSizes;
    inputSizes.resize(1);
    inputSizes[0] = inputSize;

    Sec_Result result = cipherEncDecMult(ctx, id, alg, inputSizes, inplace);
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("CipherEncDecMult failed");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result cipherEncDecSingle(TestCtx* ctx, SEC_OBJECTID id_pub, SEC_OBJECTID id_priv, Sec_CipherAlgorithm alg,
        SEC_SIZE inputSize, SEC_BOOL inplace) {

    std::vector<SEC_SIZE> inputSizes;
    inputSizes.resize(1);
    inputSizes[0] = inputSize;

    Sec_Result result = cipherEncDecMult(ctx, id_pub, id_priv, alg, inputSizes, inplace);
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("CipherEncDecMult failed");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result cipherEncDecMult(TestCtx* ctx, SEC_OBJECTID id, Sec_CipherAlgorithm alg,
        const std::vector<SEC_SIZE>& inputSizes, SEC_BOOL inplace) {

    //gen iv
    std::vector<SEC_BYTE> iv = TestCtx::random(SEC_AES_BLOCK_SIZE);
    TestCtx::printHex("iv", iv);

    //gen clear input
    std::vector<SEC_BYTE> clear = TestCtx::random(TestCtx::coalesceInputSizes(inputSizes));
    TestCtx::printHex("clear", clear);

    //encrypt
    std::vector<SEC_BYTE> encrypted = cipherSecApi(ctx, ctx->getKey(id), alg, SEC_CIPHERMODE_ENCRYPT, iv, clear,
            inputSizes, inplace);
    if (encrypted.empty()) {
        SEC_LOG_ERROR("CipherSecApi failed");
        return SEC_RESULT_FAILURE;
    }
    TestCtx::printHex("encrypted", encrypted);

    //decrypt
    std::vector<SEC_BYTE> decrypted = cipherSecApi(ctx, ctx->getKey(id), alg, SEC_CIPHERMODE_DECRYPT, iv, encrypted,
            inputSizes, inplace);
    if (decrypted.empty()) {
        SEC_LOG_ERROR("CipherSecApi failed");
        return SEC_RESULT_FAILURE;
    }

    TestCtx::printHex("decrypted", decrypted);

    //check if results match
    if (clear != decrypted) {
        SEC_LOG_ERROR("Results do not match");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result cipherEncDecMult(TestCtx* ctx, SEC_OBJECTID id_pub, SEC_OBJECTID id_priv, Sec_CipherAlgorithm alg,
        const std::vector<SEC_SIZE>& inputSizes, SEC_BOOL inplace) {

    //gen clear input
    std::vector<SEC_BYTE> clear = TestCtx::random(TestCtx::coalesceInputSizes(inputSizes));
    TestCtx::printHex("clear", clear);

    //encrypt
    std::vector<SEC_BYTE> encrypted = cipherSecApi(ctx, ctx->getKey(id_pub), alg, SEC_CIPHERMODE_ENCRYPT,
            {}, clear, inputSizes, inplace);
    if (encrypted.empty()) {
        SEC_LOG_ERROR("CipherSecApi failed");
        return SEC_RESULT_FAILURE;
    }

    TestCtx::printHex("encrypted", encrypted);

    //decrypt
    std::vector<SEC_BYTE> decrypted = cipherSecApi(ctx, ctx->getKey(id_priv), alg, SEC_CIPHERMODE_DECRYPT,
            {}, encrypted, inputSizes, inplace);
    if (decrypted.empty()) {
        SEC_LOG_ERROR("CipherSecApi failed");
        return SEC_RESULT_FAILURE;
    }

    TestCtx::printHex("decrypted", decrypted);

    //check if results match
    if (clear != decrypted) {
        SEC_LOG_ERROR("Results do not match");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result testCipherBandwidth(SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc, Sec_CipherAlgorithm alg,
        Sec_CipherMode mode, SEC_SIZE inputSize, SEC_SIZE intervalS) {

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

    //gen iv
    std::vector<SEC_BYTE> iv = TestCtx::random(SEC_AES_BLOCK_SIZE);
    TestCtx::printHex("iv", iv);

    //mode
    bool testEncrypt = (mode == SEC_CIPHERMODE_ENCRYPT || mode == SEC_CIPHERMODE_ENCRYPT_NATIVEMEM);

    //gen clear input
    std::vector<SEC_BYTE> clear = TestCtx::random(inputSize);
    TestCtx::printHex("clear", clear);

    //encrypt
    std::vector<SEC_BYTE> encrypted;
    time_t start_t = 0;
    time_t end_t = 0;
    int loops = 0;
    if (testEncrypt) {
        start_t = time(nullptr);
        end_t = start_t;

        while ((end_t - start_t) < static_cast<int>(intervalS)) {
            encrypted = cipherSecApiSingle(&ctx, keyHandle, alg, SEC_CIPHERMODE_ENCRYPT, iv, clear, SEC_FALSE);
            ++loops;
            end_t = time(nullptr);
        }
    } else {
        //use openssl to encrypt
        encrypted = cipherOpenSSL(key, alg, SEC_CIPHERMODE_ENCRYPT, &iv[0], clear);
    }

    TestCtx::printHex("encrypted", encrypted);

    //decrypt
    std::vector<SEC_BYTE> decrypted;
    if (testEncrypt) {
        //use openssl to decrypt
        decrypted = cipherOpenSSL(key, alg, SEC_CIPHERMODE_DECRYPT, &iv[0], encrypted);
    } else {
        start_t = time(nullptr);
        end_t = start_t;

        while ((end_t - start_t) < static_cast<int>(intervalS)) {
            decrypted = cipherSecApiSingle(&ctx, keyHandle, alg, SEC_CIPHERMODE_DECRYPT, iv, encrypted, SEC_FALSE);
            ++loops;
            end_t = time(nullptr);
        }
    }

    TestCtx::printHex("decrypted", decrypted);

    //check if results match
    if (clear != decrypted) {
        SEC_LOG_ERROR("Results do not match");
        return SEC_RESULT_FAILURE;
    }

    //print timing data
    SEC_PRINT("Data processed: %d MB\n", (inputSize * loops) / (1024 * 1024));
    SEC_PRINT("Time elapsed: %d s\n", end_t - start_t);
    if (end_t != start_t) {
        SEC_PRINT("Bandwidth: %d MB/s\n",
                ((inputSize * loops) / (1024 * 1024)) / (end_t - start_t));
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result testCipherBandwidthSingleCipher(SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc,
        Sec_CipherAlgorithm alg, Sec_CipherMode mode, SEC_SIZE inputSize,
        SEC_SIZE intervalS) {

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

    //gen iv
    std::vector<SEC_BYTE> iv = TestCtx::random(SEC_AES_BLOCK_SIZE);
    TestCtx::printHex("iv", iv);

    //mode
    bool testEncrypt = (mode == SEC_CIPHERMODE_ENCRYPT || mode == SEC_CIPHERMODE_ENCRYPT_NATIVEMEM);

    //gen clear input
    std::vector<SEC_BYTE> clear = TestCtx::random(inputSize);
    TestCtx::printHex("clear", clear);

    //encrypt
    std::vector<SEC_BYTE> encrypted;
    time_t start_t = 0;
    time_t end_t = 0;
    int loops = 0;
    if (testEncrypt) {
        start_t = time(nullptr);
        end_t = start_t;

        Sec_CipherHandle* cipherHandle = ctx.acquireCipher(alg, mode, keyHandle, &iv[0]);
        if (cipherHandle == nullptr) {
            SEC_LOG_ERROR("TestCtx::acquireCipher failed");
            return SEC_RESULT_FAILURE;
        }

        while ((end_t - start_t) < static_cast<int>(intervalS)) {
            encrypted = cipherSecApiSingle(&ctx, cipherHandle, iv, clear, SEC_FALSE);
            ++loops;
            end_t = time(nullptr);
        }
    } else {
        //use openssl to encrypt
        encrypted = cipherOpenSSL(key, alg, SEC_CIPHERMODE_ENCRYPT, &iv[0], clear);
    }

    //decrypt
    std::vector<SEC_BYTE> decrypted;
    if (testEncrypt) {
        //use openssl to decrypt
        decrypted = cipherOpenSSL(key, alg, SEC_CIPHERMODE_DECRYPT, &iv[0], encrypted);
    } else {
        start_t = time(nullptr);
        end_t = start_t;

        Sec_CipherHandle* cipherHandle = ctx.acquireCipher(alg, mode, keyHandle, &iv[0]);
        if (cipherHandle == nullptr) {
            SEC_LOG_ERROR("TestCtx::acquireCipher failed");
            return SEC_RESULT_FAILURE;
        }

        while ((end_t - start_t) < static_cast<int>(intervalS)) {
            decrypted = cipherSecApiSingle(&ctx, cipherHandle, iv, encrypted, SEC_FALSE);
            ++loops;
            end_t = time(nullptr);
        }
    }

    //print timing data
    SEC_PRINT("Data processed: %d MB\n", (inputSize * loops) / (1024 * 1024));
    SEC_PRINT("Time elapsed: %d s\n", end_t - start_t);
    if (end_t != start_t) {
        SEC_PRINT("Bandwidth: %d MB/s\n",
                ((inputSize * loops) / (1024 * 1024)) / (end_t - start_t));
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result testCipherUpdateIV(SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc, Sec_CipherAlgorithm alg,
        Sec_CipherMode mode, SEC_SIZE inputSize, SEC_BOOL inplace) {

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

    //gen ivs
    std::vector<SEC_BYTE> iv1 = TestCtx::random(SEC_AES_BLOCK_SIZE);
    TestCtx::printHex("iv1", iv1);
    std::vector<SEC_BYTE> iv2 = TestCtx::random(SEC_AES_BLOCK_SIZE);
    TestCtx::printHex("iv2", iv2);

    //mode
    bool testEncrypt = (mode == SEC_CIPHERMODE_ENCRYPT || mode == SEC_CIPHERMODE_ENCRYPT_NATIVEMEM);

    //gen clear input
    std::vector<SEC_BYTE> clear = TestCtx::random(inputSize);
    TestCtx::printHex("clear", clear);

    //encrypt
    std::vector<SEC_BYTE> encrypted1;
    std::vector<SEC_BYTE> encrypted2;
    if (testEncrypt) {
        Sec_CipherHandle* cipherHandle = ctx.acquireCipher(alg, SEC_CIPHERMODE_ENCRYPT, keyHandle, &iv1[0]);
        if (cipherHandle == nullptr) {
            SEC_LOG_ERROR("TestCtx::acquireCipher failed");
            return SEC_RESULT_FAILURE;
        }

        encrypted1 = cipherSecApiSingle(&ctx, cipherHandle, iv1, clear, SEC_FALSE);
        if (encrypted1.empty()) {
            SEC_LOG_ERROR("CipherSecApiSingle failed");
            return SEC_RESULT_FAILURE;
        }
        encrypted2 = cipherSecApiSingle(&ctx, cipherHandle, iv2, clear, SEC_FALSE);
        if (encrypted2.empty()) {
            SEC_LOG_ERROR("CipherSecApiSingle failed");
            return SEC_RESULT_FAILURE;
        }
    } else {
        //use openssl to encrypt
        encrypted1 = cipherOpenSSL(key, alg, SEC_CIPHERMODE_ENCRYPT, &iv1[0], clear);
        if (encrypted1.empty()) {
            SEC_LOG_ERROR("CipherOpenSSL failed");
            return SEC_RESULT_FAILURE;
        }
        encrypted2 = cipherOpenSSL(key, alg, SEC_CIPHERMODE_ENCRYPT, &iv2[0], clear);
        if (encrypted2.empty()) {
            SEC_LOG_ERROR("CipherOpenSSL failed");
            return SEC_RESULT_FAILURE;
        }
    }

    TestCtx::printHex("encrypted1", encrypted1);
    TestCtx::printHex("encrypted2", encrypted2);

    //decrypt
    std::vector<SEC_BYTE> decrypted1;
    std::vector<SEC_BYTE> decrypted2;
    if (testEncrypt) {
        //use openssl to decrypt
        decrypted1 = cipherOpenSSL(key, alg, SEC_CIPHERMODE_DECRYPT, &iv1[0], encrypted1);
        if (decrypted1.empty()) {
            SEC_LOG_ERROR("CipherOpenSSL failed");
            return SEC_RESULT_FAILURE;
        }
        decrypted2 = cipherOpenSSL(key, alg, SEC_CIPHERMODE_DECRYPT, &iv2[0], encrypted2);
        if (decrypted2.empty()) {
            SEC_LOG_ERROR("CipherOpenSSL failed");
            return SEC_RESULT_FAILURE;
        }
    } else {
        //use sec api to decrypt
        Sec_CipherHandle* cipherHandle = ctx.acquireCipher(alg, SEC_CIPHERMODE_DECRYPT, keyHandle, &iv1[0]);
        if (cipherHandle == nullptr) {
            SEC_LOG_ERROR("TestCtx::acquireCipher failed");
            return SEC_RESULT_FAILURE;
        }

        decrypted1 = cipherSecApiSingle(&ctx, cipherHandle, iv1, encrypted1, SEC_FALSE);
        if (decrypted1.empty()) {
            SEC_LOG_ERROR("CipherSecApiSingle failed");
            return SEC_RESULT_FAILURE;
        }
        decrypted2 = cipherSecApiSingle(&ctx, cipherHandle, iv2, encrypted2, SEC_FALSE);
        if (decrypted2.empty()) {
            SEC_LOG_ERROR("CipherSecApiSingle failed");
            return SEC_RESULT_FAILURE;
        }
    }

    TestCtx::printHex("decrypted1", decrypted1);
    TestCtx::printHex("decrypted2", decrypted2);

    //check if results match
    if (clear != decrypted1 || clear != decrypted2 || encrypted1 == encrypted2) {
        SEC_LOG_ERROR("Results do not match");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

std::vector<SEC_BYTE> cipherSecApiCtrSubBlock(TestCtx* ctx, Sec_KeyHandle* keyHandle, Sec_CipherMode mode,
        const std::vector<SEC_BYTE>& iv, const std::vector<SEC_BYTE>& input, SEC_BOOL inplace) {

    std::vector<SEC_BYTE> output = input;
    output.resize(input.size() + BUFFER_SIZE);

    SEC_SIZE inputProcessed = 0;
    SEC_SIZE outputWritten = 0;
    SEC_SIZE written = 0;

    Sec_CipherHandle* cipherHandle = ctx->acquireCipher(SEC_CIPHERALGORITHM_AES_CTR, mode, keyHandle,
            const_cast<SEC_BYTE*>(&iv[0]));
    if (cipherHandle == nullptr) {
        SEC_LOG_ERROR("TestCtx::acquireCipher failed");
        return {};
    }

    //calculate the offset and make sure it is not on the SEC_AES_BLOCK_SIZE boundary
    SEC_SIZE split_offset = input.size() / 2;
    if (split_offset % SEC_AES_BLOCK_SIZE == 0) {
        split_offset -= 1;
    }

    SEC_PRINT("init ctr: %d\n", Sec_BEBytesToUint64(const_cast<SEC_BYTE*>(&iv[8])));
    uint64_t init_counter = Sec_BEBytesToUint64(const_cast<SEC_BYTE*>(&iv[8]));

    if (SecCipher_Process(cipherHandle, const_cast<SEC_BYTE*>(inplace == SEC_TRUE ? &output[0] : &input[0]),
                split_offset, SEC_FALSE, &output[0], output.size(), &written) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecCipher_Process failed");
        return {};
    }

    outputWritten += written;
    inputProcessed += split_offset;

    //set the iv
    uint64_t counter;
    counter = init_counter + split_offset / SEC_AES_BLOCK_SIZE;
    Sec_Uint64ToBEBytes(counter, const_cast<SEC_BYTE*>(&iv[8]));

    SEC_PRINT("updated ctr: %d\n", Sec_BEBytesToUint64(const_cast<SEC_BYTE*>(&iv[8])));

    /* TODO
    if (SecCipher_UpdateIV(cipherHandle, (SEC_BYTE*) &iv[0]) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecCipher_UpdateIV failed");
        return {};
    }
    */

    //last input
    Sec_Result result = SecCipher_ProcessCtrWithDataShift(cipherHandle,
            const_cast<SEC_BYTE*>(inplace == SEC_TRUE ? &output[inputProcessed] : &input[inputProcessed]),
            input.size() - inputProcessed, &output[outputWritten], output.size() - outputWritten, &written,
            split_offset % SEC_AES_BLOCK_SIZE);
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecCipher_Process failed");
        return {};
    }

    outputWritten += written;

    output.resize(outputWritten);

    ctx->releaseCipher(cipherHandle);

    return output;
}

Sec_Result testProcessCtrWithDataShift(SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc, Sec_CipherMode mode,
        SEC_BOOL inplace) {
#if 0 // Feature not implemented in SecApi 2 Adapter
    TestCtx ctx;

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    Sec_KeyHandle *keyHandle = nullptr;
    if ((keyHandle = ctx.provisionKey(id, loc, key, kc)) == nullptr) {
        SEC_LOG_ERROR("ctx.provisionKey failed");
        return SEC_RESULT_FAILURE;
    }

    //gen iv
    std::vector<SEC_BYTE> iv = TestCtx::random(SEC_AES_BLOCK_SIZE);
    TestCtx::printHex("iv", iv);

    /* TODO
    //set the counter to ff to test rollover
    memset(&iv[8], 0xff, 8);
    */

    //mode
    SEC_BOOL testEncrypt = (mode == SEC_CIPHERMODE_ENCRYPT || mode == SEC_CIPHERMODE_ENCRYPT_NATIVEMEM);

    //gen clear input
    std::vector<SEC_BYTE> clear = TestCtx::random(SEC_AES_BLOCK_SIZE * 3);
    TestCtx::printHex("clear", clear);

    //encrypt
    std::vector<SEC_BYTE> encrypted;
    std::vector<SEC_BYTE> ivCopy = iv;
    if (testEncrypt) {
        encrypted = cipherSecApiCtrSubBlock(&ctx, keyHandle, SEC_CIPHERMODE_ENCRYPT, ivCopy, clear, inplace);
    } else {
        //use openssl to encrypt
        encrypted = cipherOpenSSL(key, SEC_CIPHERALGORITHM_AES_CTR, SEC_CIPHERMODE_ENCRYPT, &ivCopy[0], clear);
    }

    TestCtx::printHex("encrypted", encrypted);
    TestCtx::printHex("iv", iv);

    //decrypt
    std::vector<SEC_BYTE> decrypted;
    if (testEncrypt) {
        //use openssl to decrypt
        decrypted = cipherOpenSSL(key, SEC_CIPHERALGORITHM_AES_CTR, SEC_CIPHERMODE_DECRYPT, &iv[0], encrypted);
    } else {
        //use sec api to decrypt
        decrypted = cipherSecApiCtrSubBlock(&ctx, keyHandle, SEC_CIPHERMODE_DECRYPT, iv, encrypted, inplace);
    }

    TestCtx::printHex("decrypted", decrypted);

    //check if results match
    if (clear != decrypted) {
        SEC_LOG_ERROR("Results do not match");
        return SEC_RESULT_FAILURE;
    }
#endif
    return SEC_RESULT_SUCCESS;
}

Sec_Result testProcessOpaqueWithMap(SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc,
        Sec_CipherAlgorithm alg, SEC_SIZE subsampleCount, SEC_SIZE bytesOfClearData) {
    TestCtx ctx;

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    Sec_KeyHandle* keyHandle = nullptr;
    if ((keyHandle = ctx.provisionKey(id, loc, key, kc)) == nullptr) {
        SEC_LOG_ERROR("ctx.provisionKey failed");
        return SEC_RESULT_FAILURE;
    }

    //gen iv
    std::vector<SEC_BYTE> iv = TestCtx::random(SEC_AES_BLOCK_SIZE);
    TestCtx::printHex("iv", iv);

    //gen clear input
    std::vector<SEC_BYTE> clear = TestCtx::random(SUBSAMPLE_SIZE * subsampleCount);
    TestCtx::printHex("clear", clear);

    //encrypt
    std::vector<SEC_BYTE> encrypted;
    std::vector<SEC_BYTE> ivCopy = iv;

    //use openssl to encrypt
    std::vector<SEC_BYTE> temp;
    for (size_t i = 0; i < subsampleCount; i++) {
        temp.insert(temp.end(),
                clear.begin() + static_cast<int64_t>(i * SUBSAMPLE_SIZE + bytesOfClearData),
                clear.begin() + static_cast<int64_t>((i + 1) * SUBSAMPLE_SIZE));
    }

    std::vector<SEC_BYTE> encryptedTemp = cipherOpenSSL(key, alg, SEC_CIPHERMODE_ENCRYPT, &ivCopy[0], temp);
    SEC_SIZE bytesOfProtectedData = SUBSAMPLE_SIZE - bytesOfClearData;
    for (size_t i = 0; i < subsampleCount; i++) {
        encrypted.insert(encrypted.end(),
                clear.begin() + static_cast<int64_t>(i * SUBSAMPLE_SIZE),
                clear.begin() + static_cast<int64_t>(i * SUBSAMPLE_SIZE + bytesOfClearData));
        encrypted.insert(encrypted.end(),
                encryptedTemp.begin() + static_cast<int64_t>(i * bytesOfProtectedData),
                encryptedTemp.begin() + static_cast<int64_t>((i + 1) * bytesOfProtectedData));
    }

    TestCtx::printHex("encrypted", encrypted);
    TestCtx::printHex("iv", iv);

    Sec_CipherHandle* cipherHandle = ctx.acquireCipher(alg, SEC_CIPHERMODE_DECRYPT, keyHandle, &iv[0]);
    if (cipherHandle == nullptr) {
        SEC_LOG_ERROR("TestCtx::acquireCipher failed");
        return SEC_RESULT_FAILURE;
    }

    auto* map = new SEC_MAP[subsampleCount];
    if (map == nullptr) {
        SEC_LOG_ERROR("malloc failed");
        return SEC_RESULT_FAILURE;
    }

    for (SEC_SIZE i = 0; i < subsampleCount; i++) {
        map[i].clear = bytesOfClearData;
        map[i].encrypted = SUBSAMPLE_SIZE - bytesOfClearData;
    }

    //decrypt
    std::vector<SEC_BYTE> decrypted;
    Sec_OpaqueBufferHandle* opaqueBufferHandle;
    SEC_SIZE bytesWritten = 0;
    Sec_Result result = SecCipher_ProcessOpaqueWithMap(cipherHandle, iv.data(), encrypted.data(), encrypted.size(),
            SEC_TRUE, map, subsampleCount, &opaqueBufferHandle, &bytesWritten);
    if (result != SEC_RESULT_SUCCESS) {
        delete[] map;
        SEC_LOG_ERROR("SecCipher_ProcessOpaqueWithMap failed");
        return result;
    }

    delete[] map;
    SecOpaqueBuffer_Free(opaqueBufferHandle);
    return result;
}

Sec_Result testProcessOpaqueWithMapVariable(SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc,
        Sec_CipherAlgorithm alg) {
    TestCtx ctx;

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    Sec_KeyHandle* keyHandle = nullptr;
    if ((keyHandle = ctx.provisionKey(id, loc, key, kc)) == nullptr) {
        SEC_LOG_ERROR("ctx.provisionKey failed");
        return SEC_RESULT_FAILURE;
    }

    size_t subsampleCount = 5;
    size_t bytesOfClearDataCtr[5] = {0, 16, 20, 50, 256};
    size_t bytesOfClearDataCbc[5] = {0, 16, 32, 48, 256};
    size_t* bytesOfClearData =
            (alg == SEC_CIPHERALGORITHM_AES_CBC_NO_PADDING) ? bytesOfClearDataCbc : bytesOfClearDataCtr;

    //gen iv
    std::vector<SEC_BYTE> iv = TestCtx::random(SEC_AES_BLOCK_SIZE);
    TestCtx::printHex("iv", iv);

    //gen clear input
    std::vector<SEC_BYTE> clear = TestCtx::random(SUBSAMPLE_SIZE * subsampleCount);
    TestCtx::printHex("clear", clear);

    //encrypt
    std::vector<SEC_BYTE> encrypted;
    std::vector<SEC_BYTE> ivCopy = iv;

    //use openssl to encrypt
    std::vector<SEC_BYTE> temp;
    for (size_t i = 0; i < subsampleCount; i++) {
        temp.insert(temp.end(),
                clear.begin() + static_cast<int64_t>(i * SUBSAMPLE_SIZE + bytesOfClearData[i]),
                clear.begin() + static_cast<int64_t>((i + 1) * SUBSAMPLE_SIZE));
    }

    std::vector<SEC_BYTE> encryptedTemp = cipherOpenSSL(key, alg, SEC_CIPHERMODE_ENCRYPT, &ivCopy[0], temp);
    int64_t pos = 0;
    for (size_t i = 0; i < subsampleCount; i++) {
        SEC_SIZE bytesOfProtectedData = SUBSAMPLE_SIZE - bytesOfClearData[i];
        encrypted.insert(encrypted.end(),
                clear.begin() + static_cast<int64_t>(i * SUBSAMPLE_SIZE),
                clear.begin() + static_cast<int64_t>(i * SUBSAMPLE_SIZE + bytesOfClearData[i]));
        encrypted.insert(encrypted.end(),
                encryptedTemp.begin() + pos,
                encryptedTemp.begin() + pos + bytesOfProtectedData);
        pos += bytesOfProtectedData;
    }

    TestCtx::printHex("encrypted", encrypted);
    TestCtx::printHex("iv", iv);

    Sec_CipherHandle* cipherHandle = ctx.acquireCipher(alg, SEC_CIPHERMODE_DECRYPT, keyHandle, &iv[0]);
    if (cipherHandle == nullptr) {
        SEC_LOG_ERROR("TestCtx::acquireCipher failed");
        return SEC_RESULT_FAILURE;
    }

    auto* map = new SEC_MAP[subsampleCount];
    if (map == nullptr) {
        SEC_LOG_ERROR("malloc failed");
        return SEC_RESULT_FAILURE;
    }

    for (SEC_SIZE i = 0; i < subsampleCount; i++) {
        map[i].clear = bytesOfClearData[i];
        map[i].encrypted = SUBSAMPLE_SIZE - bytesOfClearData[i];
    }

    //decrypt
    std::vector<SEC_BYTE> decrypted;
    Sec_OpaqueBufferHandle* opaqueBufferHandle;
    SEC_SIZE bytesWritten = 0;
    Sec_Result result = SecCipher_ProcessOpaqueWithMap(cipherHandle, iv.data(), encrypted.data(), encrypted.size(),
            SEC_TRUE, map, subsampleCount, &opaqueBufferHandle, &bytesWritten);
    if (result != SEC_RESULT_SUCCESS) {
        delete[] map;
        SEC_LOG_ERROR("SecCipher_ProcessOpaqueWithMap failed");
        return result;
    }

    delete[] map;
    SecOpaqueBuffer_Free(opaqueBufferHandle);
    return result;
}

Sec_Result aesKeyCheck(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID id, SEC_BYTE* key, SEC_SIZE key_len) {
    SEC_PRINT("--- aes key check ---\n");

    std::vector<SEC_BYTE> clear = TestCtx::random(SEC_AES_BLOCK_SIZE);
    TestCtx::printHex("clear", clear);

    std::vector<SEC_BYTE> cipher_secapi;
    cipher_secapi.resize(SEC_AES_BLOCK_SIZE);
    SEC_SIZE cipher_secapi_len;

    if (SecCipher_SingleInputId(processorHandle, SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, SEC_CIPHERMODE_ENCRYPT, id,
                nullptr, &clear[0], clear.size(), &cipher_secapi[0], cipher_secapi.size(), &cipher_secapi_len) !=
            SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecCipher_SingleInputId failed");
        return SEC_RESULT_FAILURE;
    }
    cipher_secapi.resize(cipher_secapi_len);
    TestCtx::printHex("cipher_secapi", cipher_secapi);

    std::vector<SEC_BYTE> openssl_key = std::vector<SEC_BYTE>(key, key + key_len);

    std::vector<SEC_BYTE> cipher_ssl = opensslAesEcb(openssl_key, SEC_CIPHERMODE_ENCRYPT, SEC_FALSE, nullptr, clear);

    TestCtx::printHex("cipher_ssl", cipher_ssl);

    SEC_PRINT("---------------------\n");

    //check if results match
    if (cipher_secapi != cipher_ssl) {
        SEC_LOG_ERROR("Results do not match");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}
