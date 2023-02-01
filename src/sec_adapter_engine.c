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

#include "sec_security.h"
#include <openssl/engine.h>
#include <pthread.h>

#define SECAPI_ENGINE_ID "securityapi"

static SEC_BOOL g_sec_openssl_inited = SEC_FALSE;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
static RSA_METHOD* rsa_method = NULL;
#endif

static void Sec_ShutdownOpenSSL() {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    if (rsa_method != NULL) {
        RSA_meth_free(rsa_method);
        rsa_method = NULL;
    }
#endif

    ENGINE* engine = ENGINE_by_id(SECAPI_ENGINE_ID);
    if (engine != NULL) {
        ENGINE_remove(engine);
        ENGINE_finish(engine);
        ENGINE_free(engine);
    }
}

static int Sec_OpenSSLPrivSign(int type, const unsigned char* m, unsigned int m_len, unsigned char* sigret,
        unsigned int* siglen, const RSA* rsa) {
    Sec_KeyHandle* keyHandle = NULL;
    Sec_SignatureAlgorithm alg;
    switch (type) {
        case NID_sha1:
            alg = SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS_DIGEST;
            break;

        case NID_sha256:
            alg = SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS_DIGEST;
            break;

        default:
            SEC_LOG_ERROR("Unknown type %d", type);
            return -1;
    }

    keyHandle = (Sec_KeyHandle*) RSA_get_app_data(rsa);
    if (keyHandle == NULL) {
        SEC_LOG_ERROR("NULL keyHandle encountered");
        return -1;
    }

    if (SecSignature_SingleInput(SecKey_GetProcessor(keyHandle), alg, SEC_SIGNATUREMODE_SIGN, keyHandle,
                (SEC_BYTE*) m, m_len, (SEC_BYTE*) sigret, siglen) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecSignature_SingleInput failed");
        return -1;
    }

    return 1;
}

static int Sec_OpenSSLPubVerify(int type, const unsigned char* m, unsigned int m_len, const unsigned char* sigret,
        unsigned int siglen, const RSA* rsa) {
    Sec_KeyHandle* keyHandle = NULL;
    Sec_SignatureAlgorithm alg;
    switch (type) {
        case NID_sha1:
            alg = SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS;
            break;

        case NID_sha256:
            alg = SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS;
            break;

        default:
            SEC_LOG_ERROR("Unknown type %d", type);
            return -1;
    }

    keyHandle = (Sec_KeyHandle*) RSA_get_app_data(rsa);
    if (keyHandle == NULL) {
        SEC_LOG_ERROR("NULL keyHandle encountered");
        return -1;
    }

    if (SecSignature_SingleInput(SecKey_GetProcessor(keyHandle), alg, SEC_SIGNATUREMODE_VERIFY, keyHandle,
                (SEC_BYTE*) m, m_len, (SEC_BYTE*) sigret, &siglen) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecSignature_SingleInput failed");
        return -1;
    }

    return 1;
}

static int Sec_OpenSSLPubEncrypt(int flen, const unsigned char* from, unsigned char* to, RSA* rsa, int padding) {
    Sec_KeyHandle* keyHandle = NULL;
    Sec_CipherAlgorithm alg;
    SEC_SIZE written;
    switch (padding) {
        case RSA_PKCS1_PADDING:
            alg = SEC_CIPHERALGORITHM_RSA_PKCS1_PADDING;
            break;

        case RSA_PKCS1_OAEP_PADDING:
            alg = SEC_CIPHERALGORITHM_RSA_OAEP_PADDING;
            break;

        default:
            SEC_LOG_ERROR("Unknown padding %d", padding);
            return -1;
    }

    keyHandle = (Sec_KeyHandle*) RSA_get_app_data(rsa);
    if (keyHandle == NULL) {
        SEC_LOG_ERROR("NULL keyHandle encountered");
        return -1;
    }

    if (SecCipher_SingleInput(SecKey_GetProcessor(keyHandle), alg, SEC_CIPHERMODE_ENCRYPT, keyHandle, NULL,
                (SEC_BYTE*) from, flen, (SEC_BYTE*) to, SecKey_GetKeyLen(keyHandle), &written) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecSignature_SingleInput failed");
        return -1;
    }

    return (int) written;
}

static int Sec_OpenSSLPrivDecrypt(int flen, const unsigned char* from, unsigned char* to, RSA* rsa, int padding) {
    Sec_KeyHandle* keyHandle = NULL;
    Sec_CipherAlgorithm alg;
    SEC_SIZE written;
    switch (padding) {
        case RSA_PKCS1_PADDING:
            alg = SEC_CIPHERALGORITHM_RSA_PKCS1_PADDING;
            break;

        case RSA_PKCS1_OAEP_PADDING:
            alg = SEC_CIPHERALGORITHM_RSA_OAEP_PADDING;
            break;

        default:
            SEC_LOG_ERROR("Unknown padding %d", padding);
            return -1;
    }

    keyHandle = (Sec_KeyHandle*) RSA_get_app_data(rsa);
    if (keyHandle == NULL) {
        SEC_LOG_ERROR("NULL keyHandle encountered");
        return -1;
    }

    if (SecCipher_SingleInput(SecKey_GetProcessor(keyHandle), alg, SEC_CIPHERMODE_DECRYPT, keyHandle, NULL,
                (SEC_BYTE*) from, flen, (SEC_BYTE*) to, SecKey_GetKeyLen(keyHandle), &written) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecSignature_SingleInput failed");
        return -1;
    }

    return (int) written;
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L

static RSA_METHOD g_sec_openssl_rsamethod = {
        "securityapi RSA method",
        Sec_OpenSSLPubEncrypt,                                            // rsa_pub_enc
        NULL,                                                             // rsa_pub_dec
        NULL,                                                             // rsa_priv_enc
        Sec_OpenSSLPrivDecrypt,                                           // rsa_priv_dec
        NULL,                                                             // rsa_mod_exp
        NULL,                                                             // bn_mod_exp
        NULL,                                                             // init
        NULL,                                                             // finish
        RSA_METHOD_FLAG_NO_CHECK | RSA_FLAG_EXT_PKEY | RSA_FLAG_SIGN_VER, // flags
        NULL,                                                             // app_data
        Sec_OpenSSLPrivSign,                                              // rsa_sign
        Sec_OpenSSLPubVerify,                                             // rsa_verify
        NULL,                                                             // rsa_keygen
};

#endif

static void ENGINE_load_securityapi(void) {
    ENGINE* engine = ENGINE_new();
    if (engine == NULL) {
        SEC_LOG_ERROR("ENGINE_new failed");
        return;
    }

    if (!ENGINE_set_id(engine, SECAPI_ENGINE_ID)) {
        SEC_LOG_ERROR("ENGINE_set_id failed");
        ENGINE_free(engine);
        return;
    }
    if (!ENGINE_set_name(engine, "SecurityApi engine")) {
        SEC_LOG_ERROR("ENGINE_set_name failed");
        ENGINE_free(engine);
        return;
    }

    if (!ENGINE_init(engine)) {
        SEC_LOG_ERROR("ENGINE_init failed");
        ENGINE_free(engine);
        return;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    if (!ENGINE_set_RSA(engine, &g_sec_openssl_rsamethod)) {
#else
    if (rsa_method == NULL) {
        rsa_method = RSA_meth_new("securityapi RSA method", RSA_METHOD_FLAG_NO_CHECK | RSA_FLAG_EXT_PKEY);
        if (rsa_method == NULL) {
            SEC_LOG_ERROR("RSA_meth_new failed");
            ENGINE_free(engine);
            return;
        }

        RSA_meth_set_pub_enc(rsa_method, Sec_OpenSSLPubEncrypt);
        RSA_meth_set_priv_dec(rsa_method, Sec_OpenSSLPrivDecrypt);
        RSA_meth_set_sign(rsa_method, Sec_OpenSSLPrivSign);
        RSA_meth_set_verify(rsa_method, Sec_OpenSSLPubVerify);
    }

    if (!ENGINE_set_RSA(engine, rsa_method)) {
#endif
        ENGINE_remove(engine);
        ENGINE_free(engine);
        return;
    }

    ENGINE_add(engine);
    ENGINE_free(engine);
    ERR_clear_error();
}

void Sec_InitOpenSSL() {
    static pthread_mutex_t init_openssl_mutex = PTHREAD_MUTEX_INITIALIZER;

    pthread_mutex_lock(&init_openssl_mutex);

    if (g_sec_openssl_inited != SEC_TRUE) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        ERR_load_crypto_strings();
        OpenSSL_add_all_algorithms();
        OpenSSL_add_all_ciphers();
        OpenSSL_add_all_digests();
#endif
        ENGINE_load_builtin_engines();
        ENGINE_register_all_complete();
        ENGINE* engine = ENGINE_by_id(OPENSSL_ENGINE_ID);
        if (engine == NULL) {
            ENGINE_load_openssl();
            engine = ENGINE_by_id(OPENSSL_ENGINE_ID);
            if (engine == NULL) {
                SEC_LOG_ERROR("ENGINE_load_openssl failed");
                return;
            }

            ENGINE_set_default(engine, ENGINE_METHOD_ALL);
            ENGINE_free(engine);
        }
        ENGINE_load_securityapi();

        if (atexit(Sec_ShutdownOpenSSL) != 0) {
            SEC_LOG_ERROR("atexit failed");
            return;
        }

        g_sec_openssl_inited = SEC_TRUE;
    }

    pthread_mutex_unlock(&init_openssl_mutex);
}

void Sec_PrintOpenSSLVersion() {
    SEC_PRINT("Built against: %s\n", OPENSSL_VERSION_TEXT);
    SEC_PRINT("Running against: %s\n", SSLeay_version(SSLEAY_VERSION));
}

RSA* SecKey_ToEngineRSA(Sec_KeyHandle* keyHandle) {
    Sec_RSARawPublicKey pubKey;
    RSA* rsa = NULL;
    ENGINE* engine = NULL;

    engine = ENGINE_by_id(SECAPI_ENGINE_ID);
    if (engine == NULL) {
        SEC_LOG_ERROR("ENGINE_by_id failed");
        return NULL;
    }

    if (SEC_RESULT_SUCCESS != SecKey_ExtractRSAPublicKey(keyHandle, &pubKey)) {
        ENGINE_free(engine);
        SEC_LOG_ERROR("SecKey_ExtractRSAPublicKey failed");
        return NULL;
    }

    rsa = RSA_new_method(engine);
    if (rsa == NULL) {
        ENGINE_free(engine);
        SEC_LOG_ERROR("RSA_new_method failed");
        return NULL;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    rsa->n = BN_bin2bn(pubKey.n, (int) Sec_BEBytesToUint32(pubKey.modulus_len_be), NULL);
    rsa->e = BN_bin2bn(pubKey.e, 4, NULL);
#else
    RSA_set0_key(rsa, BN_bin2bn(pubKey.n, (int) Sec_BEBytesToUint32(pubKey.modulus_len_be), NULL),
            BN_bin2bn(pubKey.e, 4, NULL), NULL);
#endif

    RSA_set_app_data(rsa, keyHandle);
    ENGINE_free(engine);
    return rsa;
}

RSA* SecKey_ToEngineRSAWithCert(Sec_KeyHandle* keyHandle, Sec_CertificateHandle* certificateHandle) {
    Sec_RSARawPublicKey pubKey;
    RSA* rsa = NULL;
    ENGINE* engine = NULL;

    engine = ENGINE_by_id(SECAPI_ENGINE_ID);
    if (engine == NULL) {
        SEC_LOG_ERROR("ENGINE_by_id failed");
        return NULL;
    }

    if (SEC_RESULT_SUCCESS != SecCertificate_ExtractRSAPublicKey(certificateHandle, &pubKey)) {
        ENGINE_free(engine);
        SEC_LOG_ERROR("SecKey_ExtractRSAPublicKey failed");
        return NULL;
    }

    rsa = RSA_new_method(engine);
    if (rsa == NULL) {
        ENGINE_free(engine);
        SEC_LOG_ERROR("RSA_new_method failed");
        return NULL;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    rsa->n = BN_bin2bn(pubKey.n, (int) Sec_BEBytesToUint32(pubKey.modulus_len_be), NULL);
    rsa->e = BN_bin2bn(pubKey.e, 4, NULL);
#else
    RSA_set0_key(rsa, BN_bin2bn(pubKey.n, (int) Sec_BEBytesToUint32(pubKey.modulus_len_be), NULL),
            BN_bin2bn(pubKey.e, 4, NULL), NULL);
#endif

    RSA_set_app_data(rsa, keyHandle);
    ENGINE_free(engine);
    return rsa;
}

EC_KEY* SecKey_ToEngineEcc(Sec_KeyHandle* keyHandle) {
    SEC_LOG_ERROR("SecKey_ToEngineEcc is not implemented");
    return NULL;
}
