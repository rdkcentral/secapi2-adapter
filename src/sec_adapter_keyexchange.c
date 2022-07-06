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

#include "sa.h"
#include "sec_adapter_key.h"
#include "sec_adapter_processor.h"
#include "sec_security.h"
#include <memory.h>

#define BUFFER_SIZE 4096

struct Sec_KeyExchangeHandle_struct {
    Sec_ProcessorHandle* processorHandle;
    Sec_KeyExchangeAlgorithm alg;
    void* parameters;
    sa_key* key;
};

Sec_Result SecKeyExchange_GetInstance(Sec_ProcessorHandle* processorHandle, Sec_KeyExchangeAlgorithm exchangeType,
        void* exchangeParameters, Sec_KeyExchangeHandle** keyExchangeHandle) {
    CHECK_PROCHANDLE(processorHandle)

    if (keyExchangeHandle == NULL) {
        SEC_LOG_ERROR("NULL keyExchangeHandle");
        return SEC_RESULT_INVALID_PARAMETERS;
    }

    if (exchangeParameters == NULL) {
        SEC_LOG_ERROR("NULL exchangeParameters");
        return SEC_RESULT_INVALID_PARAMETERS;
    }

    *keyExchangeHandle = NULL;
    sa_generate_parameters_dh* dh_parameters = NULL;
    sa_generate_parameters_ec* ec_parameters = NULL;

    switch (exchangeType) {
        case SEC_KEYEXCHANGE_DH:
            dh_parameters = calloc(1, sizeof(sa_generate_parameters_dh));
            if (dh_parameters == NULL) {
                SEC_LOG_ERROR("Calloc failed");
                return SEC_RESULT_FAILURE;
            }

            Sec_DHParameters* sec_dh_parameters = (Sec_DHParameters*) exchangeParameters;
            dh_parameters->g = sec_dh_parameters->g;
            dh_parameters->g_length = sec_dh_parameters->gLen;
            dh_parameters->p = sec_dh_parameters->p;
            dh_parameters->p_length = sec_dh_parameters->pLen;
            break;

        case SEC_KEYEXCHANGE_ECDH:
            if (((Sec_ECDHParameters*) exchangeParameters)->curve != NISTP256) {
                SEC_LOG_ERROR("Unknown EC curve");
                return SEC_RESULT_INVALID_PARAMETERS;
            }

            ec_parameters = calloc(1, sizeof(sa_generate_parameters_ec));
            if (ec_parameters == NULL) {
                SEC_LOG_ERROR("Calloc failed");
                return SEC_RESULT_FAILURE;
            }

            ec_parameters->curve = SA_ELLIPTIC_CURVE_NIST_P256;
            break;

        default:
            SEC_LOG_ERROR("Unknown exchange_type encountered: %d", exchangeType);
            return SEC_RESULT_INVALID_PARAMETERS;
    }

    *keyExchangeHandle = calloc(1, sizeof(Sec_KeyExchangeHandle));
    if (*keyExchangeHandle == NULL) {
        SEC_FREE(dh_parameters);
        SEC_FREE(ec_parameters);
        SEC_LOG_ERROR("Calloc failed");
        return SEC_RESULT_FAILURE;
    }

    (*keyExchangeHandle)->processorHandle = processorHandle;
    (*keyExchangeHandle)->alg = exchangeType;
    (*keyExchangeHandle)->parameters = dh_parameters != NULL ? (void*) dh_parameters : (void*) ec_parameters;

    return *keyExchangeHandle != NULL ? SEC_RESULT_SUCCESS : SEC_RESULT_FAILURE;
}

Sec_Result SecKeyExchange_GenerateKeys(Sec_KeyExchangeHandle* keyExchangeHandle, SEC_BYTE* publicKey,
        SEC_SIZE pubKeySize) {
    CHECK_HANDLE(keyExchangeHandle)
    if (publicKey == NULL) {
        SEC_LOG_ERROR("NULL publicKey");
        return SEC_RESULT_INVALID_PARAMETERS;
    }

    sa_key_type type;
    sa_rights rights;
    switch (keyExchangeHandle->alg) {
        case SEC_KEYEXCHANGE_DH:
            type = SA_KEY_TYPE_DH;
            rights_set_allow_all(&rights, SEC_KEYTYPE_RSA_1024);
            break;

        case SEC_KEYEXCHANGE_ECDH:
            type = SA_KEY_TYPE_EC;
            rights_set_allow_all(&rights, SEC_KEYTYPE_ECC_NISTP256);
            break;

        default:
            SEC_LOG_ERROR("Invalid key exchange type");
            return SEC_RESULT_FAILURE;
    }

    keyExchangeHandle->key = calloc(1, sizeof(sa_key));
    if (keyExchangeHandle->key == NULL) {
        SEC_LOG_ERROR("calloc failed");
        return SEC_RESULT_FAILURE;
    }

    sa_status status = sa_key_generate(keyExchangeHandle->key, &rights, type, keyExchangeHandle->parameters);
    CHECK_STATUS(status)
    size_t out_length = BUFFER_SIZE;
    SEC_BYTE public_key_bytes[BUFFER_SIZE];
    status = sa_key_get_public(&public_key_bytes, &out_length, *keyExchangeHandle->key);
    CHECK_STATUS(status)

    switch (keyExchangeHandle->alg) {
        case SEC_KEYEXCHANGE_DH: {
            EVP_PKEY* evp_pkey;
            const unsigned char* p = public_key_bytes;
            evp_pkey = d2i_PUBKEY(NULL, &p, (long) out_length);
            if (evp_pkey == NULL) {
                SEC_LOG_ERROR("d2i_PUBKEY failed");
                return SEC_RESULT_FAILURE;
            }

            DH* dh = EVP_PKEY_get1_DH(evp_pkey);
            if (dh == NULL) {
                EVP_PKEY_free(evp_pkey);
                SEC_LOG_ERROR("EVP_PKEY_get0_DH failed");
                return SEC_RESULT_FAILURE;
            }

#if OPENSSL_VERSION_NUMBER >= 0x10100000
            const BIGNUM* dh_public_key = DH_get0_pub_key(dh);
#else
            const BIGNUM* dh_public_key = dh->pub_key;
#endif
            if (dh_public_key == NULL) {
                EVP_PKEY_free(evp_pkey);
                DH_free(dh);
                SEC_LOG_ERROR("DH_get0_pub_key failed");
                return SEC_RESULT_FAILURE;
            }

            if (SecUtils_BigNumToBuffer(dh_public_key, publicKey, pubKeySize) != SEC_RESULT_SUCCESS) {
                EVP_PKEY_free(evp_pkey);
                DH_free(dh);
                SEC_LOG_ERROR("SecUtils_BigNumToBuffer failed");
                return SEC_RESULT_FAILURE;
            }

            EVP_PKEY_free(evp_pkey);
            DH_free(dh);
            break;
        }
        case SEC_KEYEXCHANGE_ECDH: {
            Sec_ECCRawPublicKey ecc_raw_public_key;
            if (Pubops_ExtractECCPubFromPUBKEYDer(public_key_bytes, out_length, &ecc_raw_public_key) != SEC_RESULT_SUCCESS) {
                SEC_LOG_ERROR("Pubops_ExtractECCPubFromPUBKEYDer failed");
                return SEC_RESULT_FAILURE;
            }

            memcpy(publicKey, &ecc_raw_public_key, sizeof(ecc_raw_public_key));
            break;
        }
        default:
            SEC_LOG_ERROR("Invalid key exchange type");
            return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result SecKeyExchange_ComputeSecret(Sec_KeyExchangeHandle* keyExchangeHandle, SEC_BYTE* otherPublicKey,
        SEC_SIZE otherPublicKeySize, Sec_KeyType typeComputed, SEC_OBJECTID idComputed,
        Sec_StorageLoc locComputed) {
    CHECK_HANDLE(keyExchangeHandle)
    if (keyExchangeHandle->key == NULL) {
        SEC_LOG_ERROR("NULL keyExchangeHandle->key");
        return SEC_RESULT_INVALID_PARAMETERS;
    }

    if (otherPublicKey == NULL) {
        SEC_LOG_ERROR("NULL otherPublicKey");
        return SEC_RESULT_INVALID_PARAMETERS;
    }

    if (!SecKey_IsSymmetric(typeComputed)) {
        SEC_LOG_ERROR("Invalid key type encountered: %d", typeComputed);
        return SEC_RESULT_FAILURE;
    }

    // Set rights to derive only.  SecApi 3.0 only allows a secret to be generated that can be fed into a derivation
    // algorithm.  It does not truncate the key to the typeComputed key type like is specified in SecApi 2.  So disable
    // the ability to sign, decrypt, encrypt, or unwrap.
    sa_key_exchange_algorithm algorithm;
    sa_rights rights;
    rights_set_allow_all(&rights, SEC_KEYTYPE_NUM);

    SEC_BYTE* public_key_bytes;
    uint32_t key_len;
    Sec_KeyContainer key_container;
    switch (keyExchangeHandle->alg) {
        case SEC_KEYEXCHANGE_DH: {
            sa_header header;
            sa_status status = sa_key_header(&header, *keyExchangeHandle->key);
            CHECK_STATUS(status)

            algorithm = SA_KEY_EXCHANGE_ALGORITHM_DH;
            BIGNUM* dh_pub_key = BN_bin2bn(otherPublicKey, (int) otherPublicKeySize, NULL);
            if (dh_pub_key == NULL) {
                SEC_LOG_ERROR("BN_bin2bn failed");
                return SEC_RESULT_FAILURE;
            }

            BIGNUM* dh_p = BN_bin2bn(header.type_parameters.dh_parameters.p,
                    (int) header.type_parameters.dh_parameters.p_length, NULL);
            if (dh_p == NULL) {
                SEC_LOG_ERROR("BN_bin2bn failed");
                BN_free(dh_pub_key);
                return SEC_RESULT_FAILURE;
            }

            BIGNUM* dh_g = BN_bin2bn(header.type_parameters.dh_parameters.g,
                    (int) header.type_parameters.dh_parameters.g_length, NULL);
            if (dh_g == NULL) {
                SEC_LOG_ERROR("BN_bin2bn failed");
                BN_free(dh_pub_key);
                BN_free(dh_p);
                return SEC_RESULT_FAILURE;
            }

            DH* dh = DH_new();
#if OPENSSL_VERSION_NUMBER >= 0x10100000
            if (DH_set0_pqg(dh, dh_p, NULL, dh_g) != 1) {
                SEC_LOG_ERROR("DH_set0_pqg failed");
                BN_free(dh_pub_key);
                BN_free(dh_p);
                BN_free(dh_g);
                DH_free(dh);
                return SEC_RESULT_FAILURE;
            }

            if (DH_set0_key(dh, dh_pub_key, NULL) != 1) {
                SEC_LOG_ERROR("DH_set0_key failed");
                BN_free(dh_pub_key);
                DH_free(dh);
                return SEC_RESULT_FAILURE;
            }
#else
            dh->p = dh_p;
            dh->g = dh_g;
            dh->pub_key = dh_pub_key;
#endif

            EVP_PKEY* evp_pkey = EVP_PKEY_new();
            if (evp_pkey == NULL) {
                SEC_LOG_ERROR("EVP_PKEY_new failed");
                DH_free(dh);
                return SEC_RESULT_FAILURE;
            }

            if (EVP_PKEY_assign_DH(evp_pkey, dh) != 1) {
                SEC_LOG_ERROR("EVP_PKEY_assign_DH failed");
                DH_free(dh);
                EVP_PKEY_free(evp_pkey);
                return SEC_RESULT_FAILURE;
            }

            key_len = i2d_PUBKEY(evp_pkey, NULL);
            if (key_len <= 0) {
                SEC_LOG_ERROR("i2d_PUBKEY failed");
                EVP_PKEY_free(evp_pkey);
                return SEC_RESULT_FAILURE;
            }

            public_key_bytes = malloc(key_len);
            if (public_key_bytes == NULL) {
                SEC_LOG_ERROR("malloc failed");
                EVP_PKEY_free(evp_pkey);
                return SEC_RESULT_FAILURE;
            }

            unsigned char* p_public_key_bytes = public_key_bytes;
            key_len = i2d_PUBKEY(evp_pkey, &p_public_key_bytes);
            EVP_PKEY_free(evp_pkey);
            if (key_len <= 0) {
                SEC_LOG_ERROR("i2d_PUBKEY failed");
                free(public_key_bytes);
                return SEC_RESULT_FAILURE;
            }

            // The resulting key is actually the length of the p value.  We just need a key container that will trigger
            // the key to be exported and the result will be an exported key container, so pick a pkcs8 key.
            key_container = SEC_KEYCONTAINER_PKCS8;
            break;
        }
        case SEC_KEYEXCHANGE_ECDH:
            algorithm = SA_KEY_EXCHANGE_ALGORITHM_ECDH;
            if (otherPublicKeySize != sizeof(Sec_ECCRawPublicKey)) {
                SEC_LOG_ERROR("Invalid ECC key");
                return SEC_RESULT_FAILURE;
            }

            if (Pubops_ExtractECCPubToPUBKEYDer((Sec_ECCRawPublicKey*) otherPublicKey, &public_key_bytes, &key_len) != SEC_RESULT_SUCCESS) {
                SEC_LOG_ERROR("Can only derive symmetric keys");
                return SEC_RESULT_FAILURE;
            }

            // The resulting secret is actually a valid AES 256 key.  We just need a key container that will trigger
            // the key to be exported and the result will be an exported key container, so just use AES_256.
            key_container = SEC_KEYCONTAINER_RAW_AES_256;
            break;

        default:
            SEC_LOG_ERROR("Unknown alg encountered: %d", keyExchangeHandle->alg);
            return SEC_RESULT_FAILURE;
    }

    sa_key shared_secret;
    sa_status status = sa_key_exchange(&shared_secret, &rights, algorithm, *keyExchangeHandle->key, public_key_bytes,
            key_len, NULL);
    free(public_key_bytes);
    CHECK_STATUS(status)

    Sec_Key key = {.handle = shared_secret};
    return prepare_and_store_key_data(keyExchangeHandle->processorHandle, locComputed, idComputed, &key, key_container,
            NULL, 0);
}

Sec_Result SecKeyExchange_Release(Sec_KeyExchangeHandle* keyExchangeHandle) {
    if (keyExchangeHandle != NULL) {
        if (keyExchangeHandle->key != NULL)
            sa_key_release(*keyExchangeHandle->key);

        SEC_FREE(keyExchangeHandle->parameters);
        SEC_FREE(keyExchangeHandle->key);
        SEC_FREE(keyExchangeHandle);
    }

    return SEC_RESULT_SUCCESS;
}
