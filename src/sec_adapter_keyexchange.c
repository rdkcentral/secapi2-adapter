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
        SEC_LOG_ERROR("Calloc failed");
        return SEC_RESULT_FAILURE;
    }

    sa_status status = sa_key_generate(keyExchangeHandle->key, &rights, type, keyExchangeHandle->parameters);
    CHECK_STATUS(status)
    size_t out_length = pubKeySize;
    SEC_BYTE public_key_bytes[BUFFER_SIZE];
    status = sa_key_get_public(&public_key_bytes, &out_length, *keyExchangeHandle->key);
    CHECK_STATUS(status)

    Sec_ECCRawPublicKey ecc_raw_public_key;
    switch (keyExchangeHandle->alg) {
        case SEC_KEYEXCHANGE_DH:
            memcpy(publicKey, &public_key_bytes, out_length);
            break;

        case SEC_KEYEXCHANGE_ECDH:
            Sec_Uint32ToBEBytes(out_length / 2, ecc_raw_public_key.key_len);
            memcpy(ecc_raw_public_key.x, &public_key_bytes[0], out_length / 2);
            memcpy(ecc_raw_public_key.y, &public_key_bytes[out_length / 2], out_length / 2);
            ecc_raw_public_key.type = SEC_KEYTYPE_ECC_NISTP256_PUBLIC;
            memcpy(publicKey, &ecc_raw_public_key, sizeof(ecc_raw_public_key));
            break;

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

    if (!SecKey_IsSymetric(typeComputed)) {
        SEC_LOG_ERROR("Invalid key type encountered: %d", typeComputed);
        return SEC_RESULT_FAILURE;
    }

    // Set rights to derive only.  SecApi 3.0 only allows a secret to be generated that can be fed into a derivation
    // algorithm.  It does not truncate the key to the typeComputed key type like is specified in SecApi 2.  So disable
    // the ability to sign, decrypt, encrypt, or unwrap.
    sa_key_exchange_algorithm algorithm;
    sa_rights rights;
    rights_set_allow_all(&rights, SEC_KEYTYPE_NUM);

    SEC_BYTE public_key_bytes[BUFFER_SIZE];
    uint32_t key_len;
    Sec_KeyContainer key_container;
    switch (keyExchangeHandle->alg) {
        case SEC_KEYEXCHANGE_DH:
            algorithm = SA_KEY_EXCHANGE_ALGORITHM_DH;
            memcpy(&public_key_bytes, otherPublicKey, otherPublicKeySize);
            key_len = otherPublicKeySize;

            // The resulting key is actually the length of the p value.  We just need a key container that will trigger
            // the key to be exported and the result will be an exported key container, so pick the largest RSA key.
            key_container = SEC_KEYCONTAINER_DER_RSA_3072;
            break;

        case SEC_KEYEXCHANGE_ECDH:
            algorithm = SA_KEY_EXCHANGE_ALGORITHM_ECDH;
            if (otherPublicKeySize != sizeof(Sec_ECCRawPublicKey)) {
                SEC_LOG_ERROR("Invalid ECC key");
                return SEC_RESULT_FAILURE;
            }

            Sec_ECCRawPublicKey* ecc_raw_public_key = (Sec_ECCRawPublicKey*) otherPublicKey;
            key_len = Sec_BEBytesToUint32(ecc_raw_public_key->key_len) * 2;
            memcpy(&public_key_bytes[0], ecc_raw_public_key->x, key_len / 2);
            memcpy(&public_key_bytes[key_len / 2], ecc_raw_public_key->y, key_len / 2);

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
