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

#include "sec_adapter_key.h" // NOLINT
#include "sec_adapter_cipher.h"
#include "sec_adapter_key_legacy.h"
#include "sec_adapter_processor.h"
#include <stdbool.h>
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#include <openssl/pem.h>
#endif

#ifndef SEC_TRACE_UNWRAP
#define SEC_TRACE_UNWRAP 0
#endif

#if SEC_TRACE_UNWRAP
#pragma message "SEC_TRACE_UNWRAP is enabled.  Please disable in production builds."
#endif

#define CHECK_MAC_RESULT(status, base_key, mac_context) \
    if ((status) != SA_STATUS_OK) { \
        if ((mac_context) != 0) \
            sa_crypto_mac_release(mac_context); \
        sa_key_release(base_key); \
        return SEC_RESULT_FAILURE; \
    }

#define PUBLIC_KEY_BUFFER_SIZE 4
#define ISO_TIME_SIZE 24

struct Sec_KeyHandle_struct {
    Sec_ProcessorHandle* processorHandle;
    Sec_KeyType key_type;
    Sec_Key key;
};

static void find_ram_key_data(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID object_id, Sec_RAMKeyData** data,
        Sec_RAMKeyData** parent);

static Sec_Result retrieve_key_data(Sec_ProcessorHandle* processorHandle,
        SEC_OBJECTID object_id, Sec_StorageLoc* location, Sec_KeyData* keyData);

static Sec_Result store_key_data(Sec_ProcessorHandle* processorHandle, Sec_StorageLoc location, SEC_OBJECTID object_id,
        Sec_KeyData* key_data);

static Sec_Result process_key_container(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID object_id,
        Sec_KeyContainer in_key_container, void* data, SEC_SIZE data_length, Sec_Key* key,
        Sec_KeyContainer* out_key_container, void* key_buffer, SEC_SIZE* key_length);

static Sec_Result process_rsa_key_container(Sec_KeyContainer in_key_container, SEC_BYTE* data,
        SEC_SIZE data_length, unsigned char* key_buffer, SEC_SIZE* key_length, Sec_KeyContainer* key_container);

static Sec_Result process_rsa_public_key_container(Sec_KeyContainer in_key_container, SEC_BYTE* data,
        SEC_SIZE data_length, RSA** rsa, unsigned char* key_buffer, SEC_SIZE* key_length,
        Sec_KeyContainer* out_key_container);

static Sec_Result process_ec_key_container(Sec_KeyContainer in_key_container, SEC_BYTE* data,
        SEC_SIZE data_length, unsigned char* key_buffer, SEC_SIZE* key_length, Sec_KeyContainer* out_key_container);

static Sec_Result process_ec_public_key_container(Sec_KeyContainer in_key_container, SEC_BYTE* data,
        SEC_SIZE data_length, EC_KEY** ec_key, unsigned char* key_buffer, SEC_SIZE* key_length,
        Sec_KeyContainer* out_key_container);

static Sec_KeyContainer convert_key_container(Sec_KeyContainer key_container);

static int disable_passphrase_prompt(char* buf, int size, int rwflag, void* u);

static Sec_Result process_asn1_key_container(Sec_ProcessorHandle* processorHandle, const void* data,
        SEC_SIZE data_length, SEC_BYTE* key_buffer, SEC_SIZE* key_length, Sec_KeyContainer* key_container);

static Sec_Result process_store_key_container(Sec_ProcessorHandle* processorHandle, void* data,
        SEC_SIZE data_length, SEC_BYTE* key_buffer, SEC_SIZE* key_length, Sec_KeyContainer* key_container);

static Sec_KeyType get_key_type(sa_header* key_header);

static Sec_Result derive_root_key_ladder(const SEC_BYTE* c1, const SEC_BYTE* c2, const SEC_BYTE* c3, const SEC_BYTE* c4,
        SEC_SIZE key_size, sa_key* key, Sec_KeyType key_type);

static Sec_Result derive_base_key(Sec_ProcessorHandle* processorHandle, SEC_BYTE* nonce, sa_key* key,
        Sec_KeyType key_type);

static Sec_Result derive_hkdf(Sec_MacAlgorithm macAlgorithm, Sec_KeyType typeDerived, const SEC_BYTE* salt,
        SEC_SIZE saltSize, const SEC_BYTE* info, SEC_SIZE infoSize, sa_key baseKey, sa_key* derived_key);

static Sec_Result derive_kdf_concat(Sec_DigestAlgorithm digestAlgorithm, Sec_KeyType typeDerived,
        const SEC_BYTE* otherInfo, SEC_SIZE otherInfoSize, sa_key baseKey, sa_key* derived_key);

static Sec_Result derive_kdf_cmac(Sec_KeyType typeDerived, const SEC_BYTE* otherData, SEC_SIZE otherDataSize,
        const SEC_BYTE* counter, SEC_SIZE counterSize, sa_key baseKey, sa_key* derived_key);

static Sec_Result unwrap_key(Sec_ProcessorHandle* processorHandle, Sec_CipherAlgorithm algorithm,
        Sec_KeyType wrapped_key_type, SEC_SIZE wrapped_key_offset, SEC_OBJECTID id, SEC_BYTE* iv, SEC_BYTE* input,
        SEC_SIZE input_len, SEC_BYTE* out_key, SEC_SIZE* out_key_len);

static Sec_Result get_sa_key_type(Sec_KeyType keyType, sa_key_type* out_key_type, void** parameters);

static Sec_Result export_key(Sec_Key* key, SEC_BYTE* derivationInput, SEC_BYTE* exportedKey, SEC_SIZE keyBufferLen,
        SEC_SIZE* keyBytesWritten);

static bool is_jwt_key_container(unsigned char* key_buffer, SEC_SIZE key_length);

Sec_KeyType SecKey_GetKeyTypeForClearKeyContainer(Sec_KeyContainer kc) {
    switch (kc) {
        case SEC_KEYCONTAINER_RAW_AES_128:
            return SEC_KEYTYPE_AES_128;

        case SEC_KEYCONTAINER_RAW_AES_256:
            return SEC_KEYTYPE_AES_256;

        case SEC_KEYCONTAINER_RAW_HMAC_128:
            return SEC_KEYTYPE_HMAC_128;

        case SEC_KEYCONTAINER_RAW_HMAC_160:
            return SEC_KEYTYPE_HMAC_160;

        case SEC_KEYCONTAINER_RAW_HMAC_256:
            return SEC_KEYTYPE_HMAC_256;

        case SEC_KEYCONTAINER_RAW_RSA_1024:
        case SEC_KEYCONTAINER_PEM_RSA_1024:
        case SEC_KEYCONTAINER_DER_RSA_1024:
            return SEC_KEYTYPE_RSA_1024;

        case SEC_KEYCONTAINER_RAW_RSA_2048:
        case SEC_KEYCONTAINER_PEM_RSA_2048:
        case SEC_KEYCONTAINER_DER_RSA_2048:
            return SEC_KEYTYPE_RSA_2048;

        case SEC_KEYCONTAINER_RAW_RSA_3072:
        case SEC_KEYCONTAINER_PEM_RSA_3072:
        case SEC_KEYCONTAINER_DER_RSA_3072:
            return SEC_KEYTYPE_RSA_3072;

        case SEC_KEYCONTAINER_RAW_RSA_1024_PUBLIC:
        case SEC_KEYCONTAINER_PEM_RSA_1024_PUBLIC:
        case SEC_KEYCONTAINER_DER_RSA_1024_PUBLIC:
            return SEC_KEYTYPE_RSA_1024_PUBLIC;

        case SEC_KEYCONTAINER_RAW_RSA_2048_PUBLIC:
        case SEC_KEYCONTAINER_PEM_RSA_2048_PUBLIC:
        case SEC_KEYCONTAINER_DER_RSA_2048_PUBLIC:
            return SEC_KEYTYPE_RSA_2048_PUBLIC;

        case SEC_KEYCONTAINER_RAW_RSA_3072_PUBLIC:
        case SEC_KEYCONTAINER_PEM_RSA_3072_PUBLIC:
        case SEC_KEYCONTAINER_DER_RSA_3072_PUBLIC:
            return SEC_KEYTYPE_RSA_3072_PUBLIC;

        case SEC_KEYCONTAINER_PEM_ECC_NISTP256:
        case SEC_KEYCONTAINER_RAW_ECC_PRIVONLY_NISTP256:
        case SEC_KEYCONTAINER_RAW_ECC_NISTP256:
        case SEC_KEYCONTAINER_DER_ECC_NISTP256:
            return SEC_KEYTYPE_ECC_NISTP256;

        case SEC_KEYCONTAINER_PEM_ECC_NISTP256_PUBLIC:
        case SEC_KEYCONTAINER_RAW_ECC_NISTP256_PUBLIC:
        case SEC_KEYCONTAINER_DER_ECC_NISTP256_PUBLIC:
            return SEC_KEYTYPE_ECC_NISTP256_PUBLIC;

        default:
            return SEC_KEYTYPE_NUM;
    }
}

SEC_SIZE SecKey_GetKeyLenForKeyType(Sec_KeyType keyType) {
    switch (keyType) {
        case SEC_KEYTYPE_AES_128:
            return 16;

        case SEC_KEYTYPE_AES_256:
            return 32;

        case SEC_KEYTYPE_HMAC_128:
            return 16;

        case SEC_KEYTYPE_HMAC_160:
            return 20;

        case SEC_KEYTYPE_HMAC_256:
            return 32;

        case SEC_KEYTYPE_RSA_1024:
        case SEC_KEYTYPE_RSA_1024_PUBLIC:
            return 128;

        case SEC_KEYTYPE_RSA_2048:
        case SEC_KEYTYPE_RSA_2048_PUBLIC:
            return 256;

        case SEC_KEYTYPE_RSA_3072:
        case SEC_KEYTYPE_RSA_3072_PUBLIC:
            return 384;

        case SEC_KEYTYPE_ECC_NISTP256:
        case SEC_KEYTYPE_ECC_NISTP256_PUBLIC:
            return SEC_ECC_NISTP256_KEY_LEN;

        default:
            SEC_LOG_ERROR("Unknown key type encountered: %d", keyType);
            return 0;
    }
}

/**
 * @brief Get the properties for the key handle.
 *
 * @param keyHandle pointer to Sec_KeyHandle.
 * @param keyProps pointer to Sec_KeyProperties where information is stored.
 */
Sec_Result SecKey_GetProperties(Sec_KeyHandle* keyHandle, Sec_KeyProperties* keyProperties) {
    CHECK_HANDLE(keyHandle)
    Sec_Memset(keyProperties, 0, sizeof(Sec_KeyProperties));

    keyProperties->keyType = keyHandle->key_type;
    sa_rights rights;
    switch (keyHandle->key_type) {
        case SEC_KEYTYPE_AES_128:
        case SEC_KEYTYPE_AES_256:
        case SEC_KEYTYPE_RSA_1024:
        case SEC_KEYTYPE_RSA_2048:
        case SEC_KEYTYPE_HMAC_128:
        case SEC_KEYTYPE_HMAC_160:
        case SEC_KEYTYPE_HMAC_256:
        case SEC_KEYTYPE_ECC_NISTP256:
        case SEC_KEYTYPE_RSA_3072: {
            sa_header key_header;
            sa_status status = sa_key_header(&key_header, keyHandle->key.handle);
            CHECK_STATUS(status)

            rights = key_header.rights;
            keyProperties->keyLength = key_header.size;
            break;
        }
        case SEC_KEYTYPE_RSA_1024_PUBLIC:
        case SEC_KEYTYPE_RSA_2048_PUBLIC:
        case SEC_KEYTYPE_RSA_3072_PUBLIC:
        case SEC_KEYTYPE_ECC_NISTP256_PUBLIC:
            rights_set_allow_all(&rights, keyHandle->key_type);
            keyProperties->keyLength = SecKey_GetKeyLenForKeyType(keyProperties->keyType);
            break;

        default:
            SEC_LOG_ERROR("Unsupported key_type %u", keyHandle->key_type);
            return SEC_RESULT_INVALID_PARAMETERS;
    }

    // Cacheable flag.
    keyProperties->cacheable = SA_USAGE_BIT_TEST(rights.usage_flags, SA_USAGE_FLAG_CACHEABLE) ? SEC_TRUE : SEC_FALSE;

    // Key ID in string format.  SecApi 2 keyId is 40 chars, SecApi 3 keyID is 64 chars.  Truncate to 39 bytes and null
    // terminate.
    memcpy(keyProperties->keyId, rights.id, 39);
    keyProperties->keyId[39] = 0;

    // Validity Period
    SecUtils_Epoch2IsoTime(rights.not_before, keyProperties->notBefore, ISO_TIME_SIZE);
    SecUtils_Epoch2IsoTime(rights.not_on_or_after, keyProperties->notOnOrAfter, ISO_TIME_SIZE);

    // Rights flags
    Sec_Memset(keyProperties->rights, SEC_KEYOUTPUTRIGHT_NOT_SET, sizeof(SEC_BYTE) * SEC_KEYOUTPUTRIGHT_NUM);
    int i = 0;
    // SEC_KEYOUTPUTRIGHT_TRANSCRIPTION_COPY_ALLOWED and SEC_KEYOUTPUTRIGHT_UNRESTRICTED_COPY_ALLOWED are not used in
    // sec api 3.
    if (!SA_USAGE_BIT_TEST(rights.usage_flags, SA_USAGE_FLAG_SVP_OPTIONAL))
        keyProperties->rights[i++] = SEC_KEYOUTPUTRIGHT_SVP_REQUIRED;
    if (SA_USAGE_BIT_TEST(rights.usage_flags, SA_USAGE_FLAG_ALLOWED_DIGITAL_DTCP))
        keyProperties->rights[i++] = SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_DTCP_ALLOWED;
    if (SA_USAGE_BIT_TEST(rights.usage_flags, SA_USAGE_FLAG_ALLOWED_DIGITAL_HDCP14))
        keyProperties->rights[i++] = SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_1_4_ALLOWED;
    if (SA_USAGE_BIT_TEST(rights.usage_flags, SA_USAGE_FLAG_ALLOWED_DIGITAL_HDCP22))
        keyProperties->rights[i++] = SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_2_2_ALLOWED;
    if (SA_USAGE_BIT_TEST(rights.usage_flags, SA_USAGE_FLAG_ALLOWED_ANALOG_CGMSA) ||
            SA_USAGE_BIT_TEST(rights.usage_flags, SA_USAGE_FLAG_ALLOWED_ANALOG_UNPROTECTED))
        keyProperties->rights[i++] = SEC_KEYOUTPUTRIGHT_ANALOG_OUTPUT_ALLOWED;
    if (SA_USAGE_BIT_TEST(rights.usage_flags, SA_USAGE_FLAG_ALLOWED_ANALOG_CGMSA) &&
            !SA_USAGE_BIT_TEST(rights.usage_flags, SA_USAGE_FLAG_ALLOWED_ANALOG_CGMSA))
        keyProperties->rights[i++] = SEC_KEYOUTPUTRIGHT_CGMSA_REQUIRED;

    // Allow usage of both since it is not identified in the key_header.
    // clang-format off
    if (SA_USAGE_BIT_TEST(rights.usage_flags, SA_USAGE_FLAG_UNWRAP) &&
           (SA_USAGE_BIT_TEST(rights.usage_flags, SA_USAGE_FLAG_DECRYPT) ||
            SA_USAGE_BIT_TEST(rights.usage_flags, SA_USAGE_FLAG_ENCRYPT) ||
            SA_USAGE_BIT_TEST(rights.usage_flags, SA_USAGE_FLAG_SIGN) ||
            SA_USAGE_BIT_TEST(rights.usage_flags, SA_USAGE_FLAG_DERIVE))) {
        keyProperties->usage = SEC_KEYUSAGE_DATA_KEY;
    } else if (SA_USAGE_BIT_TEST(rights.usage_flags, SA_USAGE_FLAG_DECRYPT) ||
            SA_USAGE_BIT_TEST(rights.usage_flags, SA_USAGE_FLAG_ENCRYPT) ||
            SA_USAGE_BIT_TEST(rights.usage_flags, SA_USAGE_FLAG_SIGN) ||
            SA_USAGE_BIT_TEST(rights.usage_flags, SA_USAGE_FLAG_DERIVE)) {
        keyProperties->usage = SEC_KEYUSAGE_DATA;
    } else if (SA_USAGE_BIT_TEST(rights.usage_flags, SA_USAGE_FLAG_UNWRAP)) {
        keyProperties->usage = SEC_KEYUSAGE_KEY;
    }
    // clang-format on

    return SEC_RESULT_SUCCESS;
}

/**
 * @brief Get the length of the specified key in bytes.
 *
 * In case of symmetric keys, the length returned is the actual size of the key data.
 * In case of asymmetric keys, the length returned is the size of the modulus in bytes.
 *
 * @param keyHandle key handle.
 *
 * @return The status of the operation.
 */
SEC_SIZE SecKey_GetKeyLen(Sec_KeyHandle* keyHandle) {
    if (keyHandle == NULL) {
        return 0;
    }

    SEC_SIZE key_length;
    sa_header key_header;
    sa_status status;
    switch (keyHandle->key_type) {
        case SEC_KEYTYPE_ECC_NISTP256_PUBLIC:
            return EC_GROUP_get_degree(EC_KEY_get0_group(keyHandle->key.ec_key)) / 8;

        case SEC_KEYTYPE_RSA_1024_PUBLIC:
        case SEC_KEYTYPE_RSA_2048_PUBLIC:
        case SEC_KEYTYPE_RSA_3072_PUBLIC:
            return RSA_size(keyHandle->key.rsa);

        case SEC_KEYTYPE_AES_128:
        case SEC_KEYTYPE_AES_256:
        case SEC_KEYTYPE_RSA_1024:
        case SEC_KEYTYPE_RSA_2048:
        case SEC_KEYTYPE_HMAC_128:
        case SEC_KEYTYPE_HMAC_160:
        case SEC_KEYTYPE_HMAC_256:
        case SEC_KEYTYPE_ECC_NISTP256:
        case SEC_KEYTYPE_RSA_3072:
            status = sa_key_header(&key_header, keyHandle->key.handle);
            if (status != SA_STATUS_OK) {
                return 0;
            }

            return key_header.size;

        default:
            return 0;
    }
}

/**
 * @brief Get the key type of the specified key handle.
 *
 * @param keyHandle key handle.
 *
 * @return The key type or SEC_KEYTYPE_NUM if the key handle is invalid.
 */
Sec_KeyType SecKey_GetKeyType(Sec_KeyHandle* keyHandle) {
    return keyHandle->key_type;
}

/**
 * @brief Obtain a handle to a provisioned key.
 *
 * @param processorHandle secure processor handle.
 * @param object_id id of the provisioned key that we are attempting to obtain.
 * @param keyHandle pointer to the output key handle.
 *
 * @return The status of the operation.
 */
Sec_Result SecKey_GetInstance(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID object_id, Sec_KeyHandle** keyHandle) {
    CHECK_PROCHANDLE(processorHandle)

    if (object_id == SEC_OBJECTID_INVALID)
        return SEC_RESULT_INVALID_PARAMETERS;

    Sec_StorageLoc location;
    Sec_KeyData* key_data = calloc(1, sizeof(Sec_KeyData));
    if (key_data == NULL) {
        SEC_LOG_ERROR("calloc failed");
        return SEC_RESULT_FAILURE;
    }

    Sec_Result result = retrieve_key_data(processorHandle, object_id, &location, key_data);
    if (result != SEC_RESULT_SUCCESS) {
        SEC_FREE(key_data);
        SEC_LOG_ERROR("retrieve_key_data failed");
        return result;
    }

    Sec_Key key;
    Sec_KeyContainer key_container;
    SEC_SIZE key_length = SEC_KEYCONTAINER_MAX_LEN;
    uint8_t* key_buffer = malloc(SEC_KEYCONTAINER_MAX_LEN);
    if (key_buffer == NULL) {
        SEC_FREE(key_data);
        SEC_LOG_ERROR("malloc failed");
        return SEC_RESULT_FAILURE;
    }

    result = process_key_container(processorHandle, object_id, key_data->info.kc_type, &key_data->key_container,
            key_data->kc_len, &key, &key_container, key_buffer, &key_length);
    SEC_FREE(key_data);
    SEC_FREE(key_buffer);
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("import_key failed");
        return result;
    }

    *keyHandle = calloc(1, sizeof(Sec_KeyHandle));
    if (*keyHandle == NULL) {
        SEC_LOG_ERROR("Calloc failed");
        return SEC_RESULT_FAILURE;
    }

    (*keyHandle)->processorHandle = processorHandle;
    memcpy(&(*keyHandle)->key, &key, sizeof(Sec_Key));
    if (key_container == SEC_KEYCONTAINER_DER_RSA_1024_PUBLIC ||
            key_container == SEC_KEYCONTAINER_DER_RSA_2048_PUBLIC ||
            key_container == SEC_KEYCONTAINER_DER_RSA_3072_PUBLIC ||
            key_container == SEC_KEYCONTAINER_DER_ECC_NISTP256_PUBLIC) {
        (*keyHandle)->key_type = SecKey_GetKeyTypeForClearKeyContainer(key_container);
    } else {
        sa_header key_header;
        sa_status status = sa_key_header(&key_header, (*keyHandle)->key.handle);
        if (status == SA_STATUS_OK) {
            (*keyHandle)->key_type = get_key_type(&key_header);
        }
    }

    return SEC_RESULT_SUCCESS;
}

/**
 * @brief Extract an RSA public key from a specified private key handle.
 *
 * @param keyHandle handle of the private key.
 * @param public_key pointer to the output structure containing the public rsa key.
 *
 * @return The status of the operation.
 */
Sec_Result SecKey_ExtractRSAPublicKey(Sec_KeyHandle* keyHandle, Sec_RSARawPublicKey* public_key) {
    CHECK_HANDLE(keyHandle)
    if (public_key == NULL)
        return SEC_RESULT_INVALID_PARAMETERS;

    switch (keyHandle->key_type) {
        case SEC_KEYTYPE_RSA_1024:
        case SEC_KEYTYPE_RSA_2048:
        case SEC_KEYTYPE_RSA_3072: {
            size_t out_len = SEC_KEYCONTAINER_MAX_LEN;
            uint8_t* out = malloc(SEC_KEYCONTAINER_MAX_LEN);
            if (out == NULL) {
                SEC_LOG_ERROR("malloc failed");
                return SEC_RESULT_FAILURE;
            }

            sa_status status;
            status = sa_key_get_public(out, &out_len, keyHandle->key.handle);
            if (status == SA_STATUS_OK)
                Pubops_ExtractRSAPubFromPUBKEYDer(out, out_len, public_key);

            SEC_FREE(out);
            CHECK_STATUS(status)
            return SEC_RESULT_SUCCESS;
        }
        case SEC_KEYTYPE_RSA_1024_PUBLIC:
        case SEC_KEYTYPE_RSA_2048_PUBLIC:
        case SEC_KEYTYPE_RSA_3072_PUBLIC: {
            Sec_Uint32ToBEBytes(RSA_size(keyHandle->key.rsa), public_key->modulus_len_be);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
            SecUtils_BigNumToBuffer(keyHandle->key.rsa->n, public_key->n,
                    Sec_BEBytesToUint32(public_key->modulus_len_be));
            SecUtils_BigNumToBuffer(keyHandle->key.rsa->e, public_key->e, PUBLIC_KEY_BUFFER_SIZE);
#else
            const BIGNUM* n = NULL;
            const BIGNUM* e = NULL;
            RSA_get0_key(keyHandle->key.rsa, &n, &e, NULL);
            SecUtils_BigNumToBuffer(n, public_key->n, Sec_BEBytesToUint32(public_key->modulus_len_be));
            SecUtils_BigNumToBuffer(e, public_key->e, PUBLIC_KEY_BUFFER_SIZE);
#endif
            return SEC_RESULT_SUCCESS;
        }
        default:
            return SEC_RESULT_INVALID_PARAMETERS;
    }
}

/**
 * @brief Extract an ECC public key from a specified private key handle.
 *
 * @param keyHandle handle of the private key.
 * @param public_key pointer to the output structure containing the public ecc key.
 *
 * @return The status of the operation.
 */
Sec_Result SecKey_ExtractECCPublicKey(Sec_KeyHandle* keyHandle, Sec_ECCRawPublicKey* public_key) {
    CHECK_HANDLE(keyHandle)
    if (public_key == NULL)
        return SEC_RESULT_INVALID_PARAMETERS;

    switch (keyHandle->key_type) {
        case SEC_KEYTYPE_ECC_NISTP256: {
            size_t out_len = SEC_KEYCONTAINER_MAX_LEN;
            uint8_t* out = malloc(SEC_KEYCONTAINER_MAX_LEN);
            if (out == NULL) {
                SEC_LOG_ERROR("malloc failed");
                return SEC_RESULT_FAILURE;
            }

            sa_status status = sa_key_get_public(out, &out_len, keyHandle->key.handle);
            if (status == SA_STATUS_OK) {
                size_t key_length = out_len / 2;
                Sec_Uint32ToBEBytes(key_length, public_key->key_len);
                memcpy(public_key->x, out, key_length);
                memcpy(public_key->y, out + key_length, key_length);
                public_key->type = SEC_KEYTYPE_ECC_NISTP256_PUBLIC;
            }

            SEC_FREE(out);
            CHECK_STATUS(status)
            return SEC_RESULT_SUCCESS;
        }
        case SEC_KEYTYPE_ECC_NISTP256_PUBLIC:
            if (SecUtils_ECCToPubBinary(keyHandle->key.ec_key, public_key) != SEC_RESULT_SUCCESS) {
                SEC_LOG_ERROR("SecUtils_ECCToPubBinary failed");
                return SEC_RESULT_FAILURE;
            }

            return SEC_RESULT_SUCCESS;

        default:
            return SEC_RESULT_INVALID_PARAMETERS;
    }
}

/**
 * @brief Generate and provision a new key.
 *
 * @param processorHandle secure processor handle.
 * @param object_id id of the key to generate.
 * @param keyType type of the key to generate.
 * @param location location where the key should be stored.
 *
 * @return The status of the operation.
 */
Sec_Result SecKey_Generate(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID object_id, Sec_KeyType keyType,
        Sec_StorageLoc location) {
    CHECK_PROCHANDLE(processorHandle)

    sa_key_type key_type;
    void* parameters;

    Sec_Result result = get_sa_key_type(keyType, &key_type, &parameters);
    if (result != SEC_RESULT_SUCCESS)
        return result;

    Sec_Key key;
    sa_rights rights;
    rights_set_allow_all(&rights, keyType);
    sa_status status = sa_key_generate(&key.handle, &rights, key_type, parameters);
    SEC_FREE(parameters);
    CHECK_STATUS(status)

    return prepare_and_store_key_data(processorHandle, location, object_id, &key, SecKey_GetClearContainer(keyType),
            NULL, 0);
}

/**
 * @brief Provision a key.
 *
 * @param processorHandle secure processor handle.
 * @param object_id id of the key to provision.
 * @param location storage location where the key should be provisioned.
 * @param data_type type of input key container that is being used.
 * @param data pointer to the input key container.
 * @param data_length the size of the input key container.
 *
 * @return The status of the operation.
 */
Sec_Result SecKey_Provision(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID object_id, Sec_StorageLoc location,
        Sec_KeyContainer data_type, SEC_BYTE* data, SEC_SIZE data_length) {
    CHECK_PROCHANDLE(processorHandle)

    if (object_id == SEC_OBJECTID_INVALID) {
        SEC_LOG_ERROR("Cannot provision object with SEC_OBJECTID_INVALID");
        return SEC_RESULT_FAILURE;
    }

    if (data_length > SEC_KEYCONTAINER_MAX_LEN) {
        SEC_LOG_ERROR("Key data is too long");
        return SEC_RESULT_FAILURE;
    }

    Sec_Key key;
    Sec_KeyContainer key_container;
    SEC_SIZE key_length = SEC_KEYCONTAINER_MAX_LEN;
    uint8_t* key_buffer = malloc(SEC_KEYCONTAINER_MAX_LEN);
    if (key_buffer == NULL) {
        SEC_LOG_ERROR("malloc failed");
        return SEC_RESULT_FAILURE;
    }

    Sec_Result result = process_key_container(processorHandle, object_id, data_type, data, data_length, &key,
            &key_container, key_buffer, &key_length);
    if (result == SEC_RESULT_SUCCESS)
        // Convert into an exported key container and store.
        result = prepare_and_store_key_data(processorHandle, location, object_id, &key, key_container, key_buffer,
                key_length);

    SEC_FREE(key_buffer);
    return result;
}

/**
 * @brief Derive and provision a key using the HKDF algorithm.
 *
 * @param processorHandle secure processor handle.
 * @param object_id_derived id of the key to provision.
 * @param type_derived derived key type.
 * @param loc_derived storage location where the derived key should be provisioned.
 * @param macAlgorithm mac algorithm to use in the key derivation process.
 * @param salt pointer to the salt value to use in key derivation process.
 * @param saltSize the length of the salt buffer in bytes.
 * @param info pointer to the info value to use in key derivation process.
 * @param infoSize the length of the info buffer in bytes.
 *
 * @return The status of the operation.
 */
Sec_Result SecKey_Derive_HKDF(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID object_id_derived,
        Sec_KeyType type_derived, Sec_StorageLoc loc_derived, Sec_MacAlgorithm macAlgorithm, SEC_BYTE* nonce,
        SEC_BYTE* salt, SEC_SIZE saltSize, SEC_BYTE* info, SEC_SIZE infoSize) {
    sa_key base_key;
    CHECK_PROCHANDLE(processorHandle)

    Sec_Result result = derive_base_key(processorHandle, nonce, &base_key, type_derived);
    if (result != SEC_RESULT_SUCCESS)
        return result;

    Sec_Key key;
    result = derive_hkdf(macAlgorithm, type_derived, salt, saltSize, info, infoSize, base_key, &key.handle);
    sa_key_release(base_key);
    if (result != SEC_RESULT_SUCCESS) {
        return result;
    }

    return prepare_and_store_key_data(processorHandle, loc_derived, object_id_derived, &key,
            SecKey_GetClearContainer(type_derived), NULL, 0);
}

/**
 * @brief Derive and provision a key using the Concat KDF algorithm.
 *
 * @param processorHandle secure processor handle.
 * @param object_id_derived id of the key to provision.
 * @param type_derived derived key type.
 * @param loc_derived storage location where the derived key should be provisioned.
 * @param digestAlgorithm digest algorithm to use in the key derivation process.
 * @param otherInfo pointer to the info value to use in key derivation process.
 * @param otherInfoSize the length of the other info buffer in bytes.
 *
 * @return The status of the operation.
 */
Sec_Result SecKey_Derive_ConcatKDF(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID object_id_derived,
        Sec_KeyType type_derived, Sec_StorageLoc loc_derived, Sec_DigestAlgorithm digestAlgorithm, SEC_BYTE* nonce,
        SEC_BYTE* otherInfo, SEC_SIZE otherInfoSize) {
    sa_key base_key;
    CHECK_PROCHANDLE(processorHandle)

    Sec_Result result = derive_base_key(processorHandle, nonce, &base_key, type_derived);
    if (result != SEC_RESULT_SUCCESS)
        return result;

    Sec_Key key;
    result = derive_kdf_concat(digestAlgorithm, type_derived, otherInfo, otherInfoSize, base_key, &key.handle);
    sa_key_release(base_key);
    if (result != SEC_RESULT_SUCCESS) {
        return result;
    }

    return prepare_and_store_key_data(processorHandle, loc_derived, object_id_derived, &key,
            SecKey_GetClearContainer(type_derived), NULL, 0);
}

Sec_Result SecKey_Derive_PBEKDF(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID object_id_derived,
        Sec_KeyType type_derived, Sec_StorageLoc loc_derived, Sec_MacAlgorithm macAlgorithm, SEC_BYTE* nonce,
        SEC_BYTE* salt, SEC_SIZE saltSize, SEC_SIZE numIterations) {
    CHECK_PROCHANDLE(processorHandle)

    SEC_BYTE loop[] = {0, 0, 0, 0};
    SEC_BYTE out_key[SEC_AES_KEY_MAX_LEN];

    if (!SecKey_IsSymetric(type_derived)) {
        SEC_LOG_ERROR("Only symmetric keys can be derived");
        return SEC_RESULT_INVALID_PARAMETERS;
    }

    sa_key base_key;
    Sec_Result result = derive_base_key(processorHandle, nonce, &base_key, type_derived);
    if (result != SEC_RESULT_SUCCESS)
        return result;

    SEC_SIZE key_length = SecKey_GetKeyLenForKeyType(type_derived);
    SEC_SIZE digest_length = SecDigest_GetDigestLenForAlgorithm(SecMac_GetDigestAlgorithm(macAlgorithm));
    SEC_SIZE l = key_length / digest_length + ((key_length % digest_length == 0) ? 0 : 1);

    for (size_t i = 1; i <= l; i++) {
        loop[3] = i;

        SEC_SIZE cp_len = (i == l) ? key_length % digest_length : digest_length;

        sa_crypto_mac_context mac_context;
        sa_mac_algorithm mac_algorithm =
                (macAlgorithm == SEC_MACALGORITHM_CMAC_AES_128) ? SA_MAC_ALGORITHM_CMAC : SA_MAC_ALGORITHM_HMAC;
        void* parameters = NULL;
        if (mac_algorithm != SEC_MACALGORITHM_CMAC_AES_128) {
            sa_mac_parameters_hmac hmac_parameters = {
                    (mac_algorithm == SEC_MACALGORITHM_HMAC_SHA1) ? SA_DIGEST_ALGORITHM_SHA1 :
                                                                    SA_DIGEST_ALGORITHM_SHA256};
            parameters = &hmac_parameters;
        }

        sa_status status = sa_crypto_mac_init(&mac_context, mac_algorithm, base_key, parameters);
        CHECK_MAC_RESULT(status, base_key, 0)

        status = sa_crypto_mac_process(mac_context, salt, saltSize);
        CHECK_MAC_RESULT(status, base_key, mac_context)

        status = sa_crypto_mac_process(mac_context, loop, sizeof(loop));
        CHECK_MAC_RESULT(status, base_key, mac_context)

        SEC_BYTE mac1[SEC_MAC_MAX_LEN];
        size_t mac1_len;
        status = sa_crypto_mac_compute(mac1, &mac1_len, mac_context);
        sa_crypto_mac_release(mac_context);
        CHECK_MAC_RESULT(status, base_key, 0)

        SEC_BYTE out[SEC_MAC_MAX_LEN];
        memcpy(out, mac1, digest_length);

        for (size_t j = 1; j < numIterations; j++) {
            status = sa_crypto_mac_init(&mac_context, mac_algorithm, base_key, parameters);
            CHECK_MAC_RESULT(status, base_key, 0)

            status = sa_crypto_mac_process(mac_context, mac1, digest_length);
            CHECK_MAC_RESULT(status, base_key, mac_context)

            SEC_BYTE mac2[SEC_MAC_MAX_LEN];
            size_t mac2_len;
            status = sa_crypto_mac_compute(mac2, &mac2_len, mac_context);
            sa_crypto_mac_release(mac_context);
            CHECK_MAC_RESULT(status, base_key, 0)

            memcpy(mac1, mac2, digest_length);

            for (int k = 0; k < digest_length; ++k) {
                out[k] ^= mac1[k];
            }
        }

        memcpy(out_key + (i - 1) * digest_length, out, cp_len);
    }

    sa_key_release(base_key);

    return SecKey_Provision(processorHandle, object_id_derived, loc_derived, SecKey_GetClearContainer(type_derived),
            out_key, key_length);
}

/**
 * @brief Derive and provision an AES 128-bit key a vendor specific key ladder algorithm.
 *
 * This function will generate a key derived from one of the OTP keys.  The
 * result of this function may not be usable in Digest and Mac _UpdateWithKey
 * functions.  In general, this function will keep the derived key more secure
 * then the other SecKey_Derive functions because the key will not be accessable
 * by the host even during the generation time.
 *
 * @param processorHandle secure processor handle.
 * @param object_id_derived id of the key to provision.
 * @param loc_derived storage location where the derived key should be provisioned.
 * @param input input buffer for the key derivation.
 * @param input_len the length of the input buffer.
 *
 * @return The status of the operation.
 */
Sec_Result SecKey_Derive_VendorAes128(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID object_id_derived,
        Sec_StorageLoc loc_derived, SEC_BYTE* input, SEC_SIZE input_len) {
    SEC_BYTE digest[SEC_DIGEST_MAX_LEN];
    SEC_SIZE digest_len;
    SEC_BYTE digest2[SEC_DIGEST_MAX_LEN];
    SEC_SIZE digest2_len;
    CHECK_PROCHANDLE(processorHandle)

    Sec_Result result = SecDigest_SingleInput(processorHandle, SEC_DIGESTALGORITHM_SHA256, input, input_len, digest,
            &digest_len);
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecDigest_SingleInput failed");
        return SEC_RESULT_FAILURE;
    }

    result = SecDigest_SingleInput(processorHandle, SEC_DIGESTALGORITHM_SHA256, digest, digest_len, digest2,
            &digest2_len);
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecDigest_SingleInput failed");
        return SEC_RESULT_FAILURE;
    }

    /* setup key ladder inputs */
    SEC_SIZE key_length = SecKey_GetKeyLenForKeyType(SEC_KEYTYPE_AES_128);
    SEC_BYTE input1[key_length];
    SEC_BYTE input2[key_length];
    SEC_BYTE input3[key_length];
    SEC_BYTE input4[key_length];
    memcpy(input1, digest, key_length);
    memcpy(input2, digest + key_length, key_length);
    memcpy(input3, digest2, key_length);
    memcpy(input4, digest2 + key_length, key_length);

    return SecKey_Derive_KeyLadderAes128(processorHandle, object_id_derived, loc_derived, SEC_KEYLADDERROOT_NUM,
            input1, input2, input3, input4);
}

/**
 * @brief Derive and provision an AES 128-bit key.
 *
 * This function will generate a key derived from one of the OTP keys.  The
 * result of this function may not be usable in Digest and Mac _UpdateWithKey
 * functions.  In general, this function will keep the derived key more secure
 * then the other SecKey_Derive functions because the key will not be accessable
 * by the host even during the generation time.
 *
 * @param processorHandle secure processor handle.
 * @param object_id_derived id of the key to provision.
 * @param type_derived derived key type.
 * @param loc_derived storage location where the derived key should be provisioned.
 * @param input1 16 byte input for stage 1 of the key ladder.
 * @param input2 16 byte input for stage 2 of the key ladder.
 * @param input3 16 byte input for stage 3 of the key ladder.
 * @param input4 16 byte input for stage 4 of the key ladder.
 *
 * @return The status of the operation.
 */
Sec_Result SecKey_Derive_KeyLadderAes128(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID object_id_derived,
        Sec_StorageLoc loc_derived, Sec_KeyLadderRoot root, SEC_BYTE* input1, SEC_BYTE* input2, SEC_BYTE* input3,
        SEC_BYTE* input4) {
    CHECK_PROCHANDLE(processorHandle)

    SEC_SIZE key_length = SecKey_GetKeyLenForKeyType(SEC_KEYTYPE_AES_128);
    Sec_Key key;
    if (derive_root_key_ladder(input1, input2, input3, input4, key_length, &key.handle, SEC_KEYTYPE_AES_128) !=
            SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("Derive_root_key_ladder failed");
        return SEC_RESULT_FAILURE;
    }

    return prepare_and_store_key_data(processorHandle, loc_derived, object_id_derived, &key,
            SEC_KEYCONTAINER_RAW_AES_128, NULL, 0);
}

Sec_Result SecKey_Derive_CMAC_AES128(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID idDerived,
        Sec_KeyType typeDerived, Sec_StorageLoc locDerived, SEC_OBJECTID derivationKey, SEC_BYTE* otherData,
        SEC_SIZE otherDataSize, SEC_BYTE* counter, SEC_SIZE counterSize) {
    Sec_KeyHandle* keyHandle;

    Sec_Result result = SecKey_GetInstance(processorHandle, derivationKey, &keyHandle);
    if (result != SEC_RESULT_SUCCESS)
        return result;

    Sec_Key key;
    result = derive_kdf_cmac(typeDerived, otherData, otherDataSize, counter, counterSize, keyHandle->key.handle,
            &key.handle);
    SecKey_Release(keyHandle);
    if (result != SEC_RESULT_SUCCESS)
        return result;

    return prepare_and_store_key_data(processorHandle, locDerived, idDerived, &key,
            SecKey_GetClearContainer(typeDerived), NULL, 0);
}

/**
 * @brief Obtain a digest value computed over the base key contents.
 *
 * @param processorHandle secure processor handle.
 * @param nonce client nonce.
 * @param alg digest algorithm.
 * @param digest output digest value.
 * @param digest_len the length of output digest value.
 *
 * @return status of the operation.
 */
Sec_Result SecKey_ComputeBaseKeyDigest(Sec_ProcessorHandle* processorHandle, SEC_BYTE* nonce,
        Sec_DigestAlgorithm alg, SEC_BYTE* digest, SEC_SIZE* digest_len) {

    if (SecKey_Derive_BaseKey(processorHandle, SEC_OBJECTID_BASE_KEY_AES, SEC_KEYTYPE_AES_128, SEC_STORAGELOC_RAM,
                nonce) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecKey_Derive_BaseKey failed");
        return SEC_RESULT_FAILURE;
    }

    if (SecDigest_SingleInputWithKeyId(processorHandle, alg, SEC_OBJECTID_BASE_KEY_AES, digest, digest_len) !=
            SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecDigest_SingleInputWithKeyId failed");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

/**
 * @brief Generates a shared symmetric key and stores it in a specified location.
 *
 * A shared secret is calculated using the ECDH algorithm.  The shared
 * secret is converted to a key using the Concat KDF (SP800-56A Section
 * 5.8.1).  If the key with the same id already exists, the call will
 * overwrite the existing key with the new key.  SHA-256 is the digest
 * algorithm.
 *
 * @param keyHandle Handle of my private ECC key.
 * @param otherPublicKey Public key for other party in key agreement.
 * @param type_derived Type of key to generate. Only symmetric keys can be derived.
 * @param id_derived 64-bit object id identifying the key to be generated.
 * @param loc_id Location where the resulting key will be stored.
 * @param digestAlgorithm Digest algorithm to use in KDF (typically SEC_DIGESTALGORITHM_SHA256).
 * @param otherInfo Input keying material
 *        AlgorithmID || PartyUInfo || PartyVInfo) {|| SuppPubInfo }{|| SuppPrivInfo}.
 * @param otherInfoSize	Size of otherInfo (in bytes).
 */
Sec_Result SecKey_ECDHKeyAgreementWithKDF(Sec_KeyHandle* keyHandle, Sec_ECCRawPublicKey* otherPublicKey,
        Sec_KeyType type_derived, SEC_OBJECTID id_derived, Sec_StorageLoc loc_derived, Sec_Kdf kdf,
        Sec_DigestAlgorithm digestAlgorithm, const SEC_BYTE* otherInfo, SEC_SIZE otherInfoSize) {
    if (kdf != SEC_KDF_CONCAT) {
        SEC_LOG_ERROR("Invalid kdf parameter encountered: %d", kdf);
        return SEC_RESULT_INVALID_PARAMETERS;
    }

    if (otherPublicKey->type != SEC_KEYTYPE_ECC_NISTP256_PUBLIC &&
            otherPublicKey->type != SEC_KEYTYPE_ECC_NISTP256) {
        SEC_LOG_ERROR("Can only exchange ECC keys");
        return SEC_RESULT_INVALID_PARAMETERS;
    }

    if (!SecKey_IsSymetric(type_derived)) {
        SEC_LOG_ERROR("Can only derive symetric keys");
        return SEC_RESULT_INVALID_PARAMETERS;
    }

    // Derive the shared secret with a key exchange.
    sa_key shared_secret;
    sa_rights rights;
    rights_set_allow_all(&rights, type_derived);

    size_t other_public_length = Sec_BEBytesToUint32(otherPublicKey->key_len);
    SEC_BYTE other_public[other_public_length * 2];
    memcpy(other_public, otherPublicKey->x, other_public_length);
    memcpy(other_public + other_public_length, otherPublicKey->y, other_public_length);

    sa_status status = sa_key_exchange(&shared_secret, &rights, SA_KEY_EXCHANGE_ALGORITHM_ECDH,
            keyHandle->key.handle, other_public, other_public_length * 2, NULL);
    CHECK_STATUS(status)

    // Derive the key from the shared secret using a key derivation algorithm.
    if (digestAlgorithm != SEC_DIGESTALGORITHM_SHA1 && digestAlgorithm != SEC_DIGESTALGORITHM_SHA256) {
        sa_key_release(shared_secret);
        SEC_LOG_ERROR("Unsupported digest algorithm specified: %d", digestAlgorithm);
        return SEC_RESULT_INVALID_PARAMETERS;
    }

    sa_digest_algorithm digest_algorithm =
            (digestAlgorithm == SEC_DIGESTALGORITHM_SHA1) ? SA_DIGEST_ALGORITHM_SHA1 : SA_DIGEST_ALGORITHM_SHA256;

    sa_kdf_algorithm kdf_algorithm;
    void* parameters;
    sa_kdf_parameters_hkdf hkdf_parameters;
    sa_kdf_parameters_concat concat_parameters;
    sa_kdf_parameters_ansi_x963 x963_parameters;
    switch (kdf) {
        case SEC_KDF_HKDF:
            kdf_algorithm = SA_KDF_ALGORITHM_HKDF;
            hkdf_parameters.key_length = SecKey_GetKeyLenForKeyType(type_derived);
            hkdf_parameters.digest_algorithm = digest_algorithm;
            hkdf_parameters.parent = shared_secret;
            hkdf_parameters.salt = NULL;
            hkdf_parameters.salt_length = 0;
            hkdf_parameters.info = otherInfo;
            hkdf_parameters.info_length = otherInfoSize;
            parameters = &hkdf_parameters;
            break;

        case SEC_KDF_CONCAT:
            kdf_algorithm = SA_KDF_ALGORITHM_CONCAT;
            concat_parameters.key_length = SecKey_GetKeyLenForKeyType(type_derived);
            concat_parameters.digest_algorithm = digest_algorithm;
            concat_parameters.parent = shared_secret;
            concat_parameters.info = otherInfo;
            concat_parameters.info_length = otherInfoSize;
            parameters = &concat_parameters;
            break;

        case SEC_KDF_ANSI_X_9_63:
            kdf_algorithm = SA_KDF_ALGORITHM_ANSI_X963;
            x963_parameters.key_length = SecKey_GetKeyLenForKeyType(type_derived);
            x963_parameters.digest_algorithm = digest_algorithm;
            x963_parameters.parent = shared_secret;
            x963_parameters.info = otherInfo;
            x963_parameters.info_length = otherInfoSize;
            parameters = &x963_parameters;
            break;

        default:
            sa_key_release(shared_secret);
            return SEC_RESULT_INVALID_PARAMETERS;
    }

    Sec_Key key;
    status = sa_key_derive(&key.handle, &rights, kdf_algorithm, parameters);
    sa_key_release(shared_secret);
    CHECK_STATUS(status)

    return prepare_and_store_key_data(keyHandle->processorHandle, loc_derived, id_derived, &key,
            SecKey_GetClearContainer(type_derived), NULL, 0);
}

Sec_Result SecKey_Derive_BaseKey(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID idDerived, Sec_KeyType key_type,
        Sec_StorageLoc loc, SEC_BYTE* nonce) {
    CHECK_PROCHANDLE(processorHandle)

    Sec_Key key;
    Sec_Result result = derive_base_key(processorHandle, nonce, &key.handle, key_type);
    if (result != SEC_RESULT_SUCCESS)
        return result;

    return prepare_and_store_key_data(processorHandle, loc, idDerived, &key, SecKey_GetClearContainer(key_type), NULL,
            0);
}

Sec_Result SecKey_Derive_HKDF_BaseKey(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID idDerived,
        Sec_KeyType typeDerived, Sec_StorageLoc locDerived, Sec_MacAlgorithm macAlgorithm, SEC_BYTE* salt,
        SEC_SIZE saltSize, SEC_BYTE* info, SEC_SIZE infoSize, SEC_OBJECTID baseKeyId) {
    Sec_KeyHandle* keyHandle;

    Sec_Result result = SecKey_GetInstance(processorHandle, baseKeyId, &keyHandle);
    if (result != SEC_RESULT_SUCCESS) {
        return result;
    }

    Sec_Key key;
    result = derive_hkdf(macAlgorithm, typeDerived, salt, saltSize, info, infoSize, keyHandle->key.handle,
            &key.handle);
    SecKey_Release(keyHandle);
    if (result != SEC_RESULT_SUCCESS)
        return result;

    return prepare_and_store_key_data(processorHandle, locDerived, idDerived, &key,
            SecKey_GetClearContainer(typeDerived), NULL, 0);
}

Sec_Result SecKey_Derive_ConcatKDF_BaseKey(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID idDerived,
        Sec_KeyType typeDerived, Sec_StorageLoc locDerived, Sec_DigestAlgorithm digestAlgorithm, SEC_BYTE* otherInfo,
        SEC_SIZE otherInfoSize, SEC_OBJECTID baseKeyId) {
    Sec_KeyHandle* keyHandle;

    Sec_Result result = SecKey_GetInstance(processorHandle, baseKeyId, &keyHandle);
    if (result != SEC_RESULT_SUCCESS) {
        return result;
    }

    Sec_Key key;
    result = derive_kdf_concat(digestAlgorithm, typeDerived, otherInfo, otherInfoSize, keyHandle->key.handle,
            &key.handle);
    SecKey_Release(keyHandle);
    if (result != SEC_RESULT_SUCCESS)
        return result;

    return prepare_and_store_key_data(processorHandle, locDerived, idDerived, &key,
            SecKey_GetClearContainer(typeDerived), NULL, 0);
}

/**
 * @brief compute inputs for the base key ladder.
 */
Sec_Result SecKey_ComputeBaseKeyLadderInputs(Sec_ProcessorHandle* processorHandle,
        const char* inputDerivationStr, const char* cipherAlgorithmStr, SEC_BYTE* nonce,
        Sec_DigestAlgorithm digestAlgorithm, SEC_SIZE inputSize, SEC_BYTE* c1, SEC_BYTE* c2, SEC_BYTE* c3,
        SEC_BYTE* c4) {
    int i;
    SEC_BYTE loop[] = {0, 0, 0, 0};
    SEC_BYTE digest[SEC_DIGEST_MAX_LEN];
    SEC_SIZE digest_len;
    Sec_Result result = SEC_RESULT_FAILURE;
    SEC_BYTE* c[4] = {c1, c2, c3, c4};
    CHECK_PROCHANDLE(processorHandle)

    if (inputSize > SecDigest_GetDigestLenForAlgorithm(digestAlgorithm)) {
        SEC_LOG_ERROR("Invalid input size for specified digest algorithm");
        return SEC_RESULT_FAILURE;
    }

    SEC_SIZE buffer_len = SEC_NONCE_LEN + strlen(inputDerivationStr) + strlen(cipherAlgorithmStr) + sizeof(loop);
    SEC_BYTE input_buffer[buffer_len];

    for (i = 1; i <= 4; i++) {
        loop[3] = i;
        SEC_SIZE offset = 0;
        memcpy(input_buffer + offset, nonce, SEC_NONCE_LEN);
        offset += SEC_NONCE_LEN;
        memcpy(input_buffer + offset, inputDerivationStr, strlen(inputDerivationStr)); // NOLINT
        offset += strlen(inputDerivationStr);
        memcpy(input_buffer + offset, cipherAlgorithmStr, strlen(cipherAlgorithmStr)); // NOLINT
        offset += strlen(cipherAlgorithmStr);
        memcpy(input_buffer + offset, loop, sizeof(loop));
        offset += sizeof(loop);

        result = SecDigest_SingleInput(processorHandle, digestAlgorithm, input_buffer, offset, digest, &digest_len);
        if (result != SEC_RESULT_SUCCESS)
            return result;

        memcpy(c[i - 1], digest, inputSize);
    }

    return result;
}

/**
 * @brief Delete a provisioned key.
 *
 * @param processorHandle secure processor handle.
 * @param object_id id of the key to delete.
 *
 * @return The status of the operation.
 */
Sec_Result SecKey_Delete(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID object_id) {
    Sec_RAMKeyData* ram_key = NULL;
    Sec_RAMKeyData* ram_key_parent = NULL;
    SEC_SIZE keys_found = 0;
    SEC_SIZE keys_deleted = 0;
    CHECK_PROCHANDLE(processorHandle)

    /* ram */
    find_ram_key_data(processorHandle, object_id, &ram_key, &ram_key_parent);
    if (ram_key != NULL) {
        if (ram_key_parent == NULL)
            processorHandle->ram_keys = ram_key->next;
        else
            ram_key_parent->next = ram_key->next;

        Sec_Memset(ram_key, 0, sizeof(Sec_RAMKeyData));

        SEC_FREE(ram_key);

        ++keys_found;
        ++keys_deleted;
    }

    /* file system */
    if (processorHandle->app_dir != NULL) {
        char file_name[SEC_MAX_FILE_PATH_LEN];
        snprintf(file_name, sizeof(file_name), SEC_KEY_FILENAME_PATTERN, processorHandle->app_dir, object_id);
        if (SecUtils_FileExists(file_name)) {
            SecUtils_RmFile(file_name);
            ++keys_found;

            if (!SecUtils_FileExists(file_name))
                ++keys_deleted;
        }

        char file_name_info[SEC_MAX_FILE_PATH_LEN];
        snprintf(file_name_info, sizeof(file_name_info), SEC_KEYINFO_FILENAME_PATTERN, processorHandle->app_dir,
                object_id);
        if (!SecUtils_FileExists(file_name) && SecUtils_FileExists(file_name_info)) {
            SecUtils_RmFile(file_name_info);
        }

        char file_name_verification[SEC_MAX_FILE_PATH_LEN];
        snprintf(file_name_verification, sizeof(file_name_verification), SEC_VERIFICATION_FILENAME_PATTERN,
                processorHandle->app_dir, object_id);
        if (!SecUtils_FileExists(file_name) && SecUtils_FileExists(file_name_verification)) {
            SecUtils_RmFile(file_name_verification);
        }
    }

    if (keys_found == 0)
        return SEC_RESULT_NO_SUCH_ITEM;

    if (keys_found != keys_deleted)
        return SEC_RESULT_ITEM_NON_REMOVABLE;

    return SEC_RESULT_SUCCESS;
}

/**
 * @brief Release the key object.
 *
 * @param keyHandle key handle to release.
 *
 * @return The status of the operation.
 */
Sec_Result SecKey_Release(Sec_KeyHandle* keyHandle) {
    CHECK_HANDLE(keyHandle)

    switch (keyHandle->key_type) {
        case SEC_KEYTYPE_ECC_NISTP256_PUBLIC:
            SEC_ECC_FREE(keyHandle->key.ec_key);
            break;

        case SEC_KEYTYPE_RSA_1024_PUBLIC:
        case SEC_KEYTYPE_RSA_2048_PUBLIC:
        case SEC_KEYTYPE_RSA_3072_PUBLIC:
            SEC_RSA_FREE(keyHandle->key.rsa);
            break;

        default:
            sa_key_release(keyHandle->key.handle);
            break;
    }

    SEC_FREE(keyHandle);
    return SEC_RESULT_SUCCESS;
}

/**
 * @brief Obtain a processor handle.
 *
 * @param keyHandle key handle.
 *
 * @return Processor handle.
 */
Sec_ProcessorHandle* SecKey_GetProcessor(Sec_KeyHandle* keyHandle) {
    if (keyHandle != NULL)
        return keyHandle->processorHandle;

    return NULL;
}

Sec_Result SecKey_ExportKey(Sec_KeyHandle* keyHandle, SEC_BYTE* derivationInput, SEC_BYTE* exportedKey,
        SEC_SIZE keyBufferLen, SEC_SIZE* keyBytesWritten) {
    CHECK_HANDLE(keyHandle)

    if (keyHandle->key_type == SEC_KEYTYPE_RSA_1024_PUBLIC ||
            keyHandle->key_type == SEC_KEYTYPE_RSA_2048_PUBLIC ||
            keyHandle->key_type == SEC_KEYTYPE_RSA_3072_PUBLIC ||
            keyHandle->key_type == SEC_KEYTYPE_ECC_NISTP256_PUBLIC)
        return SEC_RESULT_FAILURE;

    return export_key(&keyHandle->key, derivationInput, exportedKey, keyBufferLen, keyBytesWritten);
}

Sec_KeyType SecKey_GetRSAKeyTypeForBitLength(int numBits) {
    switch (numBits) {
        case 1024:
            return SEC_KEYTYPE_RSA_1024;

        case 2048:
            return SEC_KEYTYPE_RSA_2048;

        case 3072:
            return SEC_KEYTYPE_RSA_3072;

        default:
            SEC_LOG_ERROR("Invalid numBits encountered: %d", numBits);
            return SEC_KEYTYPE_NUM;
    }
}

Sec_KeyType SecKey_GetRSAKeyTypeForByteLength(int numBytes) {
    switch (numBytes) {
        case 128:
            return SEC_KEYTYPE_RSA_1024;

        case 256:
            return SEC_KEYTYPE_RSA_2048;

        case 384:
            return SEC_KEYTYPE_RSA_3072;

        default:
            SEC_LOG_ERROR("Invalid numBytes encountered: %d", numBytes);
            return SEC_KEYTYPE_NUM;
    }
}

/**
 * @brief Checks if a passed in key type is symmetric.
 *
 * @param type key type.
 *
 * @return 1 if key type is symmetric, 0 if asymmetric.
 */
SEC_BOOL SecKey_IsSymetric(Sec_KeyType type) {
    switch (type) {
        case SEC_KEYTYPE_AES_128:
        case SEC_KEYTYPE_AES_256:
        case SEC_KEYTYPE_HMAC_128:
        case SEC_KEYTYPE_HMAC_160:
        case SEC_KEYTYPE_HMAC_256:
            return SEC_TRUE;

        default:
            break;
    }

    return SEC_FALSE;
}

/**
 * @brief Checks if a passed in key type is an AES key.
 *
 * @param type key type.
 *
 * @return 1 if key type is AES, 0 if not.
 */
SEC_BOOL SecKey_IsAES(Sec_KeyType type) {
    switch (type) {
        case SEC_KEYTYPE_AES_128:
        case SEC_KEYTYPE_AES_256:
            return SEC_TRUE;

        default:
            break;
    }

    return SEC_FALSE;
}

SEC_BOOL SecKey_IsHMAC(Sec_KeyType type) {
    switch (type) {
        case SEC_KEYTYPE_HMAC_128:
        case SEC_KEYTYPE_HMAC_160:
        case SEC_KEYTYPE_HMAC_256:
            return SEC_TRUE;

        default:
            break;
    }

    return SEC_FALSE;
}

/**
 * @brief Checks if a passed in key type is RSA.
 *
 * @param type key type.
 *
 * @return 1 if key type is rsa, 0 otherwise.
 */
SEC_BOOL SecKey_IsRsa(Sec_KeyType type) {
    switch (type) {
        case SEC_KEYTYPE_RSA_1024:
        case SEC_KEYTYPE_RSA_1024_PUBLIC:
        case SEC_KEYTYPE_RSA_2048:
        case SEC_KEYTYPE_RSA_2048_PUBLIC:
        case SEC_KEYTYPE_RSA_3072:
        case SEC_KEYTYPE_RSA_3072_PUBLIC:
            return SEC_TRUE;

        default:
            break;
    }

    return SEC_FALSE;
}

/**
 * @brief Checks if a passed in key type is pub RSA.
 *
 * @param type key type.
 *
 * @return 1 if key type is pub rsa, 0 otherwise.
 */
SEC_BOOL SecKey_IsPubRsa(Sec_KeyType type) {
    switch (type) {
        case SEC_KEYTYPE_RSA_1024_PUBLIC:
        case SEC_KEYTYPE_RSA_2048_PUBLIC:
        case SEC_KEYTYPE_RSA_3072_PUBLIC:
            return SEC_TRUE;

        default:
            break;
    }

    return SEC_FALSE;
}

/**
 * @brief Checks if a passed in key type is priv RSA.
 *
 * @param type key type.
 *
 * @return 1 if key type is priv rsa, 0 otherwise.
 */
SEC_BOOL SecKey_IsPrivRsa(Sec_KeyType type) {
    switch (type) {
        case SEC_KEYTYPE_RSA_1024:
        case SEC_KEYTYPE_RSA_2048:
        case SEC_KEYTYPE_RSA_3072:
            return SEC_TRUE;

        default:
            break;
    }

    return SEC_FALSE;
}

/**
 * @brief Checks if a passed in key type is ECC.
 *
 * @param type key type.
 *
 * @return 1 if key type is priv ECC, 0 otherwise.
 */
SEC_BOOL SecKey_IsEcc(Sec_KeyType type) {
    switch (type) {
        case SEC_KEYTYPE_ECC_NISTP256:
        case SEC_KEYTYPE_ECC_NISTP256_PUBLIC:
            return SEC_TRUE;

        default:
            break;
    }

    return SEC_FALSE;
}

/**
 * @brief Checks if a passed in key type is priv ECC.
 *
 * @param type key type.
 *
 * @return 1 if key type is priv ECC, 0 otherwise.
 */
SEC_BOOL SecKey_IsPrivEcc(Sec_KeyType type) {
    if (type == SEC_KEYTYPE_ECC_NISTP256)
        return SEC_TRUE;

    return SEC_FALSE;
}

/**
 * @brief Checks if a passed in key type is pub ECC.
 *
 * @param type key type.
 *
 * @return 1 if key type is pub ECC, 0 otherwise.
 */
SEC_BOOL SecKey_IsPubEcc(Sec_KeyType type) {
    if (type == SEC_KEYTYPE_ECC_NISTP256_PUBLIC)
        return SEC_TRUE;

    return SEC_FALSE;
}

/**
 * @brief Is the specified container a raw (clear) container.
 */
SEC_BOOL SecKey_IsClearKeyContainer(Sec_KeyContainer kct) {
    switch (kct) {
        case SEC_KEYCONTAINER_RAW_AES_128:
        case SEC_KEYCONTAINER_RAW_AES_256:
        case SEC_KEYCONTAINER_RAW_HMAC_128:
        case SEC_KEYCONTAINER_RAW_HMAC_160:
        case SEC_KEYCONTAINER_RAW_HMAC_256:
        case SEC_KEYCONTAINER_RAW_RSA_1024:
        case SEC_KEYCONTAINER_RAW_RSA_2048:
        case SEC_KEYCONTAINER_RAW_RSA_3072:
        case SEC_KEYCONTAINER_RAW_RSA_1024_PUBLIC:
        case SEC_KEYCONTAINER_RAW_RSA_2048_PUBLIC:
        case SEC_KEYCONTAINER_RAW_RSA_3072_PUBLIC:
        case SEC_KEYCONTAINER_PEM_RSA_1024:
        case SEC_KEYCONTAINER_PEM_RSA_2048:
        case SEC_KEYCONTAINER_PEM_RSA_3072:
        case SEC_KEYCONTAINER_PEM_RSA_1024_PUBLIC:
        case SEC_KEYCONTAINER_PEM_RSA_2048_PUBLIC:
        case SEC_KEYCONTAINER_PEM_RSA_3072_PUBLIC:
        case SEC_KEYCONTAINER_RAW_ECC_NISTP256:
        case SEC_KEYCONTAINER_RAW_ECC_NISTP256_PUBLIC:
            return SEC_TRUE;

        default:
            return SEC_FALSE;
    }
}

/**
 * @brief  Obtain a key container type for a specified key type.
 *
 * @param key_type key type.
 * @return key container type.
 */
Sec_KeyContainer SecKey_GetClearContainer(Sec_KeyType key_type) {
    switch (key_type) {
        case SEC_KEYTYPE_AES_128:
            return SEC_KEYCONTAINER_RAW_AES_128;

        case SEC_KEYTYPE_AES_256:
            return SEC_KEYCONTAINER_RAW_AES_256;

        case SEC_KEYTYPE_HMAC_128:
            return SEC_KEYCONTAINER_RAW_HMAC_128;

        case SEC_KEYTYPE_HMAC_160:
            return SEC_KEYCONTAINER_RAW_HMAC_160;

        case SEC_KEYTYPE_HMAC_256:
            return SEC_KEYCONTAINER_RAW_HMAC_256;

        case SEC_KEYTYPE_RSA_1024:
            return SEC_KEYCONTAINER_DER_RSA_1024;

        case SEC_KEYTYPE_RSA_2048:
            return SEC_KEYCONTAINER_DER_RSA_2048;

        case SEC_KEYTYPE_RSA_3072:
            return SEC_KEYCONTAINER_DER_RSA_3072;

        case SEC_KEYTYPE_RSA_1024_PUBLIC:
            return SEC_KEYCONTAINER_DER_RSA_1024_PUBLIC;

        case SEC_KEYTYPE_RSA_2048_PUBLIC:
            return SEC_KEYCONTAINER_DER_RSA_2048_PUBLIC;

        case SEC_KEYTYPE_RSA_3072_PUBLIC:
            return SEC_KEYCONTAINER_DER_RSA_3072_PUBLIC;

        case SEC_KEYTYPE_ECC_NISTP256:
            return SEC_KEYCONTAINER_RAW_ECC_PRIVONLY_NISTP256;

        case SEC_KEYTYPE_ECC_NISTP256_PUBLIC:
            return SEC_KEYCONTAINER_DER_ECC_NISTP256_PUBLIC;

        default:
            return SEC_KEYCONTAINER_NUM;
    }
}

/**
 * @brief Find if the key with a specific id has been provisioned.
 *
 * @param processorHandle secure processor handle.
 * @param object_id id of the certificate.
 *
 * @return 1 if an object has been provisioned, 0 if it has not been.
 */
SEC_BOOL SecKey_IsProvisioned(Sec_ProcessorHandle* processorHandle,
        SEC_OBJECTID object_id) {
    Sec_KeyHandle* keyHandle;

    if (SEC_OBJECTID_INVALID == object_id)
        return SEC_FALSE;

    if (SecKey_GetInstance(processorHandle, object_id, &keyHandle) != SEC_RESULT_SUCCESS)
        return SEC_FALSE;

    SecKey_Release(keyHandle);
    return SEC_TRUE;
}

/**
 * @brief finds the first available key id in the range passed in.
 *
 * @param proc secure processor.
 * @param base bottom of the range to search.
 * @param top top of the range to search.
 * @return
 */
SEC_OBJECTID SecKey_ObtainFreeObjectId(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID base, SEC_OBJECTID top) {
    SEC_OBJECTID id;
    Sec_KeyHandle* keyHandle;
    Sec_Result result;

    for (id = base; id < top; ++id) {
        result = SecKey_GetInstance(processorHandle, id, &keyHandle);
        if (result == SEC_RESULT_SUCCESS)
            SecKey_Release(keyHandle);
        else
            return id;
    }

    return SEC_OBJECTID_INVALID;
}

/**
 * @brief Get the type (MSB byte) of the object id.
 */
uint8_t SecKey_GetObjectType(SEC_OBJECTID object_id) {
    return (SEC_BYTE) ((object_id & 0xff00000000000000ULL) >> 56);
}

/**
 * @brief Obtain a digest value computed over a specified key.
 *
 * @param proc secure processor handle.
 * @param key_id key id.
 * @param alg digest algorithm to use.
 * @param digest output digest value.
 * @param digest_len size of the written digest value.
 * @return
 */
Sec_Result SecKey_ComputeKeyDigest(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID key_id, Sec_DigestAlgorithm alg,
        SEC_BYTE* digest, SEC_SIZE* digest_len) {
    Sec_KeyHandle* keyHandle = NULL;
    Sec_DigestHandle* digestHandle = NULL;
    Sec_Result result = SEC_RESULT_FAILURE;
    do {
        if (SecKey_GetInstance(processorHandle, key_id, &keyHandle) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecKey_GetInstance returned error");
            break;
        }

        if (SecDigest_GetInstance(processorHandle, alg, &digestHandle) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecDigest_GetInstance returned error");
            break;
        }

        if (SecDigest_UpdateWithKey(digestHandle, keyHandle) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecDigest_UpdateWithKey returned error");
            break;
        }

        result = SecDigest_Release(digestHandle, digest, digest_len);
        digestHandle = NULL;
    } while (SEC_FALSE);

    if (keyHandle != NULL)
        SecKey_Release(keyHandle);

    if (digestHandle != NULL)
        SecDigest_Release(digestHandle, digest, digest_len);

    return result;
}

Sec_Result SecKey_ExtractWrappedKeyParamsAsn1V3(Sec_Asn1KC* kc, SEC_BYTE* payload, SEC_SIZE payloadLen,
        SEC_SIZE* written, Sec_KeyType* wrappedKeyType, SEC_OBJECTID* wrappingId, SEC_BYTE* wrappingIv,
        Sec_CipherAlgorithm* wrappingAlg, SEC_SIZE* key_offset, SEC_BYTE* wrappingKey, SEC_SIZE wrappingKeyLen,
        SEC_SIZE* writtenWrappingKey) {
    uint64_t ulong_val;
    SEC_SIZE written_iv;

    *writtenWrappingKey = 0;
    *wrappingId = 0;

    if (kc == NULL)
        return SEC_RESULT_FAILURE;

    if (SecAsn1KC_GetAttrBuffer(kc, SEC_ASN1KC_WRAPPEDKEY, payload, payloadLen, written) != SEC_RESULT_SUCCESS) {
        SEC_TRACE(SEC_TRACE_UNWRAP, "SecAsn1KC_GetAttrBuffer SEC_ASN1KC_WRAPPEDKEY failed");
        return SEC_RESULT_FAILURE;
    }

    if (SecAsn1KC_GetAttrUlong(kc, SEC_ASN1KC_WRAPPEDKEYTYPEID, &ulong_val) != SEC_RESULT_SUCCESS) {
        SEC_TRACE(SEC_TRACE_UNWRAP, "SecAsn1KC_GetAttrBuffer SEC_ASN1KC_WRAPPEDKEYTYPEID failed");
        return SEC_RESULT_FAILURE;
    }

    *wrappedKeyType = (Sec_KeyType) ulong_val;

    if (SecAsn1KC_HasAttr(kc, SEC_ASN1KC_WRAPPEDKEYOFFSET)) {
        if (SecAsn1KC_GetAttrUlong(kc, SEC_ASN1KC_WRAPPEDKEYOFFSET, &ulong_val) != SEC_RESULT_SUCCESS) {
            SEC_TRACE(SEC_TRACE_UNWRAP, "SecAsn1KC_GetAttrBuffer SEC_ASN1KC_WRAPPEDKEYOFFSET failed");
            return SEC_RESULT_FAILURE;
        }

        *key_offset = (SEC_SIZE) ulong_val;
    } else
        *key_offset = (SEC_SIZE) 0; // default value

    if (SecAsn1KC_HasAttr(kc, SEC_ASN1KC_WRAPPINGIV) &&
            SecAsn1KC_GetAttrBuffer(kc, SEC_ASN1KC_WRAPPINGIV, wrappingIv, SEC_AES_BLOCK_SIZE, &written_iv) !=
                    SEC_RESULT_SUCCESS) {
        SEC_TRACE(SEC_TRACE_UNWRAP, "SecAsn1KC_GetAttrBuffer SEC_ASN1KC_WRAPPEDKEYOFFSET failed");
        return SEC_RESULT_FAILURE;
    }

    if (SecAsn1KC_GetAttrUlong(kc, SEC_ASN1KC_WRAPPINGALGORITHMID, &ulong_val) != SEC_RESULT_SUCCESS) {
        SEC_TRACE(SEC_TRACE_UNWRAP, "SecAsn1KC_GetAttrBuffer SEC_ASN1KC_WRAPPINGALGORITHMID failed");
        return SEC_RESULT_FAILURE;
    }

    *wrappingAlg = (Sec_CipherAlgorithm) ulong_val;

    if (SecAsn1KC_HasAttr(kc, SEC_ASN1KC_WRAPPINGKEY)) {
        if (SecAsn1KC_GetAttrBuffer(kc, SEC_ASN1KC_WRAPPINGKEY, wrappingKey, wrappingKeyLen, writtenWrappingKey) !=
                SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecAsn1KC_GetAttrBuffer SEC_ASN1KC_WRAPPINGKEY failed");
            return SEC_RESULT_FAILURE;
        }
    } else {
        if (SecAsn1KC_GetAttrUint64(kc, SEC_ASN1KC_WRAPPINGKEYID, wrappingId) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecAsn1KC_GetAttrBuffer SEC_ASN1KC_WRAPPINGKEYID failed");
            return SEC_RESULT_FAILURE;
        }
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result SecKey_ExtractWrappedKeyParamsAsn1BufferOff(SEC_BYTE* asn1, SEC_SIZE asn1_len, SEC_BYTE* payload,
        SEC_SIZE payloadLen, SEC_SIZE* written, Sec_KeyType* wrappedKeyType, SEC_OBJECTID* wrappingId,
        SEC_BYTE* wrappingIv, Sec_CipherAlgorithm* wrappingAlg, SEC_SIZE* key_offset) {
    Sec_Asn1KC* asn1kc = NULL;
    Sec_Result result = SEC_RESULT_FAILURE;

    asn1kc = SecAsn1KC_Decode(asn1, asn1_len);
    if (asn1kc == NULL) {
        SEC_LOG_ERROR("SecAsn1KC_Decode failed");
        SecAsn1KC_Free(asn1kc);
        return result;
    }

    result = SecKey_ExtractWrappedKeyParamsAsn1Off(asn1kc, payload, payloadLen, written, wrappedKeyType, wrappingId,
            wrappingIv, wrappingAlg, key_offset);
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecKey_ExtractWrappedKeyParamsAsn1Off failed");
        SecAsn1KC_Free(asn1kc);
        return result;
    }

    SecAsn1KC_Free(asn1kc);
    return SEC_RESULT_SUCCESS;
}

#ifndef SEC_COMMON_17

Sec_Result SecKey_GenerateWrappedKeyAsn1(SEC_BYTE* wrappedKey, SEC_SIZE wrappedKeyLen, Sec_KeyType wrappedKeyType,
        SEC_OBJECTID wrappingKeyId, SEC_BYTE* wrappingIv, Sec_CipherAlgorithm wrappingAlgorithm, SEC_BYTE* output,
        SEC_SIZE output_len, SEC_SIZE* written) {
    Sec_Asn1KC* asn1kc = NULL;
    Sec_Result result = SEC_RESULT_FAILURE;

    asn1kc = SecAsn1KC_Alloc();
    if (SecAsn1KC_AddAttrBuffer(asn1kc, SEC_ASN1KC_WRAPPEDKEY, wrappedKey, wrappedKeyLen) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecAsn1KC_AddAttrBuffer failed");
        if (asn1kc != NULL) {
            SecAsn1KC_Free(asn1kc);
            asn1kc = NULL;
        }

        return result;
    }

    if (SecAsn1KC_AddAttrUlong(asn1kc, SEC_ASN1KC_WRAPPEDKEYTYPEID, wrappedKeyType) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecAsn1KC_AddAttrUlong failed");
        if (asn1kc != NULL) {
            SecAsn1KC_Free(asn1kc);
            asn1kc = NULL;
        }

        return result;
    }

    if (SecAsn1KC_AddAttrUint64(asn1kc, SEC_ASN1KC_WRAPPINGKEYID, wrappingKeyId) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecAsn1KC_AddAttrUint64 failed");
        if (asn1kc != NULL) {
            SecAsn1KC_Free(asn1kc);
            asn1kc = NULL;
        }

        return result;
    }

    if (wrappingIv != NULL) {
        if (SecAsn1KC_AddAttrBuffer(asn1kc, SEC_ASN1KC_WRAPPINGIV, wrappingIv, SEC_AES_BLOCK_SIZE) !=
                SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecAsn1KC_AddAttrBuffer failed");
            if (asn1kc != NULL) {
                SecAsn1KC_Free(asn1kc);
                asn1kc = NULL;
            }

            return result;
        }
    }

    if (SecAsn1KC_AddAttrUlong(asn1kc, SEC_ASN1KC_WRAPPINGALGORITHMID, wrappingAlgorithm) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecAsn1KC_AddAttrUlong failed");
        if (asn1kc != NULL) {
            SecAsn1KC_Free(asn1kc);
            asn1kc = NULL;
        }

        return result;
    }

    if (SecAsn1KC_Encode(asn1kc, output, output_len, written) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecAsn1KC_Encode failed");
        if (asn1kc != NULL) {
            SecAsn1KC_Free(asn1kc);
            asn1kc = NULL;
        }

        return result;
    }

    if (asn1kc != NULL) {
        SecAsn1KC_Free(asn1kc);
        asn1kc = NULL;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result SecKey_GenerateWrappedKeyAsn1Off(SEC_BYTE* payload, SEC_SIZE payloadLen, Sec_KeyType wrappedKeyType,
        SEC_OBJECTID wrappingKeyId, SEC_BYTE* wrappingIv, Sec_CipherAlgorithm wrappingAlgorithm, SEC_BYTE* output,
        SEC_SIZE output_len, SEC_SIZE* written, SEC_SIZE key_offset) {
    Sec_Asn1KC* asn1kc = NULL;
    Sec_Result result = SEC_RESULT_FAILURE;

    asn1kc = SecAsn1KC_Alloc();
    if (SecAsn1KC_AddAttrBuffer(asn1kc, SEC_ASN1KC_WRAPPEDKEY, payload, payloadLen) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecAsn1KC_AddAttrBuffer failed");
        if (asn1kc != NULL) {
            SecAsn1KC_Free(asn1kc);
            asn1kc = NULL;
        }

        return result;
    }

    if (SecAsn1KC_AddAttrUlong(asn1kc, SEC_ASN1KC_WRAPPEDKEYTYPEID, wrappedKeyType) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecAsn1KC_AddAttrUlong failed");
        if (asn1kc != NULL) {
            SecAsn1KC_Free(asn1kc);
            asn1kc = NULL;
        }

        return result;
    }

    if (SecAsn1KC_AddAttrUint64(asn1kc, SEC_ASN1KC_WRAPPINGKEYID, wrappingKeyId) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecAsn1KC_AddAttrUint64 failed");
        if (asn1kc != NULL) {
            SecAsn1KC_Free(asn1kc);
            asn1kc = NULL;
        }

        return result;
    }

    if (wrappingIv != NULL) {
        if (SecAsn1KC_AddAttrBuffer(asn1kc, SEC_ASN1KC_WRAPPINGIV, wrappingIv, SEC_AES_BLOCK_SIZE) !=
                SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecAsn1KC_AddAttrBuffer failed");
            if (asn1kc != NULL) {
                SecAsn1KC_Free(asn1kc);
                asn1kc = NULL;
            }

            return result;
        }
    }

    if ((key_offset + SecKey_GetKeyLenForKeyType(wrappedKeyType)) > payloadLen) {
        SEC_LOG_ERROR("Illegal key_offset %ld", (long) key_offset);
        if (asn1kc != NULL) {
            SecAsn1KC_Free(asn1kc);
            asn1kc = NULL;
        }

        return result;
    }

    if (SecAsn1KC_AddAttrUlong(asn1kc, SEC_ASN1KC_WRAPPEDKEYOFFSET, key_offset) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecAsn1KC_AddAttrUlong failed");
        if (asn1kc != NULL) {
            SecAsn1KC_Free(asn1kc);
            asn1kc = NULL;
        }

        return result;
    }

    if (SecAsn1KC_AddAttrUlong(asn1kc, SEC_ASN1KC_WRAPPINGALGORITHMID, wrappingAlgorithm) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecAsn1KC_AddAttrUlong failed");
        if (asn1kc != NULL) {
            SecAsn1KC_Free(asn1kc);
            asn1kc = NULL;
        }

        return result;
    }

    if (SecAsn1KC_Encode(asn1kc, output, output_len, written) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecAsn1KC_Encode failed");
        if (asn1kc != NULL) {
            SecAsn1KC_Free(asn1kc);
            asn1kc = NULL;
        }

        return result;
    }

    if (asn1kc != NULL) {
        SecAsn1KC_Free(asn1kc);
        asn1kc = NULL;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result SecKey_GenerateWrappedKeyAsn1V3(SEC_BYTE* payload, SEC_SIZE payloadLen, Sec_KeyType wrappedKeyType,
        SEC_BYTE* wrappingKey, SEC_SIZE wrappingKeyLen, SEC_BYTE* wrappingIv,
        Sec_CipherAlgorithm wrappingAlgorithm, SEC_BYTE* output, SEC_SIZE output_len,
        SEC_SIZE* written, SEC_SIZE key_offset) {
    Sec_Asn1KC* asn1kc = NULL;
    Sec_Result result = SEC_RESULT_FAILURE;

    asn1kc = SecAsn1KC_Alloc();
    if (SecAsn1KC_AddAttrBuffer(asn1kc, SEC_ASN1KC_WRAPPEDKEY, payload, payloadLen) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecAsn1KC_AddAttrBuffer failed");
        if (asn1kc != NULL) {
            SecAsn1KC_Free(asn1kc);
            asn1kc = NULL;
        }

        return result;
    }

    if (SecAsn1KC_AddAttrUlong(asn1kc, SEC_ASN1KC_WRAPPEDKEYTYPEID, wrappedKeyType) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecAsn1KC_AddAttrUlong failed");
        if (asn1kc != NULL) {
            SecAsn1KC_Free(asn1kc);
            asn1kc = NULL;
        }

        return result;
    }

    if (SecAsn1KC_AddAttrBuffer(asn1kc, SEC_ASN1KC_WRAPPINGKEY, wrappingKey, wrappingKeyLen) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecAsn1KC_AddAttrBuffer failed");
        if (asn1kc != NULL) {
            SecAsn1KC_Free(asn1kc);
            asn1kc = NULL;
        }

        return result;
    }

    if (wrappingIv != NULL) {
        if (SecAsn1KC_AddAttrBuffer(asn1kc, SEC_ASN1KC_WRAPPINGIV, wrappingIv, SEC_AES_BLOCK_SIZE) !=
                SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecAsn1KC_AddAttrBuffer failed");
            if (asn1kc != NULL) {
                SecAsn1KC_Free(asn1kc);
                asn1kc = NULL;
            }

            return result;
        }
    }

    if ((key_offset + SecKey_GetKeyLenForKeyType(wrappedKeyType)) > payloadLen) {
        SEC_LOG_ERROR("Illegal key_offset %ld", (long) key_offset);
        if (asn1kc != NULL) {
            SecAsn1KC_Free(asn1kc);
            asn1kc = NULL;
        }

        return result;
    }

    if (SecAsn1KC_AddAttrUlong(asn1kc, SEC_ASN1KC_WRAPPEDKEYOFFSET, key_offset) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecAsn1KC_AddAttrUlong failed");
        if (asn1kc != NULL) {
            SecAsn1KC_Free(asn1kc);
            asn1kc = NULL;
        }

        return result;
    }

    if (SecAsn1KC_AddAttrUlong(asn1kc, SEC_ASN1KC_WRAPPINGALGORITHMID, wrappingAlgorithm) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecAsn1KC_AddAttrUlong failed");
        if (asn1kc != NULL) {
            SecAsn1KC_Free(asn1kc);
            asn1kc = NULL;
        }

        return result;
    }

    if (SecAsn1KC_Encode(asn1kc, output, output_len, written) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecAsn1KC_Encode failed");
        if (asn1kc != NULL) {
            SecAsn1KC_Free(asn1kc);
            asn1kc = NULL;
        }

        return result;
    }

    if (asn1kc != NULL) {
        SecAsn1KC_Free(asn1kc);
        asn1kc = NULL;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result SecKey_ExtractWrappedKeyParamsAsn1Off(Sec_Asn1KC* kc, SEC_BYTE* payload, SEC_SIZE payloadLen,
        SEC_SIZE* written, Sec_KeyType* wrappedKeyType, SEC_OBJECTID* wrappingId, SEC_BYTE* wrappingIv,
        Sec_CipherAlgorithm* wrappingAlg, SEC_SIZE* key_offset) {
    uint64_t ulong_val;
    SEC_SIZE written_iv;

    if (kc == NULL)
        return SEC_RESULT_FAILURE;

    if (SecAsn1KC_GetAttrBuffer(kc, SEC_ASN1KC_WRAPPEDKEY, payload, payloadLen, written) != SEC_RESULT_SUCCESS) {
        SEC_TRACE(SEC_TRACE_UNWRAP, "SecAsn1KC_GetAttrBuffer SEC_ASN1KC_WRAPPEDKEY failed");
        return SEC_RESULT_FAILURE;
    }

    if (SecAsn1KC_GetAttrUlong(kc, SEC_ASN1KC_WRAPPEDKEYTYPEID, &ulong_val) != SEC_RESULT_SUCCESS) {
        SEC_TRACE(SEC_TRACE_UNWRAP, "SecAsn1KC_GetAttrUlong SEC_ASN1KC_WRAPPEDKEYTYPEID failed");
        return SEC_RESULT_FAILURE;
    }

    *wrappedKeyType = (Sec_KeyType) ulong_val;

    if (SecAsn1KC_GetAttrUint64(kc, SEC_ASN1KC_WRAPPINGKEYID, wrappingId) != SEC_RESULT_SUCCESS) {
        SEC_TRACE(SEC_TRACE_UNWRAP, "SecAsn1KC_GetAttrUint64 SEC_ASN1KC_WRAPPINGKEYID failed");
        return SEC_RESULT_FAILURE;
    }

    if (SecAsn1KC_HasAttr(kc, SEC_ASN1KC_WRAPPEDKEYOFFSET)) {
        if (SecAsn1KC_GetAttrUlong(kc, SEC_ASN1KC_WRAPPEDKEYOFFSET, &ulong_val) != SEC_RESULT_SUCCESS) {
            SEC_TRACE(SEC_TRACE_UNWRAP, "SecAsn1KC_GetAttrUlong SEC_ASN1KC_WRAPPEDKEYOFFSET failed");
            return SEC_RESULT_FAILURE;
        }
        *key_offset = (SEC_SIZE) ulong_val;
    } else {
        *key_offset = (SEC_SIZE) 0; // default value
    }

    if (SecAsn1KC_HasAttr(kc, SEC_ASN1KC_WRAPPINGIV) &&
            SecAsn1KC_GetAttrBuffer(kc, SEC_ASN1KC_WRAPPINGIV, wrappingIv, SEC_AES_BLOCK_SIZE, &written_iv) !=
                    SEC_RESULT_SUCCESS) {
        SEC_TRACE(SEC_TRACE_UNWRAP, "SecAsn1KC_GetAttrBuffer SEC_ASN1KC_WRAPPINGIV failed");
        return SEC_RESULT_FAILURE;
    }

    if (SecAsn1KC_GetAttrUlong(kc, SEC_ASN1KC_WRAPPINGALGORITHMID, &ulong_val) != SEC_RESULT_SUCCESS) {
        SEC_TRACE(SEC_TRACE_UNWRAP, "SecAsn1KC_GetAttrUlong SEC_ASN1KC_WRAPPINGALGORITHMID failed");
        return SEC_RESULT_FAILURE;
    }

    *wrappingAlg = (Sec_CipherAlgorithm) ulong_val;
    return SEC_RESULT_SUCCESS;
}

#endif

void rights_set_allow_all(sa_rights* rights, Sec_KeyType key_type) {
    memset(rights, 0, sizeof(sa_rights));

    rights->not_before = 0;
    rights->not_on_or_after = UINT64_MAX;

    rights->usage_flags = 0;
    switch (key_type) {
        case SEC_KEYTYPE_AES_128:
        case SEC_KEYTYPE_AES_256:
            SA_USAGE_BIT_SET(rights->usage_flags, SA_USAGE_FLAG_UNWRAP);
            SA_USAGE_BIT_SET(rights->usage_flags, SA_USAGE_FLAG_ENCRYPT);
            SA_USAGE_BIT_SET(rights->usage_flags, SA_USAGE_FLAG_DECRYPT);
            SA_USAGE_BIT_SET(rights->usage_flags, SA_USAGE_FLAG_SIGN);
            SA_USAGE_BIT_SET(rights->usage_flags, SA_USAGE_FLAG_DERIVE);
            break;

        case SEC_KEYTYPE_HMAC_128:
        case SEC_KEYTYPE_HMAC_160:
        case SEC_KEYTYPE_HMAC_256:
            SA_USAGE_BIT_SET(rights->usage_flags, SA_USAGE_FLAG_SIGN);
            SA_USAGE_BIT_SET(rights->usage_flags, SA_USAGE_FLAG_DERIVE);
            break;

        case SEC_KEYTYPE_RSA_1024:
        case SEC_KEYTYPE_RSA_2048:
        case SEC_KEYTYPE_RSA_3072:
        case SEC_KEYTYPE_ECC_NISTP256:
            SA_USAGE_BIT_SET(rights->usage_flags, SA_USAGE_FLAG_UNWRAP);
            SA_USAGE_BIT_SET(rights->usage_flags, SA_USAGE_FLAG_DECRYPT);
            SA_USAGE_BIT_SET(rights->usage_flags, SA_USAGE_FLAG_SIGN);
            break;

        case SEC_KEYTYPE_RSA_1024_PUBLIC:
        case SEC_KEYTYPE_RSA_2048_PUBLIC:
        case SEC_KEYTYPE_RSA_3072_PUBLIC:
        case SEC_KEYTYPE_ECC_NISTP256_PUBLIC:
            SA_USAGE_BIT_SET(rights->usage_flags, SA_USAGE_FLAG_ENCRYPT);
            break;

        default:
            SA_USAGE_BIT_SET(rights->usage_flags, SA_USAGE_FLAG_DERIVE);
            break;
    }

    SA_USAGE_BIT_SET(rights->usage_flags, SA_USAGE_FLAG_KEY_EXCHANGE);
    rights->usage_flags |= SA_USAGE_OUTPUT_PROTECTIONS_MASK;
    SA_USAGE_BIT_SET(rights->usage_flags, SA_USAGE_FLAG_CACHEABLE);
    Sec_Memset(rights->allowed_tas, 0, sizeof(rights->allowed_tas));

    const sa_uuid ALL_MATCH = {
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    memcpy(&rights->allowed_tas[7], &ALL_MATCH, sizeof(sa_uuid));
}

Sec_Result prepare_and_store_key_data(Sec_ProcessorHandle* processorHandle, Sec_StorageLoc location,
        SEC_OBJECTID object_id, Sec_Key* key, Sec_KeyContainer key_container, void* key_buffer, SEC_SIZE key_length) {
    Sec_KeyData* key_data = calloc(1, sizeof(Sec_KeyData));
    if (key_data == NULL) {
        SEC_LOG_ERROR("calloc failed");
        return SEC_RESULT_FAILURE;
    }

    Sec_Result result;
    switch (key_container) {
        case SEC_KEYCONTAINER_RAW_AES_128:
        case SEC_KEYCONTAINER_RAW_AES_256:
        case SEC_KEYCONTAINER_RAW_HMAC_128:
        case SEC_KEYCONTAINER_RAW_HMAC_160:
        case SEC_KEYCONTAINER_RAW_HMAC_256:
        case SEC_KEYCONTAINER_DER_RSA_1024:
        case SEC_KEYCONTAINER_DER_RSA_2048:
        case SEC_KEYCONTAINER_DER_RSA_3072:
        case SEC_KEYCONTAINER_RAW_ECC_PRIVONLY_NISTP256:
        case SEC_KEYCONTAINER_SOC:
            key_data->info.kc_type = SEC_KEYCONTAINER_EXPORTED;
            result = export_key(key, NULL, key_data->key_container, SEC_KEYCONTAINER_MAX_LEN, &key_data->kc_len);
            sa_key_release(key->handle);
            break;

        case SEC_KEYCONTAINER_EXPORTED:
        case SEC_KEYCONTAINER_JTYPE:
            if (key_buffer != NULL && key_length != 0) {
                key_data->info.kc_type = key_container;
                memcpy(key_data->key_container, key_buffer, key_length);
                key_data->kc_len = key_length;
                sa_key_release(key->handle);
                result = SEC_RESULT_SUCCESS;
            } else {
                result = SEC_RESULT_INVALID_PARAMETERS;
            }

            break;

        case SEC_KEYCONTAINER_DER_RSA_1024_PUBLIC:
        case SEC_KEYCONTAINER_DER_RSA_2048_PUBLIC:
        case SEC_KEYCONTAINER_DER_RSA_3072_PUBLIC:
            if (key_buffer != NULL && key_length != 0) {
                key_data->info.kc_type = key_container;
                memcpy(key_data->key_container, key_buffer, key_length);
                key_data->kc_len = key_length;
                RSA_free(key->rsa);
                result = SEC_RESULT_SUCCESS;
            } else {
                result = SEC_RESULT_INVALID_PARAMETERS;
            }

            break;

        case SEC_KEYCONTAINER_DER_ECC_NISTP256_PUBLIC:
            if (key_buffer != NULL && key_length != 0) {
                key_data->info.kc_type = key_container;
                memcpy(key_data->key_container, key_buffer, key_length);
                key_data->kc_len = key_length;
                EC_KEY_free(key->ec_key);
                result = SEC_RESULT_SUCCESS;
            } else {
                result = SEC_RESULT_INVALID_PARAMETERS;
            }

            break;

        default:
            result = SEC_RESULT_UNIMPLEMENTED_FEATURE;
    }

    if (result == SEC_RESULT_SUCCESS)
        result = store_key_data(processorHandle, location, object_id, key_data);

    SEC_FREE(key_data);
    return result;
}

const Sec_Key* get_key(Sec_KeyHandle* keyHandle) {
    return &keyHandle->key;
}

static Sec_KeyType get_key_type(sa_header* key_header) {
    Sec_KeyType key_type;
    switch ((*key_header).type) {
        case SA_KEY_TYPE_SYMMETRIC:
            if ((SA_USAGE_BIT_TEST((*key_header).rights.usage_flags, SA_USAGE_FLAG_SIGN) ||
                        SA_USAGE_BIT_TEST((*key_header).rights.usage_flags, SA_USAGE_FLAG_DERIVE)) &&
                    !SA_USAGE_BIT_TEST((*key_header).rights.usage_flags, SA_USAGE_FLAG_ENCRYPT) &&
                    !SA_USAGE_BIT_TEST((*key_header).rights.usage_flags, SA_USAGE_FLAG_DECRYPT) &&
                    !SA_USAGE_BIT_TEST((*key_header).rights.usage_flags, SA_USAGE_FLAG_UNWRAP)) {
                if ((*key_header).size == 16)
                    key_type = SEC_KEYTYPE_HMAC_128;
                else if ((*key_header).size == 20)
                    key_type = SEC_KEYTYPE_HMAC_160;
                else if ((*key_header).size == 32)
                    key_type = SEC_KEYTYPE_HMAC_256;
                else
                    key_type = SEC_KEYTYPE_NUM;
            } else if (SA_USAGE_BIT_TEST((*key_header).rights.usage_flags, SA_USAGE_FLAG_DERIVE) ||
                       SA_USAGE_BIT_TEST((*key_header).rights.usage_flags, SA_USAGE_FLAG_ENCRYPT) ||
                       SA_USAGE_BIT_TEST((*key_header).rights.usage_flags, SA_USAGE_FLAG_DECRYPT) ||
                       SA_USAGE_BIT_TEST((*key_header).rights.usage_flags, SA_USAGE_FLAG_SIGN) ||
                       SA_USAGE_BIT_TEST((*key_header).rights.usage_flags, SA_USAGE_FLAG_UNWRAP)) {
                if ((*key_header).size == 16)
                    key_type = SEC_KEYTYPE_AES_128;
                else if ((*key_header).size == 20)
                    key_type = SEC_KEYTYPE_HMAC_160;
                else if ((*key_header).size == 32)
                    key_type = SEC_KEYTYPE_AES_256;
                else
                    key_type = SEC_KEYTYPE_NUM;
            } else {
                key_type = SEC_KEYTYPE_NUM;
            }

            break;

        case SA_KEY_TYPE_EC:
            key_type = SEC_KEYTYPE_ECC_NISTP256;
            break;

        case SA_KEY_TYPE_RSA:
            if ((*key_header).size == 128)
                key_type = SEC_KEYTYPE_RSA_1024;
            else if ((*key_header).size == 256)
                key_type = SEC_KEYTYPE_RSA_2048;
            else if ((*key_header).size == 384)
                key_type = SEC_KEYTYPE_RSA_3072;
            else
                key_type = SEC_KEYTYPE_NUM;
            break;

        case SA_KEY_TYPE_DH:
        default:
            key_type = SEC_KEYTYPE_NUM;
            break;
    }

    return key_type;
}

static void find_ram_key_data(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID object_id, Sec_RAMKeyData** data,
        Sec_RAMKeyData** parent) {
    *parent = NULL;
    *data = processorHandle->ram_keys;

    while ((*data) != NULL) {
        if (object_id == (*data)->object_id)
            return;

        *parent = (*data);
        *data = (*data)->next;
    }

    *parent = NULL;
}

static Sec_Result retrieve_key_data(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID object_id,
        Sec_StorageLoc* location, Sec_KeyData* keyData) {
    char file_name_key[SEC_MAX_FILE_PATH_LEN];
    char file_name_info[SEC_MAX_FILE_PATH_LEN];
    char file_name_verification[SEC_MAX_FILE_PATH_LEN];
    Sec_RAMKeyData* ram_key = NULL;
    Sec_RAMKeyData* ram_key_parent = NULL;
    SEC_SIZE data_read;

    CHECK_PROCHANDLE(processorHandle)

    /* check in RAM */
    find_ram_key_data(processorHandle, object_id, &ram_key, &ram_key_parent);
    if (ram_key != NULL) {
        memcpy(keyData, &(ram_key->key_data), sizeof(Sec_KeyData));
        *location = SEC_STORAGELOC_RAM;
        return SEC_RESULT_SUCCESS;
    }

    /* check in app_dir */
    char* sec_dirs[] = {processorHandle->app_dir, processorHandle->global_dir};
    for (int i = 0; i < 2; i++) {
        if (sec_dirs[i] != NULL) {
            snprintf(file_name_key, sizeof(file_name_key), SEC_KEY_FILENAME_PATTERN, sec_dirs[i],
                    object_id);
            snprintf(file_name_info, sizeof(file_name_info), SEC_KEYINFO_FILENAME_PATTERN, sec_dirs[i],
                    object_id);
            snprintf(file_name_verification, sizeof(file_name_verification), SEC_VERIFICATION_FILENAME_PATTERN,
                    sec_dirs[i], object_id);
            if (SecUtils_FileExists(file_name_key) && SecUtils_FileExists(file_name_info)) {
                if (SecUtils_ReadFile(file_name_key, keyData->key_container, sizeof(keyData->key_container),
                            &keyData->kc_len) != SEC_RESULT_SUCCESS ||
                        SecUtils_ReadFile(file_name_info, &keyData->info, sizeof(keyData->info), &data_read) !=
                                SEC_RESULT_SUCCESS) {
                    SEC_LOG_ERROR("Could not read one of the key files");
                    return SEC_RESULT_FAILURE;
                }

                if (data_read != sizeof(keyData->info)) {
                    SEC_LOG_ERROR("File is not of the correct size");
                    return SEC_RESULT_FAILURE;
                }

                if (SecUtils_FileExists(file_name_verification)) {
                    if (verify_verification_file(processorHandle, file_name_verification, keyData->key_container,
                                keyData->kc_len, (SEC_BYTE*) &keyData->info, sizeof(keyData->info)) !=
                            SEC_RESULT_SUCCESS) {
                        SEC_LOG_ERROR("Key verification failed");
                        return SEC_RESULT_FAILURE;
                    }
                } else {
                    // If the verification file doesn't exist, the key file was created by an old SecApi. If the key
                    // container type is Exported, the old SecApi uses a different export format and the key file cannot
                    // be read. So fail the key retrieval.
                    if (keyData->info.kc_type == SEC_KEYCONTAINER_EXPORTED) {
                        SEC_LOG_ERROR("Old Exported key container format");
                        return SEC_RESULT_FAILURE;
                    }

                    if (write_verification_file(processorHandle, file_name_verification, keyData->key_container,
                                keyData->kc_len, (SEC_BYTE*) &keyData->info, sizeof(keyData->info)) !=
                            SEC_RESULT_SUCCESS) {
                        SEC_LOG_ERROR("Could not write verification file");
                    }
                }
                *location = SEC_STORAGELOC_FILE;
                return SEC_RESULT_SUCCESS;
            }
        }
    }

    return SEC_RESULT_NO_SUCH_ITEM;
}

static Sec_Result store_key_data(Sec_ProcessorHandle* processorHandle, Sec_StorageLoc location, SEC_OBJECTID object_id,
        Sec_KeyData* key_data) {
    Sec_RAMKeyData* ram_key;

    if (location == SEC_STORAGELOC_RAM || location == SEC_STORAGELOC_RAM_SOFT_WRAPPED) {
        SecKey_Delete(processorHandle, object_id);

        ram_key = calloc(1, sizeof(Sec_RAMKeyData));
        if (ram_key == NULL) {
            SEC_LOG_ERROR("Calloc failed");
            return SEC_RESULT_FAILURE;
        }

        ram_key->object_id = object_id;
        memcpy(&(ram_key->key_data), key_data, sizeof(Sec_KeyData));
        ram_key->next = processorHandle->ram_keys;
        processorHandle->ram_keys = ram_key;
        return SEC_RESULT_SUCCESS;
    }

    if (location == SEC_STORAGELOC_FILE || location == SEC_STORAGELOC_FILE_SOFT_WRAPPED) {
        if (processorHandle->app_dir == NULL) {
            SEC_LOG_ERROR("Cannot write file because app_dir is NULL");
            return SEC_RESULT_FAILURE;
        }

        SecKey_Delete(processorHandle, object_id);

        char file_name_key[SEC_MAX_FILE_PATH_LEN];
        char file_name_info[SEC_MAX_FILE_PATH_LEN];
        char file_name_verification[SEC_MAX_FILE_PATH_LEN];
        snprintf(file_name_key, sizeof(file_name_key), SEC_KEY_FILENAME_PATTERN, processorHandle->app_dir,
                object_id);
        snprintf(file_name_info, sizeof(file_name_info), SEC_KEYINFO_FILENAME_PATTERN,
                processorHandle->app_dir, object_id);
        snprintf(file_name_verification, sizeof(file_name_verification), SEC_VERIFICATION_FILENAME_PATTERN,
                processorHandle->app_dir, object_id);

        if (SecUtils_WriteFile(file_name_key, key_data->key_container, key_data->kc_len) !=
                        SEC_RESULT_SUCCESS ||
                SecUtils_WriteFile(file_name_info, &key_data->info, sizeof(key_data->info)) !=
                        SEC_RESULT_SUCCESS ||
                write_verification_file(processorHandle, file_name_verification,
                        key_data->key_container, key_data->kc_len,
                        (SEC_BYTE*) &key_data->info, sizeof(key_data->info)) !=
                        SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("Could not write info file");
            SecUtils_RmFile(file_name_key);
            SecUtils_RmFile(file_name_info);
            SecUtils_RmFile(file_name_verification);
            return SEC_RESULT_FAILURE;
        }

        return SEC_RESULT_SUCCESS;
    }

    SEC_LOG_ERROR("Unimplemented location type");
    return SEC_RESULT_UNIMPLEMENTED_FEATURE;
}

static Sec_Result process_key_container(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID object_id,
        Sec_KeyContainer in_key_container, void* data, SEC_SIZE data_length, Sec_Key* key,
        Sec_KeyContainer* out_key_container, void* key_buffer, SEC_SIZE* key_length) {
    Sec_Result result;
    unsigned char* p_data;
    SEC_SIZE key_size;
    Sec_KeyType key_type;
    sa_rights rights;
    sa_key_format key_format;
    void* parameters;
    sa_import_parameters_symmetric symmetric_parameters;
    sa_import_parameters_rsa_private_key_info rsa_parameters;
    sa_import_parameters_ec_private_bytes ec_parameters;
    sa_import_parameters_typej typej_parameters;
    sa_import_parameters_soc_legacy parameters_soc_legacy;
    Sec_KeyHandle* cipherKeyHandle = NULL;
    Sec_KeyHandle* hmacKeyHandle = NULL;
    sa_status status;

    if (in_key_container == SEC_KEYCONTAINER_STORE) {
        result = process_store_key_container(processorHandle, data, data_length, key_buffer, key_length,
                out_key_container);
        if (result != SEC_RESULT_SUCCESS)
            return result;

        p_data = key_buffer;
    } else {
        *out_key_container = in_key_container;
        p_data = data;
        *key_length = data_length;
    }

    if (*out_key_container == SEC_KEYCONTAINER_ASN1) {
        result = process_asn1_key_container(processorHandle, p_data, *key_length, key_buffer, key_length,
                out_key_container);
        if (result != SEC_RESULT_SUCCESS)
            return result;

        p_data = key_buffer;
    }

    switch (*out_key_container) {
        case SEC_KEYCONTAINER_RAW_AES_128:
        case SEC_KEYCONTAINER_RAW_AES_256:
        case SEC_KEYCONTAINER_RAW_HMAC_128:
        case SEC_KEYCONTAINER_RAW_HMAC_160:
        case SEC_KEYCONTAINER_RAW_HMAC_256:
            key_type = SecKey_GetKeyTypeForClearKeyContainer(*out_key_container);
            key_size = SecKey_GetKeyLenForKeyType(key_type);
            if (*key_length != key_size) {
                SEC_LOG_ERROR("Invalid key container length");
                return SEC_RESULT_INVALID_PARAMETERS;
            }

            memmove(key_buffer, p_data, *key_length);
            key_format = SA_KEY_FORMAT_SYMMETRIC_BYTES;
            rights_set_allow_all(&rights, SecKey_GetKeyTypeForClearKeyContainer(*out_key_container));
            symmetric_parameters.rights = &rights;
            parameters = &symmetric_parameters;
            break;

        case SEC_KEYCONTAINER_DER_RSA_1024:
        case SEC_KEYCONTAINER_DER_RSA_2048:
        case SEC_KEYCONTAINER_DER_RSA_3072:
        case SEC_KEYCONTAINER_RAW_RSA_1024:
        case SEC_KEYCONTAINER_RAW_RSA_2048:
        case SEC_KEYCONTAINER_RAW_RSA_3072:
        case SEC_KEYCONTAINER_PEM_RSA_1024:
        case SEC_KEYCONTAINER_PEM_RSA_2048:
        case SEC_KEYCONTAINER_PEM_RSA_3072:
            result = process_rsa_key_container(*out_key_container, p_data, *key_length, key_buffer, key_length,
                    out_key_container);
            if (result != SEC_RESULT_SUCCESS)
                return result;

            key_format = SA_KEY_FORMAT_RSA_PRIVATE_KEY_INFO;
            rights_set_allow_all(&rights, SecKey_GetKeyTypeForClearKeyContainer(*out_key_container));
            rsa_parameters.rights = &rights;
            parameters = &rsa_parameters;
            break;

        case SEC_KEYCONTAINER_DER_RSA_1024_PUBLIC:
        case SEC_KEYCONTAINER_DER_RSA_2048_PUBLIC:
        case SEC_KEYCONTAINER_DER_RSA_3072_PUBLIC:
        case SEC_KEYCONTAINER_RAW_RSA_1024_PUBLIC:
        case SEC_KEYCONTAINER_RAW_RSA_2048_PUBLIC:
        case SEC_KEYCONTAINER_RAW_RSA_3072_PUBLIC:
        case SEC_KEYCONTAINER_PEM_RSA_1024_PUBLIC:
        case SEC_KEYCONTAINER_PEM_RSA_2048_PUBLIC:
        case SEC_KEYCONTAINER_PEM_RSA_3072_PUBLIC:
            result = process_rsa_public_key_container(*out_key_container, p_data, *key_length, &key->rsa,
                    key_buffer, key_length, out_key_container);
            if (result != SEC_RESULT_SUCCESS)
                return result;

            // Public key so skip key import.
            return SEC_RESULT_SUCCESS;

        case SEC_KEYCONTAINER_DER_ECC_NISTP256:
        case SEC_KEYCONTAINER_RAW_ECC_NISTP256:
        case SEC_KEYCONTAINER_RAW_ECC_PRIVONLY_NISTP256:
        case SEC_KEYCONTAINER_PEM_ECC_NISTP256:
            result = process_ec_key_container(*out_key_container, p_data, *key_length, key_buffer, key_length,
                    out_key_container);
            if (result != SEC_RESULT_SUCCESS)
                return result;

            key_format = SA_KEY_FORMAT_EC_PRIVATE_BYTES;
            rights_set_allow_all(&rights, SecKey_GetKeyTypeForClearKeyContainer(*out_key_container));
            ec_parameters.rights = &rights;
            ec_parameters.curve = SA_ELLIPTIC_CURVE_NIST_P256;
            parameters = &ec_parameters;
            break;

        case SEC_KEYCONTAINER_DER_ECC_NISTP256_PUBLIC:
        case SEC_KEYCONTAINER_RAW_ECC_NISTP256_PUBLIC:
        case SEC_KEYCONTAINER_PEM_ECC_NISTP256_PUBLIC:
            result = process_ec_public_key_container(*out_key_container, p_data, *key_length, &key->ec_key,
                    key_buffer, key_length, out_key_container);
            if (result != SEC_RESULT_SUCCESS)
                return result;

            // Public key so skip key import.
            return SEC_RESULT_SUCCESS;

        case SEC_KEYCONTAINER_SOC:
        case SEC_KEYCONTAINER_SOC_INTERNAL_0:
        case SEC_KEYCONTAINER_SOC_INTERNAL_1:
        case SEC_KEYCONTAINER_SOC_INTERNAL_2:
        case SEC_KEYCONTAINER_SOC_INTERNAL_3:
        case SEC_KEYCONTAINER_SOC_INTERNAL_4:
        case SEC_KEYCONTAINER_SOC_INTERNAL_5:
        case SEC_KEYCONTAINER_SOC_INTERNAL_6:
        case SEC_KEYCONTAINER_SOC_INTERNAL_7:
        case SEC_KEYCONTAINER_SOC_INTERNAL_8:
        case SEC_KEYCONTAINER_SOC_INTERNAL_9:
        case SEC_KEYCONTAINER_SOC_INTERNAL_10:
        case SEC_KEYCONTAINER_SOC_INTERNAL_11:
        case SEC_KEYCONTAINER_SOC_INTERNAL_12:
        case SEC_KEYCONTAINER_SOC_INTERNAL_13:
        case SEC_KEYCONTAINER_SOC_INTERNAL_14:
        case SEC_KEYCONTAINER_SOC_INTERNAL_15:
            *out_key_container = SEC_KEYCONTAINER_SOC;
            memmove(key_buffer, p_data, *key_length);
            key_format = SA_KEY_FORMAT_SOC;
            if (is_jwt_key_container(key_buffer, *key_length)) {
                parameters = NULL;
            } else {
                size_t length = sizeof(sa_import_parameters_soc_legacy);
                rights_set_allow_all(&rights, SEC_KEYTYPE_AES_128);
                parameters_soc_legacy.length[0] = length >> 8 & 0xff;
                parameters_soc_legacy.length[1] = length & 0xff;
                parameters_soc_legacy.version = VERSION_2_KEY_CONTAINER;
                parameters_soc_legacy.default_rights = rights;
                parameters_soc_legacy.object_id = object_id;
                parameters = &parameters_soc_legacy;
            }

            break;

        case SEC_KEYCONTAINER_EXPORTED:
            memmove(key_buffer, p_data, *key_length);
            key_format = SA_KEY_FORMAT_EXPORTED;
            parameters = NULL;
            break;

        case SEC_KEYCONTAINER_JTYPE:
            memmove(key_buffer, p_data, *key_length);
            key_format = SA_KEY_FORMAT_TYPEJ;

            result = SecKey_GetInstance(processorHandle, SEC_OBJECTID_COMCAST_XCALSESSIONENCKEY, &cipherKeyHandle);
            if (result != SEC_RESULT_SUCCESS)
                return result;

            result = SecKey_GetInstance(processorHandle, SEC_OBJECTID_COMCAST_XCALSESSIONMACKEY, &hmacKeyHandle);
            if (result != SEC_RESULT_SUCCESS) {
                if (cipherKeyHandle != NULL)
                    SecKey_Release(cipherKeyHandle);

                return result;
            }

            typej_parameters.kcipher = cipherKeyHandle->key.handle;
            typej_parameters.khmac = hmacKeyHandle->key.handle;
            parameters = &typej_parameters;
            break;

        default:
            return SEC_RESULT_FAILURE;
    }

    // Validate the key and import it.
    status = sa_key_import(&key->handle, key_format, key_buffer, *key_length, parameters);

    if (cipherKeyHandle != NULL)
        SecKey_Release(cipherKeyHandle);

    if (hmacKeyHandle != NULL)
        SecKey_Release(hmacKeyHandle);

    CHECK_STATUS(status)
    return SEC_RESULT_SUCCESS;
}

static bool is_jwt_key_container(SEC_BYTE* key_buffer, SEC_SIZE key_length) {

    SEC_BYTE* in_string = key_buffer;
    SEC_BYTE* in_string_end = in_string + key_length;

    SEC_BYTE* header_b64 = in_string;
    SEC_BYTE* header_b64_end = memchr(header_b64, '.', in_string_end - header_b64);
    if (header_b64_end == NULL)
        return false;

    SEC_SIZE header_b64_length = header_b64_end - header_b64;
    SEC_BYTE* payload_b64 = header_b64_end + 1;
    if (payload_b64 >= in_string_end)
        return false;

    SEC_BYTE* payload_b64_end = memchr(payload_b64, '.', in_string_end - payload_b64);
    if (payload_b64_end == NULL)
        return false;

    SEC_SIZE payload_b64_length = payload_b64_end - payload_b64;
    SEC_BYTE* mac_b64 = payload_b64_end + 1;
    if (mac_b64 >= in_string_end)
        return false;

    SEC_BYTE* mac_b64_end = in_string_end;
    SEC_SIZE mac_b64_length = mac_b64_end - mac_b64;
    SEC_SIZE header_length = 3 * header_b64_length / 4;
    SEC_SIZE length;
    SEC_BYTE* header = malloc(header_length);
    Sec_Result result = SecUtils_Base64Decode(header_b64, header_b64_length, header, header_length, &length);
    free(header);
    if (result != SEC_RESULT_SUCCESS)
        return false;

    SEC_SIZE payload_length = 3 * payload_b64_length / 4;
    SEC_BYTE* payload = malloc(payload_length);
    result = SecUtils_Base64Decode(payload_b64, payload_b64_length, payload, payload_length, &length);
    free(payload);
    if (result != SEC_RESULT_SUCCESS)
        return false;

    SEC_SIZE mac_length = 3 * mac_b64_length / 4;
    SEC_BYTE* mac = malloc(mac_length);
    result = SecUtils_Base64Decode(mac_b64, mac_b64_length, mac, mac_length, &length);
    free(mac);
    if (result != SEC_RESULT_SUCCESS)
        return false;

    return true;
}

static Sec_Result process_rsa_key_container(Sec_KeyContainer in_key_container, SEC_BYTE* data,
        SEC_SIZE data_length, unsigned char* key_buffer, SEC_SIZE* key_length, Sec_KeyContainer* out_key_container) {
    RSA* rsa = NULL;
    switch (in_key_container) {
        case SEC_KEYCONTAINER_DER_RSA_1024:
        case SEC_KEYCONTAINER_DER_RSA_2048:
        case SEC_KEYCONTAINER_DER_RSA_3072: {
            const unsigned char* p_data = data;
            rsa = d2i_RSAPrivateKey(NULL, &p_data, data_length);
            if (rsa == NULL) {
                SEC_LOG_ERROR("d2i_RSAPrivateKey failed");
                return SEC_RESULT_INVALID_PARAMETERS;
            }

            break;
        }
        case SEC_KEYCONTAINER_RAW_RSA_1024:
        case SEC_KEYCONTAINER_RAW_RSA_2048:
        case SEC_KEYCONTAINER_RAW_RSA_3072: {
            if (data_length != sizeof(Sec_RSARawPrivateKey)) {
                SEC_LOG_ERROR("Invalid key container length");
                return SEC_RESULT_INVALID_PARAMETERS;
            }

            // Validate the key and convert to RSA.
            Sec_RSARawPrivateKey* rawPrivateKey = (Sec_RSARawPrivateKey*) data;
            rsa = RSA_new();
            if (rsa == NULL) {
                SEC_LOG_ERROR("RSA_new failed");
                return SEC_RESULT_INVALID_PARAMETERS;
            }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
            rsa->n = BN_bin2bn(rawPrivateKey->n, (int) Sec_BEBytesToUint32(rawPrivateKey->modulus_len_be), NULL);
            rsa->e = BN_bin2bn(rawPrivateKey->e, 4, NULL);
            rsa->d = BN_bin2bn(rawPrivateKey->d, (int) Sec_BEBytesToUint32(rawPrivateKey->modulus_len_be), NULL);
#else
            RSA_set0_key(rsa,
                    BN_bin2bn(rawPrivateKey->n, (int) Sec_BEBytesToUint32(rawPrivateKey->modulus_len_be), NULL),
                    BN_bin2bn(rawPrivateKey->e, 4, NULL),
                    BN_bin2bn(rawPrivateKey->d, (int) Sec_BEBytesToUint32(rawPrivateKey->modulus_len_be), NULL));
#endif
            break;
        }
        case SEC_KEYCONTAINER_PEM_RSA_1024:
        case SEC_KEYCONTAINER_PEM_RSA_2048:
        case SEC_KEYCONTAINER_PEM_RSA_3072: {
            // Validate the key and convert to RSA.
            BIO* bio = BIO_new_mem_buf(data, (int) data_length);
            rsa = PEM_read_bio_RSAPrivateKey(bio, &rsa, disable_passphrase_prompt, NULL);
            Sec_KeyType key_type = SecKey_GetKeyTypeForClearKeyContainer(in_key_container);
            if ((rsa == NULL) || ((SEC_SIZE) RSA_size(rsa) != SecKey_GetKeyLenForKeyType(key_type))) {
                SEC_RSA_FREE(rsa);
                SEC_LOG_ERROR("Invalid RSA key container");
                return SEC_RESULT_INVALID_PARAMETERS;
            }

            break;
        }
        default:
            return SEC_RESULT_FAILURE;
    }

    Sec_KeyType key_type = SecKey_GetKeyTypeForClearKeyContainer(in_key_container);
    if ((rsa == NULL) || ((SEC_SIZE) RSA_size(rsa) != SecKey_GetKeyLenForKeyType(key_type))) {
        SEC_RSA_FREE(rsa);
        SEC_LOG_ERROR("Invalid RSA key container");
        return SEC_RESULT_INVALID_PARAMETERS;
    }

    *out_key_container = convert_key_container(in_key_container);
    unsigned char* p_data = key_buffer;
    *key_length = i2d_RSAPrivateKey(rsa, &p_data);
    SEC_RSA_FREE(rsa);
    if (*key_length <= 0) {
        SEC_LOG_ERROR("Invalid RSA key container");
        return SEC_RESULT_INVALID_PARAMETERS;
    }

    return SEC_RESULT_SUCCESS;
}

static Sec_Result process_rsa_public_key_container(Sec_KeyContainer in_key_container, SEC_BYTE* data,
        SEC_SIZE data_length, RSA** rsa, unsigned char* key_buffer, SEC_SIZE* key_length,
        Sec_KeyContainer* out_key_container) {
    switch (in_key_container) {
        case SEC_KEYCONTAINER_DER_RSA_1024_PUBLIC:
        case SEC_KEYCONTAINER_DER_RSA_2048_PUBLIC:
        case SEC_KEYCONTAINER_DER_RSA_3072_PUBLIC: {
            const unsigned char* p_data = data;
            *rsa = d2i_RSA_PUBKEY(NULL, &p_data, data_length);
            if (*rsa == NULL)
                *rsa = d2i_RSAPublicKey(NULL, &p_data, data_length);

            if (*rsa == NULL) {
                SEC_LOG_ERROR("d2i_RSAPublicKey failed");
                return SEC_RESULT_INVALID_PARAMETERS;
            }

            break;
        }
        case SEC_KEYCONTAINER_RAW_RSA_1024_PUBLIC:
        case SEC_KEYCONTAINER_RAW_RSA_2048_PUBLIC:
        case SEC_KEYCONTAINER_RAW_RSA_3072_PUBLIC: {
            if (data_length < sizeof(Sec_RSARawPublicKey)) {
                SEC_LOG_ERROR("Invalid key container length");
                return SEC_RESULT_INVALID_PARAMETERS;
            }

            // Validate the key and convert to RSA.
            Sec_RSARawPublicKey* rawPublicKey = (Sec_RSARawPublicKey*) data;
            *rsa = RSA_new();
            if (rsa == NULL) {
                SEC_LOG_ERROR("RSA_new failed");
                return SEC_RESULT_FAILURE;
            }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
            (*rsa)->n = BN_bin2bn(rawPublicKey->n, (int) Sec_BEBytesToUint32(rawPublicKey->modulus_len_be), NULL);
            (*rsa)->e = BN_bin2bn(rawPublicKey->e, 4, NULL);
#else
            RSA_set0_key(*rsa,
                    BN_bin2bn(rawPublicKey->n, (int) Sec_BEBytesToUint32(rawPublicKey->modulus_len_be), NULL),
                    BN_bin2bn(rawPublicKey->e, 4, NULL),
                    NULL);
#endif
            break;
        }
        case SEC_KEYCONTAINER_PEM_RSA_1024_PUBLIC:
        case SEC_KEYCONTAINER_PEM_RSA_2048_PUBLIC:
        case SEC_KEYCONTAINER_PEM_RSA_3072_PUBLIC: {
            BIO* bio = BIO_new_mem_buf(data, (int) data_length);
            EVP_PKEY* evp_pkey = PEM_read_bio_PUBKEY(bio, &evp_pkey, disable_passphrase_prompt, NULL);
            if (evp_pkey == NULL) {
                SEC_LOG_ERROR("PEM_read_bio_PUBKEY failed");
                return SEC_RESULT_INVALID_PARAMETERS;
            }

            *rsa = EVP_PKEY_get1_RSA(evp_pkey);
            EVP_PKEY_free(evp_pkey);
            if (*rsa == NULL) {
                SEC_LOG_ERROR("EVP_PKEY_get0_RSA failed");
                return SEC_RESULT_FAILURE;
            }

            break;
        }
        default:
            return SEC_RESULT_FAILURE;
    }

    Sec_KeyType key_type = SecKey_GetKeyTypeForClearKeyContainer(in_key_container);
    if ((SEC_SIZE) RSA_size(*rsa) != SecKey_GetKeyLenForKeyType(key_type)) {
        SEC_RSA_FREE(*rsa);
        *rsa = NULL;
        SEC_LOG_ERROR("Invalid RSA key container");
        return SEC_RESULT_INVALID_PARAMETERS;
    }

    *out_key_container = convert_key_container(in_key_container);
    unsigned char* p_data = key_buffer;
    *key_length = i2d_RSAPublicKey(*rsa, &p_data);
    if (*key_length <= 0) {
        SEC_LOG_ERROR("Invalid RSA key container");
        return SEC_RESULT_INVALID_PARAMETERS;
    }

    return SEC_RESULT_SUCCESS;
}

static Sec_Result process_ec_key_container(Sec_KeyContainer in_key_container, SEC_BYTE* data,
        SEC_SIZE data_length, unsigned char* key_buffer, SEC_SIZE* key_length, Sec_KeyContainer* out_key_container) {
    switch (in_key_container) {
        case SEC_KEYCONTAINER_DER_ECC_NISTP256: {
            const unsigned char* p_der = data;
            EC_KEY* ec_key = d2i_ECPrivateKey(NULL, &p_der, data_length);
            if (ec_key == NULL) {
                SEC_LOG_ERROR("Invalid ECC key container");
                return SEC_RESULT_INVALID_PARAMETERS;
            }

            *key_length = BN_bn2bin(EC_KEY_get0_private_key(ec_key), key_buffer);
            SEC_ECC_FREE(ec_key);
            break;
        }
        case SEC_KEYCONTAINER_RAW_ECC_NISTP256: {
            if (data_length != sizeof(Sec_ECCRawPrivateKey)) {
                SEC_LOG_ERROR("Invalid key container length");
                SEC_LOG_ERROR("Data_len != sizeof(Sec_ECCRawPrivateKey) data_length: %d, expected: %d", data_length,
                        sizeof(Sec_ECCRawPrivateKey));
                return SEC_RESULT_INVALID_PARAMETERS;
            }

            Sec_ECCRawPrivateKey* rawPrivateKey = (Sec_ECCRawPrivateKey*) data;
            if (rawPrivateKey->type != SEC_KEYTYPE_ECC_NISTP256) {
                SEC_LOG_ERROR("Invalid ECC key container");
                return SEC_RESULT_INVALID_PARAMETERS;
            }

            memcpy(key_buffer, rawPrivateKey->prv, SEC_ECC_NISTP256_KEY_LEN);
            *key_length = SEC_ECC_NISTP256_KEY_LEN;
            break;
        }
        case SEC_KEYCONTAINER_RAW_ECC_PRIVONLY_NISTP256: {
            if (data_length != sizeof(Sec_ECCRawOnlyPrivateKey)) {
                SEC_LOG_ERROR("Invalid key container length");
                SEC_LOG_ERROR("Data_len != sizeof(Sec_ECCRawOnlyPrivateKey) data_length: %d, expected: %d", data_length,
                        sizeof(Sec_ECCRawOnlyPrivateKey));
                return SEC_RESULT_INVALID_PARAMETERS;
            }

            memcpy(key_buffer, ((Sec_ECCRawOnlyPrivateKey*) data)->prv, SEC_ECC_NISTP256_KEY_LEN);
            *key_length = SEC_ECC_NISTP256_KEY_LEN;
            break;
        }
        case SEC_KEYCONTAINER_PEM_ECC_NISTP256: {
            BIO* bio = BIO_new_mem_buf(data, (int) data_length);
            EC_KEY* ec_key = PEM_read_bio_ECPrivateKey(bio, &ec_key, disable_passphrase_prompt, NULL);
            SEC_BIO_FREE(bio);
            if (ec_key == NULL) {
                SEC_LOG_ERROR("Invalid ECC key container");
                return SEC_RESULT_INVALID_PARAMETERS;
            }

            *key_length = BN_bn2bin(EC_KEY_get0_private_key(ec_key), key_buffer);
            SEC_ECC_FREE(ec_key);
            break;
        }
        default:
            return SEC_RESULT_FAILURE;
    }

    *out_key_container = convert_key_container(in_key_container);
    return SEC_RESULT_SUCCESS;
}

static Sec_Result process_ec_public_key_container(Sec_KeyContainer in_key_container, SEC_BYTE* data,
        SEC_SIZE data_length, EC_KEY** ec_key, unsigned char* key_buffer, SEC_SIZE* key_length,
        Sec_KeyContainer* out_key_container) {
    switch (in_key_container) {
        case SEC_KEYCONTAINER_DER_ECC_NISTP256_PUBLIC: {
            const unsigned char* p_data = data;
            *ec_key = d2i_EC_PUBKEY(NULL, &p_data, data_length);
            if (*ec_key == NULL) {
                SEC_LOG_ERROR("d2i_EC_PUBKEY failed");
                return SEC_RESULT_INVALID_PARAMETERS;
            }

            break;
        }
        case SEC_KEYCONTAINER_RAW_ECC_NISTP256_PUBLIC: {
            Sec_ECCRawPublicKey* binary = (Sec_ECCRawPublicKey*) data;
            BN_CTX* bn_ctx = BN_CTX_new();

            if (*key_length < sizeof(Sec_ECCRawPublicKey)) {
                SEC_LOG_ERROR("Invalid key container length");
                return SEC_RESULT_INVALID_PARAMETERS;
            }

            if (binary->type != SEC_KEYTYPE_ECC_NISTP256_PUBLIC && binary->type != SEC_KEYTYPE_ECC_NISTP256)
                return SEC_RESULT_INVALID_PARAMETERS;

            //create ec_key structure with NIST p256 curve;
            *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
            const EC_GROUP* group = EC_KEY_get0_group(*ec_key);
            EC_POINT* ec_point = EC_POINT_new(group);
            BN_CTX_start(bn_ctx);
            BIGNUM* xp;
            BIGNUM* yp;

            if (((xp = BN_CTX_get(bn_ctx)) == NULL) || ((yp = BN_CTX_get(bn_ctx)) == NULL))
                return SEC_RESULT_INVALID_PARAMETERS;

            EC_POINT_set_affine_coordinates_GFp(group, ec_point,
                    BN_bin2bn(binary->x, (int) Sec_BEBytesToUint32(binary->key_len), xp),
                    BN_bin2bn(binary->y, (int) Sec_BEBytesToUint32(binary->key_len), yp), bn_ctx);
            EC_KEY_set_public_key(*ec_key, ec_point);

            EC_POINT_free(ec_point);
            BN_CTX_end(bn_ctx);
            BN_CTX_free(bn_ctx);
            return SEC_RESULT_SUCCESS;
        }
        case SEC_KEYCONTAINER_PEM_ECC_NISTP256_PUBLIC: {
            BIO* bio = BIO_new_mem_buf(data, (int) data_length);
            EVP_PKEY* evp_pkey = NULL;
            evp_pkey = PEM_read_bio_PUBKEY(bio, &evp_pkey, disable_passphrase_prompt, NULL);
            if (evp_pkey == NULL) {
                SEC_LOG_ERROR("PEM_read_bio_PUBKEY failed");
                return SEC_RESULT_INVALID_PARAMETERS;
            }

            *ec_key = EVP_PKEY_get1_EC_KEY(evp_pkey);
            EVP_PKEY_free(evp_pkey);
            if (*ec_key == NULL) {
                SEC_LOG_ERROR("EVP_PKEY_get0_EC_KEY failed");
                return SEC_RESULT_FAILURE;
            }

            break;
        }
        default:
            return SEC_RESULT_FAILURE;
    }

    *out_key_container = convert_key_container(in_key_container);
    *key_length = i2d_EC_PUBKEY(*ec_key, &key_buffer);
    if (*key_length < 0)
        return SEC_RESULT_INVALID_PARAMETERS;

    return SEC_RESULT_SUCCESS;
}

static Sec_KeyContainer convert_key_container(Sec_KeyContainer key_container) {
    switch (key_container) {
        case SEC_KEYCONTAINER_RAW_RSA_1024:
        case SEC_KEYCONTAINER_PEM_RSA_1024:
            return SEC_KEYCONTAINER_DER_RSA_1024;

        case SEC_KEYCONTAINER_RAW_RSA_2048:
        case SEC_KEYCONTAINER_PEM_RSA_2048:
            return SEC_KEYCONTAINER_DER_RSA_2048;

        case SEC_KEYCONTAINER_RAW_RSA_3072:
        case SEC_KEYCONTAINER_PEM_RSA_3072:
            return SEC_KEYCONTAINER_DER_RSA_3072;

        case SEC_KEYCONTAINER_RAW_RSA_1024_PUBLIC:
        case SEC_KEYCONTAINER_PEM_RSA_1024_PUBLIC:
            return SEC_KEYCONTAINER_DER_RSA_1024_PUBLIC;

        case SEC_KEYCONTAINER_RAW_RSA_2048_PUBLIC:
        case SEC_KEYCONTAINER_PEM_RSA_2048_PUBLIC:
            return SEC_KEYCONTAINER_DER_RSA_2048_PUBLIC;

        case SEC_KEYCONTAINER_RAW_RSA_3072_PUBLIC:
        case SEC_KEYCONTAINER_PEM_RSA_3072_PUBLIC:
            return SEC_KEYCONTAINER_DER_RSA_3072_PUBLIC;

        case SEC_KEYCONTAINER_DER_ECC_NISTP256:
        case SEC_KEYCONTAINER_RAW_ECC_NISTP256:
        case SEC_KEYCONTAINER_PEM_ECC_NISTP256:
        case SEC_KEYCONTAINER_RAW_ECC_PRIVONLY_NISTP256:
            return SEC_KEYCONTAINER_RAW_ECC_PRIVONLY_NISTP256;

        case SEC_KEYCONTAINER_RAW_ECC_NISTP256_PUBLIC:
        case SEC_KEYCONTAINER_PEM_ECC_NISTP256_PUBLIC:
            return SEC_KEYCONTAINER_DER_ECC_NISTP256_PUBLIC;

        default:
            return key_container;
    }
}

static Sec_Result process_asn1_key_container(Sec_ProcessorHandle* processorHandle, const void* data,
        SEC_SIZE data_length, SEC_BYTE* key_buffer, SEC_SIZE* key_length, Sec_KeyContainer* key_container) {
    SEC_SIZE tempkc_length = SEC_KEYCONTAINER_MAX_LEN;
    uint8_t* tempkc = malloc(SEC_KEYCONTAINER_MAX_LEN);
    if (tempkc == NULL) {
        SEC_LOG_ERROR("malloc failed");
        return SEC_RESULT_FAILURE;
    }

    Sec_KeyType wrapped_key_type;
    SEC_OBJECTID wrapping_id;
    SEC_BYTE wrapping_iv[SEC_AES_BLOCK_SIZE];
    Sec_CipherAlgorithm wrapping_alg;
    SEC_SIZE wrapped_key_offset;
    SEC_SIZE wrapping_key_length = SEC_KEYCONTAINER_MAX_LEN;
    uint8_t* wrapping_key = malloc(SEC_KEYCONTAINER_MAX_LEN);
    if (wrapping_key == NULL) {
        SEC_FREE(tempkc);
        SEC_LOG_ERROR("malloc failed");
        return SEC_RESULT_FAILURE;
    }

    Sec_Asn1KC* asn1kc = SecAsn1KC_Decode(data, data_length);
    if (asn1kc == NULL) {
        SEC_FREE(tempkc);
        SEC_FREE(wrapping_key);
        SEC_LOG_ERROR("SecAsn1KC_Decode failed");
        return SEC_RESULT_FAILURE;
    }

    if (SecKey_ExtractWrappedKeyParamsAsn1V3(asn1kc, tempkc, SEC_KEYCONTAINER_MAX_LEN, &tempkc_length,
                &wrapped_key_type, &wrapping_id, wrapping_iv, &wrapping_alg, &wrapped_key_offset, wrapping_key,
                SEC_KEYCONTAINER_MAX_LEN, &wrapping_key_length) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecKey_ExtractWrappedKeyParamsAsn1V3 failed");
        SEC_FREE(tempkc);
        SEC_FREE(wrapping_key);
        SecAsn1KC_Free(asn1kc);
        return SEC_RESULT_FAILURE;
    }

    SecAsn1KC_Free(asn1kc);

    //V3
    if (wrapping_key_length > 0) {
        //get free id
        wrapping_id = SecKey_ObtainFreeObjectId(processorHandle, SEC_OBJECTID_RESERVED_BASE, SEC_OBJECTID_RESERVED_TOP);
        if (SEC_OBJECTID_INVALID == wrapping_id) {
            SEC_LOG_ERROR("SecKey_ObtainFreeObjectId failed");
            SEC_FREE(tempkc);
            SEC_FREE(wrapping_key);
            return SEC_RESULT_FAILURE;
        }

        // provision wrapping key--we don't know whether it is a SEC_KEYCONTAINER_ASN1 or a SEC_KEYCONTAINER_SOC
        // so try the ASN1 container first.  If it fails, then try to SOC container.
        if (SecKey_Provision(processorHandle, wrapping_id, SEC_STORAGELOC_RAM, SEC_KEYCONTAINER_ASN1, wrapping_key,
                    wrapping_key_length) != SEC_RESULT_SUCCESS) {
            if (SecKey_Provision(processorHandle, wrapping_id, SEC_STORAGELOC_RAM, SEC_KEYCONTAINER_SOC, wrapping_key,
                        wrapping_key_length) != SEC_RESULT_SUCCESS) {
                SEC_LOG_ERROR("SecKey_Provision failed");
                SEC_FREE(tempkc);
                SEC_FREE(wrapping_key);
                return SEC_RESULT_FAILURE;
            }
        }
    }

    //unwrap
    sa_key unwrapped_key;
    Sec_Result result = unwrap_key(processorHandle, wrapping_alg, wrapped_key_type, wrapped_key_offset, wrapping_id,
            wrapping_iv, tempkc, tempkc_length, key_buffer, key_length);
    *key_container = SEC_KEYCONTAINER_EXPORTED;
    if (wrapping_key_length > 0)
        SecKey_Delete(processorHandle, wrapping_id);

    SEC_FREE(tempkc);
    SEC_FREE(wrapping_key);
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("Unwrap_key failed");
        return result;
    }

    return SEC_RESULT_SUCCESS;
}

static Sec_Result process_store_key_container(Sec_ProcessorHandle* processorHandle, void* data,
        SEC_SIZE data_length, SEC_BYTE* key_buffer, SEC_SIZE* key_length, Sec_KeyContainer* key_container) {
    if (SecStore_GetStoreLen(data) != data_length) {
        SEC_LOG_ERROR("Secure store length does not match the expected one");
        return SEC_RESULT_FAILURE;
    }

    /* validate the store */
    Sec_Result result = SecUtils_ValidateKeyStore(processorHandle, SEC_FALSE, data, data_length);
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecUtils_ValidateKeyStore failed");
        return SEC_RESULT_FAILURE;
    }

    SecUtils_KeyStoreHeader keystore_header;
    result = SecStore_RetrieveData(processorHandle, SEC_FALSE, &keystore_header, sizeof(keystore_header),
            key_buffer, SEC_KEYCONTAINER_MAX_LEN, data, data_length);
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecUtils_ValidateKeyStore failed");
        return SEC_RESULT_FAILURE;
    }

    if (keystore_header.inner_kc_type == SEC_KEYCONTAINER_SOC_INTERNAL_0) {
        if (sizeof(SecAdapter_DerivedInputs) != SecStore_GetDataLen(data)) {
            SEC_LOG_ERROR("Invalid key length in the store");
            return SEC_RESULT_FAILURE;
        }

        SecAdapter_DerivedInputs* derived_inputs = (SecAdapter_DerivedInputs*) key_buffer;
        Sec_Key derived_key;
        result = derive_root_key_ladder(derived_inputs->input1, derived_inputs->input2, derived_inputs->input3,
                derived_inputs->input4, SEC_AES_BLOCK_SIZE, &derived_key.handle, SEC_KEYTYPE_AES_128);
        if (result != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("Derive_root_key_ladder failed");
            return SEC_RESULT_FAILURE;
        }

        // Export the key
        result = export_key(&derived_key, NULL, key_buffer, SEC_KEYCONTAINER_MAX_LEN, key_length);
        sa_key_release(derived_key.handle);
        if (result != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("Export of store keycontainer derived key failed");
            return SEC_RESULT_FAILURE;
        }

        *key_container = SEC_KEYCONTAINER_EXPORTED;
    } else if (SecKey_IsClearKeyContainer(keystore_header.inner_kc_type)) {
        *key_container = keystore_header.inner_kc_type;
        *key_length = SecStore_GetDataLen(data);
    } else {
        SEC_LOG_ERROR("Unsupported key container in store");
        return SEC_RESULT_UNIMPLEMENTED_FEATURE;
    }

    return SEC_RESULT_SUCCESS;
}

static Sec_Result derive_root_key_ladder(const SEC_BYTE* c1, const SEC_BYTE* c2, const SEC_BYTE* c3, const SEC_BYTE* c4,
        SEC_SIZE key_size, sa_key* key, Sec_KeyType key_type) {

    sa_kdf_parameters_root_key_ladder kdf_parameters = {
            .c1 = c1,
            .c1_length = c1 != NULL ? key_size : 0,
            .c2 = c2,
            .c2_length = c2 != NULL ? key_size : 0,
            .c3 = c3,
            .c3_length = c3 != NULL ? key_size : 0,
            .c4 = c4,
            .c4_length = c4 != NULL ? key_size : 0};

    sa_rights rights;
    rights_set_allow_all(&rights, key_type);
    sa_status status = sa_key_derive(key, &rights, SA_KDF_ALGORITHM_ROOT_KEY_LADDER, &kdf_parameters);
    CHECK_STATUS(status)
    return SEC_RESULT_SUCCESS;
}

static Sec_Result derive_base_key(Sec_ProcessorHandle* processorHandle, SEC_BYTE* nonce, sa_key* key,
        Sec_KeyType key_type) {
    SEC_SIZE keySize = SEC_AES_BLOCK_SIZE;
    SEC_BYTE c1[keySize];
    SEC_BYTE c2[keySize];
    SEC_BYTE c3[keySize];
    SEC_BYTE c4[keySize];

    // Most SOCs use aesEcbNone. Some SOCs use desEdeNone and this will be fixed with a SOC specific patch.
    Sec_Result result = SecKey_ComputeBaseKeyLadderInputs(processorHandle, "sivSha1", "aesEcbNone", nonce,
            SEC_DIGESTALGORITHM_SHA1, keySize, c1, c2, c3, c4);
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecKey_ComputeBaseKeyLadderInputs failed");
        return SEC_RESULT_FAILURE;
    }

    // the first input is fixed to 0x00..01
    memset(c1, 0, sizeof(c1));
    c1[15] = 0x01;

    result = derive_root_key_ladder(c1, c2, c3, c4, keySize, key, key_type);
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecKey_ComputeBaseKeyLadderInputs failed");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

static Sec_Result derive_hkdf(Sec_MacAlgorithm macAlgorithm, Sec_KeyType typeDerived, const SEC_BYTE* salt,
        SEC_SIZE saltSize, const SEC_BYTE* info, SEC_SIZE infoSize, sa_key baseKey,
        sa_key* derived_key) {
    if (macAlgorithm != SEC_MACALGORITHM_HMAC_SHA1 && macAlgorithm != SEC_MACALGORITHM_HMAC_SHA256) {
        SEC_LOG_ERROR("Unsupported mac algorithm specified: %d", macAlgorithm);
        return SEC_RESULT_FAILURE;
    }

    if (!SecKey_IsSymetric(typeDerived)) {
        SEC_LOG_ERROR("Can only derive symmetric keys");
        return SEC_RESULT_INVALID_PARAMETERS;
    }

    sa_digest_algorithm digest_algorithm =
            (macAlgorithm == SEC_MACALGORITHM_HMAC_SHA1) ? SA_DIGEST_ALGORITHM_SHA1 : SA_DIGEST_ALGORITHM_SHA256;
    sa_kdf_parameters_hkdf kdf_parameters = {
            .key_length = SecKey_GetKeyLenForKeyType(typeDerived),
            .digest_algorithm = digest_algorithm,
            .parent = baseKey,
            .salt = salt,
            .salt_length = saltSize,
            .info = info,
            .info_length = infoSize};

    sa_rights rights;
    rights_set_allow_all(&rights, typeDerived);
    sa_status status = sa_key_derive(derived_key, &rights, SA_KDF_ALGORITHM_HKDF, &kdf_parameters);
    CHECK_STATUS(status)
    return SEC_RESULT_SUCCESS;
}

static Sec_Result derive_kdf_concat(Sec_DigestAlgorithm digestAlgorithm, Sec_KeyType typeDerived,
        const SEC_BYTE* otherInfo, SEC_SIZE otherInfoSize, sa_key baseKey,
        sa_key* derived_key) {
    if (digestAlgorithm != SEC_DIGESTALGORITHM_SHA1 && digestAlgorithm != SEC_DIGESTALGORITHM_SHA256) {
        SEC_LOG_ERROR("Unsupported digest algorithm specified: %d", digestAlgorithm);
        return SEC_RESULT_FAILURE;
    }

    if (!SecKey_IsSymetric(typeDerived)) {
        SEC_LOG_ERROR("Can only derive symmetric keys");
        return SEC_RESULT_INVALID_PARAMETERS;
    }

    sa_digest_algorithm digest_algorithm =
            (digestAlgorithm == SEC_DIGESTALGORITHM_SHA1) ? SA_DIGEST_ALGORITHM_SHA1 : SA_DIGEST_ALGORITHM_SHA256;
    sa_kdf_parameters_concat kdf_parameters = {
            .key_length = SecKey_GetKeyLenForKeyType(typeDerived),
            .digest_algorithm = digest_algorithm,
            .parent = baseKey,
            .info = otherInfo,
            .info_length = otherInfoSize};

    sa_rights rights;
    rights_set_allow_all(&rights, typeDerived);
    sa_status status = sa_key_derive(derived_key, &rights, SA_KDF_ALGORITHM_CONCAT, &kdf_parameters);
    CHECK_STATUS(status)
    return SEC_RESULT_SUCCESS;
}

static Sec_Result derive_kdf_cmac(Sec_KeyType typeDerived, const SEC_BYTE* otherData, SEC_SIZE otherDataSize,
        const SEC_BYTE* counter, SEC_SIZE counterSize, sa_key baseKey, sa_key* derived_key) {
    if (!SecKey_IsSymetric(typeDerived)) {
        SEC_LOG_ERROR("Can only derive symmetric keys");
        return SEC_RESULT_INVALID_PARAMETERS;
    }

    if (counterSize != 1) {
        SEC_LOG_ERROR("Only 1 byte counter is supported");
        return SEC_RESULT_INVALID_PARAMETERS;
    }

    if (*counter < 1 || *counter > 4) {
        SEC_LOG_ERROR("Invalid counter passed in: %d", *counter);
        return SEC_RESULT_INVALID_PARAMETERS;
    }

    sa_kdf_parameters_cmac cmac_parameters = {
            .key_length = SecKey_GetKeyLenForKeyType(typeDerived),
            .parent = baseKey,
            .other_data = otherData,
            .other_data_length = otherDataSize,
            .counter = *counter};

    sa_rights rights;
    rights_set_allow_all(&rights, typeDerived);
    sa_status status = sa_key_derive(derived_key, &rights, SA_KDF_ALGORITHM_CMAC, &cmac_parameters);
    CHECK_STATUS(status)
    return SEC_RESULT_SUCCESS;
}

static Sec_Result unwrap_key(Sec_ProcessorHandle* processorHandle, Sec_CipherAlgorithm algorithm,
        Sec_KeyType wrapped_key_type, SEC_SIZE wrapped_key_offset, SEC_OBJECTID id, SEC_BYTE* iv, SEC_BYTE* input,
        SEC_SIZE input_len, SEC_BYTE* out_key, SEC_SIZE* out_key_len) {
    Sec_KeyHandle* keyHandle;
    Sec_Result result = SecKey_GetInstance(processorHandle, id, &keyHandle);
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecKey_GetInstance failed");
        return result;
    }

    sa_rights rights;
    rights_set_allow_all(&rights, wrapped_key_type);
    sa_key_type key_type;
    void* key_parameters;
    result = get_sa_key_type(wrapped_key_type, &key_type, &key_parameters);
    if (result != SEC_RESULT_SUCCESS) {
        SecKey_Release(keyHandle);
        SEC_LOG_ERROR("Get_sa_key_type failed");
        return result;
    }

    void* cipher_parameters;
    sa_cipher_algorithm cipher_algorithm;
    result = get_cipher_algorithm(algorithm, SEC_TRUE, &cipher_algorithm, &cipher_parameters, iv,
            SecKey_GetKeyLenForKeyType(wrapped_key_type), wrapped_key_offset);
    if (result != SEC_RESULT_SUCCESS) {
        SEC_FREE(key_parameters);
        SecKey_Release(keyHandle);
        SEC_LOG_ERROR("Get_cipher_algorithm failed");
        return result;
    }

    Sec_Key unwrapped_key;
    sa_status status = sa_key_unwrap(&unwrapped_key.handle, &rights, key_type, key_parameters, cipher_algorithm,
            cipher_parameters, keyHandle->key.handle, input, input_len);
    SEC_FREE(key_parameters);
    SEC_FREE(cipher_parameters);
    SecKey_Release(keyHandle);
    CHECK_STATUS(status)

    // Export the key
    result = export_key(&unwrapped_key, NULL, out_key, SEC_KEYCONTAINER_MAX_LEN, out_key_len);
    sa_key_release(unwrapped_key.handle);
    return result;
}

static Sec_Result get_sa_key_type(Sec_KeyType keyType, sa_key_type* out_key_type, void** parameters) {

    sa_generate_parameters_symmetric parameters_symmetric;
    sa_generate_parameters_rsa parameters_rsa;
    sa_generate_parameters_ec parameters_ec;
    *parameters = NULL;
    switch (keyType) {
        case SEC_KEYTYPE_AES_128:
        case SEC_KEYTYPE_AES_256:
        case SEC_KEYTYPE_HMAC_128:
        case SEC_KEYTYPE_HMAC_160:
        case SEC_KEYTYPE_HMAC_256:
            *out_key_type = SA_KEY_TYPE_SYMMETRIC;
            *parameters = calloc(1, sizeof(parameters_symmetric));
            if (parameters == NULL)
                return SEC_RESULT_FAILURE;

            ((sa_generate_parameters_symmetric*) *parameters)->key_length = SecKey_GetKeyLenForKeyType(keyType);
            return SEC_RESULT_SUCCESS;

        case SEC_KEYTYPE_RSA_1024:
        case SEC_KEYTYPE_RSA_2048:
        case SEC_KEYTYPE_RSA_3072:
            *out_key_type = SA_KEY_TYPE_RSA;
            *parameters = calloc(1, sizeof(sa_generate_parameters_rsa));
            if (parameters == NULL)
                return SEC_RESULT_FAILURE;

            ((sa_generate_parameters_rsa*) *parameters)->modulus_length = SecKey_GetKeyLenForKeyType(keyType);
            return SEC_RESULT_SUCCESS;

        case SEC_KEYTYPE_ECC_NISTP256:
            *out_key_type = SA_KEY_TYPE_EC;
            *parameters = calloc(1, sizeof(sa_generate_parameters_ec));
            if (parameters == NULL)
                return SEC_RESULT_FAILURE;

            ((sa_generate_parameters_ec*) *parameters)->curve = SA_ELLIPTIC_CURVE_NIST_P256;
            return SEC_RESULT_SUCCESS;

        default:
            return SEC_RESULT_UNIMPLEMENTED_FEATURE;
    }
}

static Sec_Result export_key(Sec_Key* key, SEC_BYTE* derivationInput, SEC_BYTE* exportedKey, SEC_SIZE keyBufferLen,
        SEC_SIZE* keyBytesWritten) {

    SEC_BYTE mixin[SEC_AES_BLOCK_SIZE];
    if (derivationInput == NULL)
        sa_crypto_random(mixin, sizeof(mixin));
    else
        memcpy(mixin, derivationInput, SEC_AES_BLOCK_SIZE);

    // Get key length.
    if (exportedKey == NULL) {
        size_t out_length = 0;
        sa_status status = sa_key_export(exportedKey, &out_length, mixin, SEC_AES_BLOCK_SIZE, key->handle);
        CHECK_STATUS(status)

        // Include the length of the derivationInput.
        *keyBytesWritten = out_length;
        return SEC_RESULT_SUCCESS;
    }

    size_t out_length = keyBufferLen;
    sa_status status = sa_key_export(exportedKey, &out_length, mixin, SEC_AES_BLOCK_SIZE, key->handle);
    CHECK_STATUS(status)
    *keyBytesWritten = out_length;
    return SEC_RESULT_SUCCESS;
}

static int disable_passphrase_prompt(char* buf, int size, int rwflag, void* u) {
    return 0;
}
