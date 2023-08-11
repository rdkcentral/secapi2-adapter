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

#include "sa_types.h"
#include "sec_adapter_processor.h"
#include "sec_security.h"

struct Sec_MacHandle_struct {
    Sec_ProcessorHandle* processorHandle;
    Sec_MacAlgorithm algorithm;
    Sec_KeyHandle* keyHandle;
    sa_crypto_mac_context mac_context;
};

Sec_Result SecMac_SingleInput(Sec_ProcessorHandle* processorHandle, Sec_MacAlgorithm alg, Sec_KeyHandle* keyHandle,
        SEC_BYTE* input, SEC_SIZE input_len, SEC_BYTE* mac, SEC_SIZE* mac_len) {
    Sec_Result result;
    Sec_MacHandle* macHandle = NULL;

    result = SecMac_GetInstance(processorHandle, alg, keyHandle, &macHandle);
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecMac_GetInstance failed");
        return result;
    }

    result = SecMac_Update(macHandle, input, input_len);
    SecMac_Release(macHandle, mac, mac_len);
    return result;
}

Sec_Result SecMac_SingleInputId(Sec_ProcessorHandle* processorHandle, Sec_MacAlgorithm alg, SEC_OBJECTID key,
        SEC_BYTE* input, SEC_SIZE input_len, SEC_BYTE* mac, SEC_SIZE* mac_len) {
    Sec_KeyHandle* keyHandle = NULL;
    Sec_Result result = SecKey_GetInstance(processorHandle, key, &keyHandle);
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecKey_GetInstance failed");
        return result;
    }

    result = SecMac_SingleInput(processorHandle, alg, keyHandle, input, input_len, mac, mac_len);
    SecKey_Release(keyHandle);

    return result;
}

/**
 * @brief Obtain a handle for the MAC calculator.
 *
 * @param processorHandle secure processor handle.
 * @param algorithm MAC algorithm to use for MAC calculation.
 * @param keyHandle key to use for the MAC calculation.
 * @param macHandle output MAC calculator handle.
 *
 * @return The status of the operation.
 */
Sec_Result SecMac_GetInstance(Sec_ProcessorHandle* processorHandle, Sec_MacAlgorithm algorithm,
        Sec_KeyHandle* keyHandle, Sec_MacHandle** macHandle) {
    CHECK_PROCHANDLE(processorHandle)
    if (macHandle == NULL) {
        SEC_LOG_ERROR("macHandle is NULL");
        return SEC_RESULT_FAILURE;
    }

    *macHandle = NULL;
    Sec_KeyType key_type = SecKey_GetKeyType(keyHandle);
    Sec_Result result = SecMac_IsValidKey(key_type, algorithm);
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("Not a valid mac key");
        return result;
    }

    Sec_MacHandle* newMacHandle = calloc(1, sizeof(Sec_MacHandle));
    if (newMacHandle == NULL) {
        SEC_LOG_ERROR("Malloc failed");
        return SEC_RESULT_FAILURE;
    }

    newMacHandle->processorHandle = processorHandle;
    newMacHandle->algorithm = algorithm;
    newMacHandle->keyHandle = keyHandle;

    sa_mac_algorithm mac_algorithm;
    sa_mac_parameters_hmac hmac_parameters;
    void* parameters;
    switch (algorithm) {
        case SEC_MACALGORITHM_HMAC_SHA1:
            mac_algorithm = SA_MAC_ALGORITHM_HMAC;
            hmac_parameters.digest_algorithm = SA_DIGEST_ALGORITHM_SHA1;
            parameters = &hmac_parameters;
            break;

        case SEC_MACALGORITHM_HMAC_SHA256:
            mac_algorithm = SA_MAC_ALGORITHM_HMAC;
            hmac_parameters.digest_algorithm = SA_DIGEST_ALGORITHM_SHA256;
            parameters = &hmac_parameters;
            break;

        case SEC_MACALGORITHM_CMAC_AES_128:
            mac_algorithm = SA_MAC_ALGORITHM_CMAC;
            parameters = NULL;
            break;

        default:
            free(newMacHandle);
            return SEC_RESULT_INVALID_PARAMETERS;
    }

    const Sec_Key* key = get_key(keyHandle);
    sa_status status = sa_invoke(processorHandle, SA_CRYPTO_MAC_INIT, &newMacHandle->mac_context, mac_algorithm,
            key->handle, parameters);
    if (status != SA_STATUS_OK)
        free(newMacHandle);

    CHECK_STATUS(status)
    *macHandle = newMacHandle;
    return SEC_RESULT_SUCCESS;
}

/**
 * @brief Updates the digest value with the input data.
 *
 * @param macHandle mac handle.
 * @param input pointer to the input data.
 * @param size of the input buffer.
 *
 * @return The status of the operation.
 */
Sec_Result SecMac_Update(Sec_MacHandle* macHandle, SEC_BYTE* input, SEC_SIZE inputSize) {
    CHECK_HANDLE(macHandle)
    sa_status status = sa_invoke(macHandle->processorHandle, SA_CRYPTO_MAC_PROCESS, macHandle->mac_context, input,
            inputSize);
    CHECK_STATUS(status)
    return SEC_RESULT_SUCCESS;
}

/**
 * @brief Updates the digest value with the contents of a key.
 *
 * @param macHandle mac handle.
 * @param keyHandle key to use.
 *
 * @return The status of the operation.
 */
Sec_Result SecMac_UpdateWithKey(Sec_MacHandle* macHandle, Sec_KeyHandle* keyHandle) {
    CHECK_HANDLE(macHandle)
    CHECK_HANDLE(keyHandle)
    const Sec_Key* key = get_key(keyHandle);
    sa_status status = sa_invoke(macHandle->processorHandle, SA_CRYPTO_MAC_PROCESS_KEY, macHandle->mac_context,
            key->handle);
    CHECK_STATUS(status)
    return SEC_RESULT_SUCCESS;
}

/**
 * @brief Calculate the resulting MAC value and release the MAC object.
 *
 * @param macHandle mac handle.
 * @param macBuffer pointer to an output buffer that will be filled with the resulting.
 * MAC value.  Buffer should be SEC_MAC_MAX_LEN bytes long.
 * @param macSize pointer to a value that will be set to actual size of the MAC value.
 *
 * @return The status of the operation.
 */
Sec_Result SecMac_Release(Sec_MacHandle* macHandle, SEC_BYTE* macBuffer, SEC_SIZE* macSize) {
    CHECK_HANDLE(macHandle)

    size_t out_length = SEC_MAC_MAX_LEN;
    sa_status status = sa_invoke(macHandle->processorHandle, SA_CRYPTO_MAC_COMPUTE, macBuffer, &out_length,
            macHandle->mac_context);
    sa_invoke(macHandle->processorHandle, SA_CRYPTO_MAC_RELEASE, macHandle->mac_context);
    *macSize = out_length;
    SEC_FREE(macHandle);
    CHECK_STATUS(status)
    return SEC_RESULT_SUCCESS;
}

/**
 * @brief Check whether the passed in key type is valid for a chosen MAC algorithm.
 *
 * @param key_type key type.
 * @param algorithm MAC algorithm.
 *
 * @return status of the operation.
 */

Sec_Result SecMac_IsValidKey(Sec_KeyType key_type, Sec_MacAlgorithm algorithm) {
    switch (algorithm) {
        case SEC_MACALGORITHM_HMAC_SHA1:
        case SEC_MACALGORITHM_HMAC_SHA256:
            // SecApi 3 does not distinguish between HMAC and AES keys.
            if (key_type == SEC_KEYTYPE_HMAC_128 ||
                    key_type == SEC_KEYTYPE_HMAC_160 ||
                    key_type == SEC_KEYTYPE_HMAC_256 ||
                    key_type == SEC_KEYTYPE_AES_128 ||
                    key_type == SEC_KEYTYPE_AES_256) {
                return SEC_RESULT_SUCCESS;
            } else {
                return SEC_RESULT_FAILURE;
            }

        case SEC_MACALGORITHM_CMAC_AES_128:
            // SecApi 3 does not distinguish between HMAC and AES keys.
            if (key_type == SEC_KEYTYPE_HMAC_128 ||
                    key_type == SEC_KEYTYPE_HMAC_256 ||
                    key_type == SEC_KEYTYPE_AES_128 ||
                    key_type == SEC_KEYTYPE_AES_256) {
                return SEC_RESULT_SUCCESS;
            } else {
                return SEC_RESULT_FAILURE;
            }

        default:
            return SEC_RESULT_UNIMPLEMENTED_FEATURE;
    }
}

/**
 * @brief Obtain a digest algorithm used by a specified MAC algorithm.
 *
 * @param alg MAC algorithm.
 *
 * @return digest algorithm used.
 */
Sec_DigestAlgorithm SecMac_GetDigestAlgorithm(Sec_MacAlgorithm algorithm) {
    switch (algorithm) {
        case SEC_MACALGORITHM_HMAC_SHA1:
            return SEC_DIGESTALGORITHM_SHA1;

        case SEC_MACALGORITHM_HMAC_SHA256:
            return SEC_DIGESTALGORITHM_SHA256;

        case SEC_MACALGORITHM_CMAC_AES_128:
        default:
            return SEC_DIGESTALGORITHM_NUM;
    }
}
