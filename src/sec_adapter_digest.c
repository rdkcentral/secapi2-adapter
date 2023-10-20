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
#include "sec_adapter_processor.h"
#include "sec_security.h"
#include <openssl/sha.h>

struct Sec_DigestHandle_struct {
    Sec_ProcessorHandle* processorHandle;
    Sec_DigestAlgorithm algorithm;
    SHA_CTX sha1_ctx;
    SHA256_CTX sha256_ctx;
    SEC_BYTE* key_digest;
    size_t key_digest_length;
    SEC_BOOL in_process;
};

/**
 * @brief Obtain a digest object handle.
 *
 * @param processorHandle secure processor handle.
 * @param algorithm digest algorithm to use.
 * @param digestHandle output digest object handle.
 *
 * @return The status of the operation.
 */
Sec_Result SecDigest_GetInstance(Sec_ProcessorHandle* processorHandle, Sec_DigestAlgorithm algorithm,
        Sec_DigestHandle** digestHandle) {
    CHECK_PROCHANDLE(processorHandle)

    if (digestHandle == NULL) {
        SEC_LOG_ERROR("digestHandle is NULL");
        return SEC_RESULT_FAILURE;
    }

    *digestHandle = NULL;
    Sec_DigestHandle* newDigestHandle = calloc(1, sizeof(Sec_DigestHandle));
    if (newDigestHandle == NULL) {
        SEC_LOG_ERROR("calloc failed");
        return SEC_RESULT_FAILURE;
    }

    newDigestHandle->algorithm = algorithm;
    newDigestHandle->processorHandle = processorHandle;

    switch (algorithm) {
        case SEC_DIGESTALGORITHM_SHA1:
            if (SHA1_Init(&(newDigestHandle->sha1_ctx)) != 1) {
                SEC_FREE(newDigestHandle);
                return SEC_RESULT_FAILURE;
            }

            break;

        case SEC_DIGESTALGORITHM_SHA256:
            if (SHA256_Init(&(newDigestHandle->sha256_ctx)) != 1) {
                SEC_FREE(newDigestHandle);
                return SEC_RESULT_FAILURE;
            }

            break;

        default:
            SEC_LOG_ERROR("Unimplemented digest algorithm");
            SEC_FREE(newDigestHandle);
            return SEC_RESULT_UNIMPLEMENTED_FEATURE;
    }

    *digestHandle = newDigestHandle;
    return SEC_RESULT_SUCCESS;
}

/**
 * @brief Update the digest value with the specified input.
 *
 * @param digestHandle handle of the digest object.
 * @param input pointer to the input buffer.
 * @param inputSize size of the input buffer.
 *
 * @return The status of the operation.
 */
Sec_Result SecDigest_Update(Sec_DigestHandle* digestHandle, SEC_BYTE* input, SEC_SIZE inputSize) {
    CHECK_HANDLE(digestHandle)

    // SecDigest_UpdateWithKey can't be mixed with SecDigest_Update.
    if (digestHandle->key_digest != NULL) {
        SEC_LOG_ERROR("SecDigest_UpdateWithKey can't be mixed with SecDigest_Update");
        return SEC_RESULT_FAILURE;
    }

    switch (digestHandle->algorithm) {
        case SEC_DIGESTALGORITHM_SHA1:
            if (SHA1_Update(&(digestHandle->sha1_ctx), input, inputSize) != 1)
                return SEC_RESULT_FAILURE;

            break;

        case SEC_DIGESTALGORITHM_SHA256:
            if (SHA256_Update(&(digestHandle->sha256_ctx), input, inputSize) != 1)
                return SEC_RESULT_FAILURE;

            break;

        default:
            return SEC_RESULT_UNIMPLEMENTED_FEATURE;
    }

    digestHandle->in_process = SEC_TRUE;
    return SEC_RESULT_SUCCESS;
}

/**
 * @brief Update the digest value with the key data.
 *
 * @param digestHandle handle of the digest object.
 * @param keyHandle key to use.
 *
 * @return The status of the operation.
 */
Sec_Result SecDigest_UpdateWithKey(Sec_DigestHandle* digestHandle, Sec_KeyHandle* keyHandle) {
    // SecDigest_UpdateWithKey can't be mixed with SecDigest_Update.
    if (digestHandle->in_process) {
        SEC_LOG_ERROR("SecDigest_UpdateWithKey can't be mixed with SecDigest_Update");
        return SEC_RESULT_FAILURE;
    }

    if (digestHandle->key_digest != NULL) {
        SEC_LOG_ERROR("SecDigest_UpdateWithKey can't be called multiple times");
        return SEC_RESULT_FAILURE;
    }

    const Sec_Key* key = get_key(keyHandle);
    sa_digest_algorithm algorithm = (digestHandle->algorithm == SEC_DIGESTALGORITHM_SHA1) ? SA_DIGEST_ALGORITHM_SHA1 :
                                                                                            SA_DIGEST_ALGORITHM_SHA256;
    sa_status status = sa_key_digest(NULL, &digestHandle->key_digest_length, key->handle, algorithm);
    CHECK_STATUS(status)

    digestHandle->key_digest = malloc(digestHandle->key_digest_length);
    if (digestHandle->key_digest == NULL) {
        SEC_LOG_ERROR("malloc failed");
        return SEC_RESULT_FAILURE;
    }

    status = sa_key_digest(digestHandle->key_digest, &digestHandle->key_digest_length, key->handle,
            algorithm);
    CHECK_STATUS(status)
    return SEC_RESULT_SUCCESS;
}

/**
 * @brief Calculate the resulting digest value and release the digest object.
 *
 * @param digestHandle digest handle.
 * @param digestOutput pointer to an output buffer that will be filled with the resulting
 * digest value.  Buffer should be SEC_DIGEST_MAX_LEN bytes long.
 * @param digestSize pointer to a value that will be set to actual size of the digest value.
 *
 * @return The status of the operation.
 */
Sec_Result SecDigest_Release(Sec_DigestHandle* digestHandle, SEC_BYTE* digestOutput, SEC_SIZE* digestSize) {
    CHECK_HANDLE(digestHandle)

    if (digestOutput == NULL) {
        SEC_LOG_ERROR("digestOutput is NULL");
        return SEC_RESULT_FAILURE;
    }

    if (digestSize == NULL) {
        SEC_LOG_ERROR("digestSize is NULL");
        return SEC_RESULT_FAILURE;
    }

    if (digestHandle->key_digest == NULL) {
        switch (digestHandle->algorithm) {
            case SEC_DIGESTALGORITHM_SHA1:
                *digestSize = SHA_DIGEST_LENGTH;
                if (SHA1_Final(digestOutput, &(digestHandle->sha1_ctx)) != 1)
                    return SEC_RESULT_FAILURE;

                break;

            case SEC_DIGESTALGORITHM_SHA256:
                *digestSize = SHA256_DIGEST_LENGTH;
                if (SHA256_Final(digestOutput, &(digestHandle->sha256_ctx)) != 1)
                    return SEC_RESULT_FAILURE;

                break;

            default:
                return SEC_RESULT_UNIMPLEMENTED_FEATURE;
        }
    } else {
        memcpy(digestOutput, digestHandle->key_digest, digestHandle->key_digest_length);
        *digestSize = digestHandle->key_digest_length;
        free(digestHandle->key_digest);
    }

    SEC_FREE(digestHandle);
    return SEC_RESULT_SUCCESS;
}

/**
 * @brief Obtain the size of the digest for a specified digest algorithm.
 *
 * @param alg digest algorithm.
 *
 * @return digest size in bytes.
 */
SEC_SIZE SecDigest_GetDigestLenForAlgorithm(Sec_DigestAlgorithm alg) {
    switch (alg) {
        case SEC_DIGESTALGORITHM_SHA1:
            return SHA_DIGEST_LENGTH;

        case SEC_DIGESTALGORITHM_SHA256:
            return SHA256_DIGEST_LENGTH;

        default:
            return 0;
    }
}

/**
 * @brief Utility function for calculating a digest value of a single input buffer.
 *
 * @param proc secure processor handle.
 * @param alg digest algorithm to use.
 * @param input input data to calculate digest over.
 * @param input_len size of input data in bytes.
 * @param digest output buffer where the calculated digest value will be written.
 * @param digest_len number of bytes written to the output digest buffer.
 *
 * @return status of the operation.
 */
Sec_Result SecDigest_SingleInput(Sec_ProcessorHandle* processorHandle, Sec_DigestAlgorithm alg, SEC_BYTE* input,
        SEC_SIZE input_len, SEC_BYTE* digest, SEC_SIZE* digest_len) {
    Sec_Result result;
    Sec_DigestHandle* digestHandle = NULL;

    result = SecDigest_GetInstance(processorHandle, alg, &digestHandle);
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecDigest_GetInstance failed");
        return result;
    }

    result = SecDigest_Update(digestHandle, input, input_len);
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecDigest_Update failed");
        SecDigest_Release(digestHandle, digest, digest_len);
        return result;
    }

    return SecDigest_Release(digestHandle, digest, digest_len);
}

/**
 * @brief Utility function for calculating a digest value of a single input buffer.
 *
 * @param proc secure processor handle.
 * @param alg digest algorithm to use.
 * @param key_id id of the key over which the digest is being calculated.
 * @param digest output buffer where the calculated digest value will be written.
 * @param digest_len number of bytes written to the output digest buffer.
 *
 * @return status of the operation.
 */
Sec_Result SecDigest_SingleInputWithKeyId(Sec_ProcessorHandle* processorHandle, Sec_DigestAlgorithm alg,
        SEC_OBJECTID key_id, SEC_BYTE* digest, SEC_SIZE* digest_len) {
    Sec_Result result = SEC_RESULT_FAILURE;

    Sec_DigestHandle* digestHandle = NULL;
    Sec_KeyHandle* keyHandle = NULL;
    do {
        if (SecDigest_GetInstance(processorHandle, alg, &digestHandle) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecDigest_GetInstance failed");
            break;
        }

        if (SecKey_GetInstance(processorHandle, key_id, &keyHandle) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecKey_GetInstance failed");
            break;
        }

        if (SecDigest_UpdateWithKey(digestHandle, keyHandle) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecDigest_UpdateWithKey failed");
            break;
        }

        result = SEC_RESULT_SUCCESS;
    } while (SEC_FALSE);

    if (digestHandle != NULL) {
        SecDigest_Release(digestHandle, digest, digest_len);
        digestHandle = NULL;
    }

    if (keyHandle != NULL) {
        SecKey_Release(keyHandle);
        keyHandle = NULL;
    }

    return result;
}
