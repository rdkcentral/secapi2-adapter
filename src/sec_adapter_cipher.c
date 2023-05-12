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

#include "sec_adapter_cipher.h" // NOLINT
#include "sa.h"
#include "sa_cenc.h"
#include <stdbool.h>

#define RSA_OAEP_PADDING_SIZE 42

struct Sec_CipherHandle_struct {
    Sec_ProcessorHandle* processorHandle;
    union {
        sa_crypto_cipher_context context;
        RSA* rsa;
        EC_KEY* ec;
    } cipher;

    Sec_CipherAlgorithm algorithm;
    Sec_CipherMode mode;
    SEC_BOOL last;
    SEC_BOOL svp_required;
    Sec_KeyHandle* keyHandle;
};

static sa_cipher_mode get_cipher_mode(Sec_CipherMode mode);

static SEC_BOOL rsa_encrypt_pkcs1v15(void* out, size_t* out_length, const RSA* rsa, const void* in, size_t in_length);

static SEC_BOOL rsa_encrypt_oaep(void* out, size_t* out_length, const RSA* rsa, const void* in, size_t in_length);

static SEC_BOOL is_svp_required(Sec_KeyProperties* props);

/**
 * @brief Initialize cipher object.
 *
 * @param processorHandle secure processor handle.
 * @param algorithm cipher algorithm to use.
 * @param mode cipher mode to use.
 * @param keyHandle handle to use.
 * @param iv initialization vector value.  Can be set to NULL is the cipher
 * algorithm chosen does not require it.
 * @param cipherHandle pointer to a cipher handle that will be set once
 * the cipher object is constructed.
 *
 * @return The status of the operation.
 */
Sec_Result SecCipher_GetInstance(Sec_ProcessorHandle* processorHandle, Sec_CipherAlgorithm algorithm,
        Sec_CipherMode mode, Sec_KeyHandle* keyHandle, SEC_BYTE* iv, Sec_CipherHandle** cipherHandle) {
    CHECK_PROCHANDLE(processorHandle)
    CHECK_HANDLE(keyHandle)
    Sec_Result result;
    Sec_KeyProperties key_properties;

    if (cipherHandle == NULL) {
        SEC_LOG_ERROR("cipherHandle is NULL");
        return SEC_RESULT_FAILURE;
    }

    *cipherHandle = NULL;

    result = SecKey_GetProperties(keyHandle, &key_properties);
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecKey_GetProperties failed");
        return result;
    }

    SEC_BOOL svp_required = is_svp_required(&key_properties);
    result = SecCipher_IsValidKey(key_properties.keyType, algorithm, mode, iv);
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("Invalid key used for specified algorithm");
        return result;
    }

    // Output Protection tests are delegated to SecApi 3.0, so removed from here.
    Sec_KeyType key_type = SecKey_GetKeyType(keyHandle);
    const Sec_Key* key = get_key(keyHandle);
    switch (key_type) {
        case SEC_KEYTYPE_AES_128:
        case SEC_KEYTYPE_AES_256:
        case SEC_KEYTYPE_RSA_1024:
        case SEC_KEYTYPE_RSA_2048:
        case SEC_KEYTYPE_HMAC_128:
        case SEC_KEYTYPE_HMAC_160:
        case SEC_KEYTYPE_HMAC_256:
        case SEC_KEYTYPE_ECC_NISTP256:
        case SEC_KEYTYPE_RSA_3072: {
            sa_cipher_algorithm cipher_algorithm;
            void* parameters;
            result = get_cipher_algorithm(algorithm, SEC_FALSE, &cipher_algorithm, &parameters, iv, 0, 0);
            if (result != SEC_RESULT_SUCCESS)
                return result;

            sa_cipher_mode cipher_mode = get_cipher_mode(mode);
            sa_crypto_cipher_context context;

            sa_status status;
            status = sa_invoke(processorHandle, SA_CRYPTO_CIPHER_INIT, &context, cipher_algorithm, cipher_mode,
                    key->handle, parameters);
            SEC_FREE(parameters);
            CHECK_STATUS(status)

            *cipherHandle = calloc(1, sizeof(Sec_CipherHandle));
            (*cipherHandle)->cipher.context = context;
            break;
        }
        case SEC_KEYTYPE_RSA_1024_PUBLIC:
        case SEC_KEYTYPE_RSA_2048_PUBLIC:
        case SEC_KEYTYPE_RSA_3072_PUBLIC: {
            if (algorithm != SEC_CIPHERALGORITHM_RSA_PKCS1_PADDING &&
                    algorithm != SEC_CIPHERALGORITHM_RSA_OAEP_PADDING) {
                return SEC_RESULT_INVALID_PARAMETERS;
            }

            if (mode != SEC_CIPHERMODE_ENCRYPT && mode != SEC_CIPHERMODE_ENCRYPT_NATIVEMEM) {
                return SEC_RESULT_INVALID_PARAMETERS;
            }

            *cipherHandle = calloc(1, sizeof(Sec_CipherHandle));
            (*cipherHandle)->cipher.rsa = key->rsa;
            break;
        }
        case SEC_KEYTYPE_ECC_NISTP256_PUBLIC: {
            if (algorithm != SEC_CIPHERALGORITHM_ECC_ELGAMAL) {
                return SEC_RESULT_INVALID_PARAMETERS;
            }

            if (mode != SEC_CIPHERMODE_ENCRYPT && mode != SEC_CIPHERMODE_ENCRYPT_NATIVEMEM) {
                return SEC_RESULT_INVALID_PARAMETERS;
            }

            *cipherHandle = calloc(1, sizeof(Sec_CipherHandle));
            (*cipherHandle)->cipher.ec = key->ec_key;
            break;
        }
        default:
            SEC_LOG_ERROR("unsupported key type %u", key_type);
            return SEC_RESULT_UNIMPLEMENTED_FEATURE;
    }

    (*cipherHandle)->keyHandle = keyHandle;
    (*cipherHandle)->processorHandle = processorHandle;
    (*cipherHandle)->algorithm = algorithm;
    (*cipherHandle)->mode = mode;
    (*cipherHandle)->svp_required = svp_required;
    return SEC_RESULT_SUCCESS;
}

/**
 * @brief Update the IV on the cipher handle.
 */
Sec_Result SecCipher_UpdateIV(Sec_CipherHandle* cipherHandle, SEC_BYTE* iv) {
    CHECK_HANDLE(cipherHandle)

    // Update IV unimplemented for RSA and EC keys.
    Sec_KeyType key_type = SecKey_GetKeyType(cipherHandle->keyHandle);
    sa_status status;
    if (key_type == SEC_KEYTYPE_AES_128 || key_type == SEC_KEYTYPE_AES_256) {
        status = sa_invoke(cipherHandle->processorHandle, SA_CRYPTO_CIPHER_UPDATE_IV, cipherHandle->cipher.context, iv,
                (size_t) SEC_AES_BLOCK_SIZE);
        CHECK_STATUS(status)
        return SEC_RESULT_SUCCESS;
    }

    return SEC_RESULT_UNIMPLEMENTED_FEATURE;
}

/**
 * @brief En/De-cipher specified input data into and output buffer.
 *
 * @param cipherHandle cipher handle.
 * @param input pointer to input data.
 * @param inputSize the length of input data in bytes.
 * @param lastInput  SEC_BOOLean value specifying whether this is the last chunk
 * of input that will be processed.
 * @param output pointer to output data buffer.
 * @param outputSize the size of the output buffer.
 * @param bytesWritten pointer to a value that will be set to number
 * of bytes written to the output buffer.
 *
 * @return The status of the operation.
 */
Sec_Result SecCipher_Process(Sec_CipherHandle* cipherHandle, SEC_BYTE* input, SEC_SIZE inputSize, SEC_BOOL lastInput,
        SEC_BYTE* output, SEC_SIZE outputSize, SEC_SIZE* bytesWritten) {
    CHECK_HANDLE(cipherHandle)
    SEC_SIZE output_size_needed = 0;

    if (cipherHandle->svp_required) {
        SEC_LOG_ERROR("An opaque buffer must be used for cipher processing when SVP is required.");
        return SEC_RESULT_FAILURE;
    }

    if (cipherHandle->last != 0) {
        SEC_LOG_ERROR("Last block has already been processed");
        return SEC_RESULT_FAILURE;
    }

    cipherHandle->last = lastInput;
    if (SecCipher_GetRequiredOutputSize(cipherHandle->algorithm, cipherHandle->mode,
                SecKey_GetKeyType(cipherHandle->keyHandle), inputSize, &output_size_needed, lastInput) !=
            SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecCipher_GetRequiredOutputSize failed");
        return SEC_RESULT_FAILURE;
    }

    if (output == NULL) {
        *bytesWritten = output_size_needed;
        return SEC_RESULT_SUCCESS;
    }

    if (output_size_needed > outputSize) {
        SEC_LOG_ERROR("Output buffer is too small");
        return SEC_RESULT_FAILURE;
    }

    size_t output_count = outputSize;
    Sec_KeyType key_type = SecKey_GetKeyType(cipherHandle->keyHandle);
    switch (key_type) {
        case SEC_KEYTYPE_AES_128:
        case SEC_KEYTYPE_AES_256:
        case SEC_KEYTYPE_RSA_1024:
        case SEC_KEYTYPE_RSA_2048:
        case SEC_KEYTYPE_HMAC_128:
        case SEC_KEYTYPE_HMAC_160:
        case SEC_KEYTYPE_HMAC_256:
        case SEC_KEYTYPE_ECC_NISTP256:
        case SEC_KEYTYPE_RSA_3072: {
            sa_buffer out_buffer;
            out_buffer.buffer_type = SA_BUFFER_TYPE_CLEAR;
            out_buffer.context.clear.buffer = output;
            out_buffer.context.clear.length = outputSize;
            out_buffer.context.clear.offset = 0;

            sa_buffer in_buffer;
            in_buffer.buffer_type = SA_BUFFER_TYPE_CLEAR;
            in_buffer.context.clear.buffer = input;
            in_buffer.context.clear.length = inputSize;
            in_buffer.context.clear.offset = 0;

            bool pkcs7 = cipherHandle->algorithm == SEC_CIPHERALGORITHM_AES_CBC_PKCS7_PADDING ||
                         cipherHandle->algorithm == SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING;
            if (lastInput && pkcs7) {
                *bytesWritten = 0;

                // In encrypt mode, if the last block is complete add a padding block.  In decrypt mode,
                // the last block is the padding block.
                size_t bytes_to_process = cipherHandle->mode == SEC_CIPHERMODE_DECRYPT ?
                                                  ((inputSize / SEC_AES_BLOCK_SIZE) - 1) * SEC_AES_BLOCK_SIZE :
                                                  (inputSize / SEC_AES_BLOCK_SIZE) * SEC_AES_BLOCK_SIZE;
                size_t bytes_left = inputSize - bytes_to_process;
                sa_status status = sa_invoke(cipherHandle->processorHandle, SA_CRYPTO_CIPHER_PROCESS, &out_buffer,
                        cipherHandle->cipher.context, &in_buffer, &bytes_to_process);
                CHECK_STATUS(status)
                *bytesWritten += bytes_to_process;

                status = sa_invoke(cipherHandle->processorHandle, SA_CRYPTO_CIPHER_PROCESS_LAST, &out_buffer,
                        cipherHandle->cipher.context, &in_buffer, &bytes_left, NULL);
                CHECK_STATUS(status)
                *bytesWritten += bytes_left;
            } else {
                size_t bytes_to_process = inputSize;
                sa_status status = sa_invoke(cipherHandle->processorHandle, SA_CRYPTO_CIPHER_PROCESS, &out_buffer,
                        cipherHandle->cipher.context, &in_buffer, &bytes_to_process);
                CHECK_STATUS(status)
                *bytesWritten = bytes_to_process;
            }

            break;
        }
        case SEC_KEYTYPE_RSA_1024_PUBLIC:
        case SEC_KEYTYPE_RSA_2048_PUBLIC:
        case SEC_KEYTYPE_RSA_3072_PUBLIC:
            if (cipherHandle->algorithm == SEC_CIPHERALGORITHM_RSA_PKCS1_PADDING) {
                if (rsa_encrypt_pkcs1v15(output, &output_count, cipherHandle->cipher.rsa, input, inputSize) ==
                        SEC_FALSE)
                    return SEC_RESULT_FAILURE;
            } else if (cipherHandle->algorithm == SEC_CIPHERALGORITHM_RSA_OAEP_PADDING) {
                if (rsa_encrypt_oaep(output, &output_count, cipherHandle->cipher.rsa, input, inputSize) == SEC_FALSE)
                    return SEC_RESULT_FAILURE;
            } else
                return SEC_RESULT_FAILURE;

            *bytesWritten = output_count;
            break;

        case SEC_KEYTYPE_ECC_NISTP256_PUBLIC:
            *bytesWritten = SecUtils_ElGamal_Encrypt(cipherHandle->cipher.ec, input, inputSize, output, outputSize);
            if (*bytesWritten == -1) {
                *bytesWritten = 0;
                return SEC_RESULT_FAILURE;
            }

            break;

        default:
            SEC_LOG_ERROR("unsupported key type %u", key_type);
            return SEC_RESULT_UNIMPLEMENTED_FEATURE;
    }

    return SEC_RESULT_SUCCESS;
}

/**
 * @brief En/De-cipher specified fragmented input data into and output buffer.
 *
 * @param cipherHandle cipher handle.
 * @param input pointer to input data.
 * @param inputSize the length of input data in bytes.
 * @param lastInput  SEC_BOOLean value specifying whether this is the last chunk
 * of input that will be processed.
 * @param output pointer to output data buffer.
 * @param outputSize the size of the output buffer.
 * @param bytesWritten pointer to a value that will be set to number
 * of bytes written to the output buffer.
 * @param fragmentOffset offset in bytes of the fragment data within larger packet.
 * @param fragmentSize length in bytes of the data fragment.
 * @param fragmentPeriod the length in bytes of the packet containing the fragment.
 *
 * @return The status of the operation.
 */
Sec_Result SecCipher_ProcessFragmented(Sec_CipherHandle* cipherHandle, SEC_BYTE* input, SEC_SIZE inputSize,
        SEC_BOOL lastInput, SEC_BYTE* output, SEC_SIZE outputSize, SEC_SIZE* bytesWritten, SEC_SIZE fragmentOffset,
        SEC_SIZE fragmentSize, SEC_SIZE fragmentPeriod) {
    SEC_SIZE lbw;
    SEC_SIZE output_size_required = 0;
    Sec_Result result = SEC_RESULT_FAILURE;

    CHECK_HANDLE(cipherHandle)

    *bytesWritten = 0;

    if (SecCipher_GetRequiredOutputSizeFragmented(cipherHandle->algorithm, cipherHandle->mode,
                SecKey_GetKeyType(cipherHandle->keyHandle), inputSize, &output_size_required, lastInput,
                fragmentOffset, fragmentSize, fragmentPeriod) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecCipher_GetRequiredOutputSizeFragmented failed");
        return result;
    }

    if (output == NULL) {
        *bytesWritten = output_size_required;
        result = SEC_RESULT_SUCCESS;
        return result;
    }

    if (output_size_required > outputSize) {
        SEC_LOG_ERROR("Output buffer is too small");
        result = SEC_RESULT_INVALID_INPUT_SIZE;
        return result;
    }

    switch (cipherHandle->algorithm) {
        case SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING:
        case SEC_CIPHERALGORITHM_AES_CBC_NO_PADDING:
        case SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING:
        case SEC_CIPHERALGORITHM_AES_CBC_PKCS7_PADDING:
        case SEC_CIPHERALGORITHM_AES_CTR:
            if (input != output) {
                memcpy(output, input, inputSize);
            }

            *bytesWritten = inputSize;
            while (inputSize > 0) {
                if (SecCipher_Process(cipherHandle, output + fragmentOffset, fragmentSize,
                            lastInput && (inputSize == fragmentPeriod), output + fragmentOffset, fragmentSize,
                            &lbw) != SEC_RESULT_SUCCESS) {
                    SEC_LOG_ERROR("SecCipher_Process failed");
                    return result;
                }

                output += fragmentPeriod;
                inputSize -= fragmentPeriod;
            }

            break;

        default:
            SEC_LOG_ERROR("Unimplemented cipher algorithm");
            return result;
    }

    result = SEC_RESULT_SUCCESS;
    return result;
}

/**
 * @brief Process the opaque buffers that were obtained with Sec_OpaqueBufferMalloc.
 *
 * @param cipherHandle cipher handle.
 * @param inputHandle opaque buffer containing input.
 * @param outputHandle opaque buffer for writing output.
 * @param inputSize the length of input to process.
 * @param lastInput  SEC_BOOLean value specifying whether this is the last chunk
 * of input that will be processed.
 * @param bytesWritten pointer to a value that will be set to number.
 * of bytes written to the output buffer.
 */
Sec_Result SecCipher_ProcessOpaque(Sec_CipherHandle* cipherHandle, Sec_OpaqueBufferHandle* inOpaqueBufferHandle,
        Sec_OpaqueBufferHandle* outOpaqueBufferHandle, SEC_SIZE inputSize, SEC_BOOL lastInput, SEC_SIZE* bytesWritten) {
    CHECK_HANDLE(cipherHandle)
    if (inOpaqueBufferHandle == NULL) {
        SEC_LOG_ERROR("Invalid inputHandle");
        return SEC_RESULT_INVALID_HANDLE;
    }

    if (outOpaqueBufferHandle == NULL) {
        SEC_LOG_ERROR("Invalid outputHandle");
        return SEC_RESULT_INVALID_HANDLE;
    }

    SEC_SIZE output_size_needed = 0;

    if (cipherHandle->last != 0) {
        SEC_LOG_ERROR("Last block has already been processed");
        return SEC_RESULT_FAILURE;
    }

    cipherHandle->last = lastInput;
    if (SecCipher_GetRequiredOutputSize(cipherHandle->algorithm, cipherHandle->mode,
                SecKey_GetKeyType(cipherHandle->keyHandle), inputSize, &output_size_needed,
                lastInput) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecCipher_GetRequiredOutputSize failed");
        return SEC_RESULT_FAILURE;
    }

    Sec_KeyType key_type = SecKey_GetKeyType(cipherHandle->keyHandle);
    switch (key_type) {
        case SEC_KEYTYPE_AES_128:
        case SEC_KEYTYPE_AES_256: {
            sa_buffer out_buffer;
            out_buffer.buffer_type = SA_BUFFER_TYPE_SVP;
            out_buffer.context.svp.offset = 0;
            out_buffer.context.svp.buffer = get_svp_buffer(cipherHandle->processorHandle, outOpaqueBufferHandle);
            if (out_buffer.context.svp.buffer == INVALID_HANDLE)
                return SEC_RESULT_FAILURE;

            sa_buffer in_buffer;
            in_buffer.buffer_type = SA_BUFFER_TYPE_SVP;
            in_buffer.context.svp.offset = 0;
            in_buffer.context.svp.buffer = get_svp_buffer(cipherHandle->processorHandle, inOpaqueBufferHandle);
            if (in_buffer.context.svp.buffer == INVALID_HANDLE)
                return SEC_RESULT_FAILURE;

            size_t bytes_to_process = inputSize;
            bool pkcs7 = cipherHandle->algorithm == SEC_CIPHERALGORITHM_AES_CBC_PKCS7_PADDING ||
                         cipherHandle->algorithm == SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING;
            if (lastInput && pkcs7) {
                sa_status status = sa_invoke(cipherHandle->processorHandle, SA_CRYPTO_CIPHER_PROCESS_LAST, &out_buffer,
                        cipherHandle->cipher.context, &in_buffer, &bytes_to_process, NULL);
                CHECK_STATUS(status)
            } else {
                sa_status status = sa_invoke(cipherHandle->processorHandle, SA_CRYPTO_CIPHER_PROCESS, &out_buffer,
                        cipherHandle->cipher.context, &in_buffer, &bytes_to_process);
                CHECK_STATUS(status)
            }

            *bytesWritten = bytes_to_process;
            break;
        }
        default:
            return SEC_RESULT_UNIMPLEMENTED_FEATURE;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result SecCipher_ProcessCtrWithOpaqueDataShift(Sec_CipherHandle* cipherHandle,
        Sec_OpaqueBufferHandle* inOpaqueBufferHandle, Sec_OpaqueBufferHandle* outOpaqueBufferHandle, SEC_SIZE inputSize,
        SEC_SIZE* bytesWritten, SEC_SIZE dataShift) {
    // Original implementation never worked right and function has not been implemented by any vendor.
    return SEC_RESULT_UNIMPLEMENTED_FEATURE;
}

/**
 * @brief Perform cipher operation on the opaque input handle and check the output against the expected value.
 *
 * @param cipherHandle pointer to Sec_CipherHandle.
 * @param void inputHandle pointer to opaque buffer containing input.
 * @param SEC_SIZE checkLength number of bytes used for comparison.
 * @param SEC_BYTE expected expected value used for comparison.
 */
Sec_Result SecCipher_KeyCheckOpaque(Sec_CipherHandle* cipherHandle, Sec_OpaqueBufferHandle* opaqueBufferHandle,
        SEC_SIZE checkLength, SEC_BYTE* expected) {

#if MIN_SA_VERSION(3, 1, 2)
    return SEC_RESULT_UNIMPLEMENTED_FEATURE;
#else
    if (opaqueBufferHandle == NULL) {
        SEC_LOG_ERROR("Null inputHandle");
        return SEC_RESULT_FAILURE;
    }

    if (checkLength < 8 || checkLength > SEC_AES_BLOCK_SIZE) {
        SEC_LOG_ERROR("Length must be >=8 and <=16");
        return SEC_RESULT_FAILURE;
    }

    if (cipherHandle == NULL) {
        SEC_LOG_ERROR("Null cipherHandle");
        return SEC_RESULT_FAILURE;
    }

    sa_status status;
    sa_buffer in_buffer;
    in_buffer.buffer_type = SA_BUFFER_TYPE_SVP;
    in_buffer.context.svp.offset = 0;
    in_buffer.context.svp.buffer = get_svp_buffer(cipherHandle->processorHandle, opaqueBufferHandle);
    if (in_buffer.context.svp.buffer == INVALID_HANDLE)
        return SEC_RESULT_FAILURE;

    if (cipherHandle->mode == SEC_CIPHERMODE_ENCRYPT)
        return SEC_RESULT_UNIMPLEMENTED_FEATURE;

    const Sec_Key* key = get_key(cipherHandle->keyHandle);
    status = sa_invoke(cipherHandle->processorHandle, SA_SVP_KEY_CHECK, key->handle, &in_buffer,
            (size_t) SEC_AES_BLOCK_SIZE, expected, (size_t) SEC_AES_BLOCK_SIZE);

    CHECK_STATUS(status)
    return SEC_RESULT_SUCCESS;
#endif
}

/**
 * @brief Release the cipher object.
 *
 * @param cipherHandle cipher handle.
 *
 * @return The status of the operation.
 */
Sec_Result SecCipher_Release(Sec_CipherHandle* cipherHandle) {
    CHECK_HANDLE(cipherHandle)

    Sec_KeyType key_type = SecKey_GetKeyType(cipherHandle->keyHandle);
    switch (key_type) {
        case SEC_KEYTYPE_AES_128:
        case SEC_KEYTYPE_AES_256:
        case SEC_KEYTYPE_RSA_1024:
        case SEC_KEYTYPE_RSA_2048:
        case SEC_KEYTYPE_HMAC_128:
        case SEC_KEYTYPE_HMAC_160:
        case SEC_KEYTYPE_HMAC_256:
        case SEC_KEYTYPE_ECC_NISTP256:
        case SEC_KEYTYPE_RSA_3072:
            sa_invoke(cipherHandle->processorHandle, SA_CRYPTO_CIPHER_RELEASE, cipherHandle->cipher.context);
            break;

        default:
            break;
    }

    SEC_FREE(cipherHandle);
    return SEC_RESULT_SUCCESS;
}

Sec_Result SecCipher_ProcessCtrWithDataShift(Sec_CipherHandle* cipherHandle, SEC_BYTE* input, SEC_SIZE inputSize,
        SEC_BYTE* output, SEC_SIZE outputSize, SEC_SIZE* bytesWritten, SEC_SIZE dataShift) {
    // Original implementation never worked right and function has not been implemented by any vendor.
    return SEC_RESULT_UNIMPLEMENTED_FEATURE;
}

int SecCipher_IsModeEncrypt(Sec_CipherMode mode) {
    return mode == SEC_CIPHERMODE_ENCRYPT || mode == SEC_CIPHERMODE_ENCRYPT_NATIVEMEM;
}

int SecCipher_IsModeDecrypt(Sec_CipherMode mode) {
    return mode == SEC_CIPHERMODE_DECRYPT || mode == SEC_CIPHERMODE_DECRYPT_NATIVEMEM;
}

/**
 * @brief Check whether the supplied key and iv are valid for the chosen cipher algorithm.
 *
 * @param key_type key type.
 * @param algorithm cipher algorithm.
 * @param mode cipher mode.
 * @param iv initialization vector.
 *
 * @return status of the call.
 */
Sec_Result SecCipher_IsValidKey(Sec_KeyType key_type, Sec_CipherAlgorithm alg, Sec_CipherMode mode,
        const SEC_BYTE* iv) {
    switch (alg) {
        case SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING:
        case SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING:
        case SEC_CIPHERALGORITHM_AES_CBC_NO_PADDING:
        case SEC_CIPHERALGORITHM_AES_CBC_PKCS7_PADDING:
        case SEC_CIPHERALGORITHM_AES_CTR:
            if (SecKey_IsAES(key_type)) {
                if (iv == NULL && alg != SEC_CIPHERALGORITHM_AES_CTR && alg != SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING &&
                        alg != SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING) {
                    SEC_LOG_ERROR("IV cannot be null in CBC and CTR modes.");
                    return SEC_RESULT_FAILURE;
                }

                return SEC_RESULT_SUCCESS;
            } else {
                SEC_LOG_ERROR("Not an AES key: %d", key_type);
                return SEC_RESULT_FAILURE;
            }

        case SEC_CIPHERALGORITHM_RSA_PKCS1_PADDING:
        case SEC_CIPHERALGORITHM_RSA_OAEP_PADDING:
            if (SecCipher_IsModeEncrypt(mode)) {
                if (!SecKey_IsRsa(key_type)) {
                    SEC_LOG_ERROR("Not an RSA key");
                    return SEC_RESULT_FAILURE;
                }

                return SEC_RESULT_SUCCESS;
            } else if (SecCipher_IsModeDecrypt(mode)) {
                if (!SecKey_IsPrivRsa(key_type)) {
                    SEC_LOG_ERROR("Not an RSA key");
                    return SEC_RESULT_FAILURE;
                }

                return SEC_RESULT_SUCCESS;
            } else {
                SEC_LOG_ERROR("Unknown cipher mode encountered: %d", mode);
                return SEC_RESULT_FAILURE;
            }

        case SEC_CIPHERALGORITHM_ECC_ELGAMAL:
            if (SecCipher_IsModeEncrypt(mode)) {
                if (!SecKey_IsEcc(key_type)) {
                    SEC_LOG_ERROR("Not an ECC key");
                    return SEC_RESULT_FAILURE;
                }

                return SEC_RESULT_SUCCESS;
            } else if (SecCipher_IsModeDecrypt(mode)) {
                if (!SecKey_IsPrivEcc(key_type)) {
                    SEC_LOG_ERROR("Not an ECC key");
                    return SEC_RESULT_FAILURE;
                }

                return SEC_RESULT_SUCCESS;
            } else {
                SEC_LOG_ERROR("Unknown cipher mode encountered: %d", mode);
                return SEC_RESULT_FAILURE;
            }

        default:
            break;
    }

    SEC_LOG_ERROR("Unimplemented algorithm: %d", alg);
    return SEC_RESULT_UNIMPLEMENTED_FEATURE;
}

SEC_BOOL SecCipher_IsCBC(Sec_CipherAlgorithm alg) {
    return alg == SEC_CIPHERALGORITHM_AES_CBC_PKCS7_PADDING || alg == SEC_CIPHERALGORITHM_AES_CBC_NO_PADDING;
}

/**
 * @brief get the required output buffer size for the specified combination of input parameters.
 *
 * Write required output buffer size for cipher configuration.
 * Returns SEC_RESULT_SUCCESS if the cipher configuration parameters are valid.
 * Returns SEC_RESULT_FAILURE otherwise (e.g. input size is not valid).
 *
 * @param algorithm cipher algorithm.
 * @param mode cipher mode.
 * @param keyType key type.
 * @param inputSize size of the input buffer.
 * @param outputSize size of the output buffer.
 * @param lastInput is this the last input to the cipher.
 *
 * @return status of the call.
 */
Sec_Result SecCipher_GetRequiredOutputSize(Sec_CipherAlgorithm alg, Sec_CipherMode mode, Sec_KeyType keyType,
        SEC_SIZE inputSize, SEC_SIZE* outputSize, SEC_BOOL lastInput) {
    SEC_SIZE max_clear_size;
    SEC_SIZE rsa_block_size;
    SEC_SIZE bn_size;
    *outputSize = 0;

    switch (alg) {
        case SEC_CIPHERALGORITHM_AES_CTR:
            *outputSize = inputSize;
            break;

        case SEC_CIPHERALGORITHM_AES_CBC_NO_PADDING:
        case SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING:
            if (inputSize % SEC_AES_BLOCK_SIZE != 0) {
                SEC_LOG_ERROR("Input size is not a multiple of block size");
                return SEC_RESULT_INVALID_INPUT_SIZE;
            }

            *outputSize = inputSize;
            break;

        case SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING:
        case SEC_CIPHERALGORITHM_AES_CBC_PKCS7_PADDING:
            if (SecCipher_IsModeEncrypt(mode) && !lastInput && inputSize % SEC_AES_BLOCK_SIZE != 0) {
                SEC_LOG_ERROR("Encryption input size is not a multiple of block size and is not last input");
                return SEC_RESULT_INVALID_INPUT_SIZE;
            }

            if (SecCipher_IsModeDecrypt(mode) && inputSize % SEC_AES_BLOCK_SIZE != 0) {
                SEC_LOG_ERROR("Decryption input size is not a multiple of block size");
                return SEC_RESULT_INVALID_INPUT_SIZE;
            }

            *outputSize = (inputSize / 16) * 16 + ((lastInput && (SecCipher_IsModeEncrypt(mode))) ? 16 : 0);
            break;

        case SEC_CIPHERALGORITHM_RSA_PKCS1_PADDING:
        case SEC_CIPHERALGORITHM_RSA_OAEP_PADDING:
            rsa_block_size = *outputSize = SecKey_GetKeyLenForKeyType(keyType);

            if (alg == SEC_CIPHERALGORITHM_RSA_OAEP_PADDING) {
                max_clear_size = rsa_block_size - RSA_OAEP_PADDING_SIZE;
            } else {
                max_clear_size = rsa_block_size - RSA_PKCS1_PADDING_SIZE;
            }

            if (SecCipher_IsModeDecrypt(mode) && inputSize != rsa_block_size) {
                SEC_LOG_ERROR("Decrypt input size %u is not equal to the RSA block size", inputSize);
                return SEC_RESULT_INVALID_INPUT_SIZE;
            }

            if ((SecCipher_IsModeEncrypt(mode)) && inputSize > max_clear_size) {
                SEC_LOG_ERROR("Encrypt input size is too large");
                return SEC_RESULT_INVALID_INPUT_SIZE;
            }

            break;

        case SEC_CIPHERALGORITHM_ECC_ELGAMAL:
            bn_size = SecKey_GetKeyLenForKeyType(keyType); // one bignum
            if (SecCipher_IsModeEncrypt(mode)) {
                if (inputSize != bn_size) { // one bignum
                    SEC_LOG_ERROR("Input size invalid for El Gamal encryption");
                    return SEC_RESULT_INVALID_INPUT_SIZE;
                }

                *outputSize = 4 * bn_size; // two points, which are four bignums
            } else {
                if (inputSize != 4 * bn_size) { // two points, which are four bignums
                    SEC_LOG_ERROR("Input size invalid for El Gamal encryption");
                    return SEC_RESULT_INVALID_INPUT_SIZE;
                }

                *outputSize = bn_size; // one bignum
            }

            break;

        default:
            SEC_LOG_ERROR("Unimplemented cipher algorithm");
            return SEC_RESULT_UNIMPLEMENTED_FEATURE;
    }

    return SEC_RESULT_SUCCESS;
}

/**
 * @brief get the required output buffer length for fragemnted encryption/decryption.
 *
 * @param algorithm cipher algorithm.
 * @param mode cipher mode.
 * @param keyType key type.
 * @param inputSize size of the input buffer.
 * @param outputSize size of the output buffer.
 * @param lastInput is this the last input to the cipher.
 * @param framentOffset offset in bytes of the fragment data within larger packet.
 * @param fragmentSize length in bytes of the data fragment.
 * @param fragmentPeriod the length in bytes of the packet containing the fragment.
 *
 * @return status of the call.
 */
Sec_Result SecCipher_GetRequiredOutputSizeFragmented(Sec_CipherAlgorithm alg, Sec_CipherMode mode, Sec_KeyType keyType,
        SEC_SIZE inputSize, SEC_SIZE* outputSizeNeeded, SEC_BOOL lastInput, SEC_SIZE fragmentOffset,
        SEC_SIZE fragmentSize, SEC_SIZE fragmentPeriod) {
    *outputSizeNeeded = 0;

    if ((inputSize % fragmentPeriod) != 0) {
        SEC_LOG_ERROR("Input size is not a multiple of a fragment period");
        return SEC_RESULT_INVALID_INPUT_SIZE;
    }

    if ((fragmentSize % SEC_AES_BLOCK_SIZE) != 0) {
        SEC_LOG_ERROR("Fragment size is not a multiple of block size");
        return SEC_RESULT_INVALID_INPUT_SIZE;
    }

    if ((fragmentOffset + fragmentSize) > fragmentPeriod) {
        SEC_LOG_ERROR("Invalid fragment parameters");
        return SEC_RESULT_INVALID_INPUT_SIZE;
    }

    switch (alg) {
        case SEC_CIPHERALGORITHM_AES_CBC_NO_PADDING:
        case SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING:
        case SEC_CIPHERALGORITHM_AES_CTR:
        case SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING:
        case SEC_CIPHERALGORITHM_AES_CBC_PKCS7_PADDING:
            *outputSizeNeeded = inputSize;
            break;

        default:
            SEC_LOG_ERROR("Unimplemented cipher algorithm");
            return SEC_RESULT_UNIMPLEMENTED_FEATURE;
    }

    return SEC_RESULT_SUCCESS;
}

/**
 * @brief Apply PKCS7 padding to the AES input block.
 *
 * @param inputBlock input data to pad.
 * @param inputSize size of input data.
 * @param outputBlock Output block.  Has to be the size of SEC_AES_BLOCKSIZE.
 */
void SecCipher_PadAESPKCS7Block(SEC_BYTE* inputBlock, SEC_SIZE inputSize, SEC_BYTE* outputBlock) {
    SEC_BYTE pad_val = (SEC_BYTE) (SEC_AES_BLOCK_SIZE - inputSize % SEC_AES_BLOCK_SIZE);
    memset(outputBlock, pad_val, SEC_AES_BLOCK_SIZE);
    memcpy(outputBlock, inputBlock, inputSize % SEC_AES_BLOCK_SIZE);
}

/**
 * @brief Checks whether the specified cipher algorithm is AES.
 */
SEC_BOOL SecCipher_IsAES(Sec_CipherAlgorithm alg) {
    return alg == SEC_CIPHERALGORITHM_AES_CBC_NO_PADDING || alg == SEC_CIPHERALGORITHM_AES_CBC_PKCS7_PADDING ||
           alg == SEC_CIPHERALGORITHM_AES_CTR || alg == SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING ||
           alg == SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING;
}

/**
 * @brief Checks whether the specified cipher algorithm is RSA.
 */
SEC_BOOL SecCipher_IsRsa(Sec_CipherAlgorithm alg) {
    return alg == SEC_CIPHERALGORITHM_RSA_OAEP_PADDING || alg == SEC_CIPHERALGORITHM_RSA_PKCS1_PADDING;
}

/**
 * @brief Checks whether the specified cipher algorithm is ECC.
 */
SEC_BOOL SecCipher_IsEcc(Sec_CipherAlgorithm alg) {
    return alg == SEC_CIPHERALGORITHM_ECC_ELGAMAL;
}

Sec_Result SecCipher_SingleInput(Sec_ProcessorHandle* processorHandle, Sec_CipherAlgorithm alg, Sec_CipherMode mode,
        Sec_KeyHandle* keyHandle, SEC_BYTE* iv, SEC_BYTE* input, SEC_SIZE input_len, SEC_BYTE* output,
        SEC_SIZE output_len, SEC_SIZE* written) {
    Sec_Result result;
    Sec_CipherHandle* cipherHandle = NULL;

    result = SecCipher_GetInstance(processorHandle, alg, mode, keyHandle, iv, &cipherHandle);
    if (result != SEC_RESULT_SUCCESS)
        return result;

    result = SecCipher_Process(cipherHandle, input, input_len, 1, output, output_len, written);
    SecCipher_Release(cipherHandle);
    return result;
}

Sec_Result SecCipher_SingleInputId(Sec_ProcessorHandle* processorHandle, Sec_CipherAlgorithm alg, Sec_CipherMode mode,
        SEC_OBJECTID key, SEC_BYTE* iv, SEC_BYTE* input, SEC_SIZE input_len, SEC_BYTE* output, SEC_SIZE output_len,
        SEC_SIZE* written) {
    Sec_Result result = SEC_RESULT_FAILURE;
    Sec_KeyHandle* keyHandle = NULL;

    if (SecKey_GetInstance(processorHandle, key, &keyHandle) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecKey_GetInstance failed");
        if (keyHandle != NULL)
            SecKey_Release(keyHandle);

        return result;
    }

    if (SecCipher_SingleInput(processorHandle, alg, mode, keyHandle, iv, input, input_len, output, output_len,
                written) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecCipher_SingleInput failed");
        if (keyHandle != NULL)
            SecKey_Release(keyHandle);

        return result;
    }

    if (keyHandle != NULL)
        SecKey_Release(keyHandle);

    return SEC_RESULT_SUCCESS;
}

SEC_BOOL SecCipher_IsPKCS7Padded(Sec_CipherAlgorithm alg) {
    return alg == SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING || alg == SEC_CIPHERALGORITHM_AES_CBC_PKCS7_PADDING;
}

SEC_BOOL SecCipher_IsDecrypt(Sec_CipherMode mode) {
    return mode == SEC_CIPHERMODE_DECRYPT || mode == SEC_CIPHERMODE_DECRYPT_NATIVEMEM;
}

Sec_Result SecCipher_ProcessOpaqueWithMap(Sec_CipherHandle* cipherHandle, SEC_BYTE* iv, SEC_BYTE* input,
        SEC_SIZE inputSize, SEC_BOOL lastInput, SEC_MAP* map, SEC_SIZE mapLength,
        Sec_OpaqueBufferHandle** opaqueBufferHandle, SEC_SIZE* bytesWritten) {

    if (cipherHandle == NULL) {
        SEC_LOG_ERROR("NULL cipherHandle");
        return SEC_RESULT_FAILURE;
    }

    if (iv == NULL) {
        SEC_LOG_ERROR("NULL iv");
        return SEC_RESULT_FAILURE;
    }

    if (input == NULL) {
        SEC_LOG_ERROR("NULL input");
        return SEC_RESULT_FAILURE;
    }

    if (map == NULL) {
        SEC_LOG_ERROR("NULL map");
        return SEC_RESULT_FAILURE;
    }

    if (opaqueBufferHandle == NULL) {
        SEC_LOG_ERROR("NULL outputHandle");
        return SEC_RESULT_FAILURE;
    }

    if (bytesWritten == NULL) {
        SEC_LOG_ERROR("NULL bytesWritten");
        return SEC_RESULT_FAILURE;
    }

    Sec_Result result = SecOpaqueBuffer_Malloc(inputSize, opaqueBufferHandle);
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecOpaqueBuffer_Malloc failed");
        return SEC_RESULT_FAILURE;
    }

    sa_subsample_length* subsample_lengths = malloc(mapLength * sizeof(sa_subsample_length));
    for (size_t i = 0; i < mapLength; i++) {
        subsample_lengths[i].bytes_of_clear_data = map[i].clear;
        subsample_lengths[i].bytes_of_protected_data = map[i].encrypted;
    }

    sa_buffer out_buffer;
    out_buffer.buffer_type = SA_BUFFER_TYPE_SVP;
    out_buffer.context.svp.offset = 0;
    out_buffer.context.svp.buffer = get_svp_buffer(cipherHandle->processorHandle, *opaqueBufferHandle);
    if (out_buffer.context.svp.buffer == INVALID_HANDLE) {
        free(subsample_lengths);
        SecOpaqueBuffer_Free(*opaqueBufferHandle);
        *opaqueBufferHandle = NULL;
        *bytesWritten = 0;
        return SEC_RESULT_FAILURE;
    }

    sa_buffer in_buffer;
    in_buffer.buffer_type = SA_BUFFER_TYPE_CLEAR;
    in_buffer.context.clear.buffer = input;
    in_buffer.context.clear.length = inputSize;
    in_buffer.context.clear.offset = 0;

    sa_sample sample;
    sample.iv = iv;
    sample.iv_length = SEC_AES_BLOCK_SIZE;
    sample.crypt_byte_block = 0;
    sample.skip_byte_block = 0;
    sample.subsample_count = mapLength;
    sample.subsample_lengths = subsample_lengths;
    sample.context = cipherHandle->cipher.context;
    sample.out = &out_buffer;
    sample.in = &in_buffer;

    sa_status status = sa_invoke(cipherHandle->processorHandle, SA_PROCESS_COMMON_ENCRYPTION, (size_t) 1, &sample);
    free(subsample_lengths);
    if (status != SA_STATUS_OK) {
        SecOpaqueBuffer_Free(*opaqueBufferHandle);
        *opaqueBufferHandle = NULL;
        *bytesWritten = 0;
        CHECK_STATUS(status)
    }

    *bytesWritten = out_buffer.context.svp.offset;
    return SEC_RESULT_SUCCESS;
}

Sec_Result get_cipher_algorithm(const Sec_CipherAlgorithm algorithm, SEC_BOOL is_unwrap,
        sa_cipher_algorithm* cipher_algorithm, void** parameters, void* iv, SEC_SIZE key_length, SEC_SIZE key_offset) {
    *parameters = NULL;
    switch (algorithm) {
        case SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING:
            *cipher_algorithm = SA_CIPHER_ALGORITHM_AES_ECB;
            return SEC_RESULT_SUCCESS;

        case SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING:
            *cipher_algorithm = SA_CIPHER_ALGORITHM_AES_ECB_PKCS7;
            return SEC_RESULT_SUCCESS;

        case SEC_CIPHERALGORITHM_AES_CBC_NO_PADDING:
            *cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
            if (is_unwrap) {
                *parameters = calloc(1, sizeof(sa_unwrap_parameters_aes_cbc));
                if (parameters == NULL)
                    return SEC_RESULT_FAILURE;

                ((sa_unwrap_parameters_aes_cbc*) *parameters)->iv = iv;
                ((sa_unwrap_parameters_aes_cbc*) *parameters)->iv_length = SEC_AES_BLOCK_SIZE;
            } else {
                *parameters = calloc(1, sizeof(sa_cipher_parameters_aes_cbc));
                if (parameters == NULL)
                    return SEC_RESULT_FAILURE;

                ((sa_cipher_parameters_aes_cbc*) *parameters)->iv = iv;
                ((sa_cipher_parameters_aes_cbc*) *parameters)->iv_length = SEC_AES_BLOCK_SIZE;
            }

            return SEC_RESULT_SUCCESS;

        case SEC_CIPHERALGORITHM_AES_CBC_PKCS7_PADDING:
            *cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC_PKCS7;
            if (is_unwrap) {
                *parameters = calloc(1, sizeof(sa_unwrap_parameters_aes_cbc));
                if (parameters == NULL)
                    return SEC_RESULT_FAILURE;

                ((sa_unwrap_parameters_aes_cbc*) *parameters)->iv = iv;
                ((sa_unwrap_parameters_aes_cbc*) *parameters)->iv_length = SEC_AES_BLOCK_SIZE;
            } else {
                *parameters = calloc(1, sizeof(sa_cipher_parameters_aes_cbc));
                if (parameters == NULL)
                    return SEC_RESULT_FAILURE;

                ((sa_cipher_parameters_aes_cbc*) *parameters)->iv = iv;
                ((sa_cipher_parameters_aes_cbc*) *parameters)->iv_length = SEC_AES_BLOCK_SIZE;
            }

            return SEC_RESULT_SUCCESS;

        case SEC_CIPHERALGORITHM_AES_CTR:
            *cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CTR;
            if (is_unwrap) {
                *parameters = calloc(1, sizeof(sa_unwrap_parameters_aes_ctr));
                if (parameters == NULL)
                    return SEC_RESULT_FAILURE;

                ((sa_unwrap_parameters_aes_ctr*) *parameters)->ctr = iv;
                ((sa_unwrap_parameters_aes_ctr*) *parameters)->ctr_length = SEC_AES_BLOCK_SIZE;
            } else {
                *parameters = calloc(1, sizeof(sa_cipher_parameters_aes_ctr));
                if (parameters == NULL)
                    return SEC_RESULT_FAILURE;

                ((sa_cipher_parameters_aes_ctr*) *parameters)->ctr = iv;
                ((sa_cipher_parameters_aes_ctr*) *parameters)->ctr_length = SEC_AES_BLOCK_SIZE;
            }

            return SEC_RESULT_SUCCESS;

        case SEC_CIPHERALGORITHM_RSA_PKCS1_PADDING:
            *cipher_algorithm = SA_CIPHER_ALGORITHM_RSA_PKCS1V15;
            return SEC_RESULT_SUCCESS;

        case SEC_CIPHERALGORITHM_RSA_OAEP_PADDING:
            *cipher_algorithm = SA_CIPHER_ALGORITHM_RSA_OAEP;
            if (is_unwrap) {
                *parameters = calloc(1, sizeof(sa_unwrap_parameters_rsa_oaep));
                if (parameters == NULL)
                    return SEC_RESULT_FAILURE;

                ((sa_unwrap_parameters_rsa_oaep*) *parameters)->digest_algorithm = SA_DIGEST_ALGORITHM_SHA1;
                ((sa_unwrap_parameters_rsa_oaep*) *parameters)->mgf1_digest_algorithm = SA_DIGEST_ALGORITHM_SHA1;
                ((sa_unwrap_parameters_rsa_oaep*) *parameters)->label = NULL;
                ((sa_unwrap_parameters_rsa_oaep*) *parameters)->label_length = 0;
            } else {
                *parameters = calloc(1, sizeof(sa_cipher_parameters_rsa_oaep));
                if (parameters == NULL)
                    return SEC_RESULT_FAILURE;

                ((sa_cipher_parameters_rsa_oaep*) *parameters)->digest_algorithm = SA_DIGEST_ALGORITHM_SHA1;
                ((sa_cipher_parameters_rsa_oaep*) *parameters)->mgf1_digest_algorithm = SA_DIGEST_ALGORITHM_SHA1;
                ((sa_cipher_parameters_rsa_oaep*) *parameters)->label = NULL;
                ((sa_cipher_parameters_rsa_oaep*) *parameters)->label_length = 0;
            }

            return SEC_RESULT_SUCCESS;

        case SEC_CIPHERALGORITHM_ECC_ELGAMAL:
            *cipher_algorithm = SA_CIPHER_ALGORITHM_EC_ELGAMAL;
            if (is_unwrap) {
                *parameters = calloc(1, sizeof(sa_unwrap_parameters_ec_elgamal));
                if (parameters == NULL)
                    return SEC_RESULT_FAILURE;

                ((sa_unwrap_parameters_ec_elgamal*) *parameters)->key_length = key_length;
                ((sa_unwrap_parameters_ec_elgamal*) *parameters)->offset = key_offset;
            }
            return SEC_RESULT_SUCCESS;

        default:
            return SEC_RESULT_INVALID_PARAMETERS;
    }
}

static sa_cipher_mode get_cipher_mode(Sec_CipherMode mode) {
    switch (mode) {
        case SEC_CIPHERMODE_ENCRYPT:
        case SEC_CIPHERMODE_ENCRYPT_NATIVEMEM:
            return SA_CIPHER_MODE_ENCRYPT;

        case SEC_CIPHERMODE_DECRYPT:
        case SEC_CIPHERMODE_DECRYPT_NATIVEMEM:
            return SA_CIPHER_MODE_DECRYPT;

        default:
            return SA_CIPHER_MODE_ENCRYPT;
    }
}

static SEC_BOOL rsa_encrypt_pkcs1v15(void* out, size_t* out_length, const RSA* rsa, const void* in, size_t in_length) {
    if (!out) {
        SEC_LOG_ERROR("NULL out");
        return SEC_FALSE;
    }

    if (!out_length) {
        SEC_LOG_ERROR("NULL out_length");
        return SEC_FALSE;
    }

    if (!rsa) {
        SEC_LOG_ERROR("NULL rsa");
        return SEC_FALSE;
    }

    if (!in) {
        SEC_LOG_ERROR("NULL in");
        return SEC_FALSE;
    }

    if (*out_length < (size_t) RSA_size(rsa)) {
        SEC_LOG_ERROR("Bad out_length");
        return SEC_FALSE;
    }

    if (in_length >= (size_t) RSA_size(rsa) - RSA_PKCS1_PADDING_SIZE) {
        SEC_LOG_ERROR("Bad in_length");
        return SEC_FALSE;
    }

    int length = RSA_public_encrypt((int) in_length, in, out, (RSA*) rsa, RSA_PKCS1_PADDING);
    if (length < 0) {
        SEC_LOG_ERROR("RSA_public_encrypt failed");
        return SEC_FALSE;
    }
    *out_length = length;

    return SEC_TRUE;
}

static SEC_BOOL rsa_encrypt_oaep(void* out, size_t* out_length, const RSA* rsa, const void* in, size_t in_length) {
    if (!out) {
        SEC_LOG_ERROR("NULL out");
        return SEC_FALSE;
    }

    if (!out_length) {
        SEC_LOG_ERROR("NULL out_length");
        return SEC_FALSE;
    }

    if (!rsa) {
        SEC_LOG_ERROR("NULL rsa");
        return SEC_FALSE;
    }

    if (!in) {
        SEC_LOG_ERROR("NULL in");
        return SEC_FALSE;
    }

    if (*out_length < (size_t) RSA_size(rsa)) {
        SEC_LOG_ERROR("Bad out_length");
        return SEC_FALSE;
    }

    if (in_length >= (size_t) RSA_size(rsa) - RSA_OAEP_PADDING_SIZE) {
        SEC_LOG_ERROR("Bad in_length");
        return SEC_FALSE;
    }

    int length = RSA_public_encrypt((int) in_length, in, out, (RSA*) rsa, RSA_PKCS1_OAEP_PADDING);
    if (length < 0) {
        SEC_LOG_ERROR("RSA_private_decrypt failed");
        return SEC_FALSE;
    }

    *out_length = length;
    return SEC_TRUE;
}

static SEC_BOOL is_svp_required(Sec_KeyProperties* props) {
    for (int i = 0; i < SEC_KEYOUTPUTRIGHT_NUM; ++i) {
        if (props->rights[i] == SEC_KEYOUTPUTRIGHT_SVP_REQUIRED) {
            return SEC_TRUE;
        }
    }

    return SEC_FALSE;
}
