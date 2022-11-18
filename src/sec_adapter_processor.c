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

#include "sec_adapter_processor.h" // NOLINT
#include "sa.h"

struct Sec_ProcessorInitParams_struct {
};

static Sec_Result Sec_SetStorageDir(const char* provided_dir, const char* default_dir, char* output_dir);

static void* sa_invoke_handler(void* processorHandle);

/**
 * @brief Initialize secure processor.
 *
 * Initializes the secure processor, generates key derivation base key,
 * sets up all required resources.  Only one secure processor can be
 * active at a time.
 *
 * @param processorHandle pointer to a processor handle that will be set to
 * a constructed handle.
 * @param socInitParams pointer to initialization information for the secure
 * processor.  This structure is implementation specific.
 *
 * @return The status of the operation.
 */
Sec_Result SecProcessor_GetInstance(Sec_ProcessorHandle** processorHandle,
        Sec_ProcessorInitParams* socInitParams) {
    return SecProcessor_GetInstance_Directories(processorHandle, SEC_GLOBAL_DIR_DEFAULT, SEC_GLOBAL_DIR_DEFAULT);
}

/**
 * @brief Initialize secure processor.
 *
 * Initializes the secure processor, generates key derivation base key,
 * sets up all required resources.  Only one secure processor can be
 * active at a time.
 *
 * @param processorHandle pointer to a processor handle that will be set to
 * a constructed handle.
 * @param globalDir path to the read only object directory.  Can be set to NULL.
 * @param appDir path to the read/write object directory.  Can be set to NULL.
 *
 * @return The status of the operation.
 */
Sec_Result SecProcessor_GetInstance_Directories(Sec_ProcessorHandle** processorHandle, const char* globalDir,
        const char* appDir) {
    Sec_Result result;
    SecAdapter_DerivedInputs derived_inputs;
    SecUtils_KeyStoreHeader keystore_header;
    SEC_BYTE store[SEC_KEYCONTAINER_MAX_LEN];

    if (processorHandle == NULL) {
        SEC_LOG_ERROR("proc_handle is NULL");
        return SEC_RESULT_FAILURE;
    }

    char* tempAppDir = (char*) calloc(1, SEC_MAX_FILE_PATH_LEN);
    if (tempAppDir == NULL) {
        SEC_LOG_ERROR("Calloc failed");
        return SEC_RESULT_FAILURE;
    }

    result = Sec_SetStorageDir(appDir, SEC_APP_DIR_DEFAULT, tempAppDir);
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("Error creating appDir");
        SEC_FREE(tempAppDir);
        return result;
    }

    char* tempGlobalDir = (char*) calloc(1, SEC_MAX_FILE_PATH_LEN);
    if (tempGlobalDir == NULL) {
        SEC_LOG_ERROR("Calloc failed");
        SEC_FREE(tempAppDir);
        return SEC_RESULT_FAILURE;
    }

    result = Sec_SetStorageDir(globalDir, SEC_GLOBAL_DIR_DEFAULT, tempGlobalDir);
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("Error creating globalDir");
        SEC_FREE(tempAppDir);
        SEC_FREE(tempGlobalDir);
        return result;
    }

    /* create handle */
    *processorHandle = calloc(1, sizeof(Sec_ProcessorHandle));
    if (*processorHandle == NULL) {
        SEC_LOG_ERROR("Calloc failed");
        SEC_FREE(tempAppDir);
        SEC_FREE(tempGlobalDir);
        return SEC_RESULT_FAILURE;
    }

    /* setup key and cert directories */
    (*processorHandle)->app_dir = tempAppDir;
    result = SecUtils_MkDir((*processorHandle)->app_dir);
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("Error creating app_dir");
        SEC_FREE((*processorHandle)->app_dir);
        SEC_FREE(tempGlobalDir);
        SEC_FREE(*processorHandle);
        return result;
    }

    (*processorHandle)->global_dir = tempGlobalDir;
    result = SecUtils_MkDir((*processorHandle)->global_dir);
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("Error creating app_dir");
        SEC_FREE((*processorHandle)->app_dir);
        SEC_FREE((*processorHandle)->global_dir);
        SEC_FREE(*processorHandle);
        return result;
    }

    if (pthread_mutex_init(&(*processorHandle)->mutex, NULL) != 0) {
        SEC_LOG_ERROR("Error creating app_dir");
        SEC_FREE((*processorHandle)->app_dir);
        SEC_FREE((*processorHandle)->global_dir);
        SEC_FREE(*processorHandle);
        return SEC_RESULT_FAILURE;
    }

    if (pthread_cond_init(&(*processorHandle)->cond, NULL) != 0) {
        SEC_LOG_ERROR("Error creating app_dir");
        pthread_mutex_destroy(&(*processorHandle)->mutex);
        SEC_FREE((*processorHandle)->app_dir);
        SEC_FREE((*processorHandle)->global_dir);
        SEC_FREE(*processorHandle);
        return SEC_RESULT_FAILURE;
    }

    if (pthread_create(&(*processorHandle)->thread, NULL, sa_invoke_handler, *processorHandle) != 0) {
        SEC_LOG_ERROR("Error creating app_dir");
        pthread_mutex_destroy(&(*processorHandle)->mutex);
        pthread_cond_destroy(&(*processorHandle)->cond);
        SEC_FREE((*processorHandle)->app_dir);
        SEC_FREE((*processorHandle)->global_dir);
        SEC_FREE(*processorHandle);
        return SEC_RESULT_FAILURE;
    }

    /* generate sec store proc ins */
    result = SecStore_GenerateLadderInputs(*processorHandle, SEC_STORE_AES_LADDER_INPUT, NULL,
            (SEC_BYTE*) &derived_inputs, sizeof(derived_inputs));
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("Error Generating LadderInputs");
        SecProcessor_Release((*processorHandle));
        return result;
    }

    result = SecUtils_FillKeyStoreUserHeader(*processorHandle, &keystore_header, SEC_KEYCONTAINER_SOC_INTERNAL_0);
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("Error Filling KeyStoreUserHeader");
        SecProcessor_Release((*processorHandle));
        return result;
    }

    result = SecStore_StoreData(*processorHandle, SEC_FALSE, SEC_FALSE, (SEC_BYTE*) SEC_UTILS_KEYSTORE_MAGIC,
            &keystore_header, sizeof(keystore_header), &derived_inputs, sizeof(derived_inputs), store, sizeof(store));
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("Error storing derived_inputs");
        SecProcessor_Release((*processorHandle));
        return result;
    }

    result = SecKey_Provision(*processorHandle, SEC_OBJECTID_STORE_AES_KEY, SEC_STORAGELOC_RAM_SOFT_WRAPPED,
            SEC_KEYCONTAINER_STORE, store, SecStore_GetStoreLen(store));
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("Error creating SEC_OBJECTID_STORE_AES_KEY");
        SecProcessor_Release((*processorHandle));
        return result;
    }

    result = SecStore_GenerateLadderInputs(*processorHandle, SEC_STORE_MAC_LADDER_INPUT, NULL,
            (SEC_BYTE*) &derived_inputs, sizeof(derived_inputs));
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("Error creating SEC_STORE_MAC_LADDER_INPUT");
        SecProcessor_Release((*processorHandle));
        return result;
    }

    result = SecUtils_FillKeyStoreUserHeader(*processorHandle, &keystore_header, SEC_KEYCONTAINER_SOC_INTERNAL_0);
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("Error creating keystore_header");
        SecProcessor_Release((*processorHandle));
        return result;
    }

    result = SecStore_StoreData(*processorHandle, SEC_FALSE, SEC_FALSE, (SEC_BYTE*) SEC_UTILS_KEYSTORE_MAGIC,
            &keystore_header, sizeof(keystore_header), &derived_inputs, sizeof(derived_inputs), store, sizeof(store));
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("Error creating sec_store");
        SecProcessor_Release((*processorHandle));
        return result;
    }

    result = SecKey_Provision(*processorHandle, SEC_OBJECTID_STORE_MACKEYGEN_KEY, SEC_STORAGELOC_RAM_SOFT_WRAPPED,
            SEC_KEYCONTAINER_STORE, store, SecStore_GetStoreLen(store));
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("Error creating SEC_OBJECTID_STORE_MACKEYGEN_KEY");
        SecProcessor_Release((*processorHandle));
        return result;
    }

    // generate certificate mac key
    const char* otherInfo = "certMacKeyhmacSha256concatKdfSha1";
    const char* nonce = "abcdefghijklmnopqr\0";
    result = SecKey_Derive_ConcatKDF(*processorHandle, SEC_OBJECTID_CERTSTORE_KEY, SEC_KEYTYPE_HMAC_256,
            SEC_STORAGELOC_RAM, SEC_DIGESTALGORITHM_SHA256, (SEC_BYTE*) nonce, (SEC_BYTE*) otherInfo,
            strlen(otherInfo));
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("Error creating certificate mac key");
        SecProcessor_Release((*processorHandle));
        return result;
    }

    return SEC_RESULT_SUCCESS;
}

/**
 * @brief Get the minimum depth of the hardware key ladder.
 *
 * @param handle pointer to a handle.
 * @param root root key type.
 *
 * @return The key ladder depth.
 */
SEC_SIZE SecProcessor_GetKeyLadderMinDepth(Sec_ProcessorHandle* processorHandle, Sec_KeyLadderRoot root) {
    return SECAPI3_KEY_DEPTH;
}

/**
 * @brief Get the maximum depth of the hardware key ladder.
 *
 * @param handle pointer to a handle.
 * @param root root key type.
 *
 * @return The key ladder depth.
 */
SEC_SIZE SecProcessor_GetKeyLadderMaxDepth(Sec_ProcessorHandle* processorHandle, Sec_KeyLadderRoot root) {
    return SECAPI3_KEY_DEPTH;
}

/**
 * @brief Prints SOC specific version info.
 *
 * @param processorHandle secure processor handle.
 */
Sec_Result SecProcessor_PrintInfo(Sec_ProcessorHandle* processorHandle) {
    CHECK_PROCHANDLE(processorHandle)

    SEC_BYTE deviceId[SEC_DEVICEID_LEN];
    if (SecProcessor_GetDeviceId(processorHandle, deviceId) == SEC_RESULT_SUCCESS)
        SEC_PRINT("device id: " SEC_OBJECTID_PATTERN "\n", Sec_BEBytesToUint64(deviceId));
    else
        SEC_PRINT("device id: unknown\n");

    SEC_PRINT("platform: SEC_API_2_ADAPTER\n");
    SEC_PRINT("version: %s\n", SEC_API_VERSION);

    SEC_PRINT("app_dir: %s\n", processorHandle->app_dir);
    SEC_PRINT("global_dir: %s\n", processorHandle->global_dir);
    Sec_PrintOpenSSLVersion();

    sa_version version;
    sa_status status = sa_invoke(processorHandle, SA_GET_VERSION, &version);
    CHECK_STATUS(status)

    SEC_PRINT("specification_major: %ld, specification_minor: %ld, "
              "specification_revision: %ld, implementation_revision: %ld\n",
            version.specification_major, version.specification_minor,
            version.specification_revision, version.implementation_revision);

    Sec_PrintOpenSSLVersion();
    return SEC_RESULT_SUCCESS;
}

/**
 * @brief Get the Security Processor information (SecAPI version and build
 * information).
 *
 * @param processorHandle secure processor handle.
 * @param pointer to secure processor information.
 */
Sec_Result SecProcessor_GetInfo(Sec_ProcessorHandle* processorHandle, Sec_ProcessorInfo* secProcInfo) {
    CHECK_PROCHANDLE(processorHandle)

    if (secProcInfo == NULL)
        return SEC_RESULT_INVALID_PARAMETERS;

    memcpy(secProcInfo->version, SEC_API_VERSION, sizeof(SEC_API_VERSION));

    return SEC_RESULT_SUCCESS;
}

/**
 * @brief Obtain the device id.
 *
 * @param processorHandle secure processor handle.
 * @param deviceId pointer to a buffer that is SEC_DEVICEID_LEN long.  The
 * buffer will be filled with a device id.
 *
 * @return The status of the operation.
 */
Sec_Result SecProcessor_GetDeviceId(Sec_ProcessorHandle* processorHandle, SEC_BYTE* deviceId) {
    CHECK_PROCHANDLE(processorHandle)

    if (deviceId == NULL)
        return SEC_RESULT_INVALID_PARAMETERS;

    uint64_t sa3_device_id;
    sa_status status = sa_invoke(processorHandle, SA_GET_DEVICE_ID, &sa3_device_id);
    CHECK_STATUS(status)

    Sec_Uint64ToBEBytes(sa3_device_id, deviceId);
    return SEC_RESULT_SUCCESS;
}

/**
 * @brief Release the security processor.
 *
 * @param processorHandle secure processor handle.
 *
 * @return The status of the operation.
 */
Sec_Result SecProcessor_Release(Sec_ProcessorHandle* processorHandle) {
    if (processorHandle == NULL)
        return SEC_RESULT_INVALID_HANDLE;

    pthread_mutex_lock(&processorHandle->mutex);
    processorHandle->shutdown = true;
    pthread_cond_broadcast(&processorHandle->cond);
    pthread_mutex_unlock(&processorHandle->mutex);

    void* thread_return = NULL;
    pthread_join(processorHandle->thread, &thread_return);
    pthread_cond_destroy(&processorHandle->cond);
    pthread_mutex_destroy(&processorHandle->mutex);

    /* release ram keys */
    while (processorHandle->ram_keys != NULL)
        SecKey_Delete(processorHandle, processorHandle->ram_keys->object_id);

    /* release ram bundles */
    while (processorHandle->ram_bundles != NULL)
        SecBundle_Delete(processorHandle, processorHandle->ram_bundles->object_id);

    /* release ram certs */
    while (processorHandle->ram_certs != NULL)
        SecCertificate_Delete(processorHandle, processorHandle->ram_certs->object_id);

    SEC_FREE(processorHandle->app_dir);
    SEC_FREE(processorHandle->global_dir);
    free(processorHandle);
    return SEC_RESULT_SUCCESS;
}

/**
 * This was done for legacy BRCM HW which would get a performance boost if used with special pool of memory for AES
 * cipher.  For SecApi3, I would just map this to malloc.
 * --Davor
 */
SEC_BYTE* Sec_NativeMalloc(Sec_ProcessorHandle* processorHandle, SEC_SIZE length) {
    if (processorHandle == NULL)
        return NULL;

    return malloc(length);
}

/**
 * This was done for legacy BRCM HW which would get a performance boost if used with special pool of memory for AES
 * cipher.  For SecApi3, I would just map this to malloc.
 * --Davor
 */
void Sec_NativeFree(Sec_ProcessorHandle* processorHandle, void* ptr) {
    if (processorHandle == NULL)
        return;

    free(ptr);
}

Sec_Result Sec_SetStorageDir(const char* provided_dir, const char* default_dir, char* output_dir) {
    const char* dir_to_use;
    size_t len;

    if (provided_dir == NULL || strlen(provided_dir) == 0) {
        if (default_dir == NULL || strlen(default_dir) == 0)
            return SEC_RESULT_FAILURE;

        dir_to_use = default_dir;
    } else
        dir_to_use = provided_dir;

    len = strlen(dir_to_use);
    if (len >= (SEC_MAX_FILE_PATH_LEN - 2)) {
        SEC_LOG_ERROR("Directory name length is too long");
        return SEC_RESULT_FAILURE;
    }

    snprintf(output_dir, SEC_MAX_FILE_PATH_LEN, "%s", dir_to_use);

    if (output_dir[len - 1] != '/' && output_dir[len - 1] != '\\') {
        output_dir[len] = '/';
        output_dir[len + 1] = '\0';
    }

    return SEC_RESULT_SUCCESS;
}

void sa_process_command(sa_command* command) {
    switch (command->command_id) {
        case SA_GET_VERSION:
            command->result = sa_get_version(va_arg(*command->arguments, sa_version*));
            break;

        case SA_GET_DEVICE_ID:
            command->result = sa_get_device_id(va_arg(*command->arguments, uint64_t*));
            break;

        case SA_KEY_GENERATE:
            command->result = sa_key_generate(va_arg(*command->arguments, sa_key*),
                    va_arg(*command->arguments, sa_rights*), va_arg(*command->arguments, sa_key_type),
                    va_arg(*command->arguments, void*));
            break;

        case SA_KEY_EXPORT:
            command->result = sa_key_export(va_arg(*command->arguments, void*), va_arg(*command->arguments, size_t*),
                    va_arg(*command->arguments, void*), va_arg(*command->arguments, size_t),
                    va_arg(*command->arguments, sa_key));
            break;

        case SA_KEY_IMPORT:
            command->result = sa_key_import(va_arg(*command->arguments, sa_key*),
                    va_arg(*command->arguments, sa_key_format), va_arg(*command->arguments, void*),
                    va_arg(*command->arguments, size_t), va_arg(*command->arguments, void*));
            break;

        case SA_KEY_UNWRAP:
            command->result = sa_key_unwrap(va_arg(*command->arguments, sa_key*),
                    va_arg(*command->arguments, sa_rights*), va_arg(*command->arguments, sa_key_type),
                    va_arg(*command->arguments, void*), va_arg(*command->arguments, sa_cipher_algorithm),
                    va_arg(*command->arguments, void*), va_arg(*command->arguments, sa_key),
                    va_arg(*command->arguments, void*), va_arg(*command->arguments, size_t));
            break;

        case SA_KEY_GET_PUBLIC:
            command->result = sa_key_get_public(va_arg(*command->arguments, void*),
                    va_arg(*command->arguments, size_t*), va_arg(*command->arguments, sa_key));
            break;

        case SA_KEY_DERIVE:
            command->result = sa_key_derive(va_arg(*command->arguments, sa_key*),
                    va_arg(*command->arguments, sa_rights*), va_arg(*command->arguments, sa_kdf_algorithm),
                    va_arg(*command->arguments, void*));
            break;

        case SA_KEY_EXCHANGE:
            command->result = sa_key_exchange(va_arg(*command->arguments, sa_key*),
                    va_arg(*command->arguments, sa_rights*), va_arg(*command->arguments, sa_key_exchange_algorithm),
                    va_arg(*command->arguments, sa_key), va_arg(*command->arguments, void*),
                    va_arg(*command->arguments, size_t), va_arg(*command->arguments, void*));
            break;

        case SA_KEY_RELEASE:
            command->result = sa_key_release(va_arg(*command->arguments, sa_key));
            break;

        case SA_KEY_HEADER:
            command->result = sa_key_header(va_arg(*command->arguments, sa_header*),
                    va_arg(*command->arguments, sa_key));
            break;

        case SA_KEY_DIGEST:
            command->result = sa_key_digest(va_arg(*command->arguments, void*), va_arg(*command->arguments, size_t*),
                    va_arg(*command->arguments, sa_key), va_arg(*command->arguments, sa_digest_algorithm));
            break;

        case SA_CRYPTO_RANDOM:
            command->result = sa_crypto_random(va_arg(*command->arguments, void*), va_arg(*command->arguments, size_t));
            break;

        case SA_CRYPTO_CIPHER_INIT:
            command->result = sa_crypto_cipher_init(va_arg(*command->arguments, sa_crypto_cipher_context*),
                    va_arg(*command->arguments, sa_cipher_algorithm), va_arg(*command->arguments, sa_cipher_mode),
                    va_arg(*command->arguments, sa_key), va_arg(*command->arguments, void*));
            break;

        case SA_CRYPTO_CIPHER_UPDATE_IV:
            command->result = sa_crypto_cipher_update_iv(va_arg(*command->arguments, sa_crypto_cipher_context),
                    va_arg(*command->arguments, void*), va_arg(*command->arguments, size_t));
            break;

        case SA_CRYPTO_CIPHER_PROCESS:
            command->result = sa_crypto_cipher_process(va_arg(*command->arguments, sa_buffer*),
                    va_arg(*command->arguments, sa_crypto_cipher_context), va_arg(*command->arguments, sa_buffer*),
                    va_arg(*command->arguments, size_t*));
            break;

        case SA_CRYPTO_CIPHER_PROCESS_LAST:
            command->result = sa_crypto_cipher_process_last(va_arg(*command->arguments, sa_buffer*),
                    va_arg(*command->arguments, sa_crypto_cipher_context), va_arg(*command->arguments, sa_buffer*),
                    va_arg(*command->arguments, size_t*), va_arg(*command->arguments, void*));
            break;

        case SA_CRYPTO_CIPHER_RELEASE:
            command->result = sa_crypto_cipher_release(va_arg(*command->arguments, sa_crypto_cipher_context));
            break;

        case SA_CRYPTO_MAC_INIT:
            command->result = sa_crypto_mac_init(va_arg(*command->arguments, sa_crypto_mac_context*),
                    va_arg(*command->arguments, sa_mac_algorithm), va_arg(*command->arguments, sa_key),
                    va_arg(*command->arguments, void*));
            break;

        case SA_CRYPTO_MAC_PROCESS:
            command->result = sa_crypto_mac_process(va_arg(*command->arguments, sa_crypto_mac_context),
                    va_arg(*command->arguments, void*), va_arg(*command->arguments, size_t));
            break;

        case SA_CRYPTO_MAC_PROCESS_KEY:
            command->result = sa_crypto_mac_process_key(va_arg(*command->arguments, sa_crypto_mac_context),
                    va_arg(*command->arguments, sa_key));
            break;

        case SA_CRYPTO_MAC_COMPUTE:
            command->result = sa_crypto_mac_compute(va_arg(*command->arguments, void*),
                    va_arg(*command->arguments, size_t*), va_arg(*command->arguments, sa_crypto_mac_context));
            break;

        case SA_CRYPTO_MAC_RELEASE:
            command->result = sa_crypto_mac_release(va_arg(*command->arguments, sa_crypto_mac_context));
            break;

        case SA_CRYPTO_SIGN:
            command->result = sa_crypto_sign(va_arg(*command->arguments, void*), va_arg(*command->arguments, size_t*),
                    va_arg(*command->arguments, sa_signature_algorithm), va_arg(*command->arguments, sa_key),
                    va_arg(*command->arguments, void*), va_arg(*command->arguments, size_t),
                    va_arg(*command->arguments, void*));
            break;

        case SA_SVP_SUPPORTED:
            command->result = sa_svp_supported();
            break;

        case SA_SVP_BUFFER_CREATE:
            command->result = sa_svp_buffer_create(va_arg(*command->arguments, sa_svp_buffer*),
                    va_arg(*command->arguments, void*), va_arg(*command->arguments, size_t));
            break;

        case SA_SVP_BUFFER_FREE:
            command->result = sa_svp_buffer_free(va_arg(*command->arguments, sa_svp_buffer));
            break;

        case SA_SVP_BUFFER_RELEASE:
            command->result = sa_svp_buffer_release(va_arg(*command->arguments, void**),
                    va_arg(*command->arguments, size_t*), va_arg(*command->arguments, sa_svp_buffer));
            break;

        case SA_SVP_BUFFER_WRITE:
            command->result = sa_svp_buffer_write(va_arg(*command->arguments, sa_svp_buffer),
                    va_arg(*command->arguments, void*), va_arg(*command->arguments, size_t),
                    va_arg(*command->arguments, sa_svp_offset*), va_arg(*command->arguments, size_t));
            break;

        case SA_SVP_BUFFER_COPY:
            command->result = sa_svp_buffer_copy(va_arg(*command->arguments, sa_svp_buffer),
                    va_arg(*command->arguments, sa_svp_buffer), va_arg(*command->arguments, sa_svp_offset*),
                    va_arg(*command->arguments, size_t));
            break;

        case SA_SVP_KEY_CHECK:
            command->result = sa_svp_key_check(va_arg(*command->arguments, sa_key),
                    va_arg(*command->arguments, sa_buffer*), va_arg(*command->arguments, size_t),
                    va_arg(*command->arguments, void*), va_arg(*command->arguments, size_t));
            break;

        case SA_SVP_BUFFER_CHECK:
            command->result = sa_svp_buffer_check(va_arg(*command->arguments, sa_svp_buffer),
                    va_arg(*command->arguments, size_t), va_arg(*command->arguments, size_t),
                    va_arg(*command->arguments, sa_digest_algorithm), va_arg(*command->arguments, void*),
                    va_arg(*command->arguments, size_t));
            break;

        case SA_PROCESS_COMMON_ENCRYPTION:
            command->result = sa_process_common_encryption(va_arg(*command->arguments, size_t),
                    va_arg(*command->arguments, sa_sample*));
            break;

        case SA_GET_NAME:
        case SA_SVP_BUFFER_ALLOC:
            // Unused
        default:
            command->result = SA_STATUS_INTERNAL_ERROR;
    }
}

sa_status sa_invoke(Sec_ProcessorHandle* processorHandle, SA_COMMAND_ID command_id, ...) {
    if (processorHandle == NULL)
        return SA_STATUS_INVALID_PARAMETER;

    va_list va_args;
    va_start(va_args, command_id);
    sa_command command = {command_id, &va_args, -1};

    bool command_sent = false;
    pthread_mutex_lock(&processorHandle->mutex);
    while (!processorHandle->shutdown && command.result == -1 && !command_sent) {
        if (processorHandle->queue_size < MAX_QUEUE_SIZE) {
            processorHandle->queue[(processorHandle->queue_front + processorHandle->queue_size) % MAX_QUEUE_SIZE] =
                    &command;
            processorHandle->queue_size++;
            pthread_cond_broadcast(&processorHandle->cond);
            command_sent = true;
        }

        pthread_cond_wait(&processorHandle->cond, &processorHandle->mutex);
    }

    va_end(va_args);
    pthread_mutex_unlock(&processorHandle->mutex);
    return command.result;
}

void* sa_invoke_handler(void* handle) {
    if (handle == NULL)
        return (void*) SEC_RESULT_INVALID_HANDLE; // NOLINT

    sa_command* command = NULL;
    Sec_ProcessorHandle* processorHandle = (Sec_ProcessorHandle*) handle;
    while (!processorHandle->shutdown) {
        pthread_mutex_lock(&processorHandle->mutex);
        if (processorHandle->queue_size > 0) {
            command = processorHandle->queue[processorHandle->queue_front];
            processorHandle->queue_front = processorHandle->queue_front++ % MAX_QUEUE_SIZE;
            processorHandle->queue_size--;
        }

        if (command != NULL) {
            pthread_mutex_unlock(&processorHandle->mutex);
            sa_process_command(command);
            command = NULL;
            pthread_mutex_lock(&processorHandle->mutex);
            pthread_cond_broadcast(&processorHandle->cond);
        }

        pthread_cond_wait(&processorHandle->cond, &processorHandle->mutex);
        pthread_mutex_unlock(&processorHandle->mutex);
    }

    return (void*) SEC_RESULT_SUCCESS;
}
