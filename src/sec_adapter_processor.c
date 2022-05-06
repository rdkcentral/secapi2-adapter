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

#include "sec_adapter_processor.h"

// Processor handles are stored in the threadlocal proc_handle. Every time SecProcessor_GetInstance_Directories is
// called, proc_handle will be searched for a Sec_ProcessorHandle with the same globalDir and appDir. If an existing
// Sec_ProcessorHandle is found, it is returned. If not, a new one is created and stored in proc_handle. All will be
// destroyed when the thread or the application shuts down. At most 25 unique Sec_ProcessorHandles can be created per
// thread. 25 was chosen because it is believed that this is more than enough to handle current applications. It
// can be increase if this is not enough.
#define MAX_PROC_HANDLES 25

struct Sec_ProcessorInitParams_struct {
};

static SEC_BOOL initialized = SEC_FALSE;
static _Thread_local Sec_ProcessorHandle* processorHandles[MAX_PROC_HANDLES];
static pthread_key_t key;
static pthread_once_t key_once = PTHREAD_ONCE_INIT;

static void make_key();

static void release_proc_handle(void* handle);

static void proc_shutdown();

static Sec_Result Sec_SetStorageDir(const char* provided_dir, const char* default_dir, char* output_dir);

static void thread_shutdown(void* unused);

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

    if (pthread_once(&key_once, make_key) != 0)
        return SEC_RESULT_FAILURE;

    if (processorHandle == NULL) {
        SEC_LOG_ERROR("proc_handle is NULL");
        return SEC_RESULT_FAILURE;
    }

    size_t free_proc_handle = MAX_PROC_HANDLES;
    for (size_t i = 0; i < MAX_PROC_HANDLES; i++) {
        const char* temp_app_dir = appDir == NULL ? SEC_APP_DIR_DEFAULT : appDir;
        const char* temp_global_dir = globalDir == NULL ? SEC_GLOBAL_DIR_DEFAULT : globalDir;
        if (processorHandles[i] != NULL) {
            if (memcmp(processorHandles[i]->global_dir, temp_global_dir, strlen(temp_global_dir)) == 0 &&
                    memcmp(processorHandles[i]->app_dir, temp_app_dir, strlen(temp_app_dir)) == 0) {
                *processorHandle = processorHandles[i];
                return SEC_RESULT_SUCCESS;
            }
        } else {
            free_proc_handle = i;
            break;
        }
    }

    if (free_proc_handle == MAX_PROC_HANDLES) {
        SEC_LOG_ERROR("No free proc handles");
        return SEC_RESULT_FAILURE;
    }

    /* create handle */
    *processorHandle = calloc(1, sizeof(Sec_ProcessorHandle));
    if (*processorHandle == NULL) {
        SEC_LOG_ERROR("Calloc failed");
        return SEC_RESULT_FAILURE;
    }

    /* setup key and cert directories */
    if (appDir == NULL)
        appDir = SEC_APP_DIR_DEFAULT;

    (*processorHandle)->app_dir = (char*) calloc(1, SEC_MAX_FILE_PATH_LEN);
    if ((*processorHandle)->app_dir == NULL) {
        SEC_LOG_ERROR("Calloc failed");
        return SEC_RESULT_FAILURE;
    }

    result = Sec_SetStorageDir(appDir, SEC_APP_DIR_DEFAULT, (*processorHandle)->app_dir);
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("Error creating app_dir");
        SEC_FREE((*processorHandle)->app_dir);
        SEC_FREE(*processorHandle);
        return result;
    }

    result = SecUtils_MkDir((*processorHandle)->app_dir);
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("Error creating app_dir");
        SEC_FREE((*processorHandle)->app_dir);
        SEC_FREE(*processorHandle);
        return result;
    }

    if (globalDir != NULL) {
        (*processorHandle)->global_dir = (char*) calloc(1, SEC_MAX_FILE_PATH_LEN);
        if ((*processorHandle)->global_dir == NULL) {
            SEC_LOG_ERROR("Calloc failed");
            return SEC_RESULT_FAILURE;
        }

        result = Sec_SetStorageDir(globalDir, SEC_GLOBAL_DIR_DEFAULT, (*processorHandle)->global_dir);
        if (result != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("Error creating global_dir");
            SEC_FREE((*processorHandle)->app_dir);
            SEC_FREE((*processorHandle)->global_dir);
            SEC_FREE(*processorHandle);
            return result;
        }
    }

    // Calls client_thread_shutdown when the thread exits.
    if (pthread_key_create(&key, thread_shutdown) != 0) {
        SEC_LOG_ERROR("tss_create failed");
        return SEC_RESULT_FAILURE;
    }

    processorHandles[free_proc_handle] = *processorHandle;
    if (pthread_setspecific(key, processorHandle) != 0) {
        SEC_LOG_ERROR("Error storing procHandle in thread local storage");
        SEC_FREE((*processorHandle)->app_dir);
        SEC_FREE((*processorHandle)->global_dir);
        processorHandles[free_proc_handle] = NULL;
        SEC_FREE(*processorHandle);
        return SEC_RESULT_FAILURE;
    }

    // Initial OpenSSL.
    Sec_InitOpenSSL();

    /* generate sec store proc ins */
    result = SecStore_GenerateLadderInputs(*processorHandle, SEC_STORE_AES_LADDER_INPUT, NULL,
            (SEC_BYTE*) &derived_inputs, sizeof(derived_inputs));
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("Error Generating LadderInputs");
        SEC_FREE((*processorHandle)->app_dir);
        SEC_FREE((*processorHandle)->global_dir);
        processorHandles[free_proc_handle] = NULL;
        SEC_FREE(*processorHandle);
        return result;
    }

    result = SecUtils_FillKeyStoreUserHeader(*processorHandle, &keystore_header, SEC_KEYCONTAINER_SOC_INTERNAL_0);
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("Error Filling KeyStoreUserHeader");
        SEC_FREE((*processorHandle)->app_dir);
        SEC_FREE((*processorHandle)->global_dir);
        processorHandles[free_proc_handle] = NULL;
        SEC_FREE(*processorHandle);
        return result;
    }

    result = SecStore_StoreData(*processorHandle, SEC_FALSE, SEC_FALSE, (SEC_BYTE*) SEC_UTILS_KEYSTORE_MAGIC,
            &keystore_header, sizeof(keystore_header), &derived_inputs, sizeof(derived_inputs), store, sizeof(store));
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("Error storing derived_inputs");
        SEC_FREE((*processorHandle)->app_dir);
        SEC_FREE((*processorHandle)->global_dir);
        processorHandles[free_proc_handle] = NULL;
        SEC_FREE(*processorHandle);
        return result;
    }

    result = SecKey_Provision(*processorHandle, SEC_OBJECTID_STORE_AES_KEY, SEC_STORAGELOC_RAM_SOFT_WRAPPED,
            SEC_KEYCONTAINER_STORE, store, SecStore_GetStoreLen(store));
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("Error creating SEC_OBJECTID_STORE_AES_KEY");
        SEC_FREE((*processorHandle)->app_dir);
        SEC_FREE((*processorHandle)->global_dir);
        processorHandles[free_proc_handle] = NULL;
        SEC_FREE(*processorHandle);
        return result;
    }

    result = SecStore_GenerateLadderInputs(*processorHandle, SEC_STORE_MAC_LADDER_INPUT, NULL,
            (SEC_BYTE*) &derived_inputs, sizeof(derived_inputs));
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("Error creating SEC_STORE_MAC_LADDER_INPUT");
        SEC_FREE((*processorHandle)->app_dir);
        SEC_FREE((*processorHandle)->global_dir);
        processorHandles[free_proc_handle] = NULL;
        SEC_FREE(*processorHandle);
        return result;
    }

    result = SecUtils_FillKeyStoreUserHeader(*processorHandle, &keystore_header, SEC_KEYCONTAINER_SOC_INTERNAL_0);
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("Error creating keystore_header");
        SEC_FREE((*processorHandle)->app_dir);
        SEC_FREE((*processorHandle)->global_dir);
        processorHandles[free_proc_handle] = NULL;
        SEC_FREE(*processorHandle);
        return result;
    }

    result = SecStore_StoreData(*processorHandle, SEC_FALSE, SEC_FALSE, (SEC_BYTE*) SEC_UTILS_KEYSTORE_MAGIC,
            &keystore_header, sizeof(keystore_header), &derived_inputs, sizeof(derived_inputs), store, sizeof(store));
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("Error creating sec_store");
        SEC_FREE((*processorHandle)->app_dir);
        SEC_FREE((*processorHandle)->global_dir);
        processorHandles[free_proc_handle] = NULL;
        SEC_FREE(*processorHandle);
        return result;
    }

    result = SecKey_Provision(*processorHandle, SEC_OBJECTID_STORE_MACKEYGEN_KEY, SEC_STORAGELOC_RAM_SOFT_WRAPPED,
            SEC_KEYCONTAINER_STORE, store, SecStore_GetStoreLen(store));
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("Error creating SEC_OBJECTID_STORE_MACKEYGEN_KEY");
        SEC_FREE((*processorHandle)->app_dir);
        SEC_FREE((*processorHandle)->global_dir);
        processorHandles[free_proc_handle] = NULL;
        SEC_FREE(*processorHandle);
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
        SEC_FREE((*processorHandle)->app_dir);
        SEC_FREE((*processorHandle)->global_dir);
        processorHandles[free_proc_handle] = NULL;
        SEC_FREE(*processorHandle);
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
    sa_status status = sa_get_version(&version);
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

    sa_version version;
    sa_status status = sa_get_version(&version);
    CHECK_STATUS(status)

    memcpy(secProcInfo, &version, sizeof(sa_version));
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
    sa_status status = sa_get_device_id(&sa3_device_id);
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
    // Do nothing. Released when the thread shutsdown.
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

static void make_key() {
    // Calls release_proc_handle on thread exit and passes in the processorHandle stored in the key. But does not run
    // on application (main thread) exit.
    pthread_key_create(&key, release_proc_handle);

    for (size_t i = 0; i < MAX_PROC_HANDLES; i++)
        processorHandles[i] = NULL;

    // Calls proc_shutdown when the application (main thread) exits.
    if (atexit(proc_shutdown) != 0) {
        SEC_LOG_ERROR("atexit failed");
        return;
    }
}

static void release_proc_handle(void* handle) {
    if (handle == NULL)
        return;

    Sec_ProcessorHandle* processorHandle = handle;

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
}

static void proc_shutdown() {
    for (size_t i = 0; i < MAX_PROC_HANDLES; i++) {
        if (processorHandles[i] != NULL) {
            release_proc_handle(processorHandles[i]);
            processorHandles[i] = NULL;
        }
    }
}

static void thread_shutdown(void* unused) {
    proc_shutdown();
}
