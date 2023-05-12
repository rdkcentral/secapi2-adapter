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

#include "sec_adapter_bundle.h"

struct Sec_BundleHandle_struct {
    Sec_ProcessorHandle* processorHandle;
    SEC_OBJECTID object_id;
    Sec_StorageLoc location;
    Sec_BundleData bundle_data;
};

void Sec_FindRAMBundleData(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID object_id, Sec_RAMBundleData** data,
        Sec_RAMBundleData** parent) {
    *parent = NULL;
    *data = processorHandle->ram_bundles;

    while ((*data) != NULL) {
        if (object_id == (*data)->object_id)
            return;

        *parent = (*data);
        *data = (*data)->next;
    }

    *parent = NULL;
}

static Sec_Result Sec_RetrieveBundleData(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID object_id,
        Sec_StorageLoc* location, Sec_BundleData* bundleData) {
    char file_name_bundle[SEC_MAX_FILE_PATH_LEN];
    char file_name_verification[SEC_MAX_FILE_PATH_LEN];
    Sec_RAMBundleData* ram_bundle = NULL;
    Sec_RAMBundleData* ram_bundle_parent = NULL;

    CHECK_PROCHANDLE(processorHandle)

    /* check in RAM */
    Sec_FindRAMBundleData(processorHandle, object_id, &ram_bundle, &ram_bundle_parent);
    if (ram_bundle != NULL) {
        memcpy(bundleData, &(ram_bundle->bundle_data), sizeof(Sec_BundleData));
        *location = SEC_STORAGELOC_RAM;
        return SEC_RESULT_SUCCESS;
    }

    /* check in app folder */
    char* sec_dirs[] = {processorHandle->app_dir, processorHandle->global_dir};
    for (int i = 0; i < 2; i++) {
        if (sec_dirs[i] != NULL) {
            snprintf(file_name_bundle, sizeof(file_name_bundle), "%s" SEC_BUNDLE_FILENAME_PATTERN, sec_dirs[i],
                    object_id);
            snprintf(file_name_verification, sizeof(file_name_verification), "%s" SEC_VERIFICATION_FILENAME_PATTERN,
                    sec_dirs[i], object_id);
            if (SecUtils_FileExists(file_name_bundle)) {
                if (SecUtils_ReadFile(file_name_bundle, bundleData->bundle, sizeof(bundleData->bundle),
                            &bundleData->bundle_len) != SEC_RESULT_SUCCESS) {
                    SEC_LOG_ERROR("Could not read one of the bundle files");
                    return SEC_RESULT_FAILURE;
                }

                if (SecUtils_FileExists(file_name_verification)) {
                    if (verify_verification_file(processorHandle, file_name_verification, bundleData->bundle,
                                bundleData->bundle_len, NULL, 0) != SEC_RESULT_SUCCESS) {
                        SEC_LOG_ERROR("Bundle verification failed");
                        return SEC_RESULT_FAILURE;
                    }
                } else {
                    // If sha file doesn't exist, the bundle file was created by an old SecApi. Just create the
                    // verification file.
                    if (write_verification_file(processorHandle, file_name_verification, bundleData->bundle,
                                bundleData->bundle_len, NULL, 0) != SEC_RESULT_SUCCESS) {
                        SEC_LOG_ERROR("Could not write SHA file");
                    }
                }

                *location = SEC_STORAGELOC_FILE;
                return SEC_RESULT_SUCCESS;
            }
        }
    }

    return SEC_RESULT_NO_SUCH_ITEM;
}

static Sec_Result Sec_StoreBundleData(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID object_id,
        Sec_StorageLoc location, Sec_BundleData* bundleData) {
    Sec_RAMBundleData* ram_bundle;

    if (location == SEC_STORAGELOC_RAM) {
        SecBundle_Delete(processorHandle, object_id);

        ram_bundle = calloc(1, sizeof(Sec_RAMBundleData));
        if (ram_bundle == NULL) {
            SEC_LOG_ERROR("Malloc failed");
            return SEC_RESULT_FAILURE;
        }
        ram_bundle->object_id = object_id;
        memcpy(&(ram_bundle->bundle_data), bundleData, sizeof(Sec_BundleData));
        ram_bundle->next = processorHandle->ram_bundles;
        processorHandle->ram_bundles = ram_bundle;

        return SEC_RESULT_SUCCESS;
    }

    if (location == SEC_STORAGELOC_FILE) {
        if (processorHandle->app_dir == NULL) {
            SEC_LOG_ERROR("Cannot write file because app_dir is NULL");
            return SEC_RESULT_FAILURE;
        }

        SecBundle_Delete(processorHandle, object_id);

        char file_name_bundle[SEC_MAX_FILE_PATH_LEN];
        char file_name_verification[SEC_MAX_FILE_PATH_LEN];
        snprintf(file_name_bundle, sizeof(file_name_bundle), "%s" SEC_BUNDLE_FILENAME_PATTERN, processorHandle->app_dir,
                object_id);
        snprintf(file_name_verification, sizeof(file_name_verification), "%s" SEC_VERIFICATION_FILENAME_PATTERN,
                processorHandle->app_dir, object_id);

        if (SecUtils_WriteFile(file_name_bundle, bundleData->bundle, bundleData->bundle_len) != SEC_RESULT_SUCCESS ||
                write_verification_file(processorHandle, file_name_verification, bundleData->bundle,
                        bundleData->bundle_len, NULL, 0) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("Could not write one of the bundle files");
            SecUtils_RmFile(file_name_bundle);
            SecUtils_RmFile(file_name_verification);
            return SEC_RESULT_FAILURE;
        }

        return SEC_RESULT_SUCCESS;
    }

    SEC_LOG_ERROR("Unimplemented location type");
    return SEC_RESULT_UNIMPLEMENTED_FEATURE;
}

/**
 * @brief Obtain a handle to a provisioned bundle.
 *
 * @param processorHandle secure processor handle.
 * @param object_id id of the provisioned bundle that we are attempting to obtain.
 * @param bundleHandle pointer to the output key handle.
 *
 * @return The status of the operation.
 */
Sec_Result SecBundle_GetInstance(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID object_id,
        Sec_BundleHandle** bundleHandle) {
    Sec_Result result;
    Sec_StorageLoc location;

    *bundleHandle = NULL;
    CHECK_PROCHANDLE(processorHandle)

    if (object_id == SEC_OBJECTID_INVALID)
        return SEC_RESULT_INVALID_PARAMETERS;

    *bundleHandle = calloc(1, sizeof(Sec_BundleHandle));
    if (*bundleHandle == NULL) {
        SEC_LOG_ERROR("Malloc failed");
        return SEC_RESULT_FAILURE;
    }

    result = Sec_RetrieveBundleData(processorHandle, object_id, &location, &(*bundleHandle)->bundle_data);
    if (result != SEC_RESULT_SUCCESS) {
        SEC_FREE(*bundleHandle);
        return result;
    }

    (*bundleHandle)->object_id = object_id;
    (*bundleHandle)->location = location;
    (*bundleHandle)->processorHandle = processorHandle;

    return SEC_RESULT_SUCCESS;
}

/**
 * @brief Provision a bundle.
 *
 * @param processorHandle secure processor handle.
 * @param object_id id of the bundle to provision.
 * @param location storage location where the bundle should be provisioned.
 * @param data pointer to the input key container.
 * @param data_len the size of the input key container.
 *
 * @return The status of the operation.
 */
Sec_Result SecBundle_Provision(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID object_id, Sec_StorageLoc location,
        SEC_BYTE* data, SEC_SIZE data_len) {
    Sec_BundleData* bundle_data;

    CHECK_PROCHANDLE(processorHandle)

    if (object_id == SEC_OBJECTID_INVALID) {
        SEC_LOG_ERROR("Cannot provision object with SEC_OBJECTID_INVALID");
        return SEC_RESULT_FAILURE;
    }

    if (data == NULL) {
        SEC_LOG_ERROR("NULL data");
        return SEC_RESULT_FAILURE;
    }

    if (data_len > SEC_BUNDLE_MAX_LEN) {
        SEC_LOG_ERROR("Input bundle is too large");
        return SEC_RESULT_FAILURE;
    }

    bundle_data = calloc(1, sizeof(Sec_BundleData));
    if (bundle_data == NULL) {
        SEC_LOG_ERROR("calloc failed");
        return SEC_RESULT_FAILURE;
    }

    memcpy(bundle_data->bundle, data, data_len);
    bundle_data->bundle_len = data_len;

    Sec_Result result = Sec_StoreBundleData(processorHandle, object_id, location, bundle_data);
    SEC_FREE(bundle_data);
    return result;
}

/**
 * @brief Delete a provisioned bundle.
 *
 * @param processorHandle secure processor handle.
 * @param object_id id of the key to delete.
 *
 * @return The status of the operation.
 */
Sec_Result SecBundle_Delete(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID object_id) {
    Sec_RAMBundleData* ram_bundle = NULL;
    Sec_RAMBundleData* ram_bundle_parent = NULL;
    SEC_SIZE bundles_found = 0;
    SEC_SIZE bundles_deleted = 0;

    CHECK_PROCHANDLE(processorHandle)

    /* ram */
    Sec_FindRAMBundleData(processorHandle, object_id, &ram_bundle, &ram_bundle_parent);
    if (ram_bundle != NULL) {
        if (ram_bundle_parent == NULL)
            processorHandle->ram_bundles = ram_bundle->next;
        else
            ram_bundle_parent->next = ram_bundle->next;

        Sec_Memset(ram_bundle, 0, sizeof(Sec_RAMBundleData));

        SEC_FREE(ram_bundle);

        ++bundles_found;
        ++bundles_deleted;
    }

    /* file system */
    if (processorHandle->app_dir != NULL) {
        char file_name_bundle[SEC_MAX_FILE_PATH_LEN];
        snprintf(file_name_bundle, sizeof(file_name_bundle), "%s" SEC_BUNDLE_FILENAME_PATTERN, processorHandle->app_dir,
                object_id);
        if (SecUtils_FileExists(file_name_bundle)) {
            SecUtils_RmFile(file_name_bundle);
            ++bundles_found;

            if (!SecUtils_FileExists(file_name_bundle))
                ++bundles_deleted;
        }

        char file_name_verification[SEC_MAX_FILE_PATH_LEN];
        snprintf(file_name_verification, sizeof(file_name_verification), "%s" SEC_VERIFICATION_FILENAME_PATTERN,
                processorHandle->app_dir, object_id);
        if (!SecUtils_FileExists(file_name_bundle) && SecUtils_FileExists(file_name_verification))
            SecUtils_RmFile(file_name_verification);
    }

    if (bundles_found == 0)
        return SEC_RESULT_NO_SUCH_ITEM;

    if (bundles_found != bundles_deleted) {
        SEC_LOG_ERROR("Could not delete the specified bundle.  It is stored in a non-removable location.");
        return SEC_RESULT_ITEM_NON_REMOVABLE;
    }

    return SEC_RESULT_SUCCESS;
}

/**
 * @brief Release the bundle object.
 *
 * @param bundleHandle bundle handle to release.
 *
 * @return The status of the operation.
 */
Sec_Result SecBundle_Release(Sec_BundleHandle* bundleHandle) {
    CHECK_HANDLE(bundleHandle)

    SEC_FREE(bundleHandle);

    return SEC_RESULT_SUCCESS;
}

/**
 * @brief Obtain the bundle data.
 *
 * @param bundleHandle bundle handle.
 * @param buffer pointer to the output buffer that will be filled with bundle data.
 * @param buffer_len the length of the output buffer.
 * @param written pointer to the output value specifying the number of bytes written to the
 * output buffer.
 *
 * @return The status of the operation.
 */
Sec_Result SecBundle_Export(Sec_BundleHandle* bundleHandle, SEC_BYTE* buffer, SEC_SIZE buffer_len, SEC_SIZE* written) {
    CHECK_HANDLE(bundleHandle)

    if (buffer == NULL) {
        *written = bundleHandle->bundle_data.bundle_len;
        return SEC_RESULT_SUCCESS;
    }

    if (buffer_len < bundleHandle->bundle_data.bundle_len)
        return SEC_RESULT_BUFFER_TOO_SMALL;

    memcpy(buffer, bundleHandle->bundle_data.bundle, bundleHandle->bundle_data.bundle_len);
    *written = bundleHandle->bundle_data.bundle_len;
    return SEC_RESULT_SUCCESS;
}

/**
 * @brief Find if the bundle with a specific id has been provisioned.
 *
 * @param processorHandle secure processor handle.
 * @param object_id id of the certificate.
 *
 * @return 1 if an object has been provisioned, 0 if it has not been.
 */
SEC_BOOL SecBundle_IsProvisioned(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID object_id) {
    Sec_BundleHandle* bundleHandle;

    if (SecBundle_GetInstance(processorHandle, object_id, &bundleHandle) != SEC_RESULT_SUCCESS) {
        return SEC_FALSE;
    }

    SecBundle_Release(bundleHandle);
    return SEC_TRUE;
}

/**
 * @brief finds the first available bundle id in the range passed in.
 *
 * @param proc secure processor.
 * @param base bottom of the range to search.
 * @param top top of the range to search.
 * @return
 */
SEC_OBJECTID SecBundle_ObtainFreeObjectId(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID base, SEC_OBJECTID top) {
    SEC_OBJECTID id;
    Sec_BundleHandle* bundleHandle;
    Sec_Result result;

    for (id = base; id < top; ++id) {
        result = SecBundle_GetInstance(processorHandle, id, &bundleHandle);
        if (result == SEC_RESULT_SUCCESS)
            SecBundle_Release(bundleHandle);
        else
            return id;
    }

    return SEC_OBJECTID_INVALID;
}
