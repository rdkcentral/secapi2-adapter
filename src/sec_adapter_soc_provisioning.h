/**
 * Copyright 2025 Comcast Cable Communications Management, LLC
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
#ifndef SEC_ADAPTER_SOC_PROVISONING_H
#define SEC_ADAPTER_SOC_PROVISONING_H
#include "sa.h"
#include "sec_adapter_cipher.h"
#include "sec_adapter_key_legacy.h"
#include "sec_adapter_processor.h"
#include "sec_security_utils.h"
#include <memory.h>


/* Number of objects to sa_key_provision_ta for provisioning */
#define WIDEVINE_OBJ 2
#define PLAY_READY_OBJ 2
#define APPLE_MFI_OBJ 2
#define APPLE_FAIR_PLAY_OBJ 1
#define NETFLIX_OBJ 4

/**
 * @brief Reads credential data which is stored via store_raw_data function
 *
 * @param filename The path to the file containing the credentials.
 * @param outSize Pointer to a size_t variable where the size of the read data will be stored.
 * @return Pointer to the read data (uint8_t*), or NULL on failure.
 */
uint8_t* readFkpsCredential(const char* filename, size_t* outSize);

/**
 * @brief Reads Widevine DRM provisioning data.
 *
 * @param processorHandle Handle to the security processor.
 * @param wvProvision Pointer to a pointer where the Widevine provisioning data will be stored.
 * @return true if successful, false otherwise.
 */
bool readWidevineData(Sec_ProcessorHandle* processorHandle, WidevineOemProvisioning** wvProvision);

/**
 * @brief Reads PlayReady DRM provisioning data.
 *
 * @param processorHandle Handle to the security processor.
 * @param prProvision Pointer to a pointer where the PlayReady provisioning data will be stored.
 * @param model_type An unsigned integer representing the model type for the PlayReady provisioning.
 * @return true if successful, false otherwise.
 */
bool readPlayReadyData(Sec_ProcessorHandle* processorHandle, PlayReadyProvisioning** prProvision,
                         unsigned int model_type);

/**
 * @brief Reads Apple FairPlay DRM provisioning data.
 *
 * @param processorHandle Handle to the security processor.
 * @param fairPlayProvision Pointer to a pointer where the FairPlay provisioning data will be stored.
 * @return true if successful, false otherwise.
 */
bool readAppleFairPlayData(Sec_ProcessorHandle* processorHandle, AppleFairPlayProvisioning** fairPlayProvision);

/**
 * @brief Reads Apple MFi provisioning data.
 *
 * @param processorHandle Handle to the security processor.
 * @param mfiProvision Pointer to a pointer where the MFi provisioning data will be stored.
 * @return true if successful, false otherwise.
 */
bool readAppleMfiData(Sec_ProcessorHandle* processorHandle, AppleMfiProvisioning** mfiProvision);

/**
 * @brief Reads Netflix-specific provisioning data.
 *
 * @param processorHandle Handle to the security processor.
 * @param nflxProvision Pointer to a pointer where the Netflix provisioning data will be stored.
 * @return true if successful, false otherwise.
 */
bool readNetflixData(Sec_ProcessorHandle* processorHandle, NetflixProvisioning** nflxProvision);

/**
 * @brief Performs vendor-specific Objects are available in the list of SEC_OBJECTID.
 *
 * @param object_id The object ID of the Key.
 * @return Result of the operation.
 */
Sec_Result SecSocProv_SocVendorSpecific(SEC_OBJECTID object_id);

/**
 * @brief Stores raw data in a specified location for a given object ID.
 *
 * @param processorHandle Handle to the security processor.
 * @param location The storage location where the data will be stored.
 * @param object_id The object ID associated with the data.
 * @param data Pointer to the raw data to be stored.
 * @param data_length The length of the data to be stored.
 * @return Result of the operation.
 */
Sec_Result store_raw_data(Sec_ProcessorHandle* processorHandle, Sec_StorageLoc location, SEC_OBJECTID object_id,
        SEC_BYTE* data, SEC_SIZE data_length);

/**
 * @brief Manages provisioning with a trusted application.
 *
 * @param processorHandle Handle to the security processor.
 * @param numPaths The number of paths for provisioning.
 * @param provisioningType The type of provisioning to be used.
 * @param dataSize The size of the data associated with the provisioning.
 * @return true if successful, false otherwise.
 */
bool provisioning_ta(Sec_ProcessorHandle* processorHandle, size_t numPaths,sa_key_type_soc_ta provisioningType, size_t dataSize);

/**
 * @brief Initiates provisioning using a trusted application key type.
 *
 * @param processorHandle Handle to the security processor.
 * @param key_type The type of key for the provisioning.
 * @return Result of the operation.
 */
Sec_Result SecSocProv_Ta_Provision(Sec_ProcessorHandle* processorHandle, sa_key_type_soc_ta key_type);


/**
 * @brief Frees memory associated with Widevine provisioning data.
 *
 * @param provision Pointer to the Widevine provisioning data to be freed.
 */
void freeWidevineProvisioning(WidevineOemProvisioning* provision);

/**
 * @brief Frees memory associated with Netflix provisioning data.
 *
 * @param provision Pointer to the Netflix provisioning data to be freed.
 */
void freeNetflixProvisioning(NetflixProvisioning* provision);

/**
 * @brief Frees memory associated with PlayReady provisioning data.
 *
 * @param provision Pointer to the PlayReady provisioning data to be freed.
 */
void freePlayReadyProvisioning(PlayReadyProvisioning* provision);

/**
 * @brief Frees memory associated with Apple MFi provisioning data.
 *
 * @param provision Pointer to the MFi provisioning data to be freed.
 */
void freeAppleMfiProvisioning(AppleMfiProvisioning* provision);

/**
 * @brief Frees memory associated with Apple FairPlay provisioning data.
 *
 * @param provision Pointer to the FairPlay provisioning data to be freed.
 */
void freeAppleFairPlayProvisioning(AppleFairPlayProvisioning* provision);
#endif // SEC_ADAPTER_SOC_PROVISONING_H
