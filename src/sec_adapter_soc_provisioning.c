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
#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>
#include "sec_adapter_key.h" // NOLINT
#include "sa.h"
#include "sec_adapter_cipher.h"
#include "sec_adapter_key_legacy.h"
#include "sec_adapter_processor.h"
#include "sec_adapter_soc_provisioning.h"
#include "sec_security.h"

static SEC_OBJECTID Soc_object_ids[] = {
#if ENABLE_SOC_PROVISION_WIDEVINE
    // Widevine
    SEC_OBJECTID_WV_KEY,
    SEC_OBJECTID_WV_CERTBUNDLE,
#endif

#if ENABLE_SOC_PROVISION_PLAYREADY_2K
    // PlayReady
    SEC_OBJECTID_PLAYREADY_MODELKEY,
    SEC_OBJECTID_PLAYREADY_MODELCERT,
#endif

#if ENABLE_SOC_PROVISION_PLAYREADY_3K
    SEC_OBJECTID_PLAYREADY_MODELKEY_3K,
    SEC_OBJECTID_PLAYREADY_MODELCERT_3K,
#endif

#if ENABLE_SOC_PROVISION_NETFLIX
    // Netflix
    SEC_OBJECTID_NETFLIX_KDE,
    SEC_OBJECTID_NETFLIX_KDH,
    SEC_OBJECTID_NETFLIX_KDW,
    SEC_OBJECTID_NETFLIX_ESN,
#endif

#if ENABLE_SOC_PROVISION_APPLE_MFI
    // Apple MFi
    SEC_OBJECTID_MFI_BASE_KEY,
    SEC_OBJECTID_MFI_BUNDLE,
#endif

#if ENABLE_SOC_PROVISION_APPLE_FAIRPLAY
    // Apple FairPlay
    SEC_OBJECTID_FAIRPLAY_BUNDLE
#endif
};

uint8_t* readFkpsCredential(const char* filename, size_t* outSize) {
    struct stat buff;

    if (stat(filename, &buff) != 0) {
        SEC_LOG_ERROR("File does not exist: %s", filename);
        return NULL;
    }
    FILE* file = fopen(filename, "rb");
    if (!file) {
        SEC_LOG_ERROR("Failed to open file: %s", filename);
        return NULL;
    }

    // Seek to end to get the size
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    rewind(file);

    if (size <= 0) {
        SEC_LOG_ERROR("Invalid file size or empty file: %s", filename);
        fclose(file);
        return NULL;
    }

    // Allocate buffer
    uint8_t* buffer = (uint8_t*)malloc(size);
    if (!buffer) {
        SEC_LOG_ERROR("Memory allocation failed for file: %s", filename);
        fclose(file);
        return NULL;
    }

    // Read the file into the buffer
    size_t bytesRead = fread(buffer, 1, size, file);
    fclose(file);

    if (bytesRead != (size_t)size) {
        SEC_LOG_ERROR("Failed to read complete file: %s", filename);
        free(buffer);
        return NULL;
    }

    *outSize = bytesRead;
    return buffer;
}


bool readNetflixData(Sec_ProcessorHandle* processorHandle, NetflixProvisioning** nflxProvision) {

    char file_esn_name[SEC_MAX_FILE_PATH_LEN];
    char file_encryption_key_name[SEC_MAX_FILE_PATH_LEN];
    char file_hmac_key_name[SEC_MAX_FILE_PATH_LEN];
    char file_wrapping_key_name[SEC_MAX_FILE_PATH_LEN];

    SEC_OBJECTID esn_container_obj = SEC_OBJECTID_NETFLIX_ESN;
    SEC_OBJECTID encryption_key_obj = SEC_OBJECTID_NETFLIX_KDE;
    SEC_OBJECTID hmac_key_obj = SEC_OBJECTID_NETFLIX_KDH;
    SEC_OBJECTID wrapping_key_obj = SEC_OBJECTID_NETFLIX_KDW;

    snprintf(file_esn_name, sizeof(file_esn_name), "%s" SEC_BUNDLE_FILENAME_PATTERN, processorHandle->app_dir,
               esn_container_obj);
    snprintf(file_encryption_key_name, sizeof(file_encryption_key_name), "%s" SEC_KEY_FILENAME_PATTERN, processorHandle->app_dir,
               encryption_key_obj);
    snprintf(file_hmac_key_name, sizeof(file_hmac_key_name), "%s" SEC_KEY_FILENAME_PATTERN, processorHandle->app_dir,
               hmac_key_obj);
    snprintf(file_wrapping_key_name, sizeof(file_wrapping_key_name), "%s" SEC_KEY_FILENAME_PATTERN, processorHandle->app_dir,
               wrapping_key_obj);


    if (!file_esn_name || !*file_esn_name) {
        SEC_LOG_ERROR("File does not exist: %s", file_esn_name);
        return false;
    }
    if (!file_encryption_key_name || !*file_encryption_key_name) {
        SEC_LOG_ERROR("File does not exist: %s", file_encryption_key_name);
        return false;
    }
    if (!file_hmac_key_name || !*file_hmac_key_name) {
        SEC_LOG_ERROR("File does not exist: %s", file_hmac_key_name);
        return false;
    }
    if (!file_wrapping_key_name || !*file_wrapping_key_name) {
        SEC_LOG_ERROR("File does not exist: %s", file_wrapping_key_name);
        return false;
    }

    void* esn_container = NULL;
    size_t esn_size = 0;
    void* encryption_key = NULL;
    size_t encryption_size = 0;
    void* hmac_key = NULL;
    size_t hmac_size = 0;
    void* wrapping_key = NULL;
    size_t wrapping_size = 0;
    
    // Read the Credentials from the moemory
    esn_container = readFkpsCredential(file_esn_name, &esn_size);
    encryption_key = readFkpsCredential(file_encryption_key_name, &encryption_size);
    hmac_key = readFkpsCredential(file_hmac_key_name, &hmac_size);
    wrapping_key = readFkpsCredential(file_wrapping_key_name, &wrapping_size);

    if (!esn_container || !encryption_key || !hmac_key || !wrapping_key) {
        SEC_LOG_ERROR("Failed to read Netflix provisioning data");
        free(esn_container);
        free(encryption_key);
        free(hmac_key);
        free(wrapping_key);
        return false;
    }

    // Allocate structure if needed
    if (!(*nflxProvision)) {
        *nflxProvision = (NetflixProvisioning*)malloc(sizeof(NetflixProvisioning));
        if (!(*nflxProvision)) {
            SEC_LOG_ERROR("Failed to allocate memory for NetflixProvisioning");
            free(esn_container);
            free(encryption_key);
            free(hmac_key);
            free(wrapping_key);
            return false;
        }
    }

    // Copy encryption key
    (*nflxProvision)->encryptionKeyLength = encryption_size;
    (*nflxProvision)->encryptionKey = malloc(encryption_size);
    if (!(*nflxProvision)->encryptionKey) {
        SEC_LOG_ERROR("Memory allocation failed for encryption key");
        free(esn_container);
        free(encryption_key);
        free(hmac_key);
        free(wrapping_key);
        return false;
    }
    memcpy((*nflxProvision)->encryptionKey, encryption_key, encryption_size);
    free(encryption_key);

    // Copy HMAC key
    (*nflxProvision)->hmacKeyLength = hmac_size;
    (*nflxProvision)->hmacKey = malloc(hmac_size);
    if (!(*nflxProvision)->hmacKey) {
        SEC_LOG_ERROR("Memory allocation failed for HMAC key");
        free(esn_container);
        free(encryption_key);
        free(hmac_key);
        free(wrapping_key);
        return false;
    }
    memcpy((*nflxProvision)->hmacKey, hmac_key, hmac_size);
    free(hmac_key);

    // Copy wrapping key
    (*nflxProvision)->wrappingKeyLength = wrapping_size;
    (*nflxProvision)->wrappingKey = malloc(wrapping_size);
    if (!(*nflxProvision)->wrappingKey) {
        SEC_LOG_ERROR("Memory allocation failed for wrapping key");
        free(esn_container);
        free(encryption_key);
        free(hmac_key);
        free(wrapping_key);
        return false;
    }
    memcpy((*nflxProvision)->wrappingKey, wrapping_key, wrapping_size);
    free(wrapping_key);

    // Copy ESN container
    (*nflxProvision)->esnContainerLength = esn_size;
    (*nflxProvision)->esnContainer = malloc(esn_size);
    if (!(*nflxProvision)->esnContainer) {
        SEC_LOG_ERROR("Memory allocation failed for ESN container");
        free(esn_container);
        free(encryption_key);
        free(hmac_key);
        free(wrapping_key);
        return false;
    }
    memcpy((*nflxProvision)->esnContainer, esn_container, esn_size);
    free(esn_container);
    return true;
}


bool readAppleMfiData(Sec_ProcessorHandle* processorHandle, AppleMfiProvisioning** mfiProvision) {

   char file_base_key_name[SEC_MAX_FILE_PATH_LEN];
   char file_provisioning_object_name[SEC_MAX_FILE_PATH_LEN];


    SEC_OBJECTID mfiBaseKey_obj = SEC_OBJECTID_MFI_BASE_KEY; 
    SEC_OBJECTID mfiProvisioning_obj = SEC_OBJECTID_MFI_BUNDLE;

    snprintf(file_base_key_name, sizeof(file_base_key_name), "%s" SEC_KEY_FILENAME_PATTERN, processorHandle->app_dir,
               mfiBaseKey_obj);
    snprintf(file_provisioning_object_name, sizeof(file_provisioning_object_name), "%s" SEC_BUNDLE_FILENAME_PATTERN, processorHandle->app_dir,
               mfiProvisioning_obj);

    if (!file_base_key_name || !*file_base_key_name) {
        SEC_LOG_ERROR("File does not exist: %s", file_base_key_name);
        return false;
    }

    if (!file_provisioning_object_name || !*file_provisioning_object_name) {
        SEC_LOG_ERROR("File does not exist: %s", file_provisioning_object_name);
        return false;
    }

    size_t base_key_size = 0;
    void* base_key = readFkpsCredential(file_base_key_name, &base_key_size);
    if (!base_key || base_key_size == 0) {
        SEC_LOG_ERROR("Failed to read: %s", file_base_key_name);
        return false;
    }

    size_t provisioning_obj_size = 0;
    void* provisioning_obj = readFkpsCredential(file_provisioning_object_name, &provisioning_obj_size);
    if (!provisioning_obj || provisioning_obj_size == 0) {
        SEC_LOG_ERROR("Failed to read: %s", file_provisioning_object_name);
        free(base_key);
        return false;
    }

    if (!(*mfiProvision)) {
        *mfiProvision = (AppleMfiProvisioning*)malloc(sizeof(AppleMfiProvisioning));
        if (!(*mfiProvision)) {
            SEC_LOG_ERROR("Memory allocation failed for AppleMfiProvisioning");
            free(base_key);
            free(provisioning_obj);
            return false;
        }
    }

    (*mfiProvision)->mfiBaseKeyLength = (unsigned int)base_key_size;
    (*mfiProvision)->mfiBaseKey = malloc(base_key_size);
    if (!(*mfiProvision)->mfiBaseKey) {
        SEC_LOG_ERROR("Memory allocation failed for base key");
        free(base_key);
        free(provisioning_obj);
        return false;
    }
    memcpy((*mfiProvision)->mfiBaseKey, base_key, base_key_size);
    free(base_key);

    (*mfiProvision)->mfiProvisioningObjectLength = (unsigned int)provisioning_obj_size;
    (*mfiProvision)->mfiProvisioningObject = malloc(provisioning_obj_size);
    if (!(*mfiProvision)->mfiProvisioningObject) {
        SEC_LOG_ERROR("Memory allocation failed for provisioning object");
        free((*mfiProvision)->mfiBaseKey);
        free(provisioning_obj);
        return false;
    }
    memcpy((*mfiProvision)->mfiProvisioningObject, provisioning_obj, provisioning_obj_size);
    free(provisioning_obj);

    return true;
}

bool readAppleFairPlayData(Sec_ProcessorHandle* processorHandle, AppleFairPlayProvisioning** fairPlayProvision) {
  
    char file_fairplay_secret_name[SEC_MAX_FILE_PATH_LEN];
    SEC_OBJECTID fairplay_secret_obj = SEC_OBJECTID_FAIRPLAY_BUNDLE;
    snprintf(file_fairplay_secret_name, sizeof(file_fairplay_secret_name), "%s" SEC_BUNDLE_FILENAME_PATTERN, processorHandle->app_dir,
               fairplay_secret_obj);
    if (!file_fairplay_secret_name || !*file_fairplay_secret_name) {
        SEC_LOG_ERROR("File does not exist: %s", file_fairplay_secret_name);
        return false;
    }

    size_t secret_size = 0;
    void* fairplay_secret = readFkpsCredential(file_fairplay_secret_name, &secret_size);
    if (!fairplay_secret || secret_size == 0) {
        SEC_LOG_ERROR("Failed to read: %s", file_fairplay_secret_name);
        return false;
    }

    if (!(*fairPlayProvision)) {
        *fairPlayProvision = (AppleFairPlayProvisioning*)malloc(sizeof(AppleFairPlayProvisioning));
        if (!(*fairPlayProvision)) {
            SEC_LOG_ERROR("Memory allocation failed for AppleFairPlayProvisioning");
            free(fairplay_secret);
            return false;
        }
    }

    (*fairPlayProvision)->fairPlaySecretLength = (unsigned int)secret_size;
    (*fairPlayProvision)->fairPlaySecret = malloc(secret_size);
    if (!(*fairPlayProvision)->fairPlaySecret) {
        SEC_LOG_ERROR("Memory allocation failed for FairPlay secret");
        free(fairplay_secret);
        return false;
    }

    memcpy((*fairPlayProvision)->fairPlaySecret, fairplay_secret, secret_size);
    free(fairplay_secret);

    return true;
}

bool readPlayReadyData(Sec_ProcessorHandle* processorHandle, PlayReadyProvisioning** prProvision,
                         unsigned int model_type) {

    char file_private_key[SEC_MAX_FILE_PATH_LEN];
    char file_oem_cert[SEC_MAX_FILE_PATH_LEN];

    SEC_OBJECTID privateKey_obj;
    SEC_OBJECTID modelCertificate_obj;
    if (model_type == PLAYREADY_MODEL_2K) {
        privateKey_obj = SEC_OBJECTID_PLAYREADY_MODELKEY;
        modelCertificate_obj = SEC_OBJECTID_PLAYREADY_MODELCERT;
    } else {
        privateKey_obj = SEC_OBJECTID_PLAYREADY_MODELKEY_3K;
        modelCertificate_obj = SEC_OBJECTID_PLAYREADY_MODELCERT_3K;
    }

    snprintf(file_private_key, sizeof(file_private_key), "%s" SEC_KEY_FILENAME_PATTERN, processorHandle->app_dir,
               privateKey_obj);
    snprintf(file_oem_cert, sizeof(file_oem_cert), "%s" SEC_BUNDLE_FILENAME_PATTERN, processorHandle->app_dir,
               modelCertificate_obj);

    if (!file_private_key || !*file_private_key) {
        SEC_LOG_ERROR("File does not exist: %s", file_private_key);
        return false;
    }
    if (!file_oem_cert || !*file_oem_cert) {
        SEC_LOG_ERROR("File does not exist: %s", file_oem_cert);
        return false;
    }

    size_t private_key_size = 0;
    void* private_key = readFkpsCredential(file_private_key, &private_key_size);
    if (!private_key || private_key_size == 0) {
        SEC_LOG_ERROR("Failed to read: %s", file_private_key);
        return false;
    }

    size_t oem_cert_size = 0;
    void* oem_cert = readFkpsCredential(file_oem_cert, &oem_cert_size);
    if (!oem_cert || oem_cert_size == 0) {
        SEC_LOG_ERROR("Failed to read: %s", file_oem_cert);
        free(private_key);
        return false;
    }

    if (!(*prProvision)) {
        *prProvision = (PlayReadyProvisioning*)malloc(sizeof(PlayReadyProvisioning));
        if (!(*prProvision)) {
            SEC_LOG_ERROR("Memory allocation failed for PlayReadyProvisioning");
            free(private_key);
            free(oem_cert);
            return false;
        }
    }

    (*prProvision)->modelType = model_type;

    (*prProvision)->privateKeyLength = (unsigned int)private_key_size;
    (*prProvision)->privateKey = malloc(private_key_size);
    if (!(*prProvision)->privateKey) {
        SEC_LOG_ERROR("Memory allocation failed for privateKey");
        free(private_key);
        free(oem_cert);
        return false;
    }
    memcpy((*prProvision)->privateKey, private_key, private_key_size);
    free(private_key);

    (*prProvision)->modelCertificateLength = (unsigned int)oem_cert_size;
    (*prProvision)->modelCertificate = malloc(oem_cert_size);
    if (!(*prProvision)->modelCertificate) {
        SEC_LOG_ERROR("Memory allocation failed for modelCertificate");
        free(oem_cert);
        return false;
    }
    memcpy((*prProvision)->modelCertificate, oem_cert, oem_cert_size);
    free(oem_cert);

    return true;
}


bool readWidevineData(Sec_ProcessorHandle* processorHandle, WidevineOemProvisioning** wvProvision) {

    char file_private_key[SEC_MAX_FILE_PATH_LEN];
    char file_oem_cert[SEC_MAX_FILE_PATH_LEN];

    SEC_OBJECTID privateKey_obj = SEC_OBJECTID_WV_KEY; 
    SEC_OBJECTID oemCertificate_obj = SEC_OBJECTID_WV_CERTBUNDLE;

    snprintf(file_private_key, sizeof(file_private_key), "%s" SEC_KEY_FILENAME_PATTERN, processorHandle->app_dir,
               privateKey_obj);
    snprintf(file_oem_cert, sizeof(file_oem_cert), "%s" SEC_BUNDLE_FILENAME_PATTERN, processorHandle->app_dir,
               oemCertificate_obj);

    if (!file_private_key || file_private_key[0] == '\0') {
        SEC_LOG_ERROR("File does not exist: %s", file_private_key);
        return false;
    }

    if (!file_oem_cert || file_oem_cert[0] == '\0') {
        SEC_LOG_ERROR("File does not exist: %s", file_oem_cert);
        return false;
    }

    // Read private key
    size_t private_key_size = 0;
    unsigned char* private_key = readFkpsCredential(file_private_key, &private_key_size);
    if (!private_key || private_key_size == 0) {
        SEC_LOG_ERROR("This file has a problem: %s", file_private_key);
        return false;
    }

    // Read OEM certificate
    size_t oem_cert_size = 0;
    unsigned char* oem_cert = readFkpsCredential(file_oem_cert, &oem_cert_size);
    if (!oem_cert || oem_cert_size == 0) {
        SEC_LOG_ERROR("This file has a problem: %s", file_oem_cert);
        free(private_key);
        return false;
    }

    // Allocate structure if needed
    if (!(*wvProvision)) {
        *wvProvision = (WidevineOemProvisioning*)malloc(sizeof(WidevineOemProvisioning));
        if (!(*wvProvision)) {
            SEC_LOG_ERROR("Failed to allocate memory for wvProvision.");
            free(private_key);
            free(oem_cert);
            return false;
        }
    }


  // Copy key
    (*wvProvision)->oemDevicePrivateKeyLength = (unsigned int)private_key_size;
    (*wvProvision)->oemDevicePrivateKey = malloc(private_key_size);
    if (!(*wvProvision)->oemDevicePrivateKey) {
        SEC_LOG_ERROR("Memory allocation failed");
        free(private_key);
        free(oem_cert);
        return false;
    }
    memcpy((*wvProvision)->oemDevicePrivateKey, private_key, private_key_size);
    free(private_key);

    // Copy cert
    (*wvProvision)->oemDeviceCertificateLength = (unsigned int)oem_cert_size;
    (*wvProvision)->oemDeviceCertificate = malloc(oem_cert_size);
    if (!(*wvProvision)->oemDeviceCertificate) {
        SEC_LOG_ERROR("Memory allocation failed");
        free(oem_cert);
        return false;
    }
    memcpy((*wvProvision)->oemDeviceCertificate, oem_cert, oem_cert_size);
    free(oem_cert);

    return true;

}

void freeWidevineProvisioning(WidevineOemProvisioning* provision) {
    if (!provision) return;

    free(provision->oemDevicePrivateKey);
    free(provision->oemDeviceCertificate);
    free(provision);
}

void freeNetflixProvisioning(NetflixProvisioning* provision) {
    if (!provision) return;
    free(provision->encryptionKey);
    free(provision->hmacKey);
    free(provision->wrappingKey);
    free(provision->esnContainer);
    free(provision);
}

void freePlayReadyProvisioning(PlayReadyProvisioning* provision) {
    if (!provision) return;
    free(provision->privateKey);
    free(provision->modelCertificate);
    free(provision);
}

void freeAppleMfiProvisioning(AppleMfiProvisioning* provision) {
    if (!provision) return;
    free(provision->mfiBaseKey);
    free(provision->mfiProvisioningObject);
    free(provision);
}

void freeAppleFairPlayProvisioning(AppleFairPlayProvisioning* provision) {
    if (!provision) return;
    free(provision->fairPlaySecret);
    free(provision);
}

Sec_Result SecSocProv_SocVendorSpecific(SEC_OBJECTID object_id) {
    for (size_t i = 0; i < sizeof(Soc_object_ids) / sizeof(Soc_object_ids[0]); ++i) {
        if (Soc_object_ids[i] == object_id) {
            return SEC_RESULT_SUCCESS;
        }
    }
    return SEC_RESULT_FAILURE;
}

Sec_Result SecSocProv_Ta_Provision(Sec_ProcessorHandle* processorHandle, sa_key_type_soc_ta key_type) {
    Sec_Result status = SEC_RESULT_FAILURE;
   switch (key_type) {
    case WIDEVINE_OEM_SOC_PROVISIONING:
#if ENABLE_SOC_PROVISION_WIDEVINE
        SEC_LOG_ERROR("Handling Widevine provisioning");
        status = provisioning_ta(processorHandle, WIDEVINE_OBJ, WIDEVINE_OEM_SOC_PROVISIONING, sizeof(WidevineOemProvisioning)); 
#endif
        break;

    case PLAYREADY_MODEL_3K_SOC_PROVISIONING:
#if ENABLE_SOC_PROVISION_PLAYREADY_3K
        SEC_LOG_ERROR("Handling PlayReady 3K provisioning");
        status = provisioning_ta(processorHandle, PLAY_READY_OBJ, PLAYREADY_MODEL_3K_SOC_PROVISIONING, sizeof(PlayReadyProvisioning));
#endif
        break;

    case PLAYREADY_MODEL_2K_SOC_PROVISIONING:
#if ENABLE_SOC_PROVISION_PLAYREADY_2K
        SEC_LOG_ERROR("Handling PlayReady 2K provisioning");
        status = provisioning_ta(processorHandle, PLAY_READY_OBJ, PLAYREADY_MODEL_2K_SOC_PROVISIONING, sizeof(PlayReadyProvisioning));
#endif
        break;

    case APPLE_MFI_SOC_PROVISIONING:
#if ENABLE_SOC_PROVISION_APPLE_MFI
        SEC_LOG_ERROR("Handling Apple MFI provisioning");
        status = provisioning_ta(processorHandle, APPLE_MFI_OBJ, APPLE_MFI_SOC_PROVISIONING, sizeof(AppleMfiProvisioning));
#endif
        break;

    case APPLE_FAIRPLAY_SOC_PROVISIONING:
#if ENABLE_SOC_PROVISION_APPLE_FAIRPLAY
        SEC_LOG_ERROR("Handling Apple FairPlay provisioning");
        status = provisioning_ta(processorHandle, APPLE_FAIR_PLAY_OBJ, APPLE_FAIRPLAY_SOC_PROVISIONING, sizeof(AppleFairPlayProvisioning));
#endif
        break;

    case NETFLIX_SOC_PROVISIONING:
#if ENABLE_SOC_PROVISION_NETFLIX
        SEC_LOG_ERROR("Handling Netflix provisioning");
        status = provisioning_ta(processorHandle, NETFLIX_OBJ, NETFLIX_SOC_PROVISIONING, sizeof(NetflixProvisioning));
#endif
        break;

    default:
        SEC_LOG_ERROR("Unknown provisioning type");
        return SEC_RESULT_FAILURE;
    }
    return status; 
}


bool provisioning_ta(Sec_ProcessorHandle* processorHandle, size_t numPaths, sa_key_type_soc_ta provisioningType, size_t dataSize) {
    sa_status status;
    sa_import_parameters_soc* parameters = (sa_import_parameters_soc*)malloc(sizeof(sa_import_parameters_soc));
    if (!parameters) {
        SEC_LOG_ERROR("Failed to allocate memory");
        return false;
    }
    parameters->length[0] = (sizeof(sa_import_parameters_soc) >> 8) & 0xff;

    parameters->length[1] = sizeof(sa_import_parameters_soc) & 0xff;
    parameters->version = SA_SPECIFICATION_MAJOR;
    memset(&parameters->default_rights, 0, sizeof(parameters->default_rights));
    parameters->object_id = SEC_DUMMY_OBJECTID;

   switch (provisioningType) {
    case WIDEVINE_OEM_SOC_PROVISIONING:
        WidevineOemProvisioning* provisioningData = NULL;
        if (readWidevineData(processorHandle, &provisioningData) == false) {
            SEC_LOG_ERROR("Failed to read widevine provisioning data");
            return SEC_RESULT_FAILURE;
        }
        status = sa_key_provision_ta(WIDEVINE_OEM_PROVISIONING, provisioningData, dataSize, parameters);
        free(provisioningData);
        free(parameters);
        if (status != SA_STATUS_OK) {
            SEC_LOG_ERROR("Falied sa_key_provision_ta call in widevine");
            return SEC_RESULT_FAILURE;
        }
        SEC_LOG_ERROR("Widevine provisioning completed successfully");
        break;

    case PLAYREADY_MODEL_2K_SOC_PROVISIONING:
        PlayReadyProvisioning* playReadyprovisioning2kData = NULL;
        if (readPlayReadyData(processorHandle, &playReadyprovisioning2kData, PLAYREADY_MODEL_2K) == false) {
            SEC_LOG_ERROR("Failed to read PlayReady 2k provisioning data");
            return SEC_RESULT_FAILURE;
        }
        status = sa_key_provision_ta(PLAYREADY_MODEL_PROVISIONING, playReadyprovisioning2kData, dataSize, parameters);
        free(playReadyprovisioning2kData);
        free(parameters);
        if (status != SA_STATUS_OK) {
            SEC_LOG_ERROR("Falied sa_key_provision_ta call in playready 2k");
            return SEC_RESULT_FAILURE;
        }
        SEC_LOG_ERROR("PlayReady Model 2K provisioning completed successfully");
        break;
        
    case PLAYREADY_MODEL_3K_SOC_PROVISIONING:
        PlayReadyProvisioning* playReadyprovisioning3kData = NULL;
        if (readPlayReadyData(processorHandle, &playReadyprovisioning3kData, PLAYREADY_MODEL_3K) == false) {
            SEC_LOG_ERROR("Failed to read PlayReady 3k provisioning data");
            return SEC_RESULT_FAILURE;
        }
        status = sa_key_provision_ta(PLAYREADY_MODEL_PROVISIONING, playReadyprovisioning3kData, dataSize, parameters);
        free(playReadyprovisioning3kData);
        free(parameters);
        if (status != SA_STATUS_OK) {
            SEC_LOG_ERROR("Falied sa_key_provision_ta call in playready 3k");
            return SEC_RESULT_FAILURE;
        }
        SEC_LOG_ERROR("PlayReady Model 3K provisioning completed successfully");
        break;

    case APPLE_MFI_SOC_PROVISIONING:
        AppleMfiProvisioning* appleMfiprovisioningData = NULL;
        if (readAppleMfiData(processorHandle, &appleMfiprovisioningData) == false) {
            SEC_LOG_ERROR("Failed to read ApplaMFI provisioning data");
            return SEC_RESULT_FAILURE;
        }
        status = sa_key_provision_ta(APPLE_MFI_PROVISIONING, appleMfiprovisioningData, dataSize, parameters);
        free(appleMfiprovisioningData);
        free(parameters);
        if (status != SA_STATUS_OK) {
            SEC_LOG_ERROR("Failed to call sa_key_provision_ta in Apple_Mfi");
            return SEC_RESULT_FAILURE;
        }
        SEC_LOG_ERROR("Apple_Mfi provisioning completed successfully");
        break;

    case APPLE_FAIRPLAY_SOC_PROVISIONING:
        AppleFairPlayProvisioning* appleFairplayProvisioningData = NULL;
        if (readAppleFairPlayData(processorHandle, &appleFairplayProvisioningData) == false) {
            SEC_LOG_ERROR("Failed to read ApplyFairplay provisioning data");
            return SEC_RESULT_FAILURE;
        }
        status = sa_key_provision_ta(APPLE_FAIRPLAY_PROVISIONING, appleFairplayProvisioningData, dataSize, parameters);
        free(appleFairplayProvisioningData);
        free(parameters);
        if (status != SA_STATUS_OK) {
            SEC_LOG_ERROR("Failed to call sa_key_provision_ta in AppleFairplay");
            return SEC_RESULT_FAILURE;
        }
        SEC_LOG_ERROR("AppeFairplay provisioning completed successfully");
        break;

    case NETFLIX_SOC_PROVISIONING:
        SEC_LOG_ERROR("Handling Netflix provisioning");
        NetflixProvisioning* netflixProvisioningData = NULL;
        if (readNetflixData(processorHandle, &netflixProvisioningData) == false) {
            SEC_LOG_ERROR("Failed to read Netflix provisioning data");
            return SEC_RESULT_FAILURE;
        }
        status = sa_key_provision_ta(NETFLIX_PROVISIONING, netflixProvisioningData, dataSize, parameters);
        free(netflixProvisioningData);
        free(parameters);
        if (status != SA_STATUS_OK) {
            SEC_LOG_ERROR("Failed to call sa_key_provision_ta in Netflix");
            return SEC_RESULT_FAILURE;
        }
        SEC_LOG_ERROR("Netflix provisioning completed successfully");
        break;

    default:
        free(parameters);
        SEC_LOG_ERROR("Unknown provisioning type");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}
Sec_Result store_raw_data(Sec_ProcessorHandle* processorHandle, Sec_StorageLoc location, SEC_OBJECTID object_id,
    SEC_BYTE* data, SEC_SIZE data_length) {

    Sec_Result status = SEC_RESULT_FAILURE;
    char file_name[SEC_MAX_FILE_PATH_LEN];

    snprintf(file_name, sizeof(file_name), "%s" SEC_KEY_FILENAME_PATTERN, processorHandle->app_dir,
                object_id);

    if (SecUtils_WriteFile(file_name, data, data_length) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("Write failed for file :%s", file_name);
        return SEC_RESULT_FAILURE;
    }
    return SEC_RESULT_SUCCESS;
}
