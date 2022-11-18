/**
 * Copyright 2020 Comcast Cable Communications Management, LLC
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

#ifndef SEC_ADAPTER_PROCESSOR_H
#define SEC_ADAPTER_PROCESSOR_H

#include "sa_types.h"
#include "sa_ta_types.h"
#include "sec_adapter_key.h"
#include "sec_security.h"
#include "sec_security_store.h"
#include "sec_security_utils.h"
#include "sec_version.h"
#include <memory.h>
#include <openssl/err.h>
#include <pthread.h>

#ifdef __cplusplus
#include <cstdint>
#else
#include <stdint.h>
#endif

#define MAX_QUEUE_SIZE 32

typedef struct {
    SA_COMMAND_ID command_id;
    va_list* arguments;
    sa_status result;
} sa_command;

typedef struct {
    SEC_BYTE input1[SEC_AES_BLOCK_SIZE];
    SEC_BYTE input2[SEC_AES_BLOCK_SIZE];
    SEC_BYTE input3[SEC_AES_BLOCK_SIZE];
    SEC_BYTE input4[SEC_AES_BLOCK_SIZE];
} SecAdapter_DerivedInputs;

typedef struct {
    SEC_BYTE mac[SEC_MAC_MAX_LEN];
    SEC_SIZE cert_len;
    SEC_BYTE cert[SEC_CERT_MAX_DATA_LEN];
} Sec_CertificateData;

typedef struct {
    SEC_BYTE bundle[SEC_BUNDLE_MAX_LEN];
    SEC_SIZE bundle_len;
} Sec_BundleData;

typedef struct Sec_RAMKeyData_struct {
    SEC_OBJECTID object_id;
    Sec_KeyData key_data;
    struct Sec_RAMKeyData_struct* next;
} Sec_RAMKeyData;

typedef struct Sec_RAMCertificateData_struct {
    SEC_OBJECTID object_id;
    Sec_CertificateData cert_data;
    struct Sec_RAMCertificateData_struct* next;
} Sec_RAMCertificateData;

typedef struct Sec_RAMBundleData_struct {
    SEC_OBJECTID object_id;
    Sec_BundleData bundle_data;
    struct Sec_RAMBundleData_struct* next;
} Sec_RAMBundleData;

struct Sec_ProcessorHandle_struct {
    Sec_RAMKeyData* ram_keys;
    Sec_RAMBundleData* ram_bundles;
    Sec_RAMCertificateData* ram_certs;
    char* global_dir;
    char* app_dir;
    int device_settings_init_flag;
    pthread_t thread;
    pthread_cond_t cond;
    pthread_mutex_t mutex;
    bool shutdown;
    sa_command* queue[MAX_QUEUE_SIZE];
    size_t queue_front;
    size_t queue_size;
};

static const int SECAPI3_KEY_DEPTH = 4;

#define SEC_APP_DIR_DEFAULT "./"
#define SEC_GLOBAL_DIR_DEFAULT "/opt/drm"

#define CHECK_PROCHANDLE(handle) CHECK_HANDLE(handle)

#define CHECK_HANDLE(handle) \
    if ((handle) == NULL) { \
        SEC_LOG_ERROR("Invalid handle"); \
        return SEC_RESULT_INVALID_HANDLE; \
    }

#define CHECK_STATUS(status) \
    switch (status) { \
        case SA_STATUS_OK: \
            break; \
        case SA_STATUS_NO_AVAILABLE_RESOURCE_SLOT: \
            return SEC_RESULT_NO_KEYSLOTS_AVAILABLE; \
        case SA_STATUS_INVALID_KEY_TYPE: \
        case SA_STATUS_NULL_PARAMETER: \
        case SA_STATUS_INVALID_PARAMETER: \
            return SEC_RESULT_INVALID_PARAMETERS; \
        case SA_STATUS_INVALID_SVP_BUFFER: \
            return SEC_RESULT_INVALID_SVP_DATA; \
        case SA_STATUS_OPERATION_NOT_SUPPORTED: \
            return SEC_RESULT_UNIMPLEMENTED_FEATURE; \
        case SA_STATUS_VERIFICATION_FAILED: \
            return SEC_RESULT_VERIFICATION_FAILED; \
        case SA_STATUS_INVALID_KEY_FORMAT: \
        case SA_STATUS_OPERATION_NOT_ALLOWED: \
        case SA_STATUS_SELF_TEST: \
        case SA_STATUS_INTERNAL_ERROR: \
        default: \
            return SEC_RESULT_FAILURE; \
    }

sa_status sa_invoke(Sec_ProcessorHandle* processorHandle, SA_COMMAND_ID command_id, ...);

#endif // SEC_ADAPTER_PROCESSOR_H
