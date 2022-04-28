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

#ifndef SEC_ADAPTER_KEY_H
#define SEC_ADAPTER_KEY_H

#include "sa.h"
#include "sec_security.h"
#include "sec_security_comcastids.h"
#include <openssl/engine.h>

typedef union Sec_Key_union {
    // if key_type is SEC_KEYTYPE_RSA_XXXX_PUBLIC
    RSA* rsa;
    // if key_type is SEC_KEYTYPE_ECC_NISTP256_PUBLIC
    EC_KEY* ec_key;
    // if key_type is anything else
    sa_key handle;
} Sec_Key;

typedef struct Sec_KeyInfo_struct {
    // This field is effectively unused, but is maintained for backward compatibility.
    Sec_KeyType key_type;
    Sec_KeyContainer kc_type;
} Sec_KeyInfo;

typedef struct Sec_KeyData_struct {
    Sec_KeyInfo info;
    SEC_BYTE key_container[SEC_KEYCONTAINER_MAX_LEN];
    SEC_SIZE kc_len;
} Sec_KeyData;

void rights_set_allow_all(sa_rights* rights, Sec_KeyType key_type);

Sec_Result prepare_and_store_key_data(Sec_ProcessorHandle* processorHandle, Sec_StorageLoc location,
        SEC_OBJECTID object_id, Sec_Key* key, Sec_KeyContainer key_container, void* key_buffer, SEC_SIZE key_length);

const Sec_Key* get_key(Sec_KeyHandle* keyHandle);

#endif // SEC_ADAPTER_KEY_H
