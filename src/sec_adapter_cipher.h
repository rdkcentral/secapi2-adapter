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

#ifndef SEC_ADAPTER_CIPHER_H
#define SEC_ADAPTER_CIPHER_H

#include "sa_types.h"
#include "sec_adapter_processor.h"
#include "sec_security_svp.h"
#include "sec_security_utils.h"
#include "sec_security.h"
#include <memory.h>
#include <openssl/rsa.h>

Sec_Result get_cipher_algorithm(Sec_CipherAlgorithm algorithm, SEC_BOOL is_unwrap,
        sa_cipher_algorithm* cipher_algorithm, void** parameters, void* iv, SEC_SIZE key_length, SEC_SIZE key_offset);

#endif // SEC_ADAPTER_CIPHER_H
