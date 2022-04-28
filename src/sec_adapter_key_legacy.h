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

#ifndef SEC_ADAPTER_KEY_LEGACY_H
#define SEC_ADAPTER_KEY_LEGACY_H

#define VERSION_2_KEY_CONTAINER 2

/**
 * Import parameters for a Legacy SOC. This structure is used to signal the version of the Legacy
 * key container. This structure is required for SecApi 2 (non-JWT) key containers and is optional for SecApi
 * 3 (or JWT) key containers. If the sa_key_import parameters field is NULL, a SecApi 3 (JWT) key container is
 * assumed.
 */
typedef struct {
    /** The size of this structure. The most significant size byte is in length[0] and the least
        significant size byte is in length[1]. */
    uint8_t length[2];

    /** The version of the key container. Must be either version 2 or version 3. */
    uint8_t version;

    /** The default key rights to use only if the key container does not contain included key rights. */
    sa_rights default_rights;

    uint64_t object_id;
} sa_import_parameters_soc_legacy;

#endif // SEC_ADAPTER_KEY_LEGACY_H
