/**
 * Copyright 2020-2021 Comcast Cable Communications Management, LLC
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

#ifndef SA_SOC_KEY_CONTAINER_H
#define SA_SOC_KEY_CONTAINER_H

#include <cstdint>
#include <string>
#include <vector>

std::vector<uint8_t> generate_sa_soc_key_container(std::vector<uint8_t>& key_clear, std::string& key_type,
        std::vector<uint8_t>& tag);

#endif
