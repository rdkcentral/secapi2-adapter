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

#ifndef SEC_ADAPTER_BUNDLE_H
#define SEC_ADAPTER_BUNDLE_H

#include "sec_adapter_processor.h"
#include "sec_security_utils.h"
#include <memory.h>

void Sec_FindRAMBundleData(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID object_id, Sec_RAMBundleData** data,
        Sec_RAMBundleData** parent);

#endif // SEC_ADAPTER_BUNDLE_H
