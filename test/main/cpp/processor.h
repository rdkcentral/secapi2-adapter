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

#ifndef PROCESSOR_H
#define PROCESSOR_H

#include "sec_security.h"

Sec_Result testProcessorPrintInfo();

Sec_Result testProcessorGetDeviceId();

Sec_Result testProcessorGetKeyLadderMinMaxDepth(Sec_KeyLadderRoot root);

Sec_Result testProcessorNativeMallocFree();

Sec_Result testProcessorGetInfo();

Sec_Result testProcessorInitReleaseInit();

#endif // PROCESSOR_H
