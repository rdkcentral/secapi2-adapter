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

#include "sec_security.h"
#include <string.h>

#define BUFFER_SIZE 1024

SecApiLogCallback g_sec_logcb = Sec_DefaultLoggerCb;

void Sec_SetLogger(SecApiLogCallback cb) {
    g_sec_logcb = cb;
}

SecApiLogCallback Sec_GetLogger(void) {
    return g_sec_logcb;
}

void Sec_DefaultLoggerCb(const char* fmt, ...) {
    va_list args;

    va_start(args, fmt);
    vfprintf(stdout, fmt, args); // NOLINT
    va_end(args);

    fflush(stdout);
}

void Sec_PrintHex(void* data, SEC_SIZE numBytes) {
    char buffer[BUFFER_SIZE];
    memset(buffer, 0, sizeof(buffer));
    char* ptr = buffer;

    size_t maxBytes = (sizeof(buffer) - 1) / 2;

    SEC_BYTE* data_ptr = (SEC_BYTE*) data;
    SEC_SIZE i;

    for (i = 0; i < SEC_MIN(maxBytes, numBytes); ++i) {
        int result = sprintf(ptr, "%02x", data_ptr[i]);
        if (result < 0)
            break;

        ptr += result;
    }

    SEC_PRINT(buffer);
}

/**
 * @brief NOP logger implementation
 */
void Sec_NOPLoggerCb(const char* fmt, ...) {
    // NOOP
}
