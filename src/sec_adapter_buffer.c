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

#include "sec_security.h"
#include <memory.h>

/**
 * @brief initialize the Sec_Buffer structure.
 *
 * @param buffer Sec_Buffer structure to initialize.
 * @param mem memory buffer to use.
 * @param len size of the memory buffer.
 */
void SecBuffer_Init(Sec_Buffer* buffer, void* mem, SEC_SIZE len) {
    buffer->base = (SEC_BYTE*) mem;
    buffer->size = len;
    buffer->written = 0;
}

/**
 * @brief reset the buffer.
 *
 * @param buffer Sec_Buffer structure to initialize.
 */
void SecBuffer_Reset(Sec_Buffer* buffer) {
    buffer->written = 0;
}

/**
 * @brief Write data to a buffer.
 *
 * @param buffer pointer to a Sec_Buffer structure to use.
 * @param data input data to write.
 * @param len length of input data.
 *
 * @return Status of the operation.  Error status will be returned if there
 * is not enough space left in the output buffer.
 * @return The status of the operation.
 */
Sec_Result SecBuffer_Write(Sec_Buffer* buffer, void* data, SEC_SIZE len) {
    SEC_SIZE space_left = buffer->size - buffer->written;

    if (space_left < 0 || space_left < len)
        return SEC_RESULT_BUFFER_TOO_SMALL;

    memcpy(buffer->base + buffer->written, data, len);
    buffer->written += len;

    return SEC_RESULT_SUCCESS;
}
