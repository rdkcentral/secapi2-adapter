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

#include "sa.h"
#include "sec_adapter_processor.h"
#include "sec_security.h"

struct Sec_RandomHandle_struct {
    Sec_ProcessorHandle* processorHandle;
};

/**
 * @brief Obtain a handle to the random number generator.
 *
 * @param processorHandle secure processor handle.
 * @param algorithm random number algorithm to use.
 * @param randomHandle output handle for the random number generator.
 *
 * @return The status of the operation.
 */
Sec_Result SecRandom_GetInstance(Sec_ProcessorHandle* processorHandle, Sec_RandomAlgorithm algorithm,
        Sec_RandomHandle** randomHandle) {
    CHECK_PROCHANDLE(processorHandle)

    if (randomHandle == NULL) {
        SEC_LOG_ERROR("signatureHandle is NULL");
        return SEC_RESULT_FAILURE;
    }

    *randomHandle = malloc(sizeof(Sec_RandomHandle));
    if (*randomHandle == NULL)
        return SEC_RESULT_FAILURE;

    (*randomHandle)->processorHandle = processorHandle;
    return SEC_RESULT_SUCCESS;
}

/**
 * @brief Generate random data.
 *
 * @param randomHandle random number generator handle.
 * @param output pointer to the output buffer where the random data will be stored.
 * @param outputSize the size of the output buffer.
 *
 * @return The status of the operation.
 */
Sec_Result SecRandom_Process(Sec_RandomHandle* randomHandle, SEC_BYTE* output, SEC_SIZE outputSize) {
    CHECK_HANDLE(randomHandle)
    int status = sa_crypto_random(output, outputSize);
    CHECK_STATUS(status)
    return SEC_RESULT_SUCCESS;
}

/**
 * @brief Release the random object.
 *
 * @param randomHandle random handle.
 *
 * @return The status of the operation.
 */
Sec_Result SecRandom_Release(Sec_RandomHandle* randomHandle) {
    SEC_FREE(randomHandle);
    return SEC_RESULT_SUCCESS;
}

/**
 * @brief Utility function for filling out a random value.
 *
 * @param proc secure processor handle.
 * @param alg random algorithm to use.
 * @param output output buffer where the random value will be written.
 * @param output_len number of bytes written to the output buffer.
 *
 * @return status of the operation.
 */
Sec_Result SecRandom_SingleInput(Sec_ProcessorHandle* processorHandle, Sec_RandomAlgorithm alg, SEC_BYTE* output,
        SEC_SIZE output_len) {
    Sec_Result result;
    Sec_RandomHandle* randomHandle = NULL;

    result = SecRandom_GetInstance(processorHandle, alg, &randomHandle);
    if (result != SEC_RESULT_SUCCESS)
        return result;

    result = SecRandom_Process(randomHandle, output, output_len);
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecRandom_Process failed");
        SecRandom_Release(randomHandle);
        return result;
    }

    SecRandom_Release(randomHandle);
    return result;
}
