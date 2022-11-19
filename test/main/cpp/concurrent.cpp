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

#include "concurrent.h" // NOLINT
#include "cipher.h"
#include "key.h"
#include "test_ctx.h"

struct Vendor128Args { // NOLINT(altera-struct-pack-align)
    SEC_OBJECTID id;
    Sec_Result result;
};

void* concurrent_vendor128(void* arg) {
    auto* args = static_cast<Vendor128Args*>(arg);

    args->result = testKeyDeriveKeyLadderAes128(
            args->id,
            SEC_KEYTYPE_AES_128,
            SEC_STORAGELOC_RAM,
            SEC_KEYLADDERROOT_UNIQUE,
            SEC_TRUE);

    return nullptr;
}

Sec_Result testConcurrentVendor128(SEC_SIZE numThreads) {

    std::vector<pthread_t> threads;
    std::vector<Vendor128Args> args;
    threads.resize(numThreads);
    args.resize(numThreads);

    SEC_PRINT("Spawning %d threads\n", numThreads);
    for (unsigned int i = 0; i < threads.size(); ++i) {
        args[i].id = SEC_OBJECTID_USER_BASE + i;

        pthread_create(&threads[i], nullptr, concurrent_vendor128, &args[i]);
    }

    SEC_PRINT("Waiting for threads to complete\n");
    for (auto& thread : threads) {
        pthread_join(thread, nullptr);
    }

    SEC_PRINT("Threads completed\n");

    //check results
    SEC_PRINT("Checking results\n");
    for (auto& arg : args) {
        if (arg.result != SEC_RESULT_SUCCESS) {
            return SEC_RESULT_FAILURE;
        }
    }

    return SEC_RESULT_SUCCESS;
}

struct RsaArgs {
    SEC_OBJECTID id;
    TestKey pub;
    TestKey priv;
    TestKc kc;

    Sec_Result result;
} __attribute__((aligned(32)));

void* concurrent_rsa(void* arg) {
    auto* args = static_cast<RsaArgs*>(arg);

    args->result = testCipherSingle(
            args->id,
            args->pub,
            args->priv,
            args->kc,
            SEC_STORAGELOC_RAM,
            SEC_CIPHERALGORITHM_RSA_PKCS1_PADDING,
            SEC_CIPHERMODE_DECRYPT,
            SEC_AES_BLOCK_SIZE);

    return nullptr;
}

Sec_Result testConcurrentRsa(TestKey pub, TestKey priv, TestKc kc, SEC_SIZE numThreads) {

    std::vector<pthread_t> threads;
    std::vector<RsaArgs> args;
    threads.resize(numThreads);
    args.resize(numThreads);

    SEC_PRINT("Spawning %d threads\n", numThreads);
    for (unsigned int i = 0; i < threads.size(); ++i) {
        args[i].id = SEC_OBJECTID_USER_BASE + i;
        args[i].pub = pub;
        args[i].priv = priv;
        args[i].kc = kc;

        pthread_create(&threads[i], nullptr, concurrent_rsa, &args[i]);
    }

    SEC_PRINT("Waiting for threads to complete\n");
    for (auto& thread : threads) {
        pthread_join(thread, nullptr);
    }

    SEC_PRINT("Threads completed\n");

    //check results
    SEC_PRINT("Checking results\n");
    for (auto& arg : args) {
        if (arg.result != SEC_RESULT_SUCCESS) {
            return SEC_RESULT_FAILURE;
        }
    }

    return SEC_RESULT_SUCCESS;
}

static void* testProcessorGetDeviceId(void* arg) {
    auto* ctx = static_cast<TestCtx*>(arg);
    SEC_BYTE device_id[SEC_DEVICEID_LEN];
    Sec_Result result = SecProcessor_GetDeviceId(ctx->proc(), device_id);
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecProcessor_GetDeviceId failed %d", result);
        return reinterpret_cast<void*>(result); // NOLINT
    }

    return reinterpret_cast<void*>(SEC_RESULT_SUCCESS); // NOLINT
}

Sec_Result testConcurrentProcessorInvoke(SEC_SIZE numThreads) {
    std::vector<pthread_t> threads;
    threads.resize(numThreads);

    TestCtx ctx;
    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    SEC_PRINT("Spawning %d threads\n", numThreads);
    for (uint64_t& thread : threads) {
        pthread_create(&thread, nullptr, testProcessorGetDeviceId, &ctx);
    }

    SEC_PRINT("Waiting for threads to complete\n");
    bool failed = false;
    for (auto& thread : threads) {
        void* return_val;
        pthread_join(thread, reinterpret_cast<void**>(&return_val));
        if (reinterpret_cast<intptr_t>(return_val) != SEC_RESULT_SUCCESS)
            failed = true;
    }

    SEC_PRINT("Threads completed\n");
    return failed ? SEC_RESULT_FAILURE : SEC_RESULT_SUCCESS;
}
