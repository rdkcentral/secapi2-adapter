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

#include "bundle.h"
#include "sec_security_utils.h"
#include "test_ctx.h"

Sec_Result testBundleProvision(SEC_OBJECTID id, Sec_StorageLoc loc, SEC_SIZE size) {
    TestCtx ctx;
    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    std::vector<SEC_BYTE> bundle = TestCtx::random(size);

    Sec_BundleHandle* bundleHandle;
    if ((bundleHandle = ctx.provisionBundle(id, loc, bundle)) == nullptr) {
        SEC_LOG_ERROR("TestCtx.provisionBundle failed");
        return SEC_RESULT_FAILURE;
    }

    //get bundle size
    SEC_SIZE written;
    if (SecBundle_Export(bundleHandle, nullptr, 0, &written) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecBundle_Export failed");
        return SEC_RESULT_FAILURE;
    }

    //export bundle
    std::vector<SEC_BYTE> out;
    out.resize(written);
    if (SecBundle_Export(bundleHandle, &out[0], size, &written) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecBundle_Export failed");
        return SEC_RESULT_FAILURE;
    }

    out.resize(written);

    if (out != bundle) {
        SEC_LOG_ERROR("Exported bundle does not match");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result testBundleProvisionNoSha(SEC_OBJECTID id) {
    TestCtx ctx;
    if (ctx.init("/tmp/sec_api_test_global", "/tmp/sec_api_test_app") != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    std::vector<SEC_BYTE> bundle = TestCtx::random(256);

    Sec_BundleHandle* bundleHandle;
    if ((bundleHandle = ctx.provisionBundle(id, SEC_STORAGELOC_FILE, bundle)) == nullptr) {
        SEC_LOG_ERROR("ctx.provisionBundle failed");
        return SEC_RESULT_FAILURE;
    }

    ctx.releaseBundle(bundleHandle);

    char file_name_verification[SEC_MAX_FILE_PATH_LEN];
    snprintf(file_name_verification, sizeof(file_name_verification), SEC_VERIFICATION_FILENAME_PATTERN,
            "/tmp/sec_api_test_app/", id); SecUtils_RmFile(file_name_verification);
    if ((bundleHandle = ctx.getBundle(id)) == nullptr) {
        SEC_LOG_ERROR("ctx.getBundle failed");
        return SEC_RESULT_FAILURE;
    }

    //get bundle size
    SEC_SIZE written;
    if (SecBundle_Export(bundleHandle, nullptr, 0, &written) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecBundle_Export failed");
        return SEC_RESULT_FAILURE;
    }

    //export bundle
    std::vector<SEC_BYTE> out;
    out.resize(written);
    if (SecBundle_Export(bundleHandle, &out[0], 256, &written) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecBundle_Export failed");
        return SEC_RESULT_FAILURE;
    }

    out.resize(written);

    if (out != bundle) {
        SEC_LOG_ERROR("Exported bundle does not match");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result testBundleProvisionNoAppDir(SEC_OBJECTID id, SEC_SIZE size) {
    TestCtx ctx;
    if (ctx.init("/tmp", nullptr) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    std::vector<SEC_BYTE> bundle = TestCtx::random(size);

    if (SecBundle_Provision(ctx.proc(), id, SEC_STORAGELOC_FILE, static_cast<SEC_BYTE*>(&bundle[0]), bundle.size()) ==
            SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecBundle_Provision succeeded, but expected to fail");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}
