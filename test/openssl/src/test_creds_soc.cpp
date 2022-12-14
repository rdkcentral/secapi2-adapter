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

#include "sa_types.h"
#include "sec_security_utils.h"
#include "test_creds.h"
#include "test_ctx.h"
#include <memory>
#include <sa_soc_key_container.h>

#define SEC_OBJECTID_OPENSSL_KPK SEC_OBJECTID_RESERVEDPLATFORM_7

static std::vector<SEC_BYTE> random(SEC_SIZE len) {
    std::vector<SEC_BYTE> res;
    res.resize(len);

    if (RAND_bytes(res.data(), static_cast<int>(len)) != OPENSSL_SUCCESS) {
        SEC_LOG_ERROR("RAND_bytes failed");
        return {};
    }

    return res;
}

static void rights_set_allow_all(sa_rights* rights, Sec_KeyContainer key_type) {
    memset(rights->id, 0, sizeof(rights->id));

    rights->not_before = 0;
    rights->not_on_or_after = UINT64_MAX;

    rights->usage_flags = 0;
    SA_USAGE_BIT_SET(rights->usage_flags, SA_USAGE_FLAG_KEY_EXCHANGE);
    SA_USAGE_BIT_SET(rights->usage_flags, SA_USAGE_FLAG_DERIVE);
    SA_USAGE_BIT_SET(rights->usage_flags, SA_USAGE_FLAG_UNWRAP);
    SA_USAGE_BIT_SET(rights->usage_flags, SA_USAGE_FLAG_ENCRYPT);
    SA_USAGE_BIT_SET(rights->usage_flags, SA_USAGE_FLAG_DECRYPT);
    SA_USAGE_BIT_SET(rights->usage_flags, SA_USAGE_FLAG_SIGN);
    rights->usage_flags |= SA_USAGE_OUTPUT_PROTECTIONS_MASK;
    SA_USAGE_BIT_SET(rights->usage_flags, SA_USAGE_FLAG_CACHEABLE);

    memset(rights->allowed_tas, 0, sizeof(rights->allowed_tas));

    const sa_uuid ALL_MATCH = {
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    memcpy(&rights->allowed_tas[7], &ALL_MATCH, sizeof(sa_uuid));
}

std::string TestCreds::b64_encode(
        const void* in,
        size_t in_length) {

    if (in == nullptr) {
        SEC_LOG_ERROR("NULL in");
        throw;
    }

    std::shared_ptr<BIO> b64(BIO_new(BIO_f_base64()), BIO_free_all);
    BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);

    BIO* sink = BIO_new(BIO_s_mem());
    if (sink == nullptr) {
        SEC_LOG_ERROR("BIO_new failed");
        throw;
    }

    BIO_push(b64.get(), sink);

    if (BIO_write(b64.get(), in, static_cast<int>(in_length)) < 0) {
        SEC_LOG_ERROR("BIO_write failed");
        throw;
    }

    if (BIO_flush(b64.get()) < 0) {
        SEC_LOG_ERROR("BIO_flush failed");
        throw;
    }

    const char* encoded;
    const uint64_t len = BIO_get_mem_data(sink, &encoded); // NOLINT
    return {encoded, len};
}

ProvKey* TestCreds::getSocKey(TestKey key, SEC_OBJECTID id) {
    ProvKey* pk = TestCreds::getKey(key, TESTKC_RAW, id);
    if (pk == nullptr) {
        return nullptr;
    }

    std::vector<uint8_t> key_clear;

    std::string key_type;
    switch (pk->kc) {
        case SEC_KEYCONTAINER_DER_RSA_1024:
        case SEC_KEYCONTAINER_DER_RSA_2048: {
            RSA* rsa = SecUtils_RSAFromDERPriv(&pk->key[0], pk->key.size());
            if (rsa == nullptr) {
                SEC_LOG_ERROR("SecUtils_RSAFromDERPriv failed ");
                delete pk;
                return nullptr;
            }

            SEC_SIZE written;
            key_clear.resize(SEC_KEYCONTAINER_MAX_LEN);
            if (SecUtils_RSAToDERPrivKeyInfo(rsa, key_clear.data(), key_clear.size(), &written) != SEC_RESULT_SUCCESS) {
                SEC_LOG_ERROR("SecUtils_RSAToDERPrivKeyInfo failed");
                SEC_RSA_FREE(rsa);
                delete pk;
                return nullptr;
            }

            SEC_RSA_FREE(rsa);

            key_clear.resize(written);
            key_type = pk->kc == SEC_KEYCONTAINER_DER_RSA_1024 ? "RSA-1024" : "RSA-2048";
        } break;

        case SEC_KEYCONTAINER_DER_ECC_NISTP256: {
            EC_KEY* ec_key = SecUtils_ECCFromDERPriv(&pk->key[0], pk->key.size());
            if (ec_key == nullptr) {
                SEC_LOG_ERROR("SecUtils_ECCFromDERPriv failed ");
                delete pk;
                return nullptr;
            }

            SEC_SIZE written;
            key_clear.resize(SEC_KEYCONTAINER_MAX_LEN);
            if (SecUtils_ECCToDERPrivKeyInfo(ec_key, key_clear.data(), key_clear.size(),
                        &written) != SEC_RESULT_SUCCESS) {
                SEC_LOG_ERROR("SecUtils_ECCToPrivBinary failed");
                SEC_ECC_FREE(ec_key);
                delete pk;
                return nullptr;
            }

            key_clear.resize(written);
            SEC_ECC_FREE(ec_key);
            key_type = "ECC-P256";
        } break;

        case SEC_KEYCONTAINER_RAW_AES_128: {
            key_clear.resize(pk->key.size());
            memcpy(key_clear.data(), &pk->key[0], pk->key.size());
            key_type = "AES-128";
        } break;

        case SEC_KEYCONTAINER_RAW_AES_256: {
            key_clear.resize(pk->key.size());
            memcpy(key_clear.data(), &pk->key[0], pk->key.size());
            key_type = "AES-256";
        } break;

        case SEC_KEYCONTAINER_RAW_HMAC_128: {
            key_clear.resize(pk->key.size());
            memcpy(key_clear.data(), &pk->key[0], pk->key.size());
            key_type = "HMAC-128";
        } break;

        case SEC_KEYCONTAINER_RAW_HMAC_160: {
            key_clear.resize(pk->key.size());
            memcpy(key_clear.data(), &pk->key[0], pk->key.size());
            key_type = "HMAC-160";
        } break;

        case SEC_KEYCONTAINER_RAW_HMAC_256: {
            key_clear.resize(pk->key.size());
            memcpy(key_clear.data(), &pk->key[0], pk->key.size());
            key_type = "HMAC-256";
        } break;

        default:
            SEC_LOG_ERROR("Unexpected kc encountered");
            delete pk;
            return nullptr;
    }

    std::vector<uint8_t> tag;
    std::vector<uint8_t> kc = generate_sa_soc_key_container(key_clear, key_type, tag);

    delete pk;
    return new ProvKey(kc, SEC_KEYCONTAINER_SOC);
}

Sec_Result TestCreds::preprovisionSoc(TestCtx* ctx) {
    //Here the soc vendors should add code to preprovision any credentials that
    //are required for the rest of the system to operate properly.

    //For most platforms this can stay a NOP

    //provision kpk
    ctx->provisionKey(SEC_OBJECTID_OPENSSL_KPK, SEC_STORAGELOC_RAM, TESTKEY_AES128, TESTKC_RAW, SEC_TRUE);

    return SEC_RESULT_SUCCESS;
}

bool TestCreds::supports(Capability cap) {
    //return whether a specific capability is supported in the target soc
#ifdef ENABLE_SOC_KEY_TESTS
    return cap != CAPABILITY_HKDF_CMAC;
#else
    return cap != CAPABILITY_HKDF_CMAC && cap != CAPABILITY_LOAD_SYM_SOC_KC;
#endif
}

void TestCreds::init() {
}

void TestCreds::shutdown() {
}
