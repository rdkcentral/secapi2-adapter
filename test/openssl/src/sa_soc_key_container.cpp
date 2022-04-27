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

#include "sa_soc_key_container.h" // NOLINT
#include "cipher.h"
#include <sec_security.h>
#include <sstream>

static std::vector<std::string> ENTITLED_TA_IDS = {
        "157f768f-bad0-470b-929d-0d7dec29d220",
        "157f768f-bad0-470b-929d-0d7dec29d221",
        "157f768f-bad0-470b-929d-0d7dec29d222",
        "157f768f-bad0-470b-929d-0d7dec29d223",
        "157f768f-bad0-470b-929d-0d7dec29d224",
        "157f768f-bad0-470b-929d-0d7dec29d225",
        "157f768f-bad0-470b-929d-0d7dec29d226",
        "00000000-0000-0000-0000-000000000001"};

static std::vector<uint8_t> TEST_C1 = {
        0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
        0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef};

static std::vector<uint8_t> TEST_C2 = {
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22};

static std::vector<uint8_t> TEST_C3 = {
        0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
        0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33};

static std::vector<uint8_t> TEST_IV = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC};

static std::vector<SEC_BYTE> derive_container_encryption_key(
        std::vector<SEC_BYTE>& c1,
        std::vector<SEC_BYTE>& c2,
        std::vector<SEC_BYTE>& c3) {

    auto stage1 = opensslAesEcb(TESTKEY_ROOT, SEC_CIPHERMODE_DECRYPT, SEC_FALSE, nullptr, c1);
    if (stage1.empty() || stage1.size() != 16)
        return {};

    auto stage2 = opensslAesEcb(stage1, SEC_CIPHERMODE_DECRYPT, SEC_FALSE, nullptr, c2);
    if (stage2.empty() || stage2.size() != 16)
        return {};

    auto stage3 = opensslAesEcb(stage2, SEC_CIPHERMODE_DECRYPT, SEC_FALSE, nullptr, c3);
    if (stage3.empty() || stage3.size() != 16)
        return {};

    return stage3;
}

std::string generate_encrypted_key(
        uint8_t container_version,
        std::string& key_type,
        std::vector<uint8_t>& key,
        std::vector<uint8_t>& iv,
        uint8_t key_usage,
        uint8_t decrypted_key_usage,
        std::vector<std::string>& entitled_ta_ids,
        std::vector<uint8_t>& c1,
        std::vector<uint8_t>& c2,
        std::vector<uint8_t>& c3,
        std::vector<uint8_t>& tag) {

    std::string alg = "A128GCM";
    std::vector<uint8_t> aad;
    aad.insert(aad.end(), alg.begin(), alg.end());
    aad.insert(aad.end(), container_version);
    aad.insert(aad.end(), key_type.begin(), key_type.end());
    aad.insert(aad.end(), key_usage);
    if (container_version >= 3 && key_usage == 2)
        aad.insert(aad.end(), decrypted_key_usage);

    aad.insert(aad.end(), iv.begin(), iv.end());
    aad.insert(aad.end(), c1.begin(), c1.end());
    aad.insert(aad.end(), c2.begin(), c2.end());
    aad.insert(aad.end(), c3.begin(), c3.end());
    for (auto& ta_id : entitled_ta_ids) {
        aad.insert(aad.end(), ta_id.begin(), ta_id.end());
    }

    tag.resize(16);

    auto derived_key = derive_container_encryption_key(c1, c2, c3);
    if (derived_key.empty())
        return "";

    std::vector<uint8_t> encrypted_key = opensslAesGcm(derived_key, SEC_CIPHERMODE_ENCRYPT, iv.data(), aad.data(),
            aad.size(), tag.data(), tag.size(), key);

    if (encrypted_key.empty())
        return "";

    return TestCreds::b64_encode(encrypted_key.data(), encrypted_key.size());
}

std::string generate_header() {
    std::string hdr = R"({"alg": "A128GCM"})";
    return TestCreds::b64_encode(hdr.data(), hdr.size());
}

std::string generate_payload(
        uint8_t container_version,
        std::string& key_type,
        std::vector<uint8_t>& key,
        std::vector<uint8_t>& iv,
        uint8_t key_usage,
        uint8_t decrypted_key_usage,
        std::vector<std::string>& entitled_ta_ids,
        std::vector<uint8_t>& c1,
        std::vector<uint8_t>& c2,
        std::vector<uint8_t>& c3,
        std::vector<uint8_t>& tag) {

    std::ostringstream oss;

    oss << R"({"containerVersion": )" << static_cast<int>(container_version);
    if (!key_type.empty())
        oss << R"(, "keyType": ")" << key_type << "\"";

    std::string encrypted_key = generate_encrypted_key(container_version, key_type, key, iv, key_usage,
            decrypted_key_usage, entitled_ta_ids, c1, c2, c3, tag);
    if (encrypted_key.empty())
        return "";

    oss << R"(, "encryptedKey": ")" << encrypted_key << "\"";

    if (!iv.empty())
        oss << R"(, "iv": ")" << TestCreds::b64_encode(iv.data(), iv.size()) << "\"";

    oss << R"(, "keyUsage": )" << static_cast<int>(key_usage);

    if (container_version >= 3 && key_usage == 2)
        oss << R"(, "decryptedKeyUsage": )" << static_cast<int>(decrypted_key_usage);

    if (!entitled_ta_ids.empty()) {
        oss << R"(, "entitledTaIds": [)";
        for (size_t i = 0; i < entitled_ta_ids.size(); i++) {
            if (i > 0)
                oss << ", ";

            oss << "\"" << entitled_ta_ids[i] << "\"";
        }

        oss << "]";
    }

    if (!c1.empty())
        oss << R"(, "c1": ")" << TestCreds::b64_encode(c1.data(), c1.size()) << "\"";

    if (!c2.empty())
        oss << R"(, "c2": ")" << TestCreds::b64_encode(c2.data(), c2.size()) << "\"";

    if (!c1.empty())
        oss << R"(, "c3": ")" << TestCreds::b64_encode(c3.data(), c3.size()) << "\"";

    oss << "}";

    return TestCreds::b64_encode(oss.str().data(), oss.str().size());
}

std::vector<uint8_t> generate_sa_soc_key_container(std::vector<uint8_t>& key_clear,
        std::string& key_type,
        std::vector<uint8_t>& tag) {
    auto jwt_header = generate_header();
    auto jwt_payload = generate_payload(3, key_type, key_clear, TEST_IV, 3, 3, ENTITLED_TA_IDS, TEST_C1, TEST_C2,
            TEST_C3, tag);
    std::string key_container = jwt_header + "." + jwt_payload + "." + TestCreds::b64_encode(tag.data(), tag.size());

    auto kc = std::vector<uint8_t>(key_container.begin(), key_container.end());
    return kc;
}
