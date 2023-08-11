# Copyright 2020-2022 Comcast Cable Communications Management, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.16)
project(sec_api_2_adapter C CXX)

set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_GNU_SOURCE -pthread")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_GNU_SOURCE")

set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/../cmake" ${CMAKE_MODULE_PATH})
message("CMAKE_MODULE_PATH=${CMAKE_MODULE_PATH}")
include(ClangFormat)

if (DEFINED ENABLE_CLANG_TIDY)
    find_program(CLANG_TIDY_COMMAND NAMES clang-tidy)
    if (CLANG_TIDY_COMMAND)
        set(CMAKE_CXX_CLANG_TIDY ${CLANG_TIDY_COMMAND}; )
        set(CMAKE_C_CLANG_TIDY ${CLANG_TIDY_COMMAND}; )
        message("clang-tidy found--enabling")
    else ()
        message("clang-tidy not found")
    endif ()
else()
    message("clang-tidy disabled")
endif ()

if (DEFINED ENABLE_SOC_KEY_TESTS)
    set(CMAKE_CXX_FLAGS "-DENABLE_SOC_KEY_TESTS ${CMAKE_CXX_FLAGS}")
    set(CMAKE_C_FLAGS "-DENABLE_SOC_KEY_TESTS ${CMAKE_C_FLAGS}")
endif ()

enable_testing()

# Set OPENSSL_ROOT_DIR if not found
find_package(OpenSSL REQUIRED)
# Set YAJL_ROOT if not found
find_package(YAJL REQUIRED)
# Set SACLIENT_ROOT if not found
find_package(SACLIENT REQUIRED)

include_directories(
        ${OPENSSL_INCLUDE_DIR}
        ${YAJL_INCLUDE_DIR}
        ${SACLIENT_INCLUDE_DIR}
        include
        src
)

if (CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang")
    add_compile_options(-DSEC_TARGET_IOS=1)
endif ()

add_compile_options(-DYAJL_V2=true)

add_library(sec_api SHARED
        include/sec_security.h
        include/sec_security_asn1kc.h
        include/sec_security_comcastids.h
        include/sec_security_common.h
        include/sec_security_datatype.h
        include/sec_security_store.h
        include/sec_security_utils.h
        include/sec_version.h
        src/sec_adapter_bundle.h        src/sec_adapter_bundle.c
        src/sec_adapter_cipher.h        src/sec_adapter_cipher.c
        src/sec_adapter_key.h           src/sec_adapter_key.c
        src/sec_adapter_processor.h     src/sec_adapter_processor.c
        src/sec_adapter_pubops.h        src/sec_adapter_pubops.c
        include/sec_security_svp.h      src/sec_adapter_svp.c
        src/sec_adapter_asn1kc.c
        src/sec_adapter_buffer.c
        src/sec_adapter_certificate.c
        src/sec_adapter_common.c
        src/sec_adapter_digest.c
        src/sec_adapter_engine.c
        src/sec_adapter_keyexchange.c
        src/sec_adapter_logger.c
        src/sec_adapter_mac.c
        src/sec_adapter_random.c
        src/sec_adapter_signature.c
        src/sec_adapter_store.c
        src/sec_adapter_utils.c
        src/sec_adapter_utils_time.c
        src/sec_adapter_key_legacy.h)

set_target_properties(sec_api PROPERTIES
        LINKER_LANGUAGE C
        SO_VERSION 2.3
        VERSION 2.3.2.26
        )

target_compile_options(sec_api PRIVATE -Wno-deprecated-declarations)

target_link_libraries(sec_api
        PRIVATE
        ${SACLIENT_LIBRARY}
        ${OPENSSL_CRYPTO_LIBRARY}
        )

target_clangformat_setup(sec_api)

add_executable(sec_api_2_adapter_test
        test/main/headers/test_creds.h
        test/openssl/headers/test_ctx.h
        test/main/cpp/bundle.cpp
        test/main/cpp/cert.cpp
        test/main/cpp/cipher.cpp
        test/main/cpp/concurrent.cpp
        test/main/cpp/digest.cpp
        test/main/cpp/exchange.cpp
        test/main/cpp/jtype.cpp
        test/main/cpp/key.cpp
        test/main/cpp/keyctrl.cpp
        test/main/cpp/mac.cpp
        test/main/cpp/processor.cpp
        test/main/cpp/random.cpp
        test/main/cpp/sec_api_utest_main.cpp
        test/main/cpp/sign.cpp
        test/main/cpp/svp.cpp
        test/main/cpp/test_creds_clear.cpp
        test/main/cpp/test_ctx.cpp
        test/main/cpp/wrapped.cpp
        test/openssl/headers/test_ctx.h
        test/openssl/headers/test_creds.h
        test/openssl/src/test_creds_soc.cpp
        test/openssl/src/sa_soc_key_container.cpp
        )

target_include_directories(sec_api_2_adapter_test
        PRIVATE
        src
        test/main/cpp
        test/openssl/headers
        )

target_compile_options(sec_api_2_adapter_test PRIVATE -Wno-deprecated-declarations)

target_link_libraries(sec_api_2_adapter_test
        PRIVATE
        sec_api
        ${SACLIENT_LIBRARY}
        ${OPENSSL_CRYPTO_LIBRARY}
        ${YAJL_LIBRARY}
        )

add_custom_command(
        TARGET sec_api_2_adapter_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_SOURCE_DIR}/test/root_keystore.p12
        ${CMAKE_CURRENT_BINARY_DIR}/root_keystore.p12)

add_test(sec_api_2_adapter_test sec_api_2_adapter_test)

target_clangformat_setup(sec_api_2_adapter_test)

# 'make install' to the correct locations (provided by GNUInstallDirs).
install(TARGETS sec_api sec_api_2_adapter_test
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
        RUNTIME DESTINATION bin
        )

install(DIRECTORY include/ DESTINATION include)
