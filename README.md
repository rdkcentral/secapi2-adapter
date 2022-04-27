# sec_api_2_adapter

## Summary

sec_api_2_adapter is a SOC neutral implementation of SecApi 2.3 that uses SecApi 3 as it's cryptographic implementation.
sec_api_2_adapter uses SecApi 2.3 unit tests to test the library.

There are a few features in SecApi 2.3 that are not supported due to incompatibility with SecApi 3:

- SecCipher_ProcessCtrWithOpaqueDataShift (Data shift not supported)
- SecCipher_ProcessCtrWithDataShift (Data shift not supported)
- SecProcessor_GetInstance (Deprecated function)
- SecOpaqueBuffer_Release (Not supported by SecApi 3)
- SecCodeIntegrity_SecureBootEnabled (Not supported by SecApi 3)
- SecSVP_SetTime (Not supported by SecApi 3)

Calling any of these functions will return a SEC_RESULT_UNIMPLEMENTED_FEATURE error.

## Directories

- The include directory contains the SecApi 2.3 API include files.
- The src directory contains the sources for the sec_api_2_adapter.
- The test directory contains the SecApi 2.3 tests that have been modified to test the sec_api_2_adapter.
- The cmake directory contains additional cmake build helper files.
- The root directory contains the master cmake build files.

## Building

### Generate Build Files

To build sec_api_2_adapter, first run cmake to generate build files.

The build assumes that the following packages have already been installed:
YAJL - include -DYAJL_ROOT=<directory> if not found
OPENSSL - include -DOPENSSL_ROOT_DIR=<directory> if not found
SecApi3 - include -DSACLIENT_ROOT=<directory> if not found
Add -DCMAKE_INSTALL_PREFIX=<directory> to install to a non-standard install directory.


```
cmake -S . -B cmake-build
```


### Build

To build sec_api_2_adapter, run a cmake build

```
cmake --build cmake-build
```

This creates a library, libsec_api.(so/dll/dylib) containing the adapter code (the extension .so/.dll/.dylib
created depends on which platform you are building on). It also creates a test application, sec_api_2_adapter_test, to
test the library.

SOC and root key tests are also disabled by default. To enable these tests, add -DENABLE_SOC_KEY_TESTS=1. The test_root
key defined in test_creds_clear.cpp must match the root key defined on the test device for these tests to pass.

Run unit test suite

```
cmake-build/sec_api_2_adapter_test
```

The tests for the reference implementation expect a SA_TEST_CLEAR_SOC_KEY_FORMAT to
exist so that SOC based key containers can be tested.


### Install

To install sec_api_2_adapter, run a cmake install

```
cmake --install cmake-build
```

This copies the include files, the library, libsec_api.(so/dll/dylib) containing the adapter code (the
extension .so/.dll/.dylib created depends on which platform you are building on), and the test application,
sec_api_2_adapter_test, to their appropriate locations on the system.
