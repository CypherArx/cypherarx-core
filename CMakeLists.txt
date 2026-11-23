cmake_minimum_required(VERSION 3.21)
project(cypherarx_core LANGUAGES CXX VERSION 0.0.1)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

option(CYPHERARX_BUILD_TESTS "Build unit tests" ON)
option(CYPHERARX_SANITIZE "Enable ASan/UBSan (non-MSVC toolchains)" OFF)

# Treat all sources as UTF-8 on MSVC (sources are UTF-8; default codepage may be cp932).
if(MSVC)
  add_compile_options(/utf-8)
endif()

find_package(unofficial-sodium CONFIG REQUIRED)
find_package(unofficial-sqlite3 CONFIG REQUIRED)

add_library(cypherarx_core
  src/crypto/secret.cpp
  src/crypto/crypto.cpp
  src/crypto/kdf.cpp
  src/crypto/vault_key.cpp
  src/crypto/totp.cpp
  src/passgen.cpp
  src/vault.cpp
)
target_include_directories(cypherarx_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(cypherarx_core
  PUBLIC unofficial-sodium::sodium
  PRIVATE unofficial::sqlite3::sqlite3
)
target_compile_features(cypherarx_core PUBLIC cxx_std_23)

if(MSVC)
  target_compile_options(cypherarx_core PRIVATE /W4 /permissive-)
else()
  target_compile_options(cypherarx_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

# ASan/UBSan are wired for non-MSVC (Clang/GCC) toolchains, used by CI.
function(cypherarx_apply_sanitizers target)
  if(CYPHERARX_SANITIZE AND NOT MSVC)
    target_compile_options(${target} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(${target} PRIVATE -fsanitize=address,undefined)
  endif()
endfunction()

cypherarx_apply_sanitizers(cypherarx_core)

if(CYPHERARX_BUILD_TESTS)
  enable_testing()
  find_package(GTest CONFIG REQUIRED)

  add_executable(cypherarx_tests
    tests/test_secret.cpp
    tests/test_crypto.cpp
    tests/test_kdf.cpp
    tests/test_vault_key.cpp
    tests/test_vault.cpp
    tests/test_entries.cpp
    tests/test_organize.cpp
    tests/test_settings.cpp
    tests/test_access_log.cpp
    tests/test_passgen.cpp
    tests/test_totp.cpp
  )
  target_link_libraries(cypherarx_tests PRIVATE cypherarx_core unofficial::sqlite3::sqlite3
                        GTest::gtest GTest::gtest_main)
  cypherarx_apply_sanitizers(cypherarx_tests)

  include(GoogleTest)
  gtest_discover_tests(cypherarx_tests)
endif()
