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

find_package(unofficial-sodium CONFIG REQUIRED)

add_library(cypherarx_core
  src/crypto/secret.cpp
  src/crypto/crypto.cpp
)
target_include_directories(cypherarx_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(cypherarx_core PUBLIC unofficial-sodium::sodium)
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
  )
  target_link_libraries(cypherarx_tests PRIVATE cypherarx_core GTest::gtest GTest::gtest_main)
  cypherarx_apply_sanitizers(cypherarx_tests)

  include(GoogleTest)
  gtest_discover_tests(cypherarx_tests)
endif()
