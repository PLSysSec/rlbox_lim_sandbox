cmake_minimum_required(VERSION 3.13)

project(rlbox_lucet
        VERSION 0.1
        DESCRIPTION "RLBox integration with WASM modules compiled with lucet")

# Project Settings ###################

# set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(DEV "Use settings suitable for dev contributions to rlbox" OFF)

file(GLOB_RECURSE
     ALL_CXX_SOURCE_FILES
     ${CMAKE_SOURCE_DIR}/include/*.[chi]pp
     ${CMAKE_SOURCE_DIR}/include/*.[chi]xx
     ${CMAKE_SOURCE_DIR}/include/*.cc
     ${CMAKE_SOURCE_DIR}/include/*.hh
     ${CMAKE_SOURCE_DIR}/include/*.ii
     ${CMAKE_SOURCE_DIR}/include/*.[CHI]
     ${CMAKE_SOURCE_DIR}/test/*.[chi]pp
     ${CMAKE_SOURCE_DIR}/test/*.[chi]xx
     ${CMAKE_SOURCE_DIR}/test/*.cc
     ${CMAKE_SOURCE_DIR}/test/*.hh
     ${CMAKE_SOURCE_DIR}/test/*.ii
     ${CMAKE_SOURCE_DIR}/test/*.[CHI]
     ${CMAKE_SOURCE_DIR}/c_src/*.[chi]pp
     ${CMAKE_SOURCE_DIR}/c_src/*.[chi]xx
     ${CMAKE_SOURCE_DIR}/c_src/*.cc
     ${CMAKE_SOURCE_DIR}/c_src/*.hh
     ${CMAKE_SOURCE_DIR}/c_src/*.ii
     ${CMAKE_SOURCE_DIR}/c_src/*.[CHI])

# Dev Tools ###################

if(DEV)
  if(MSVC)
    add_compile_options(/W4) # warnings
    add_compile_options(/WX) # warnings as errors
  else()
    add_compile_options(-Wall -Wextra -pedantic) # warnings
    add_compile_options(-Werror) # warnings as errors
    add_compile_options(-fsanitize=address)
    add_link_options(-fsanitize=address)
    add_compile_options(-fsanitize=undefined)
    add_link_options(-fsanitize=undefined)
  endif()

  find_program(CLANG_TIDY "clang-tidy")
  if(CLANG_TIDY)
    # Config in .clang-tidy
    set(CMAKE_CXX_CLANG_TIDY clang-tidy)
  endif()

  find_program(CLANG_FORMAT "clang-format")
  if(CLANG_FORMAT)
    # Config in .clang-format
    add_custom_target(format-source
                      COMMAND clang-format
                              -i
                              -style=file
                              ${ALL_CXX_SOURCE_FILES})
  endif()

endif()

# Dependencies ###################

include(FetchContent)

FetchContent_Declare(
  rlbox
  GIT_REPOSITORY https://github.com/PLSysSec/rlbox_api_cpp17.git)
FetchContent_GetProperties(rlbox)
if(NOT rlbox_POPULATED)
  FetchContent_Populate(rlbox)
endif()

FetchContent_Declare(catch2
                     GIT_REPOSITORY https://github.com/catchorg/Catch2.git
                     GIT_TAG v2.9.1)
FetchContent_GetProperties(catch2)
if(NOT catch2_POPULATED)
  FetchContent_Populate(catch2)
endif()

add_subdirectory("${catch2_SOURCE_DIR}")
list(APPEND CMAKE_MODULE_PATH "${catch2_SOURCE_DIR}/contrib")

# Lib ###################

add_library(lim_sandbox c_src/lim_sandbox_wrapper.c)

target_include_directories(lim_sandbox PRIVATE ${CMAKE_SOURCE_DIR}/../lim_simics/malloc
                                               ${CMAKE_SOURCE_DIR}/include)

# The malloc wrap symbols needed by the wasm module are in this static lib, but must
# be part of the symbol table (locatable through dlsym). We need the following
# flag for this.
if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
target_link_options(lim_sandbox INTERFACE "-framework" "Security" "-rdynamic")
else()
target_link_options(lim_sandbox INTERFACE "-rdynamic")
endif()

# Tests ###################

add_library(glue_lib SHARED ${rlbox_SOURCE_DIR}/code/tests/rlbox_glue/lib/libtest.c)

target_link_options(glue_lib PRIVATE "-Wl,--wrap=malloc" "-Wl,--wrap=calloc" "-Wl,--wrap=realloc" "-Wl,--wrap=free" "-Wl,--wrap=memcpy")

set(GLUE_LIB_SO "${CMAKE_BINARY_DIR}/libglue_lib.so")             

include(CTest)
include(Catch)

add_executable(test_rlbox_glue test/test_lim_sandbox_glue_main.cpp
                               test/test_lim_sandbox_glue.cpp)
target_include_directories(test_rlbox_glue PUBLIC include)
target_include_directories(test_rlbox_glue
                           PUBLIC ${rlbox_SOURCE_DIR}/code/include)
target_include_directories(test_rlbox_glue
                           PUBLIC ${rlbox_SOURCE_DIR}/code/tests/rlbox_glue)
target_include_directories(test_rlbox_glue
                           PUBLIC ${rlbox_SOURCE_DIR}/code/tests/rlbox_glue/lib)

find_package(Threads REQUIRED)

add_dependencies(test_rlbox_glue glue_lib)

target_compile_definitions(test_rlbox_glue PUBLIC
                           GLUE_LIB_LIM_PATH="${GLUE_LIB_SO}")

target_link_libraries(test_rlbox_glue
                      lim_sandbox
                      Catch2::Catch2
                      ${CMAKE_THREAD_LIBS_INIT}
                      ${CMAKE_DL_LIBS}
                      )

if(UNIX AND NOT (${CMAKE_SYSTEM_NAME} MATCHES "Darwin"))
  target_link_libraries(test_rlbox_glue rt)
endif()
catch_discover_tests(test_rlbox_glue)

# LIM SIMICS test ###################

add_executable(test_lim_simics c_src/lim_function_test.c)
target_include_directories(test_lim_simics PRIVATE ${CMAKE_SOURCE_DIR}/../lim_simics/malloc)

add_executable(test_lim_signal c_src/lim_signal_test.c)
target_include_directories(test_lim_signal PRIVATE ${CMAKE_SOURCE_DIR}/../lim_simics/malloc)

# Shortcuts ###################

add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND} -V)
add_dependencies(check test_rlbox_glue)

