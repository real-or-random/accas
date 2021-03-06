### Copyright (c) 2015 Tim Ruffing <tim.ruffing@mmci.uni-saarland.de>
###
### Permission is hereby granted, free of charge, to any person
### obtaining a copy of this software and associated documentation
### files (the "Software"), to deal in the Software without
### restriction, including without limitation the rights to use,
### copy, modify, merge, publish, distribute, sublicense, and/or sell
### copies of the Software, and to permit persons to whom the
### Software is furnished to do so, subject to the following
### conditions:
###
### The above copyright notice and this permission notice shall be
### included in all copies or substantial portions of the Software.
###
### THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
### EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
### OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
### NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
### HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
### WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
### FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
### OTHER DEALINGS IN THE SOFTWARE.

cmake_minimum_required(VERSION 2.6)
project(acca)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)

set(ACCA_CT_LEN 8
    CACHE STRING "Length of a assertion context in bytes. This value should be at least 8.")
add_definitions(-DACCA_CT_LEN=${ACCA_CT_LEN})

# tell libsecp256k1 to use its config.h file
add_definitions(-DHAVE_CONFIG_H)

add_subdirectory(test)

enable_testing()
find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

find_package(GMP REQUIRED)
include_directories(${GMP_INCLUDE_DIR})

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE release)
endif(NOT CMAKE_BUILD_TYPE)

add_executable(authenticatortest test/authenticatortest.cpp chameleonhash.cpp authenticator.cpp prf.cpp node.cpp)

set_target_properties(authenticatortest PROPERTIES COMPILE_FLAGS -fpermissive)

target_link_libraries(authenticatortest ${GTEST_BOTH_LIBRARIES})
target_link_libraries(authenticatortest ${GMP_LIBRARY})
add_test(ChameleonHash authenticatortest)

# install(TARGETS acca RUNTIME DESTINATION bin)

