cmake_minimum_required(VERSION 3.27)
project(ecc_tests)

set(CMAKE_CXX_STANDARD 17)
add_definitions(-DENABLE_MODULE_SILENTPAYMENTS=1 -DENABLE_MODULE_EXTRAKEYS=1 -DENABLE_MODULE_ECDH=1)

include_directories(secp256k1)

add_subdirectory(secp256k1)

add_executable(ecc_tests main.cpp sp_self.cpp
        vectors.h
        sp_module.cpp
        sp_module.h
        utils.h
        utils.cpp)

target_link_libraries(ecc_tests secp256k1)
