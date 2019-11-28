cmake_minimum_required(VERSION 3.6)
set(PROJECT_NAME GrimaldoNative)
project(${PROJECT_NAME})

if(${ANDROID})
else()
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin")
endif()

set(CMAKE_CXX_STANDARD 11)

include_directories(mongoose sphincsplus argparse)

add_compile_options(-fpermissive -frtti -fexceptions)

set(SRC_FILES
        mongoose/mongoose.c
        sphincsplus/address.cpp
        sphincsplus/randombytes.cpp
        sphincsplus/wots.cpp
        sphincsplus/utils.cpp
        sphincsplus/fors.cpp
        sphincsplus/hash_shake256.cpp
        sphincsplus/thash_shake256_robust.cpp
        sphincsplus/fips202.cpp
        sphincsplus/sign.cpp
        main.cpp
        )

if(${ANDROID})
    set(EXE_NAME libgrimald.so)
else()
    set(EXE_NAME grimald)
endif()

add_executable(${EXE_NAME} ${SRC_FILES})

if(WIN32)
    target_link_libraries(${EXE_NAME} bcrypt wsock32 ws2_32)
endif()