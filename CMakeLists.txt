cmake_minimum_required(VERSION 3.26)
set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
set(BUILD_SHARED_LIBS OFF)
set(CMAKE_EXE_LINKER_FLAGS "-static")

project(npj)

add_executable(npj
    ./src/inj.cpp
)
