cmake_minimum_required(VERSION 3.20)
project(MicroService)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

set(CMAKE_PREFIX_PATH "/home/chen/vcpkg/installed/x64-linux")
set(CMAKE_TOOLCHAIN_FILE "/home/chen/vcpkg/scripts/buildsystems/vcpkg.cmake")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)



add_subdirectory(./src)
