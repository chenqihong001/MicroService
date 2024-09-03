set(INCLUDE_PATH ${CMAKE_SOURCE_DIR}/include)
set(INCLUDE_PROTO ${CMAKE_SOURCE_DIR}/proto/generated)

aux_source_directory(./ SRC_LIST)
aux_source_directory(${CMAKE_SOURCE_DIR}/proto/generated PROTO_SRCS)

# message(STATUS "SRC_LIST: ${SRC_LIST}")
# message(STATUS "PROTO_SRCS: ${PROTO_SRCS}")

# 添加头文件目录
include_directories(${INCLUDE_PATH})
include_directories(${INCLUDE_PROTO})

# 查找包
find_package(fmt CONFIG REQUIRED)
find_package(amqpcpp CONFIG REQUIRED)
find_package(Boost REQUIRED COMPONENTS asio)
find_path(JWT_CPP_INCLUDE_DIRS "jwt-cpp/base.h")
find_package(gRPC CONFIG REQUIRED)

# note: 8 additional targets are not displayed.
add_executable(main ${SRC_LIST} ${PROTO_SRCS})

# 连接库
target_link_libraries(main PRIVATE fmt::fmt-header-only)
target_link_libraries(main PRIVATE amqpcpp)
target_link_libraries(main PRIVATE Boost::asio)
target_include_directories(main PRIVATE ${JWT_CPP_INCLUDE_DIRS})
target_link_libraries(main PRIVATE gRPC::gpr gRPC::grpc gRPC::grpc++ gRPC::grpc++_alts)