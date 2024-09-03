set(GRPC_PLUGIN "/home/chen/vcpkg/installed/x64-linux/tools/grpc/grpc_cpp_plugin")
set(PROTOC "/home/chen/vcpkg/installed/x64-linux/tools/protobuf/protoc")

set(PROTO_OUTPUT "${CMAKE_CURRENT_SOURCE_DIR}/generated")

# 创建输出路径
file(MAKE_DIRECTORY ${PROTO_OUTPUT})

file(GLOB PROTO_FILES ${CMAKE_CURRENT_SOURCE_DIR}/*.proto)

execute_process(
    COMMAND ${PROTOC}
    -I=${CMAKE_CURRENT_SOURCE_DIR}
    --grpc_out=${PROTO_OUTPUT}
    --plugin=protoc-gen-grpc=${GRPC_PLUGIN}
    --cpp_out=${PROTO_OUTPUT} ${PROTO_FILES}
)