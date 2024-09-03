set(INCLUDE_PATH ${CMAKE_SOURCE_DIR}/include)

aux_source_directory(./ SRC_LIST)



# 查找包
find_package(fmt CONFIG REQUIRED)
find_package(amqpcpp CONFIG REQUIRED)
find_package(Boost REQUIRED COMPONENTS asio)


add_executable(main ${SRC_LIST})


# 连接库
target_link_libraries(main PRIVATE fmt::fmt-header-only)
target_link_libraries(main PRIVATE amqpcpp)    
target_link_libraries(main PRIVATE Boost::asio)



# 添加头文件目录
target_include_directories(main PRIVATE ${INCLUDE_PATH})

