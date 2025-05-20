cmake_minimum_required(VERSION 3.23)

project(tcp_ip)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
if(CMAKE_EXPORT_COMPILE_COMMANDS)
  set(CMAKE_CXX_STANDARD_INCLUDE_DIRECTORIES
      ${CMAKE_CXX_IMPLICIT_INCLUDE_DIRECTORIES})
endif()

file(GLOB_RECURSE sources "${CMAKE_SOURCE_DIR}/src/*.c"
     "${CMAKE_SOURCE_DIR}/src/*.cpp")

add_executable(tcp_ip ${sources})

add_definitions(-std=c++26 -DLOG_LEVEL=TRACE)

# Add more include directories if needed
target_include_directories(tcp_ip PUBLIC "${CMAKE_SOURCE_DIR}/include")
