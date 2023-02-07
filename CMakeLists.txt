cmake_minimum_required(VERSION 3.24.2)

set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang)

project(iotrace)
add_subdirectory(libs)

# Tell cmake where to find BpfObject module
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/libs/tools)
# Set BpfObject input parameters -- note this is usually not necessary unless
# you're in a highly vendored environment (like libbpf-bootstrap)
set(BPFOBJECT_BPFTOOL_EXE bpftool)
set(LIBBPF_INCLUDE_DIRS ${CMAKE_BINARY_DIR}/libs/libbpf)
set(LIBBPF_LIBRARIES ${CMAKE_BINARY_DIR}/libs/libbpf/libbpf.a)
find_package(BpfObject REQUIRED)

add_subdirectory(src)