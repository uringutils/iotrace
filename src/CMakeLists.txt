
# Build object skeleton and depend skeleton on libbpf build
bpf_object(probe probe.bpf.c)
add_dependencies(probe_skel libbpf-build)
target_include_directories(probe_skel SYSTEM INTERFACE ${CMAKE_SOURCE_DIR}/include)
add_executable(iotrace iotrace.c)
target_compile_options(iotrace PRIVATE -static)
target_link_libraries(iotrace probe_skel)
