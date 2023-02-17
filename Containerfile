FROM registry.opensuse.org/opensuse/tumbleweed:latest as base
RUN zypper in --no-recommends -yl clang lld llvm llvm15-devel cmake ninja gcc-devel libelf-devel bpftool glibc-devel-32bit
