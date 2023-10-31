FROM registry.opensuse.org/opensuse/tumbleweed:latest as base
RUN zypper in --no-recommends -yl \
    gcc clang lld llvm llvm-devel\
    meson cmake ninja \
    glibc-devel glibc-devel-static \
    libstdc++-devel awk
COPY libs /tmp/libs
RUN cmake -B /tmp/build -S /tmp/libs -DINSTALL_DIR=/usr/share/vendor && cmake --build /tmp/build && rm -rf /tmp/*
ENV PKG_CONFIG_PATH "/usr/share/vendor/lib64/pkgconfig:/usr/share/vendor/lib/pkgconfig"
ENV CC=clang
ENV CC_LD=lld