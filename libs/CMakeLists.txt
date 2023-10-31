cmake_minimum_required(VERSION 3.26.3)
project(dependencies)
include(ExternalProject)
set(INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/build CACHE STRING "Installation prefix for iotrace dependencies")
set(EXTRA_CFLAGS "-fPIC -O3" CACHE STRING "EXTRA_CFLAGS used in every library build")
set(EXTRA_CFLAGS "${EXTRA_CFLAGS} -I${INSTALL_DIR}/include")
set(EXTRA_LDFLAGS "" CACHE STRING "EXTRA_LDFLAGS used in every library build")
set(EXTRA_LDFLAGS "${EXTRA_LDLAGS} -L${INSTALL_DIR}/lib")
set(DOWNLOAD_DIR ${CMAKE_CURRENT_BINARY_DIR}/downloads CACHE STRING "Download artifacts")

# zlib build
ExternalProject_Add(zlib
  URL "https://github.com/madler/zlib/releases/download/v1.2.13/zlib-1.2.13.tar.gz"
  DOWNLOAD_DIR ${DOWNLOAD_DIR}
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
  CONFIGURE_COMMAND bash -c "CFLAGS=\"${EXTRA_CFLAGS}\" ./configure --prefix=${INSTALL_DIR}" 
  BUILD_COMMAND make -j
  BUILD_IN_SOURCE TRUE
  INSTALL_COMMAND make install
)

# libelf build
ExternalProject_Add(libelf
  DEPENDS zlib
  URL "https://sourceware.org/elfutils/ftp/0.189/elfutils-0.189.tar.bz2"
  DOWNLOAD_DIR ${DOWNLOAD_DIR}
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
  CONFIGURE_COMMAND
    bash configure --prefix=${INSTALL_DIR}
      --disable-libdebuginfod
      --disable-debuginfod
      --disable-demangler
      --disable-textrelcheck
      --disable-symbol-versioning
      --enable-install-elfh
      --without-valgrind
      --without-bzlib
      --without-lzma
      --without-zstd
      CC=clang
      CFLAGS=${EXTRA_CFLAGS}
      LDFLAGS=-L${INSTALL_DIR}/lib
  BUILD_COMMAND make -j -C libelf libelf.a
  BUILD_IN_SOURCE TRUE
  INSTALL_COMMAND make -C libelf install-libLIBRARIES
  COMMAND make -C libelf install-includeHEADERS
  COMMAND make -C config install
  STEP_TARGETS build
)

# bpftool build
ExternalProject_Add(bpftool
  DEPENDS libelf
  URL "https://github.com/libbpf/bpftool/releases/download/v7.2.0/bpftool-libbpf-v7.2.0-sources.tar.gz"
  DOWNLOAD_DIR ${DOWNLOAD_DIR}
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
  CONFIGURE_COMMAND ""
  BUILD_COMMAND make -C src -j EXTRA_CFLAGS=${EXTRA_CFLAGS} EXTRA_LDFLAGS=${EXTRA_LDFLAGS}
  COMMAND make -C libbpf/src -j EXTRA_CFLAGS=${EXTRA_CFLAGS} EXTRA_LDFLAGS=${EXTRA_LDFLAGS} PREFIX=${INSTALL_DIR}
  BUILD_IN_SOURCE TRUE
  INSTALL_COMMAND make -C src DESTDIR=${INSTALL_DIR} install
  COMMAND make -C libbpf/src PREFIX=${INSTALL_DIR} install
  STEP_TARGETS build
)