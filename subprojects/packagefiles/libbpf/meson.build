project('libbpf', 'c',
  meson_version : '>=1.1.0',
)

fs = import('fs')

build_includes = include_directories('include', 'src')
libelf = subproject('elfutils').get_variable('libelf_dep')
zlib = subproject('zlib').get_variable('zlib_dep')

libbpf = static_library('libbpf',
  'src/bpf.c',
  'src/bpf_prog_linfo.c',
  'src/btf.c',
  'src/btf_dump.c',
  'src/gen_loader.c',
  'src/hashmap.c',
  'src/libbpf.c',
  'src/libbpf_errno.c',
  'src/libbpf_probes.c',
  'src/linker.c',
  'src/netlink.c',
  'src/nlattr.c',
  'src/relo_core.c',
  'src/ringbuf.c',
  'src/str_error.c',
  'src/strset.c',
  'src/usdt.c',
  'src/zip.c',
  dependencies: [zlib, libelf],
  include_directories: build_includes)

subdir('bpf')
libbpf_dep = declare_dependency(
  include_directories : include_directories('bpf'),
  link_with : libbpf,
  variables : {'includes': meson.current_build_dir()})