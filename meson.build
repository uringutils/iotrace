project('iotrace', 'c')

zlib = subproject('zlib').get_variable('zlib_dep')
libelf = subproject('elfutils').get_variable('libelf_dep')
libbpf = subproject('libbpf').get_variable('libbpf_dep')
libbpf_includes = libbpf.get_variable('includes')
bpftool = find_program('bpftool', '/usr/share/vendor/usr/local/sbin/bpftool')
clang = find_program('clang')

vmlinux = custom_target(
    'vmlinux.h',
    output : 'vmlinux.h',
    capture: true,
    command : [bpftool, 'btf', 'dump', 'file', '/sys/kernel/btf/vmlinux', 'format', 'c'],
)
probe = custom_target(
    'probe.bpf.o',
    input:'src/probe.bpf.c',
    output : 'probe.bpf.o',
    depends: [vmlinux],
    command : [clang, '-g', '-O2', 
                '-target', 'bpf',
                '-I', meson.current_build_dir(),
                '-isystem', libbpf_includes,
                '-c', '@INPUT@', '-o', '@OUTPUT@',
                ''.join('-D__TARGET_ARCH_', target_machine.cpu())]
)
probe_header = custom_target(
    'probe.bpf.h',
    input: probe,
    output: 'probe.bpf.h',
    capture: true,
    command : [bpftool, 'gen', 'skeleton', '@INPUT@'],
)
incdir = include_directories('include')
exe = executable('iotrace', 
    'src/iotrace.c',
    'src/print.c',
    vmlinux,
    probe_header,
    include_directories:incdir,
    dependencies: [zlib, libelf, libbpf])