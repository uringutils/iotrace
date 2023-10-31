project('iotrace', 'c')

zlib = dependency('zlib', static: true)
libelf = dependency('libelf', static: true)
libbpf = dependency('libbpf', static: true)

vendor = get_option('vendor')
bpftool = find_program('bpftool', dirs: [vendor / 'usr/local/sbin/', vendor / 'sbin', '/usr/sbin'])
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
                '-isystem', libbpf.get_variable(pkgconfig:'includedir'),
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
    install: true,
    install_dir : '/usr/sbin',
    dependencies: [zlib, libelf, libbpf])
