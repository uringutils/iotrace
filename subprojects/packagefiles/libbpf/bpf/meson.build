fs = import('fs')
bpf_includes = [
  'bpf_endian.h',
  'bpf_core_read.h',
  'bpf_gen_internal.h',
  'bpf.h',
  'bpf_helper_defs.h',
  'bpf_helpers.h',
  'bpf_tracing.h',
  'btf.h',
  'hashmap.h',
  'libbpf_common.h',
  'libbpf.h',
  'libbpf_internal.h',
  'libbpf_legacy.h',
  'libbpf_version.h',
  'nlattr.h',
  'relo_core.h',
  'skel_internal.h',
  'str_error.h',
  'strset.h',
  'usdt.bpf.h',
  'zip.h',
]
foreach include_file : bpf_includes
  debug(include_file)
  fs.copyfile(join_paths('../src',include_file))
endforeach

debug('done')