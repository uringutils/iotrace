project('elfutils', 'c',
  meson_version : '>=1.1.0',
)

mod = import('unstable-external_project')

project = mod.add_project('configure',
  configure_options : ['--prefix=@PREFIX@',
                       '--disable-libdebuginfod',
                       '--disable-debuginfod',
                       '--disable-demangler',
                       '--disable-textrelcheck',
                       '--disable-symbol-versioning',
                       '--enable-install-elfh',
                       '--without-valgrind',
                       '--without-bzlib',
                       '--without-lzma',
                       '--without-zstd',
                       'CFLAGS=-I/shared/iotrace/vendor/include',
                       'LDFLAGS=-L/shared/iotrace/vendor/lib',
                      ],
)

libelf_dep = project.dependency('libelf')
meson.override_dependency('libelf', libelf_dep)
