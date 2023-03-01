common_lib = static_library('common_lib',
    nasm_gen.process('../../common/exit.nasm')
)

tests = {
    'iret_emulation': {},
}

install_dir = pkglibdir / 'tests' / 'libos' / 'regression' / 'x86_64'

musl_execs = []
foreach name, params : tests
    filenames = nasm_gen.process('@0@.nasm'.format(name))

    exe = executable(name,
        filenames,

        link_with: [
            params.get('link_with', [common_lib]),
        ],

        link_args: params.get('link_args', ['-nostdlib', '-static']),
        include_directories: params.get('include_directories', []),

        install: true,
        install_dir: install_dir,
    )
    musl_execs += exe
endforeach

if enable_musl
    meson.add_install_script(
        find_program('../install_musl_tests.sh'),
        prefix / pkglibdir / 'tests' / 'libos' / 'regression' / 'musl' / 'x86_64',
        musl_execs,
    )
endif
