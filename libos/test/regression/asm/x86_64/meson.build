common_lib = static_library('common_lib',
    nasm_gen.process('../../../common/x86_64/exit.nasm')
)

tests = {
    'iret_emulation': {},
}

install_dir = pkglibdir / 'tests' / 'libos' / 'regression' / 'asm' / 'x86_64'

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
endforeach
