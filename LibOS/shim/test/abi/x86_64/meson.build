common_lib = static_library('common_lib',
    'common.c',
    nasm_gen.process('exit.asm')
)

tests = {
    'atexit_func': {},
    'fpu_control_word': {},
    'mxcsr': {},
    'rflags': {},
    'stack': {},
    'stack_arg': {},
}

install_dir = join_paths(pkglibdir, 'tests', 'libos', 'entrypoint')

foreach name, params : tests
    filename = ''
    if (params.get('type', 'asm') == 'asm')
        filename = nasm_gen.process('@0@.asm'.format(name))
    else
        filename = '@0@.c'.format(name)
    endif

    exe = executable(name,
        filename,

        link_with: [
            params.get('link_with', [common_lib]),
        ],

        link_args: params.get('link_args', ['-nostdlib', '-static']),

        install: true,
        install_dir: install_dir,
    )
endforeach
