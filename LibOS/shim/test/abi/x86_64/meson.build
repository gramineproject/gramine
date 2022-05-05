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
    'stack_env': {},
    'stack_auxiliary': {
        'filenames': [
            'stack_auxiliary.c',
            nasm_gen.process('call_auxiliary.asm')
        ],
    },
}

install_dir = join_paths(pkglibdir, 'tests', 'libos', 'entrypoint')

foreach name, params : tests
    filenames = ''
    if (params.has_key('filenames'))
        filenames = params.get('filenames')
    elif (params.get('type', 'asm') == 'asm')
        filenames = nasm_gen.process('@0@.asm'.format(name))
    else
        filenames = '@0@.c'.format(name)
    endif

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
