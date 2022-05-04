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
        'filename': [
            'stack_auxiliary.c',
            nasm_gen.process('call_auxiliary.asm')
        ],
        'include_directories': [
            # For 'elf/elf.h'
            include_directories('../../../../../Pal/include'),
        ],
    },

}

install_dir = join_paths(pkglibdir, 'tests', 'libos', 'entrypoint')

foreach name, params : tests
    filename = ''
    if (params.has_key('filename'))
        filename = params.get('filename')
    elif (params.get('type', 'asm') == 'asm')
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
        include_directories: params.get('include_directories', []),

        install: true,
        install_dir: install_dir,
    )
endforeach
