common_lib = static_library('common_lib',
    'common.c',
    nasm_gen.process('exit.asm')
)

tests = {
    'atexit_func': {
        'type': 'asm',
        'link_args': ['-nostdlib', '-static'],
        'link_with': [common_lib],
    },
    'fpu_control_word': {
        'type': 'asm',
        'link_args': ['-nostdlib', '-static'],
        'link_with': [common_lib],
    },
    'mxcsr': {
        'type': 'asm',
        'link_args': ['-nostdlib', '-static'],
        'link_with': [common_lib],
    },
    'rflags': {
        'type': 'asm',
        'link_args': ['-nostdlib', '-static'],
        'link_with': [common_lib],
    },
    'stack': {
        'type': 'asm',
        'link_args': ['-nostdlib', '-static'],
        'link_with': [common_lib],
    },
    'stack_argc1': {
        'type': 'asm',
        'link_args': ['-nostdlib', '-static'],
        'link_with': [common_lib],
    },
    'stack_argc3': {
        'type': 'asm',
        'link_args': ['-nostdlib', '-static'],
        'link_with': [common_lib],
    },
    'stack_argv1': {
        'type': 'asm',
        'link_args': ['-nostdlib', '-static'],
        'link_with': [common_lib],
    },
    'stack_argv3': {
        'type': 'asm',
        'link_args': ['-nostdlib', '-static'],
        'link_with': [common_lib],
    },
}

install_dir = join_paths(pkglibdir, 'tests', 'libos', 'entrypoint')

foreach name, params : tests
    filename = ''
    if (params.get('type') == 'asm')
        filename = nasm_gen.process('@0@.asm'.format(name))
    else
        filename = '@0@.c'.format(name)
    endif

    exe = executable(name,
        filename,

        link_with: [
            params.get('link_with', []),
        ],

        link_args: params.get('link_args', []),

        install: true,
        install_dir: install_dir,
    )
endforeach
