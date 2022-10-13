cflags_libos = [
    '-fPIC',
    # TODO: check whether all standard functions implemented in Gramine match their APIs and remove
    # this
    '-ffreestanding',

    '-DIN_LIBOS',
]

cflags_libos += cc.get_supported_arguments(
    # Some of the code uses alignof on expressions, which is a GNU extension.
    # Silence Clang - it complains but does support it.
    '-Wno-gnu-alignof-expression',
)

if host_machine.cpu_family() == 'x86_64'
    cflags_libos += ['-mfxsr', '-mxsave']
endif

subdir('include')
subdir('src')

if enable_tests
    subdir('test')
endif
