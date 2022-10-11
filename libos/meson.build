cflags_libos = [
    '-fPIC',
    # TODO: check whether all standard functions implemented in Gramine match their APIs
    '-ffreestanding',

    '-DIN_LIBOS',
]

if host_machine.cpu_family() == 'x86_64'
    cflags_libos += ['-mfxsr', '-mxsave']
endif

subdir('include')
subdir('src')

if enable_tests
    subdir('test')
endif
