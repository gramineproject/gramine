cflags_pal_common = [
    '-DIN_PAL',
    '-fno-builtin',
]

pal_common_sources = files(
    'db_events.c',
    'db_exception.c',
    'db_main.c',
    'db_memory.c',
    'db_misc.c',
    'db_object.c',
    'db_process.c',
    'db_rtld.c',
    'db_streams.c',
    'db_threading.c',
    'pal_error.c',
    'printf.c',
    'slab.c',
)

pal_common_sources_arch = [
    'pal_cpuid.c',
]
foreach src : pal_common_sources_arch
    pal_common_sources += files(join_paths('arch', host_machine.cpu_family(), src))
endforeach

subdir('host')
