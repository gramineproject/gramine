cflags_pal_common = [
    '-DIN_PAL',
    '-ffreestanding',
    '-fPIC',
]

pal_common_sources = files(
    'pal_events.c',
    'pal_exception.c',
    'pal_main.c',
    'pal_memory.c',
    'pal_misc.c',
    'pal_object.c',
    'pal_process.c',
    'pal_rtld.c',
    'pal_sockets.c',
    'pal_streams.c',
    'pal_threading.c',
    'printf.c',
    'slab.c',
)

# Arch-specific meson.build must define the following Meson variables:
#   - `pal_common_sources_arch` - a list of arch-specific sources.
subdir('arch')
pal_common_sources += pal_common_sources_arch

subdir('host')
