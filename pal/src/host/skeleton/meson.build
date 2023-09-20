# Arch-specific meson.build must define the following Meson variables:
#   - `pal_skeleton_lds` - a full path to PAL linker script.
subdir('arch')

pal_skeleton_map = custom_target('pal.map[skeleton]',
    command: [gen_pal_map_prog, '@INPUT@', '@OUTPUT@'],
    input: ['../../pal_symbols', 'pal.map.template'],
    output: 'pal.map',
)

libpal_skeleton = shared_library('pal',
    'pal_console.c',
    'pal_devices.c',
    'pal_eventfd.c',
    'pal_events.c',
    'pal_exception.c',
    'pal_files.c',
    'pal_main.c',
    'pal_memory.c',
    'pal_misc.c',
    'pal_object.c',
    'pal_pipes.c',
    'pal_process.c',
    'pal_rtld.c',
    'pal_sockets.c',
    'pal_streams.c',
    'pal_threading.c',
    pal_common_sources,

    include_directories: [
        includes_pal_common,
        include_directories(
            '../../../include/arch/@0@/skeleton'.format(host_machine.cpu_family()),
        ),
    ],

    c_args: [
        cflags_pal_common,
        cflags_custom_stack_protector,
        cflags_sanitizers,
        '-DHOST_TYPE=Skeleton',

        # in Skeleton, every single parameter is unused
        '-Wno-unused-parameter',
    ],

    link_args: [
        '-nostdlib',

        # For PAL symbol resolution, we use old-style hash (DT_HASH) table instead of the
        # default GNU hash (DT_GNU_HASH) table -- to figure out the number of dynamic symbols in
        # the SYMTAB symbol table
        '-Wl,--hash-style=sysv',

        # PAL is expected to be linked with RELRO (Relocation Read-Only)
        '-Wl,-zrelro',
        '-Wl,-znow',

        '-Wl,-zcombreloc',
        '-Wl,-zdefs',
        '-Wl,--version-script=@0@'.format(pal_skeleton_map.full_path()),
        '-Wl,-T@0@'.format(pal_skeleton_lds),
        '-Wl,--eh-frame-hdr',
    ],
    link_depends: [
        pal_skeleton_map,
        pal_skeleton_lds,
    ],

    dependencies: [
        common_dep,
    ],

    install: true,
    install_dir: pkglibdir / 'skeleton',
)

libpal_skeleton_dep = declare_dependency(
    link_with: libpal_skeleton,
)

if debug
    custom_target('libpal.so.map',
        input: libpal_skeleton,
        command: gen_symbol_map_cmd,
        capture: true,
        output: 'libpal.so.map',

        install: true,
        install_dir: pkglibdir / 'skeleton',
    )
endif
