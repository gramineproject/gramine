pal_direct_sources = files(
    'db_devices.c',
    'db_eventfd.c',
    'db_events.c',
    'db_exception.c',
    'db_files.c',
    'db_main.c',
    'db_memory.c',
    'db_misc.c',
    'db_object.c',
    'db_pipes.c',
    'db_process.c',
    'db_rtld.c',
    'db_sockets.c',
    'db_streams.c',
    'db_threading.c',
)

pal_direct_sources_arch = [
    'db_arch_exception.c',
    'db_arch_misc.c',
    'pal_start.S',
]
foreach src : pal_direct_sources_arch
    pal_direct_sources += join_paths('arch', host_machine.cpu_family(), src)
endforeach

pal_direct_lds = join_paths(
    meson.current_source_dir(), 'arch', host_machine.cpu_family(), 'pal.lds')

pal_direct_map = custom_target('pal.map[direct]',
    command: [gen_pal_map_prog, '@INPUT@', '@OUTPUT@'],
    input: ['../../pal-symbols', 'pal.map.template'],
    output: 'pal.map',
)

# TODO after meson>=0.46 change this to both_libraries
foreach target_type : ['shared_library', 'static_library']
    target = build_target('pal',
        pal_common_sources,
        pal_linux_common_sources,
        pal_direct_sources,

        include_directories: [
            includes_pal_common,
            include_directories(
                '../../../include/arch/@0@/Linux'.format(host_machine.cpu_family()),
                '../../../include/host/Linux-common',
            ),
        ],

        c_args: [
            cflags_pal_common,
            cflags_sanitizers,
            cflags_custom_stack_protector,
            '-DHOST_TYPE=Linux',
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
            '-Wl,--version-script=@0@'.format(pal_direct_map.full_path()),
            '-Wl,-T@0@'.format(pal_direct_lds),
            '-Wl,--eh-frame-hdr',
        ],
        link_depends: [
            pal_direct_map,
            pal_direct_lds,
        ],

        dependencies: [
            common_dep,
        ],

        install: true,
        install_dir: join_paths(pkglibdir, 'direct'),

        target_type: target_type)

    if target_type == 'shared_library'
        libpal_direct = target
    else
        libpal_direct_static = target
    endif
endforeach

libpal_direct_dep = declare_dependency(
    link_with: libpal_direct,
)

if debug
    install_data(
        'gdb_integration/gramine_linux_gdb.py',
        install_dir: join_paths(pkglibdir, 'direct/gdb_integration'),
    )
endif

meson.add_install_script('/bin/sh', '-c',
    'ln -sf libpal.so "$MESON_INSTALL_DESTDIR_PREFIX"/@0@'.format(
        join_paths(pkglibdir, 'direct/loader')))
