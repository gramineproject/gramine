gsgx_h = configure_file(
    input: 'gsgx.h.in',
    output: 'gsgx.h',
    configuration: conf_sgx,
)

sgx_inc = [
    includes_pal_common,
    include_directories(
        '.',
        '../../../include/arch/@0@/Linux'.format(host_machine.cpu_family()),
        '../../../include/host/Linux-common',
        'protected-files',
    ),
]

cflags_pal_sgx = [
    '-DIN_PAL',
    '-DHOST_TYPE=Linux-SGX',
    '-fno-builtin',
    # Some of the code uses `alignof` on expressions, which is a GNU extension. Silence Clang - it
    # complains but does support it.
    '-Wno-gnu-alignof-expression',
]

# HACK: We explicitly define include directories in `-I...` format, for use in the the custom target
# below. Unfortunately, `sgx_inc` is a nested list of opaque IncludeDirs objects, so it's not
# possible to generate this list from `sgx_inc`.
sgx_inc_i = [
    '-I@0@'.format(meson.current_source_dir()),
    '-I@0@'.format(meson.current_build_dir()),
    '-I@0@'.format(join_paths(meson.current_source_dir(),
                              'protected-files')),
    '-I@0@'.format(join_paths(meson.current_source_dir(),
                              '../../../../common/include')),
    '-I@0@'.format(join_paths(meson.current_source_dir(),
                              '../../../../common/include/arch', host_machine.cpu_family())),
    '-I@0@'.format(join_paths(meson.current_source_dir(),
                              '../../../../Pal/include')),
    '-I@0@'.format(join_paths(meson.current_source_dir(),
                              '../../../../Pal/include/pal')),
    '-I@0@'.format(join_paths(meson.current_source_dir(),
                              '../../../../Pal/include/arch', host_machine.cpu_family())),
    '-I@0@'.format(join_paths(meson.current_source_dir(),
                              '../../../../Pal/include/arch', host_machine.cpu_family(), 'Linux')),
    '-I@0@'.format(join_paths(meson.current_source_dir(),
                              '../../../../Pal/include/host/Linux-common')),
    '-I@0@'.format(tomlc99_incpath),
]

pal_sgx_generated_offsets_s = custom_target('generated-offsets-pal-sgx.s',
    command: [
        cc.cmd_array(),
        cflags_pal_sgx,
        sgx_inc_i,
        '-S',
        '-MD', '-MP', '-MF', '@DEPFILE@',
        '@INPUT@',
        '-o', '@OUTPUT@'
    ],
    output: 'generated-offsets-pal-sgx.s',
    input: 'generated-offsets.c',
    depfile: 'generated_offsets.c.d',

    depends: tomlc99_src,
)

# TODO: after meson 0.54 those two targets can be combined, and the second one might be passed to
# installs in python/ directory
pal_sgx_asm_offsets = custom_target('asm-offsets.h[pal-sgx]',
    command: [gen_offsets_prog, '--output-h', '@OUTPUT@', '@INPUT@'],
    input: pal_sgx_generated_offsets_s,
    output: 'asm-offsets.h',
)
pal_sgx_offsets_py = custom_target('_offsets.py',
    command: [gen_offsets_prog, '--output-py', '@OUTPUT@', '@INPUT@'],
    input: pal_sgx_generated_offsets_s,
    output: '_offsets.py',

    install: true,
    install_dir: python3_pkgdir,
)

pal_sgx_map = custom_target('pal.map',
    command: [gen_pal_map_prog, '@INPUT@', '@OUTPUT@'],
    input: ['../../pal-symbols', 'pal.map.template'],
    output: 'pal.map',
)

pal_sgx_lds = join_paths(meson.current_source_dir(), 'enclave.lds')

libpal_sgx = shared_library('pal',
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
    'enclave_ecalls.c',
    'enclave_entry.S',
    'enclave_framework.c',
    'enclave_ocalls.c',
    'enclave_pages.c',
    'enclave_pf.c',
    'enclave_platform.c',
    'enclave_untrusted.c',
    'enclave_xstate.c',
    'protected-files/lru_cache.c',
    'protected-files/protected_files.c',
    pal_sgx_asm_offsets,
    pal_common_sources,
    pal_linux_common_sources_enclave,
    gsgx_h,

    include_directories: sgx_inc,

    c_args: [
        cflags_pal_common,
        cflags_pal_sgx,
        '-DIN_ENCLAVE',
    ],

    link_args: [
        '-nostdlib',
        '-Wl,-zcombreloc',
        '-Wl,-zdefs',
        '-Wl,--version-script=@0@'.format(pal_sgx_map.full_path()),
        '-Wl,-T@0@'.format(pal_sgx_lds),
        '-Wl,--eh-frame-hdr',
        '-Wl,-zrelro',
        '-Wl,-znow',
    ],

    link_depends: [
        pal_sgx_map,
        pal_sgx_lds,
    ],

    dependencies: [
        common_dep,
        cryptoadapter_pal_dep,
    ],

    install: true,
    install_dir: join_paths(pkglibdir, 'sgx'),
)

# URTS (untrusted runtime)
executable('loader',
    'sgx_enclave.c',
    'sgx_entry.S',
    'sgx_exception.c',
    'sgx_framework.c',
    'sgx_gdb_info.c',
    'sgx_log.c',
    'sgx_main.c',
    'sgx_perf_data.c',
    'sgx_platform.c',
    'sgx_process.c',
    'sgx_profile.c',
    'sgx_profile_glibc.c',
    'sgx_syscall.c',
    'sgx_thread.c',
    pal_linux_common_sources_urts,
    pal_sgx_asm_offsets,
    aesm_proto_ch,
    gsgx_h,

    include_directories: sgx_inc,
    c_args: [
        cflags_sanitizers,
        cflags_pal_sgx,
        # URTS uses stack protector with standard parameters (not the ones defined for Pal/LibOS)
        '-fstack-protector-strong',
    ],
    link_args: [
        '-Wl,-zrelro',
        '-Wl,-znow',
    ],
    pie: true,

    dependencies: [
        common_dep,
        protobuf_dep,
    ],

    install: true,
    install_dir: join_paths(pkglibdir, 'sgx'),
)

libpal_sgx_dep = declare_dependency(
    link_with: libpal_sgx,
    include_directories: includes_pal_common,
)

if debug
    shared_library('sgx_gdb',
        'gdb_integration/sgx_gdb.c',

        # just `sgx_gdb.so`, without `lib`
        name_prefix: '',

        c_args: [
            # optimize even in a debug build
            '-O3',
        ],

        install: true,
        install_dir: join_paths(pkglibdir, 'sgx/gdb_integration'),
    )

    install_data(
        'gdb_integration/gramine_sgx.gdb',
        'gdb_integration/gramine_sgx_gdb.py',
        install_dir: join_paths(pkglibdir, 'sgx/gdb_integration'),
    )
endif

subdir('protected-files')
subdir('tools')
