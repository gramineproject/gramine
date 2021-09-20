subdir('crt_init')

executables = [
    '..Bootstrap',
    'AttestationReport',
    'avl_tree_test',
    'Bootstrap',
    'Bootstrap3',
    'Bootstrap7',
    'Directory',
    'Event',
    'Exit',
    'File',
    'File2',
    'HelloWorld',
    'Hex',
    'Memory',
    'Misc',
    'Pie',
    'Pipe',
    'Process',
    'Process3',
    'Process4',
    'Select',
    'SendHandle',
    'Socket',
    'Symbols',
    'Tcp',
    'Thread2',
    'Udp',
    'normalize_path',
]

if host_machine.cpu_family() == 'x86_64'
    executables += [
        'Exception',
        'Exception2',
        'Segment',
        'Thread',
    ]
endif

pal_regression_inc = [
    includes_pal_common,

    include_directories(
        # for AttestationReport
        '../src/host/Linux-SGX',

        # for pal_host-arch.h
        join_paths(
        '../include/arch', host_machine.cpu_family(), 'Linux-SGX'),
    ),
]

foreach pal : ['direct', 'sgx']
    if not get_variable(pal)
        continue
    endif

    my_libpal_dep = get_variable('libpal_@0@_dep'.format(pal))
    install_dir = join_paths(pkglibdir, pal, 'tests')

    preload1 = shared_library('Preload1-@0@'.format(pal),
        'Preload1.c',
        'utils.c',

        c_args: [
            '-DIN_SHIM',

            # TODO
            '-Wno-discarded-qualifiers',
            '-Wno-unused-parameter',
        ],

        include_directories: pal_regression_inc,

        dependencies: [
            common_dep,
            crt_init_shared_dep,
            my_libpal_dep,
        ],

        install: true,
        install_dir: install_dir,
    )

    preload2 = shared_library('Preload2-@0@'.format(pal),
        'Preload2.c',
        'utils.c',

        c_args: [
            '-DIN_SHIM',

            # TODO
            '-Wno-discarded-qualifiers',
            '-Wno-unused-parameter',
        ],

        include_directories: pal_regression_inc,

        dependencies: [
            common_dep,
            crt_init_shared_dep,
            my_libpal_dep,
        ],

        install: true,
        install_dir: install_dir,
    )

    foreach exe : executables
        executable('@0@-@1@'.format(exe, pal),
            '@0@.c'.format(exe),
            'utils.c',

            pie: exe == 'Pie',
            c_args: [
                '-DIN_SHIM',
                '-fno-stack-protector',
                '-fno-builtin',
                '-nostdlib',

                # TODO
                '-Wno-discarded-qualifiers',
                '-Wno-unused-parameter',
            ],

            include_directories: pal_regression_inc,

            link_with: [
                preload1,
                preload2,
            ],

            dependencies: [
                common_dep,
                my_libpal_dep,
            ],

            install: true,
            install_dir: install_dir,
        )
    endforeach
endforeach
