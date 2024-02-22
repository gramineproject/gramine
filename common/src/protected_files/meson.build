protected_files_inc = [
    include_directories('.',
                        '../../../pal/include/pal',
                        '../../../pal/include/arch' / host_machine.cpu_family(),
                        '../../../pal/include/arch' / host_machine.cpu_family() / 'linux'),
    common_inc,
]

protected_files_dep = declare_dependency(
    sources: [
        'protected_files.c',

        'protected_files_format.h',
        'protected_files.h',
        'protected_files_internal.h',
    ],

    include_directories: protected_files_inc,

    dependencies: [
        uthash_dep,
        common_dep,
    ]
)
