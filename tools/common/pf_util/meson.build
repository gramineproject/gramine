pf_util_dep = declare_dependency(
    sources: [
        'pf_util.c',
        'pf_util.h',
    ],

    include_directories: [
        include_directories('.'),
        tools_common_inc,
        protected_files_inc,
    ],

    dependencies: [
        tools_util_dep,
        common_utils_dep,
        mbedtls_static_dep,
        protected_files_dep,
    ],

    compile_args: [
        '-DIN_TOOLS',
    ],
)
