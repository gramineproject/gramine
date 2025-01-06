pf_util_inc = include_directories('.')

pf_util = static_library('pf_util',
    'pf_util.c',
    'pf_util.h',

    c_args: [
        '-DIN_TOOLS',
    ],

    include_directories: [
        common_inc,
    ],

    dependencies: [
        tools_util_dep,
        common_utils_dep,
        mbedtls_static_dep,
        protected_files_dep,
    ],

    install: true,
    install_rpath: get_option('prefix') / get_option('libdir'),
)

pf_util_dep = declare_dependency(
    link_with: pf_util,
    include_directories: [
        pf_util_inc,
        tools_common_inc,
        protected_files_inc,
    ],
)
