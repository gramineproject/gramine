sgx_util = static_library('sgx_util',
    'ias.c',
    'ias.h',
    'pf_util.c',
    'pf_util.h',
    'quote.c',
    'quote.h',
    'util.c',
    'util.h',

    c_args: [
        '-DIN_TOOLS',
    ],

    include_directories: [
        pal_sgx_inc, # this is only for `sgx_arch.h` and `sgx_attest.h`
        common_inc,
    ],
    dependencies: [
        cjson_dep,
        common_utils_dep,
        libcurl_dep,
        protected_files_dep,
        mbedtls_static_dep,
    ],

    install: true,
    install_rpath: join_paths(get_option('prefix'), get_option('libdir')),
)

sgx_util_dep = declare_dependency(
    link_with: sgx_util,
    include_directories: [
        include_directories('.'),
        pal_sgx_inc, # this is only for `sgx_arch.h` and `sgx_attest.h`
        protected_files_inc,
    ],
)
