sgx_util = static_library('sgx_util',
    'quote.c',
    'quote.h',

    include_directories: pal_sgx_inc, # this is only for `sgx_arch.h` and `sgx_attest.h`

    dependencies: [
        tools_util_dep,
        common_utils_dep,
    ],

    install: true,
    install_rpath: get_option('prefix') / get_option('libdir'),
)

sgx_util_dep = declare_dependency(
    link_with: sgx_util,
    include_directories: [
        include_directories('.'),
        tools_common_inc,
        pal_sgx_inc, # this is only for `sgx_arch.h` and `sgx_attest.h`
    ],
)
