sgx_util = static_library('sgx_util',
    'quote.c',
    'quote.h',

    include_directories: pal_sgx_inc, # this is only for `sgx_arch.h` and `sgx_attest.h`

    dependencies: [
        tools_util_dep,
    ],

    install: true,
)

sgx_util_dep = declare_dependency(
    link_with: sgx_util,
    include_directories: [
        include_directories('.'),
        tools_common_inc,
        pal_sgx_inc, # this is only for `sgx_arch.h` and `sgx_attest.h`
    ],
)
