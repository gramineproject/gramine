executable('gramine-sgx-ias-request',
    'ias_request.c',

    dependencies: [
        sgx_ias_util_dep,
        sgx_util_dep,
    ],

    install: true,
    install_rpath: get_option('prefix') / get_option('libdir'),
)
