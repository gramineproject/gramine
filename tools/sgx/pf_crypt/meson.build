executable('gramine-sgx-pf-crypt',
    'pf_crypt.c',

    dependencies: [
        sgx_util_dep,
    ],

    install: true,
    install_rpath: get_option('prefix') / get_option('libdir'),
)
