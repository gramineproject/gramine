executable('gramine-sgx-ias-verify-report',
    'verify_ias_report.c',

    dependencies: [
        sgx_ias_util_dep,
        sgx_util_dep,
    ],

    install: true,
    install_rpath: get_option('prefix') / get_option('libdir'),
)
