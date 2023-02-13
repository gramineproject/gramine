executable('gramine-sgx-pf-tamper',
    'pf_tamper.c',

    dependencies: [
        sgx_util_dep,
    ],

    include_directories: common_inc, # for api.h

    install: true,
    install_rpath: get_option('prefix') / get_option('libdir'),
)
