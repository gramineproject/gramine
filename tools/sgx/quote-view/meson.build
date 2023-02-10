executable('gramine-sgx-quote-view',
    'quote_view.c',

    dependencies: [
        sgx_util_dep,
    ],

    install: true,
    install_rpath: get_option('prefix') / get_option('libdir'),
)
