executable('gramine-sgx-quote-dump',
    'quote_dump.c',

    dependencies: [
        sgx_util_dep,
    ],

    install: true,
    install_rpath: join_paths(get_option('prefix'), get_option('libdir')),
)
