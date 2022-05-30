executable('is-sgx-available',
    'is_sgx_available.cpp',

    cpp_args: [
        '-Wno-multichar',
    ],

    install: true,
    install_rpath: prefix / get_option('libdir'),
)
