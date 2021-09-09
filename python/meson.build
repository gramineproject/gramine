subdir('graminelibos')

install_data([
    'gramine-manifest',
], install_dir: get_option('bindir'))

if sgx
    install_data([
        'gramine-sgx-get-token',
        'gramine-sgx-sign',
    ], install_dir: get_option('bindir'))
endif
