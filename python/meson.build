subdir('graminelibos')
subdir('graminelibos.dist-info')

install_data([
    'gramine-gen-depend',
    'gramine-manifest',
    'gramine-manifest-check',
], install_dir: get_option('bindir'))

if enable_tests
    install_data([
        'gramine-test',
    ], install_dir: get_option('bindir'))
endif

if sgx
    install_data([
        'gramine-sgx-gen-private-key',
        'gramine-sgx-sign',
        'gramine-sgx-sigstruct-view',
    ], install_dir: get_option('bindir'))
endif
