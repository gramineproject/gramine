subdir('graminelibos')

if meson.version().version_compare('>=0.62')
    meson.add_devenv({
        'PATH': meson.current_source_dir(),
        'PYTHONPATH': meson.current_source_dir(),
    }, method: 'append')
endif

install_data([
    'gramine-gen-depend',
    'gramine-manifest',
], install_dir: get_option('bindir'))

if enable_tests
    install_data([
        'gramine-test',
    ], install_dir: get_option('bindir'))
endif

if sgx
    install_data([
        'gramine-sgx-gen-private-key',
        'gramine-sgx-get-token',
        'gramine-sgx-sign',
    ], install_dir: get_option('bindir'))
endif
