sgx_inc = [
    includes_pal_common,
    include_directories(
        '.',
        '../../../include/arch/@0@/Linux'.format(host_machine.cpu_family()),
        '../../../include/host/Linux-common',
        'protected-files',
    ),
]

subdir('protected-files')
subdir('tools')

install_data(
    'pal-sgx',
    install_dir: join_paths(pkglibdir, 'sgx'))
install_data(
    'libpal.so',
    install_dir: join_paths(pkglibdir, 'sgx'))
install_subdir('gdb_integration',
    install_dir: join_paths(pkglibdir, 'sgx'),
    exclude_directories: ['common'])
install_subdir('../../../gdb_integration',
    install_dir: join_paths(pkglibdir, 'sgx/gdb_integration/common'),
    strip_directory: true)

meson.add_install_script('/bin/sh', '-c',
    'ln -sf pal-sgx "$MESON_INSTALL_DESTDIR_PREFIX"/@0@'.format(
        join_paths(pkglibdir, 'sgx', 'loader')))

libpal_sgx_dep = cc.find_library('pal', static: false, dirs: meson.current_source_dir())
