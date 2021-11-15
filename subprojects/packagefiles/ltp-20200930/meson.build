project('ltp', 'c', version: '20200930')

# HACK: We cannot use the 'install:' parameter to install all of LTP, because Meson will require a
# full list of installed files, and this is complicated to determine. Instead, we create a tarball,
# and unpack it using a custom install script.

ltp_tarball = custom_target('ltp',
    command: [
        find_program('compile.sh'),
        '@CURRENT_SOURCE_DIR@',
        meson.current_build_dir(),
        '@PRIVATE_DIR@',
        'ltp.tar.gz',
    ],

    input: 'configure',

    output: 'ltp.tar.gz',

    console: true,
)

meson.add_install_script('install.sh',
    [ltp_tarball, join_paths(get_option('libdir'), 'gramine/tests/ltp')],
)
