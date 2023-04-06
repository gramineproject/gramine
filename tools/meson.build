gramine_with_git_version = vcs_tag(
    command: ['git', 'describe'],
    input: 'gramine.in',
    output: 'gramine.pre',
    replace_string: '@GRAMINE_VERSION@',
)

if direct
    hostpalpath_direct = prefix / pkglibdir / 'direct'

    custom_target('gramine-direct',
        command: [
            find_program('gramine-sed.sh'),
            '@INPUT@',
            '@OUTPUT@',
            '0',                               # @SGX@
            '',                                # @CONFIG_SGX_DRIVER@
            prefix,                            # @PREFIX@
            get_option('bindir'),              # @BINDIR@
            hostpalpath_direct,                # @HOST_PAL_PATH@
            hostpalpath_direct / 'libpal.so',  # @LIBPAL_PATH@
            hostpalpath_direct / 'loader',     # @PAL_CMD@
        ],

        input: gramine_with_git_version,
        output: 'gramine-direct',

        install: true,
        install_dir: get_option('bindir'),
    )
endif

if sgx
    subdir('sgx')

    hostpalpath_linux_sgx = prefix / pkglibdir / 'sgx'

    custom_target('gramine-sgx',
        command: [
            find_program('gramine-sed.sh'),
            '@INPUT@',
            '@OUTPUT@',
            '1',                                  # @SGX@
            sgx_driver,                           # @CONFIG_SGX_DRIVER@
            prefix,                               # @PREFIX@
            get_option('bindir'),                 # @BINDIR@
            hostpalpath_linux_sgx,                # @HOST_PAL_PATH@
            hostpalpath_linux_sgx / 'libpal.so',  # @LIBPAL_PATH@
            hostpalpath_linux_sgx / 'loader',     # @PAL_CMD@
        ],

        input: gramine_with_git_version,
        output: 'gramine-sgx',

        install: true,
        install_dir: get_option('bindir'),
    )
endif

executable('gramine-argv-serializer',
    'argv_serializer.c',
    install: true)
