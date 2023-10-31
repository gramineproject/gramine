conf = configuration_data()
conf.set_quoted('IN_GIT', '')
conf.set_quoted('PREFIX', get_option('prefix'))
conf.set_quoted('BINDIR', get_option('bindir'))

gramine_vcs_tag = vcs_tag(
    command: ['git', 'rev-parse', '--verify', 'HEAD'],
    input: 'vcs_tag.in',
    output: 'vcs_tag',
)

if direct
    hostpalpath_direct = get_option('prefix') / pkglibdir / 'direct'
    custom_target('gramine-direct',
        command: [meson_render_script_prog,
            '--mode', '755',
            '--config', gramine_vcs_tag,
            '-D', 'VERSION=@0@'.format(meson.project_version()),
            '-D', 'SGX=0',
            '-D', 'HOST_PAL_PATH=@0@'.format(hostpalpath_direct),
            '-D', 'LIBPAL_PATH=@0@'.format(hostpalpath_direct / 'libpal.so'),
            '-D', 'PAL_CMD=@0@'.format(hostpalpath_direct / 'loader'),
            '-D', 'CONFIG_SGX_DRIVER=',
            '@INPUT@',
            '@OUTPUT@',
        ],
        input: 'gramine.in',
        output: 'gramine-direct',
        install: true,
        install_dir: get_option('bindir'),
    )
endif

if sgx
    subdir('sgx')

    hostpalpath_linux_sgx = get_option('prefix') / pkglibdir / 'sgx'

    custom_target('gramine-sgx',
        command: [meson_render_script_prog,
            '--mode', '755',
            '--config', gramine_vcs_tag,
            '-D', 'VERSION=@0@'.format(meson.project_version()),
            '-D', 'SGX=1',
            '-D', 'HOST_PAL_PATH=@0@'.format(hostpalpath_linux_sgx),
            '-D', 'LIBPAL_PATH=@0@'.format(hostpalpath_linux_sgx / 'libpal.so'),
            '-D', 'PAL_CMD=@0@'.format(get_option('prefix') / pkglibdir / 'sgx' / 'loader'),
            '-D', 'CONFIG_SGX_DRIVER=@0@'.format(sgx_driver),
            '@INPUT@',
            '@OUTPUT@',
        ],
        input: 'gramine.in',
        output: 'gramine-sgx',
        install: true,
        install_dir: get_option('bindir'),
    )
endif

executable('gramine-argv-serializer',
    'argv_serializer.c',
    install: true)
