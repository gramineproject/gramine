gramine_vcs_tag = vcs_tag(
    command: ['git', 'rev-parse', '--verify', 'HEAD'],
    input: 'vcs_tag.in',
    output: 'vcs_tag',
)

common_render_defines = [
    '--config', gramine_vcs_tag,
    '-D', 'VERSION=@0@'.format(meson.project_version()),
    '-D', 'PREFIX=@0@'.format(get_option('prefix')),
    '-D', 'BINDIR=@0@'.format(get_option('bindir')),
]

subdir('common')
subdir('pf_crypt')
subdir('pf_tamper')

if direct
    hostpalpath_direct = get_option('prefix') / pkglibdir / 'direct'
    custom_target('gramine-direct',
        command: [meson_render_script_prog,
            '--mode', '755',
            common_render_defines,
            '-D', 'SGX=0',
            '-D', 'HOST_PAL_PATH=@0@'.format(hostpalpath_direct),
            '-D', 'LIBPAL_PATH=@0@'.format(hostpalpath_direct / 'libpal.so'),
            '-D', 'PAL_CMD=@0@'.format(hostpalpath_direct / 'loader'),
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
            common_render_defines,
            '-D', 'SGX=1',
            '-D', 'HOST_PAL_PATH=@0@'.format(hostpalpath_linux_sgx),
            '-D', 'LIBPAL_PATH=@0@'.format(hostpalpath_linux_sgx / 'libpal.so'),
            '-D', 'PAL_CMD=@0@'.format(get_option('prefix') / pkglibdir / 'sgx' / 'loader'),
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
