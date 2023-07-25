# Link mbedtls statically to Gramine-provided libraries, e.g., RA-TLS and Secret Provisioning
# libraries. This is because they are loaded dynamically to users' software and we don't want our
# patched mbedtls to collide with libraries the program already uses.

pkgconfig = import('pkgconfig')

install_headers('ra_tls.h', 'ra_tls_common.h', 'secret_prov.h', subdir : 'gramine')

libra_tls_inc = include_directories('.')

ra_tls_map = join_paths(meson.current_source_dir(), 'ra_tls.map')
ra_tls_link_args = [
    '-Wl,--version-script=@0@'.format(ra_tls_map),
]

secret_prov_map = join_paths(meson.current_source_dir(), 'secret_prov.map')
secret_prov_link_args = [
    '-Wl,--version-script=@0@'.format(secret_prov_map),
]

libra_tls_attest = shared_library('ra_tls_attest',
    'ra_tls_attest.c',
    link_args: ra_tls_link_args,
    include_directories: pal_sgx_inc, # this is only for `sgx_arch.h` and `sgx_attest.h`
    dependencies: [
        mbedtls_static_dep,
    ],
    install: true,
    install_rpath: get_option('prefix') / get_option('libdir'),
)
if get_option('libc') == 'glibc' and host_has_glibc
    meson.add_install_script('/bin/sh', '-c',
        'ln -sf ../../../libra_tls_attest.so ' +
        '"$MESON_INSTALL_DESTDIR_PREFIX"/@0@/gramine/runtime/@1@/'.format(
            get_option('libdir'), get_option('libc')))
endif

libra_tls_verify = static_library('ra_tls_verify',
    'ra_tls_verify_common.c',

    include_directories: pal_sgx_inc,
    dependencies: [
        sgx_util_dep,
        mbedtls_static_dep,
    ],
    install: true,
    install_rpath: get_option('prefix') / get_option('libdir'),
)
if get_option('libc') == 'glibc' and host_has_glibc
    meson.add_install_script('/bin/sh', '-c',
        'ln -sf ../../../libra_tls_verify.a ' +
        '"$MESON_INSTALL_DESTDIR_PREFIX"/@0@/gramine/runtime/@1@/'.format(
            get_option('libdir'), get_option('libc')))
endif

libra_tls_verify_dep = declare_dependency(
    link_with: libra_tls_verify,
    include_directories: pal_sgx_inc,
)

libra_tls_verify_epid = shared_library('ra_tls_verify_epid',
    'ra_tls_verify_epid.c',

    link_args: ra_tls_link_args,
    dependencies: [
        libra_tls_verify_dep.as_link_whole(),
        mbedtls_static_dep,
        sgx_ias_util_dep,
        sgx_util_dep,
    ],
    install: true,
    install_rpath: join_paths(get_option('prefix'), get_option('libdir')),
)
if get_option('libc') == 'glibc' and host_has_glibc
    meson.add_install_script('/bin/sh', '-c',
        'ln -sf ../../../libra_tls_verify_epid.so ' +
        '"$MESON_INSTALL_DESTDIR_PREFIX"/@0@/gramine/runtime/@1@/'.format(
            get_option('libdir'), get_option('libc')))
endif

libsecret_prov_attest = shared_library('secret_prov_attest',
    'secret_prov_attest.c',
    'secret_prov_common.c',
    'ra_tls_attest.c',

    link_args: secret_prov_link_args,
    include_directories: pal_sgx_inc,
    dependencies: [
        mbedtls_static_dep,
        sgx_util_dep,
    ],
    install: true,
    install_rpath: get_option('prefix') / get_option('libdir'),
)
if get_option('libc') == 'glibc' and host_has_glibc
    meson.add_install_script('/bin/sh', '-c',
        'ln -sf ../../../libsecret_prov_attest.so ' +
        '"$MESON_INSTALL_DESTDIR_PREFIX"/@0@/gramine/runtime/@1@/'.format(
            get_option('libdir'), get_option('libc')))
endif

libsecret_prov_verify = static_library('secret_prov_verify',
    'secret_prov_verify.c',
    'secret_prov_common.c',

    dependencies: [
        libra_tls_verify_dep,
        mbedtls_static_dep,
        sgx_util_dep,
    ],
    install: true,
    install_rpath: join_paths(get_option('prefix'), get_option('libdir')),
)
if get_option('libc') == 'glibc' and host_has_glibc
    meson.add_install_script('/bin/sh', '-c',
        'ln -sf ../../../libsecret_prov_verify.a ' +
        '"$MESON_INSTALL_DESTDIR_PREFIX"/@0@/gramine/runtime/@1@/'.format(
            get_option('libdir'), get_option('libc')))
endif

libsecret_prov_verify_dep = declare_dependency(
    link_with: libsecret_prov_verify,
    include_directories: pal_sgx_inc,
)

libsecret_prov_verify_epid = shared_library('secret_prov_verify_epid',
    'ra_tls_verify_epid.c',

    link_args: secret_prov_link_args,
    dependencies: [
        libsecret_prov_verify_dep.as_link_whole(),
        mbedtls_static_dep,
        sgx_ias_util_dep,
        sgx_util_dep,
        threads_dep,
    ],
    install: true,
    install_rpath: get_option('prefix') / get_option('libdir'),
)
if get_option('libc') == 'glibc' and host_has_glibc
    meson.add_install_script('/bin/sh', '-c',
        'ln -sf ../../../libsecret_prov_verify_epid.so ' +
        '"$MESON_INSTALL_DESTDIR_PREFIX"/@0@/gramine/runtime/@1@/'.format(
            get_option('libdir'), get_option('libc')))
endif

if dcap
    libra_tls_verify_dcap = shared_library('ra_tls_verify_dcap',
        'ra_tls_verify_dcap.c',

        link_args: ra_tls_link_args,
        dependencies: [
            libra_tls_verify_dep.as_link_whole(),
            mbedtls_static_dep,
            sgx_dcap_quoteverify_dep,
            sgx_util_dep,
        ],
        install: true,
        install_rpath: get_option('prefix') / get_option('libdir'),
    )
    if get_option('libc') == 'glibc' and host_has_glibc
        meson.add_install_script('/bin/sh', '-c',
            'ln -sf ../../../libra_tls_verify_dcap.so ' +
            '"$MESON_INSTALL_DESTDIR_PREFIX"/@0@/gramine/runtime/@1@/'.format(
                get_option('libdir'), get_option('libc')))
    endif

    libra_tls_verify_dcap_gramine = shared_library('ra_tls_verify_dcap_gramine',
        'ra_tls_verify_dcap.c',
        'ra_tls_verify_dcap_gramine.c',

        link_args: ra_tls_link_args,
        dependencies: [
            libra_tls_verify_dep.as_link_whole(),
            mbedtls_static_dep,
            sgx_dcap_quoteverify_dep,
            sgx_util_dep,
        ],
        install: true,
        install_rpath: get_option('prefix') / get_option('libdir'),
    )
    if get_option('libc') == 'glibc' and host_has_glibc
        meson.add_install_script('/bin/sh', '-c',
            'ln -sf ../../../libra_tls_verify_dcap_gramine.so ' +
            '"$MESON_INSTALL_DESTDIR_PREFIX"/@0@/gramine/runtime/@1@/'.format(
                get_option('libdir'), get_option('libc')))
    endif

    libsecret_prov_verify_dcap = shared_library('secret_prov_verify_dcap',
        'ra_tls_verify_dcap.c',

        link_args: secret_prov_link_args,
        include_directories: pal_sgx_inc,
        dependencies: [
            libsecret_prov_verify_dep.as_link_whole(),
            mbedtls_static_dep,
            sgx_dcap_quoteverify_dep,
            sgx_util_dep,
            threads_dep,
        ],
        install: true,
        install_rpath: get_option('prefix') / get_option('libdir'),
    )
    if get_option('libc') == 'glibc' and host_has_glibc
        meson.add_install_script('/bin/sh', '-c',
            'ln -sf ../../../libsecret_prov_verify_dcap.so ' +
            '"$MESON_INSTALL_DESTDIR_PREFIX"/@0@/gramine/runtime/@1@/'.format(
                get_option('libdir'), get_option('libc')))
    endif
endif

pkgconfig.generate(
    name: 'ra_tls_gramine',
    filebase: 'ra_tls_gramine',
    description: 'RA-TLS (SGX Remote Attestation TLS library) for Gramine',
    subdirs: 'gramine',
    libraries: [
        '-L${libdir}',
        '-Wl,-rpath,${libdir}',
        # RA-TLS consists of multiple independent libs, let user decide which to link
    ],
)

pkgconfig.generate(
    name: 'secret_prov_gramine',
    filebase: 'secret_prov_gramine',
    description: 'Secret Provisioning library for Gramine',
    subdirs: 'gramine',
    libraries: [
        '-L${libdir}',
        '-Wl,-rpath,${libdir}',
        # Secret Prov consists of multiple independent libs, let user decide which to link
    ],
)

executable('gramine-ratls',
    'gramine-ratls.c',
    link_with: libra_tls_attest,
    dependencies: [
        sgx_util_dep,
        mbedtls_static_dep,
    ],
    install: true,
)
