executable('gramine-sgx-quote-view',
    'quote_view.c',

    dependencies: [
        sgx_util_dep,
    ],

    install: true,
    install_rpath: join_paths(get_option('prefix'), get_option('libdir')),
)

meson.add_install_script('/bin/sh', '-c',
    'ln -sf gramine-sgx-quote-view ' +
    '"$MESON_INSTALL_DESTDIR_PREFIX"/bin/gramine-sgx-quote-dump')
