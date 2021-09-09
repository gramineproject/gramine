executable('gramine-argv-serializer',
    'argv_serializer.c',
    install: true)

meson.add_install_script('/bin/sh', '-c',
    'ln -sf legacy-graphene-to-gramine "$MESON_INSTALL_DESTDIR_PREFIX"/@0@'.format(
        join_paths(get_option('bindir'), 'graphene-argv-serializer')))

install_data(
    'legacy-graphene-to-gramine',
    install_dir: get_option('bindir'))
