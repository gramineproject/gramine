install_dir = python3_platlib / 'graminelibos.dist-info'
conf = configuration_data()
conf.set('NAME', meson.project_name())
conf.set('VERSION', meson.project_version())
conf.set('LICENSE', ', '.join(meson.project_license()))

# https://packaging.python.org/en/latest/specifications/core-metadata/
configure_file(
    input: 'METADATA.in',
    output: 'METADATA',
    install_dir: install_dir,
    configuration: conf,
)

install_data('entry_points.txt', install_dir: install_dir)
