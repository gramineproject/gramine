install_dir = python3_platlib / 'graminelibos.dist-info'
conf = configuration_data()
conf.set('NAME', meson.project_name())
conf.set('LICENSE', ', '.join(meson.project_license()))

# VERSION needs to comply with the official specification, which is restrictive:
# https://packaging.python.org/en/latest/specifications/version-specifiers/
# In Gramine, we use X.Y, X.Y.Z, X.Y~rcN and X.Ypost~UNRELEASED, which is
# exactly what we want for distro packages (~ sorts negative), but can't be used
# for python distributions.
conf.set('VERSION',
    meson.project_version().replace('~UNRELEASED', '').replace('~', ''))

# https://packaging.python.org/en/latest/specifications/core-metadata/
configure_file(
    input: 'METADATA.in',
    output: 'METADATA',
    install_dir: install_dir,
    configuration: conf,
)

install_data('entry_points.txt', install_dir: install_dir)
