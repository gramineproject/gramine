project('curl', 'c', version: '7.84.0')

mbedtls_gramine = dependency('mbedtls_proj')

curl_libs_output = [
    'libcurl.a',
]

libmbedtls = static_library('mbedtls',
    dependencies: mbedtls_gramine,
)

curl = custom_target('curl',
    command: [
        find_program('compile.sh'),
        '@CURRENT_SOURCE_DIR@',
        meson.current_build_dir(),
        '@PRIVATE_DIR@',
        '@0@'.format(join_paths(meson.build_root(), 'subprojects')),
    ],

    output: curl_libs_output,

    depends: libmbedtls,
)

curl_minimal_dep = declare_dependency(
    link_with: curl,
    include_directories: 'include',
)
