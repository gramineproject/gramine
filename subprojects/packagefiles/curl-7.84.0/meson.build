project('curl', 'c', version: '7.84.0')

mbedtls_inc = join_paths(
    meson.source_root(),
    'subprojects/mbedtls-mbedtls-3.2.1/mbedtls-mbedtls-3.2.1/include',
)

curl_libs_output = [
    'libcurl.a',
]

curl = custom_target('curl',
    command: [
        find_program('compile.sh'),
        '@CURRENT_SOURCE_DIR@',
        meson.current_build_dir(),
        '@PRIVATE_DIR@',
        mbedtls_inc,
    ],

    output: curl_libs_output,
)

curl_minimal_dep = declare_dependency(
    link_with: curl,
    include_directories: 'include',
)
