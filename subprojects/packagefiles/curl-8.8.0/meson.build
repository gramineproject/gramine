project('curl', 'c', version: '8.8.0')

curl_libs_output = [
    'libcurl.a',
]

curl = custom_target('curl',
    command: [
        find_program('compile.sh'),
        '@CURRENT_SOURCE_DIR@',
        meson.current_build_dir(),
        '@PRIVATE_DIR@',
        meson.build_root() / 'subprojects',
    ],

    depends: subproject('mbedtls-3.6.3').get_variable('mbedtls_curl_libs'),
    output: curl_libs_output,
)

curl_minimal_dep = declare_dependency(
    link_with: curl,
    include_directories: 'include',
)
