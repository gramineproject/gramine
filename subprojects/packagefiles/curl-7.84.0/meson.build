project('curl', 'c', version: '7.84.0')

curl_libs_output = [
    'libcurl.a',
]

curl = custom_target('curl',
    command: [
        find_program('compile.sh'),
        '@CURRENT_SOURCE_DIR@',
        meson.current_build_dir(),
        '@PRIVATE_DIR@',
        join_paths(meson.build_root(), 'subprojects'),
    ],

    depends: subproject('mbedtls-mbedtls-3.3.0').get_variable('mbedtls_curl_libs'),
    output: curl_libs_output,
)

curl_minimal_dep = declare_dependency(
    link_with: curl,
    include_directories: 'include',
)
