project('curl', 'c', version: '7.84.0')

mbedtls_gramine = dependency('mbedtls_curl')

# This dummy target is needed, because custom_target(depends:) needs a "target", not a "dependency"
mbedtls_dummy_tgt = static_library('dummy', 'dummy.c', dependencies: mbedtls_gramine)

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

    depends: mbedtls_dummy_tgt,
    output: curl_libs_output,
)

curl_minimal_dep = declare_dependency(
    link_with: curl,
    include_directories: 'include',
)
