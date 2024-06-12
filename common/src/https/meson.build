https_inc = [
    include_directories('.'),
    common_inc,
]

https_dep = declare_dependency(
    sources: [
        'https.c',
    ],
    include_directories: https_inc,
    dependencies: mbedtls_pal_dep,
    compile_args: [
        '-DCRYPTO_USE_MBEDTLS',
    ],
)
