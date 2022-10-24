common_src_libc = files(
    'printf.c',
    'string/atoi.c',
    'string/ctype.c',
    'string/memcmp.c',
    'string/memcpy.c',
    'string/memset.c',
    'string/strchr.c',
    'string/strcmp.c',
    'string/strlen.c',
    'string/strspn.c',
    'string/strstr.c',
    'string/util.c',
)

common_src_utils = files(
    'path_utils.c',
    'string_utils.c',
)

common_src_internal = files(
    'avl_tree.c',
    'init.c',
    'location.c',
    'network/hton.c',
    'network/inet_pton.c',
    'socket_utils.c',
    'stack_protector.c',
    'string/toml_utils.c',
)

# Arch-specific meson.build must define the following Meson variables:
#   - `common_src_arch` - a list of arch-specific sources.
subdir('arch')
# Current common arch-specific sources are for `common_src_internal` only.
common_src_internal += common_src_arch

common_dep_utils = declare_dependency(
    sources: common_src_utils,

    include_directories: common_inc,
)

common_dep_libc = declare_dependency(
    sources: common_src_libc,

    include_directories: common_inc,

    dependencies: [
        common_dep_utils,
    ],
)

common_dep_internal = declare_dependency(
    sources: common_src_internal,

    include_directories: common_inc,

    dependencies: [
        common_dep_libc,
        common_dep_utils,
        tomlc99_dep,
    ],
)

common_src_san = files()
if asan
    common_src_san += files('asan.c')
endif
if ubsan
    common_src_san += files('ubsan.c')
endif
common_dep_san = declare_dependency(
    sources: common_src_san,

    include_directories: common_inc,

    dependencies: [
        common_dep_libc,
    ],
)

common_dep = declare_dependency(
    dependencies: [
        common_dep_libc,
        common_dep_utils,
        common_dep_san,
        common_dep_internal,
        uthash_dep,
        tomlc99_dep,
    ],
)

generated_offsets_print_src = files('generated_offsets_print.c')

cryptoadapter_dep = declare_dependency(
    dependencies: mbedtls_pal_dep,
    sources: 'crypto/adapters/mbedtls_adapter.c',
    compile_args: [
        '-DCRYPTO_USE_MBEDTLS',
    ],
)

subdir('protected_files')
