common_src_utils = files(
    'path_utils.c',
    'string_utils.c',
)

common_src_internal = files(
    'avl_tree.c',
    'init.c',
    'location.c',
    'network/hton.c',
    'printf.c',
    'network/inet_pton.c',
    'socket_utils.c',
    'stack_protector.c',
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
    'string/toml_utils.c',
    'string/util.c',
)

# Arch-specific meson.build must define the following Meson variables:
#   - `common_src_arch` - a list of arch-specific sources.
subdir('arch')
# Current common arch-specific sources are for `common_src_internal` only.
common_src_internal += common_src_arch

if asan
    common_src_internal += files('asan.c')
endif
if ubsan
    common_src_internal += files('ubsan.c')
endif

common_utils_dep = declare_dependency(
    sources: common_src_utils,

    include_directories: common_inc,
)

common_internal_dep = declare_dependency(
    sources: common_src_internal,

    include_directories: common_inc,

    dependencies: [
        common_utils_dep,
        tomlc99_dep,
    ],
)

common_dep = declare_dependency(
    dependencies: [
        common_utils_dep,
        common_internal_dep,
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
