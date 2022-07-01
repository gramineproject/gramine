string_src = files(
    'atoi.c',
    'ctype.c',
    'memcmp.c',
    'memcpy.c',
    'memset.c',
    'strchr.c',
    'strcmp.c',
    'strlen.c',
    'strspn.c',
    'strstr.c',
    'toml_utils.c',
    'utils.c',
)

# Arch-specific meson.build must define the following Meson variables:
#   - `string_src_arch` - a list of arch-specific sources.
subdir('arch')
string_src += string_src_arch
