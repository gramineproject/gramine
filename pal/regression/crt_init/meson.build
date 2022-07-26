pal_regression_user_start = files('start_main.c')

# Arch-specific meson.build must define the following Meson variables:
#  - `pal_regression_arch_user_start` - a list of arch-specific sources.
subdir('arch')
pal_regression_user_start += pal_regression_arch_user_start
