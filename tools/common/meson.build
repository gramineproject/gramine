tools_common_inc = include_directories('.')

tools_util_dep = declare_dependency(
    sources: [
        'util.c',
        'util.h',
    ],
    include_directories: [
        tools_common_inc,
        common_inc,
    ],
)

subdir('pf_util')
