common_lib = static_library('test_fs',
    'common.c',
)

common_lib_copy = static_library('test_fs_copy',
    'common_copy.c',
    c_args: [
        '-Wno-sign-compare',
    ],
)

common_lib_copy_mmap = static_library('test_fs_copy_mmap',
    'common_copy.c',
    c_args: [
        '-Wno-sign-compare',
        '-DCOPY_MMAP',
    ],
)

tests = {
    'copy_mmap_rev': {
        'libs': common_lib_copy_mmap,
    },
    'copy_mmap_seq': {
        'libs': common_lib_copy_mmap,
    },
    'copy_mmap_whole': {
        'libs': common_lib_copy_mmap,
    },
    'copy_rev': {
        'libs': common_lib_copy,
    },
    'copy_seq': {
        'libs': common_lib_copy,
    },
    'copy_whole': {
        'libs': common_lib_copy,
    },
    'copy_sendfile': {
        'libs': common_lib_copy,
    },
    'delete': {},
    'multiple_writers': {
        'link_args': '-lpthread',
    },
    'open_close': {},
    'open_flags': {},
    'read_write': {},
    'seek_tell': {},
    'stat': {},
    'truncate': {},
}

install_dir = join_paths(pkglibdir, 'tests', 'libos', 'fs')

foreach name, params : tests
    exe = executable(name,
        '@0@.c'.format(name),

        link_with: [
            common_lib,
            params.get('libs', []),
        ],

        c_args: [
            '-Wno-sign-compare',
            params.get('c_args', []),
        ],

        link_args: params.get('link_args', []),

        dependencies: params.get('dependencies', []),

        install: enable_tests,
        install_dir: install_dir,
    )
endforeach
