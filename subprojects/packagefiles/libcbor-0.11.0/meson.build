project('libcbor', 'c', version: '0.11.0')

fs = import('fs')

# NOTE: This is custom_target, because CMake integration in Meson doesn't work correctly with PIC
#       static libraries, see https://github.com/mesonbuild/meson/issues/10764.
libcbor_lib = custom_target('libcbor',
    command: [
        find_program('compile.sh'),
        '@CURRENT_SOURCE_DIR@',
        meson.current_build_dir(),
        '@PRIVATE_DIR@',
    ],

    input: 'CMakeLists.txt',
    output: [
        'libcbor.a',
        'cbor.h',
    ],

    console: true,

    install: true,
    install_dir: [get_option('libdir'), get_option('includedir') / 'gramine'],
)

# We can't use `include_directories('include')` because the `include/` dir is generated in the
# custom target above, but Meson checks for existence of the dir *before* running the target,
# see https://github.com/mesonbuild/meson/issues/1855
libcbor_inc = include_directories('.')

libcbor_dep = declare_dependency(
    link_with: libcbor_lib[0],
    # HACK: Use the generated "cbor.h" file and propagate it as part of the RA-TLS build dependency
    # to enforce compile order, i.e., to make sure libcbor headers are ready before RA-TLS sources
    # start compiling.
    sources: libcbor_lib[1],
    include_directories: libcbor_inc,
    compile_args: '-Wno-strict-prototypes',
)
