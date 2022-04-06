foreach script : [
    'check-no-reloc.sh',
    'gen-pal-map.py',
    'get-python-platlib.py',
    'meson-clang-format.sh',
    'run-cargo.sh',
]
    set_variable('@0@_prog'.format(script.split('.')[0].underscorify()),
        find_program(script))
endforeach

run_cargo_cmd = [
    run_cargo_prog, '@INPUT@', '@OUTPUT@',
    meson.build_root() / 'target',
    get_option('buildtype')
]
