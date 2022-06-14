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
    # Use build_root() as opposed to @PRIVATE_DIR@, so that the intermediate results
    # from compiling Rust crates are shared between the various Cargo invokations.
    meson.build_root() / 'target',
    get_option('debug').to_string(),
    get_option('optimization')
]
