foreach script : [
    'check-no-reloc.sh',
    'gen-offsets.py',
    'gen-pal-map.py',
    'get-python-platlib.py',
    'meson-clang-format.sh',
]
    set_variable('@0@_prog'.format(script.split('.')[0].underscorify()),
        find_program(script))
endforeach

install_data(
    'legacy-graphene-to-gramine',
    install_dir: get_option('bindir'))
