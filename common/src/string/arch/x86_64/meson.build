string_src_arch_list = {
    'ct_memcmp.nasm': { 'type': 'nasm' },
}

string_src_arch = files()

foreach src, params : string_src_arch_list
    if params.get('type', '') == 'nasm'
        string_src_arch += nasm_gen.process(src)
    else
        string_src_arch += files(src)
    endif
endforeach
