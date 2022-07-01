common_src_arch_list = {
    'ct_memcmp.nasm': { 'type': 'nasm' },
}

common_src_arch = files()

foreach src, params : common_src_arch_list
    if params.get('type', '') == 'nasm'
        common_src_arch += nasm_gen.process(src)
    else
        common_src_arch += files(src)
    endif
endforeach
