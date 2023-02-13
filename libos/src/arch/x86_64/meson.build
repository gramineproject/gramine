libos_sources_arch_list = {
    'fs_proc/info.c': {},
    'libos_arch_prctl.c': {},
    'libos_context.c': {},
    'libos_cpuid.c': {},
    'libos_elf_entry.nasm': { 'type': 'nasm' },
    'libos_table.c': {},
    'start.S': {},
    'syscallas.S': {},
}

libos_sources_arch = files()

foreach src, params : libos_sources_arch_list
    if params.get('type', '') == 'nasm'
        libos_sources_arch += nasm_gen.process(src)
    else
        libos_sources_arch += files(src)
    endif
endforeach

libos_lds = meson.current_source_dir() / 'libos.lds'
