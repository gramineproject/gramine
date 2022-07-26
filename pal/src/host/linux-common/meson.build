pal_linux_common_sources_enclave = files(
    'bogomips.c',
    'gramine_unix_socket_addr.c',
    'file_info.c',
)
pal_linux_common_sources_host = files(
    'debug_map.c',
    'etc_host_info.c',
    'file_utils.c',
    'main_exec_path.c',
    'proc_maps.c',
    'reserved_ranges.c',
    'timespec_utils.c',
    'topo_info.c',
)

# Arch-specific meson.build must define the following Meson variables:
#   - `pal_linux_common_sources_host_arch` - a list of arch-specific sources.
subdir('arch')
pal_linux_common_sources_host += pal_linux_common_sources_host_arch

pal_linux_common_sources = [
    pal_linux_common_sources_enclave,
    pal_linux_common_sources_host,
]
