includes_pal_common = [
    include_directories(
        '.',
        'pal',
        'arch' / host_machine.cpu_family(),
    ),
    common_inc,
]

includes_pal_for_libos = [
    include_directories(
        '.',
        'pal',
        'elf',
        'arch' / host_machine.cpu_family(),
        'arch' / host_machine.cpu_family() / 'linux',
    ),
    # PAL headers use `api.h`, `cpu.h` etc.
    common_inc,
]
