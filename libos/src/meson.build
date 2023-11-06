if skeleton
    libpal = libpal_skeleton_dep
elif direct
    libpal = libpal_direct_dep
elif sgx
    libpal = libpal_sgx_dep
else
    error('need to link LibOS against a PAL library, but no PAL version is enabled')
endif

libos_sources = files(
    'bookkeep/libos_handle.c',
    'bookkeep/libos_pid.c',
    'bookkeep/libos_process.c',
    'bookkeep/libos_signal.c',
    'bookkeep/libos_thread.c',
    'bookkeep/libos_vma.c',
    'fs/chroot/encrypted.c',
    'fs/chroot/fs.c',
    'fs/dev/attestation.c',
    'fs/dev/fs.c',
    'fs/etc/fs.c',
    'fs/eventfd/fs.c',
    'fs/libos_dcache.c',
    'fs/libos_fs.c',
    'fs/libos_fs_encrypted.c',
    'fs/libos_fs_hash.c',
    'fs/libos_fs_lock.c',
    'fs/libos_fs_mem.c',
    'fs/libos_fs_path.c',
    'fs/libos_fs_pseudo.c',
    'fs/libos_fs_synthetic.c',
    'fs/libos_fs_util.c',
    'fs/libos_namei.c',
    'fs/pipe/fs.c',
    'fs/proc/fs.c',
    'fs/proc/info.c',
    'fs/proc/ipc_thread.c',
    'fs/proc/thread.c',
    'fs/shm/fs.c',
    'fs/socket/fs.c',
    'fs/sys/cache_info.c',
    'fs/sys/cpu_info.c',
    'fs/sys/fs.c',
    'fs/sys/node_info.c',
    'fs/tmpfs/fs.c',
    'gramine_hash.c',
    'ipc/libos_ipc.c',
    'ipc/libos_ipc_child.c',
    'ipc/libos_ipc_fs_lock.c',
    'ipc/libos_ipc_pid.c',
    'ipc/libos_ipc_process_info.c',
    'ipc/libos_ipc_signal.c',
    'ipc/libos_ipc_sync.c',
    'ipc/libos_ipc_vmid.c',
    'ipc/libos_ipc_worker.c',
    'libos_async.c',
    'libos_call.c',
    'libos_checkpoint.c',
    'libos_debug.c',
    'libos_init.c',
    'libos_malloc.c',
    'libos_object.c',
    'libos_parser.c',
    'libos_pollable_event.c',
    'libos_rtld.c',
    'libos_rwlock.c',
    'libos_syscalls.c',
    'libos_utils.c',
    'net/ip.c',
    'net/unix.c',
    'sync/libos_sync_client.c',
    'sync/libos_sync_server.c',
    'sys/libos_access.c',
    'sys/libos_alarm.c',
    'sys/libos_brk.c',
    'sys/libos_clone.c',
    'sys/libos_dup.c',
    'sys/libos_epoll.c',
    'sys/libos_eventfd.c',
    'sys/libos_exec.c',
    'sys/libos_exit.c',
    'sys/libos_fcntl.c',
    'sys/libos_file.c',
    'sys/libos_fork.c',
    'sys/libos_futex.c',
    'sys/libos_getcwd.c',
    'sys/libos_getpid.c',
    'sys/libos_getrandom.c',
    'sys/libos_getrlimit.c',
    'sys/libos_getuid.c',
    'sys/libos_ioctl.c',
    'sys/libos_mlock.c',
    'sys/libos_mmap.c',
    'sys/libos_open.c',
    'sys/libos_pipe.c',
    'sys/libos_poll.c',
    'sys/libos_sched.c',
    'sys/libos_sigaction.c',
    'sys/libos_sleep.c',
    'sys/libos_socket.c',
    'sys/libos_stat.c',
    'sys/libos_time.c',
    'sys/libos_uname.c',
    'sys/libos_wait.c',
    'sys/libos_wrappers.c',
    'utils/log.c',
)

# Arch-specific meson.build must define the following Meson variables:
#   - `libos_sources_arch` - a list of arch-specific sources,
#   - `libos_lds` - a full path to LibOS linker script.
subdir('arch')
libos_sources += libos_sources_arch

libos_map = meson.current_source_dir() / 'libos.map'

subdir('vdso')

vdso_data_o = custom_target('vdso_data.o',
    input: 'vdso/vdso_data.S',
    output: 'vdso_data.o',
    command: [
        cc.cmd_array(),
        cflags_libos,
        '-Wa,--noexecstack',
        '-DVDSO_SO_FULL_PATH="@0@"'.format(vdso_so.full_path()),
        '-c',
        '@INPUT@',
        '-o', '@OUTPUT@',
    ],
    depends: vdso_so,
)

libos = shared_library('sysdb',
    libos_sources,
    vdso_data_o,
    libos_asm_offsets_h,
    gramine_hash_header,

    c_args: [
        cflags_libos,
        cflags_sanitizers,

        # use TLS-based stack protector of GCC (we rely on the fact that LibOS reuses the same TCB
        # as its underlying PAL which must have a canary in its PAL_TCB at offset 0x8, so no
        # additional enabling is required in the LibOS code)
        cflags_custom_stack_protector,
    ],
    link_args: [
        '-nostdlib',

        # PAL expects that LibOS binary has old-style hash (DT_HASH) table instead of the default
        # GNU hash (DT_GNU_HASH) table; PAL symbol resolution uses DT_HASH to figure out the number
        # of dynamic symbols in the SYMTAB symbol table
        '-Wl,--hash-style=sysv',

        # PAL expects that LibOS binary is linked with RELRO (Relocation Read-Only)
        '-Wl,-zrelro',
        '-Wl,-znow',

        '-Wl,-zcombreloc',
        '-Wl,--no-undefined',
        '-Wl,--version-script=@0@'.format(libos_map),
        '-Wl,-T@0@'.format(libos_lds),
        '-Wl,--eh-frame-hdr',
    ],
    link_depends: [
        libos_map,
        libos_lds,
    ],
    dependencies: [
        common_dep,
        cryptoadapter_dep,
        protected_files_dep,
        libpal,
    ],

    include_directories: includes_libos,
    install: true,
    install_dir: pkglibdir,
)

if debug
    custom_target('libsysdb.so.map',
        input: libos,
        command: gen_symbol_map_cmd,
        capture: true,
        output: 'libsysdb.so.map',

        install: true,
        install_dir: pkglibdir,
    )
endif
