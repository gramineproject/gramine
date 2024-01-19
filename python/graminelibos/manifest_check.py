# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (C) 2024 Wojtek Porczyk <woju@invisiblethingslab.com>

from voluptuous import (
    Any,
    Extra,
    Required,
    Schema,
)

_size = str # maybe find a way to specify number + suffix

GramineManifestSchema = Schema({
    Required('fs'): {
        Required('mounts'): [Any(
            {
                Required('type'): 'encrypted',
                Required('path'): str,
                Required('uri'): str,
                Required('key_name'): str,
            },
            {
                'type': Any('chroot', 'tmpfs', 'untrusted_shm'),
                Required('path'): str,
                Required('uri'): str,
            },
        )],
        'root': {
            'type': Any('chroot', 'encrypted', 'tmpfs', 'untrusted_shm'),
            'uri': str,
        },
        'start_dir': str,
        'insecure__keys': {str, str},
    },
    Required('libos'): {
        Required('entrypoint'): str,
        'check_invalid_pointers': bool,
    },
    Required('loader'): {
        Required('entrypoint'): str,
        'argv': [str],
        'argv_src_file': str,
        'env': {str: Any(str, {'value': str}, {'passthrough': True})},
        'env_src_file': str,
        'gid': int,
        'insecure__use_cmdline_argv': bool,
        'insecure__use_host_env': bool,
        'insecure__disable_aslr': bool,
        'log_file': str,
        'log_level': Any('none', 'error', 'warning', 'debug', 'trace', 'all'),
        'uid': int,
    },
    'sgx': {
        'allowed_files': [str],
        'cpu_features': {
            Any('avx', 'avx512', 'amx'): Any('unspecified', 'disabled', 'required'),
            Any('mpx', 'pkru'): Any('disabled', 'required'),
        },
        'debug': bool,
        'edmm_enable': bool,
        'enable_stats': bool,
        'enclave_size': _size,
        'file_check_policy': Any('strict', 'allow_all_byt_log'),
        'insecure__rpc_thread_num': int,
        'isvprodid': int,
        'isvsvn': int,
        'max_threads': int,
        'preheat_enclave': bool,
        'profile': {
            'enable': Any('none', 'main', 'all'),
            'mode': Any('aex', 'ocall_inner', 'ocall_outer'),
            'with_stack': bool,
            'frequency': int,
        },
        'ra_client_linkable': bool,
        'ra_client_spid': str,
        'remote_attestation': Any('none', 'dcap', 'epid'),
        'require_amx': bool,        # deprecated
        'require_avx': bool,        # deprecated
        'require_avx512': bool,     # deprecated
        'require_exinfo': bool,     # deprecated
        'require_mpx': bool,        # deprecated
        'require_pkru': bool,       # deprecated
        'seal_key': {
            'flags_mask': str,
            'xfrm_mask': str,
            'misc_mask': str,
        },
        'trusted_files': [Any(str, {'uri': str, 'sha256': str})],
        'use_exinfo': bool,
        'vtune_profile': bool,
    },
    'sys': {
        'allowed_ioctls': [{
            Required('request_code'): int,
            'struct': str,
        }],
        'brk': {'max_size': _size},
        'disallow_subprocesses': bool,
        'enable_extra_runtime_domain_names_conf': bool,
        'enable_sigterm_injection': bool,
        'experimental__enable_flock': bool,
        'insecure__allow_eventfd': bool,
        'ioctl_structs': {str: [{str: object}]}, # XXX: I'm afraid description of this thing is above my pay grade
        'stack_size': _size,
    },
})
