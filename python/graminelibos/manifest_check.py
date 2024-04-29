# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (C) 2024 Intel Corporation
#                    Wojtek Porczyk <woju@invisiblethingslab.com>

from voluptuous import (
    Any,
    Required,
    Schema,
)

# size (number + suffix)
# TODO: write a better validator
_size = str

# masks for sgx.seal_key.*_mask fields
# TODO: write a better validator
_mask64 = str
_mask32 = str

# TODO: write a better validator
_uri = str

# fs.root and fs.mounts[] are almost the same, but fs.root does not contain path= key
_fs_base = (
    {
        'type': 'chroot',
        Required('uri'): _uri,
    },
    {
        Required('type'): 'encrypted',
        Required('uri'): _uri,
        'key_name': str,
    },
    {
        Required('type'): 'tmpfs',
        'uri': str, # not _uri, this field is ignored by Gramine
    },
    {
        Required('type'): 'untrusted_shm',
        Required('uri'): _uri,
    },
)

_fs_root = Any(*_fs_base)
_fs_mount = Any(*({**d, Required('path'): str} for d in _fs_base))

GramineManifestSchema = Schema({
    Required('fs'): {
        Required('mounts'): [_fs_mount],
        'root': _fs_root,
        'start_dir': str,
        'insecure__keys': {str: str},
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
        'file_check_policy': Any('strict', 'allow_all_but_log'),
        'insecure__allow_memfaults_without_exinfo': bool,
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
        'seal_key': {
            'flags_mask': _mask64,
            'xfrm_mask': _mask64,
            'misc_mask': _mask32,
        },
        # TODO: validator for sha256
        'trusted_files': [Any(str, {'uri': _uri, 'sha256': str})],
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

        # Description of this thing will be both very hard to write, and mostly useless, since
        # majority of errors will be semantic (wrong offsets), not syntactic. We'll leave it almost
        # not validated.
        'ioctl_structs': {str: object},

        'stack': {'size': _size},
    },
})
