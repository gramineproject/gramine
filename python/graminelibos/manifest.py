# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2021 Wojtek Porczyk <woju@invisiblethingslab.com>
# Copyright (c) 2020 Intel Corporation
#                    Michał Kowalczyk <mkow@invisiblethingslab.com>
# Copyright (c) 2021 Intel Corporation
#                    Borys Popławski <borysp@invisiblethingslab.com>

'''
Gramine manifest renderer
'''

import hashlib
import pathlib

import toml

from . import _env

DEFAULT_ENCLAVE_SIZE = '256M'
DEFAULT_THREAD_NUM = 4

class ManifestError(Exception):
    pass

def hash_file_contents(path):
    with open(path, 'rb') as f:
        sha = hashlib.sha256()
        sha.update(f.read())
        return sha.hexdigest()

def uri2path(uri):
    if not uri.startswith('file:'):
        raise ManifestError(f'Unsupported URI type: {uri}')
    return pathlib.Path(uri[len('file:'):])

def append_tf(trusted_files, uri, hash_):
    trusted_files.append({'uri': uri, 'sha256': hash_})

def append_trusted_dir_or_file(trusted_files, val):
    if isinstance(val, dict):
        uri = val['uri']
        if val.get('sha256'):
            append_tf(trusted_files, uri, val['sha256'])
            return
    elif isinstance(val, str):
        uri = val
    else:
        raise ValueError(f'Unknown trusted file format: {val!r}')

    path = uri2path(uri)
    if not path.exists():
        raise ManifestError(f'Cannot resolve {path}')
    if path.is_dir():
        if not uri.endswith('/'):
            raise ManifestError(f'Directory URI ({uri}) does not end with "/"')
        for sub_path in sorted(filter(pathlib.Path.is_file, path.rglob('*'))):
            append_tf(trusted_files, f'file:{sub_path}', hash_file_contents(sub_path))
    else:
        assert path.is_file()
        append_tf(trusted_files, uri, hash_file_contents(path))

class Manifest:
    def __init__(self, manifest_str):
        manifest = toml.loads(manifest_str)

        sgx = manifest.setdefault('sgx', {})
        sgx.setdefault('trusted_files', [])
        sgx.setdefault('enclave_size', DEFAULT_ENCLAVE_SIZE)
        sgx.setdefault('thread_num', DEFAULT_THREAD_NUM)
        sgx.setdefault('isvprodid', 0)
        sgx.setdefault('isvsvn', 0)
        sgx.setdefault('remote_attestation', False)
        sgx.setdefault('debug', False)
        sgx.setdefault('require_avx', False)
        sgx.setdefault('require_avx512', False)
        sgx.setdefault('require_mpx', False)
        sgx.setdefault('require_pkru', False)
        sgx.setdefault('support_exinfo', False)
        sgx.setdefault('nonpie_binary', False)
        sgx.setdefault('enable_stats', False)

        loader = manifest.setdefault('loader', {})
        loader.setdefault('preload', '')

        # Current toml versions (< 1.0) do not support non-homogeneous arrays
        trusted_files = []
        for tf in sgx['trusted_files']:
            if isinstance(tf, dict):
                trusted_files.append(tf)
            elif isinstance(tf, str):
                append_tf(trusted_files, tf, None)
            else:
                raise ValueError(f'Unknown trusted file format: {tf!r}')

        sgx['trusted_files'] = trusted_files

        self._manifest = manifest

    def __getitem__(self, key):
        return self._manifest[key]

    def __setitem__(self, key, val):
        self._manifest[key] = val

    @classmethod
    def from_template(cls, template, variables=None):
        '''Render template into a Manifest from the given string. Optional variables may be given
        as mapping.'''
        return cls(_env.from_string(template).render(**(variables or {})))

    @classmethod
    def loads(cls, s):
        return cls(s)

    @classmethod
    def load(cls, f):
        return cls.loads(f.read())

    def dumps(self):
        return toml.dumps(self._manifest)

    def dump(self, f):
        toml.dump(self._manifest, f)

    def expand_all_trusted_files(self):
        trusted_files = []
        for tf in self['sgx']['trusted_files']:
            append_trusted_dir_or_file(trusted_files, tf)

        preloads = set(filter(None, self['loader']['preload'].split(',')))
        # remove all preloads that were already expanded
        for tf in trusted_files:
            preloads.discard(tf['uri'])

        for uri in sorted(preloads):
            append_trusted_dir_or_file(trusted_files, uri)

        self['sgx']['trusted_files'] = trusted_files

    def get_dependencies(self):
        deps = set()

        preload_str = self['loader']['preload']
        # `filter` below is needed for the case where preload_str == '' (`split` returns [''] then)
        for uri in filter(None, preload_str.split(',')):
            deps.add(uri2path(uri))

        for tf in self['sgx']['trusted_files']:
            if not tf.get('sha256'):
                deps.add(uri2path(tf['uri']))

        return deps
