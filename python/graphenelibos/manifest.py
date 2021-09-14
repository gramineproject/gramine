# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2021 Wojtek Porczyk <woju@invisiblethingslab.com>
# Copyright (c) 2020 Intel Corporation
#                    Michał Kowalczyk <mkow@invisiblethingslab.com>
# Copyright (c) 2021 Intel Corporation
#                    Borys Popławski <borysp@invisiblethingslab.com>

'''
Graphene manifest renderer
'''

import hashlib
import os
import pathlib
import subprocess
import sys
import sysconfig

import jinja2
import toml

from . import (
    _CONFIG_PKGLIBDIR,
)

DEFAULT_ENCLAVE_SIZE = '256M'
DEFAULT_THREAD_NUM = 4

def ldd(*args):
    '''
    Args:
        binaries for which to generate manifest trusted files list.
    '''
    # Be careful: We have to skip vdso, which doesn't have a corresponding file on the disk (we
    # assume that such files have paths starting with '/', seems ldd always prints absolute paths).
    # Also, old ldd (from Ubuntu 16.04) prints vdso differently than newer ones:
    # old:
    #     linux-vdso.so.1 =>  (0x00007ffd31fee000)
    # new:
    #     linux-vdso.so.1 (0x00007ffd31fee000)
    ret = set()
    for line in subprocess.check_output(['ldd', *(os.fspath(i) for i in args)]).decode('ascii'):
        line = line.strip().split()
        if line[1] == '=>' and line[2].startswith('/'):
            ret.add(line[2])
        elif line[0].startswith('/') and line[1].startswith('/'):
            ret.add(line[0])
    return sorted(ret)

def add_globals_from_python(env):
    paths = sysconfig.get_paths()
    env.globals['python'] = {
        'stdlib': pathlib.Path(paths['stdlib']),
        'platstdlib': pathlib.Path(paths['platstdlib']),
        'purelib': pathlib.Path(paths['purelib']),

        # TODO rpm-based distros
        'distlib': pathlib.Path(sysconfig.get_path('stdlib',
                vars={'py_version_short': sys.version_info[0]})
            ) / 'dist-packages',

        'get_config_var': sysconfig.get_config_var,
        'ext_suffix': sysconfig.get_config_var('EXT_SUFFIX'),

        'get_path': sysconfig.get_path,
        'get_paths': sysconfig.get_paths,

        'implementation': sys.implementation,
    }

class Runtimedir:
    @staticmethod
    def __call__(libc='glibc'):
        return (pathlib.Path(_CONFIG_PKGLIBDIR) / 'runtime' / libc).resolve()
    def __str__(self):
        return str(self())
    def __truediv__(self, other):
        return self() / other

def add_globals_from_graphene(env):
    env.globals['graphene'] = {
        'libos': pathlib.Path(_CONFIG_PKGLIBDIR) / 'libsysdb.so',
        'pkglibdir': pathlib.Path(_CONFIG_PKGLIBDIR),
        'runtimedir': Runtimedir(),
    }

    try:
        from . import _offsets as offsets # pylint: disable=import-outside-toplevel
    except ImportError: # no SGX graphene installed, skipping
        pass
    else:
        env.globals['graphene'].update(
            (k, v) for k, v in offsets.__dict__.items()
            if not k.startswith('_'))

def add_globals_misc(env):
    env.globals['env'] = os.environ
    env.globals['ldd'] = ldd

def make_env():
    env = jinja2.Environment(undefined=jinja2.StrictUndefined, keep_trailing_newline=True)
    add_globals_from_graphene(env)
    add_globals_from_python(env)
    add_globals_misc(env)
    return env

class ManifestError(Exception):
    pass

def hash_path(path):
    # FIXME: is this name ok? Doesn't it sound like the path itself is hashed?
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
            # XXX: do we want to check this?
            raise ManifestError(f'Directory URI ({uri}) does not end with "/"')
        for sub_path in filter(pathlib.Path.is_file, path.rglob('*')):
            append_tf(trusted_files, f'file:{sub_path}', hash_path(sub_path))
    else:
        assert path.is_file()
        append_tf(trusted_files, uri, hash_path(path))

class Manifest:
    _env = make_env()

    def __init__(self, manifest_str):
        manifest = toml.loads(manifest_str)

        sgx = manifest.setdefault('sgx', {})
        sgx.setdefault('trusted_files', [])
        sgx.setdefault('enclave_size', DEFAULT_ENCLAVE_SIZE)
        sgx.setdefault('thread_num', DEFAULT_THREAD_NUM)
        sgx.setdefault('isvprodid', 0)
        sgx.setdefault('isvsvn', 0)
        sgx.setdefault('remote_attestation', False)
        sgx.setdefault('debug', True)
        sgx.setdefault('require_avx', False)
        sgx.setdefault('require_avx512', False)
        sgx.setdefault('require_mpx', False)
        sgx.setdefault('require_pkru', False)
        sgx.setdefault('support_exinfo', False)
        sgx.setdefault('nonpie_binary', False)
        sgx.setdefault('enable_stats', False)

        loader = manifest.setdefault('loader', {})
        loader.setdefault('preload', '')

        # Current toml versions (< 1.0) do not support non homogeneous arrays
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
        return cls(cls._env.from_string(template).render(**(variables or {})))

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

    def has_tfs_expanded(self):
        tfs = self['sgx']['trusted_files']
        preloads = set(filter(None, self['loader']['preload'].split(',')))
        preloads_seen = False
        for tf in tfs:
            if not isinstance(tf, dict):
                return False
            if not tf.get('sha256'):
                return False
            if tf['uri'] in preloads:
                preloads_seen = True
        return preloads_seen or not preloads

    def expand_all_trusted_files(self):
        assert not self.has_tfs_expanded()
        trusted_files = []

        preload_str = self['loader']['preload']
        # `filter` below is needed for the case where preload_str == '' (`split` returns [''] then)
        for uri in filter(None, preload_str.split(',')):
            append_trusted_dir_or_file(trusted_files, uri)

        for tf in self['sgx']['trusted_files']:
            append_trusted_dir_or_file(trusted_files, tf)

        self['sgx']['trusted_files'] = trusted_files

    def get_dependencies(self):
        if self.has_tfs_expanded() and self['sgx']['trusted_files']:
            raise ManifestError('Trusted files are already expanded in this manifest cannot decide '
                                'which files are local')

        deps = set()

        preload_str = self['loader']['preload']
        # `filter` below is needed for the case where preload_str == '' (`split` returns [''] then)
        for uri in filter(None, preload_str.split(',')):
            deps.add(uri2path(uri))

        for tf in self['sgx']['trusted_files']:
            if not tf.get('sha256'):
                deps.add(uri2path(tf['uri']))

        return deps
