# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (C) 2021 Wojtek Porczyk <woju@invisiblethingslab.com>
# Copyright (C) 2022 Intel Corporation
#                    Michał Kowalczyk <mkow@invisiblethingslab.com>
#                    Borys Popławski <borysp@invisiblethingslab.com>

"""
Gramine manifest management and rendering
"""

import hashlib
import os
import pathlib

import tomli
import tomli_w

from . import _env

DEFAULT_ENCLAVE_SIZE_NO_EDMM = '256M'
DEFAULT_ENCLAVE_SIZE_WITH_EDMM = '1024G'  # 1TB; note that DebugInfo is at 1TB and ASan at 1.5TB
DEFAULT_THREAD_NUM = 4

class ManifestError(Exception):
    """Thrown at errors in manifest parsing and handling.

    Contains a string with error description.
    """

def hash_file_contents(path):
    with open(path, 'rb') as f:
        sha = hashlib.sha256()
        for chunk in iter(lambda: f.read(128 * sha.block_size), b''):
            sha.update(chunk)
        return sha.hexdigest()

def uri2path(uri):
    if not uri.startswith('file:'):
        raise ManifestError(f'Unsupported URI type: {uri}')
    return pathlib.Path(uri[len('file:'):])

class Manifest:
    """Just a representation of a manifest.

    You can access or change specific manifest entries via ``[]`` operator (just like a normal
    python ``dict``).

    Args:
        manifest_str (str): the manifest in the TOML format.
    """

    def __init__(self, manifest_str):
        manifest = tomli.loads(manifest_str)

        sgx = manifest.setdefault('sgx', {})
        sgx.setdefault('trusted_files', [])
        sgx.setdefault('max_threads', DEFAULT_THREAD_NUM)
        sgx.setdefault('isvprodid', 0)
        sgx.setdefault('isvsvn', 0)
        sgx.setdefault('remote_attestation', "none")
        sgx.setdefault('debug', False)
        sgx.setdefault('enable_stats', False)
        sgx.setdefault('edmm_enable', False)

        if sgx['edmm_enable']:
            sgx.setdefault('enclave_size', DEFAULT_ENCLAVE_SIZE_WITH_EDMM)
        else:
            sgx.setdefault('enclave_size', DEFAULT_ENCLAVE_SIZE_NO_EDMM)

        # TODO: below was deprecated in release v1.6, remove this check in v1.7
        #       (but keep the `if` body)
        if not 'require_exinfo' in sgx:
            sgx.setdefault('use_exinfo', False)

        # TODO: below were deprecated in release v1.6, remove this check in v1.7
        #       (but keep the `if` body)
        deprecated = ['require_avx', 'require_avx512', 'require_amx', 'require_mpx', 'require_pkru']
        if not any(key in sgx for key in deprecated):
            sgx_cpu_features = sgx.setdefault('cpu_features', {})
            sgx_cpu_features.setdefault('avx', "unspecified")
            sgx_cpu_features.setdefault('avx512', "unspecified")
            sgx_cpu_features.setdefault('amx', "unspecified")
            sgx_cpu_features.setdefault('mpx', "disabled")
            sgx_cpu_features.setdefault('pkru', "disabled")

        if not isinstance(sgx['trusted_files'], list):
            raise ValueError("Unsupported trusted files syntax, more info: " +
                  "https://gramine.readthedocs.io/en/latest/manifest-syntax.html#trusted-files")

        trusted_files = []
        for tf in sgx['trusted_files']:
            if isinstance(tf, dict) and 'uri' in tf:
                trusted_files.append(tf)
            elif isinstance(tf, str):
                trusted_files.append({'uri': tf})
            else:
                raise ManifestError(f'Unknown trusted file format: {tf!r}')

        sgx['trusted_files'] = trusted_files

        self._manifest = manifest

    def __getitem__(self, key):
        return self._manifest[key]

    def __setitem__(self, key, val):
        self._manifest[key] = val

    @classmethod
    def from_template(cls, template, variables=None):
        """Render template into Manifest.

        Creates a manifest from the jinja template given as string. Optional variables may be given
        as mapping.

        Args:
            template (str): jinja2 template of the manifest
            variables (:obj:`dict`, optional): Dictionary of variables that are used in
                the template.

        Returns:
            Manifest: instance created from rendered template.
        """
        return cls(_env.from_string(template).render(**(variables or {})))

    @classmethod
    def loads(cls, s):
        return cls(s)

    @classmethod
    def load(cls, f):
        return cls.loads(f.read())

    def dumps(self):
        return tomli_w.dumps(self._manifest)

    def dump(self, f):
        tomli_w.dump(self._manifest, f)

    def expand_all_trusted_files(self, chroot=None):
        """Expand all trusted files entries.

        Collects all trusted files entries, hashes each of them (skipping these which already had a
        hash present) and updates ``sgx.trusted_files`` manifest entry with the result.

        Returns a list of all expanded files, i.e. files that we need to hash, and directories that
        we needed to list.

        Raises:
            ManifestError: There was an error with the format of some trusted files in the manifest
                or some of them could not be loaded from the filesystem.

        """
        trusted_files = {}
        expanded = []

        def in_chroot(path):
            if chroot is None:
                return path
            if not path.is_absolute():
                raise ManifestError('only absolute paths can be measured in chroot')
            return chroot / path.relative_to('/')

        def out_chroot(path):
            if chroot is None:
                return path
            if not path.is_absolute():
                raise ManifestError('only absolute paths can be measured in chroot')
            return '/' / path.relative_to(chroot)

        def append_tf(chroot_path):
            if path not in trusted_files:
                trusted_files[out_chroot(chroot_path)] = hash_file_contents(chroot_path)

        for tf in self['sgx']['trusted_files']:
            if isinstance(tf, dict):
                uri = tf['uri']

                path = uri2path(uri)
                if tf.get('sha256') and path not in trusted_files:
                    trusted_files[path] = tf['sha256']
                    continue

            elif isinstance(tf, str):
                uri = tf

            else:
                raise ManifestError(f'Unknown trusted file format: {tf!r}')

            path = uri2path(uri)
            chroot_path = in_chroot(path)

            if not chroot_path.exists():
                raise ManifestError(f'Cannot resolve {path}')
            if chroot_path.is_dir():
                if not uri.endswith('/'):
                    raise ManifestError(f'Directory URI ({uri}) does not end with "/"')

                expanded.append(path)
                for sub_path in sorted(chroot_path.rglob('*')):
                    expanded.append(out_chroot(sub_path))
                    if sub_path.is_file():
                        # Skip inaccessible files
                        if os.access(sub_path, os.R_OK):
                            append_tf(sub_path)
            else:
                assert chroot_path.is_file()
                append_tf(chroot_path)
                expanded.append(path)

        self['sgx']['trusted_files'] = [
            {'uri': f'file:{k}', 'sha256': v} for k, v in trusted_files.items()
        ]
        return expanded

    def get_dependencies(self):
        """Generate list of files which this manifest depends on.

        Collects all trusted files that are not yet expanded (do not have a hash in the entry) and
        returns them.

        Returns:
            list(pathlib.Path): List of paths to the files this manifest depends on.

        Raises:
            ManifestError: One of the found URIs is in an unsupported format.
        """
        deps = set()

        for tf in self['sgx']['trusted_files']:
            if not tf.get('sha256'):
                deps.add(uri2path(tf['uri']))

        return deps
