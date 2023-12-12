# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (C) 2021 Wojtek Porczyk <woju@invisiblethingslab.com>
# Copyright (C) 2022 Intel Corporation
#                    Michał Kowalczyk <mkow@invisiblethingslab.com>
#                    Borys Popławski <borysp@invisiblethingslab.com>
# Copyright (C) 2023 Intel Corporation
#                    Wojtek Porczyk <woju@invisiblethingslab.com>

"""
Gramine manifest management and rendering
"""

import errno
import hashlib
import os
import pathlib
import posixpath

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

def uri2path(uri):
    if not uri.startswith('file:'):
        raise ManifestError(f'Unsupported URI type: {uri}')
    return pathlib.Path(uri[len('file:'):])


# loosely based on posixpath._joinrealpath
def resolve_symlinks(path, *, chroot, seen=None):
    """Resolve symlink inside chroot

    Args:
        path (pathlib.Path or str): the path to resolve
        chroot (pathlib.Path): path to chroot

    Raises:
        OSError: When resolution fails. The following variants can be raised: ``ENOTDIR`` aka
            :py:class:`NotADirectoryError` for paths like ``a/b/file/c``; ``ELOOP`` for loops.
    """
    path = pathlib.Path(path)
    if not path.is_absolute():
        raise ManifestError('only absolute paths can be measured in chroot')

    if seen is None:
        # a mapping of linksrc -> linkdest (all within chroot), but linkdest values can be None
        # while recursing, and if None is encountered, then we'll know we have a loop
        seen = {}

    # Current state (what we already resolved). This is a path that is:
    # - an instance of pathlib.Path;
    # - absolute (starts with '/');
    # - already resolved path (contains no symlinks);
    # - inside chroot (outer_current_path is this path as seen from outside).
    # Therefore it's safe to traverse '..' in inner_current_path by just taking .parent attribute.
    inner_current_path = pathlib.Path('/')
    outer_current_path = chroot / inner_current_path.relative_to('/')

    for part in path.relative_to('/').parts:
        if not outer_current_path.is_dir():
            raise NotADirectoryError(errno.ENOTDIR, os.strerror(errno.ENOTDIR), inner_current_path)

        if part == posixpath.curdir: # '.'
            continue

        if part == posixpath.pardir: # '..'
            inner_current_path = inner_current_path.parent # this works also for /, just returns /
            outer_current_path = chroot / inner_current_path.relative_to('/')
            continue

        inner_current_path /= part
        outer_current_path = chroot / inner_current_path.relative_to('/')

        if not outer_current_path.is_symlink():
            continue

        # else: here's the hard part, symlink resolution

        if inner_current_path not in seen:
            seen[inner_current_path] = None
            # TODO after python >= 3.9: use Path.readlink()
            next_path = pathlib.Path(os.readlink(outer_current_path))

            # XXX(woju 12.12.2023): The following path concatenation is suboptimal, it will cause
            # the recurring function to traverse and stat() all parts of inner_current_path again,
            # so it's easy to construct exploding O(n²) tree. However, to write this optimally, it
            # would require to complicate already convoluted logic. Trees that would trigger
            # suboptimal complexity are uncommon, so I think it's a reasonable tradeoff.
            if not next_path.is_absolute():
                next_path = inner_current_path.parent / next_path

            seen[inner_current_path] = resolve_symlinks(next_path, chroot=chroot, seen=seen)

        if seen[inner_current_path] is None:
            # we have a loop in symlinks
            raise OSError(errno.ELOOP, os.strerror(errno.ELOOP), inner_current_path)

        inner_current_path = seen[inner_current_path]
        outer_current_path = chroot / inner_current_path.relative_to('/')
        continue

    return inner_current_path


class TrustedFile:
    """Represents a single entry in sgx.trusted_files.

    Args:
        uri (str): URI
        sha256 (str or None): sha256
        chroot (pathlib.Path or None): optional path to chroot, if being measured in chroot dir

    Raises:
        graminelibos.ManifestError: on invalid URI values, or when *chroot* is not None and realpath
            is not absolute
    """
    def __init__(self, uri, sha256=None, *, chroot=None):
        #: URI of the trusted file
        self.uri = uri
        #: sha256 of the trusted file as str of hex digits, or None if not measured
        self.sha256 = sha256
        #: optional chroot, if the file is to be measured in a subdirectory
        self.chroot = pathlib.Path(chroot) if chroot is not None else chroot

        #: real path to the file on disk, including chroot path if specified
        self.realpath = None

        path = pathlib.PurePosixPath(uri2path(uri))

        if self.chroot is None:
            self.realpath = pathlib.Path(path)
        else:
            self.realpath = chroot / resolve_symlinks(path, chroot=self.chroot).relative_to('/')

    @classmethod
    def from_manifest(cls, data, *, chroot=None):
        """Create an instance from an entry in manifest.

        Args:
            data (str or dict): what is found in manifest data
            chroot (pathlib.Path or None): optional path to chroot, if being measured in chroot dir

        Returns:
            TrustedFile: a single instance of TrustedFile

        Raises:
            graminelibos.ManifestError: on errors in data
        """
        if isinstance(data, str):
            uri, sha256 = data, None

        elif isinstance(data, dict):
            uri, sha256 = data.pop('uri'), data.pop('sha256', None)
            if data:
                # there are some unknown keys left after two .pop()s above
                raise ManifestError(f'Leftover trusted file items: {data!r}')

        else:
            raise ManifestError(f'Unknown trusted file format: {data!r}')

        return cls(uri, sha256, chroot=chroot)

    @classmethod
    def from_realpath(cls, realpath, *, chroot=None):
        """Create an instance from a realpath.

        This is used for recursive expansion of directories.

        Args:
            realpath (pathlib.Path): path to the file
            chroot (pathlib.Path or None): optional path to chroot, if being measured in chroot dir

        Returns:
            TrustedFile: a single instance of TrustedFile

        Raises:
            ValueError: when *chroot* is not None and realpath is not inside manifest
        """
        path = pathlib.PurePosixPath(realpath)
        if chroot is not None:
            # path.relative_to(chroot) will throw ValueError if the path is not relative to chroot
            path = '/' / path.relative_to(chroot)
        self = cls(f'file:{path}{"/" if realpath.is_dir() else ""}', chroot=chroot)
        return self

    def __repr__(self):
        return (f'<{type(self).__name__}('
                    f'uri={self.uri!r}, sha256={self.sha256!r}, chroot={self.chroot!r}'
                f') realpath={self.realpath!r}>')


    def to_manifest(self):
        """Returns the representation of the current file for manifest.

        Returns:
            str or dict: To be included as element in ``sgx.trusted_files`` list.
        """
        if self.sha256 is None:
            return self.uri
        return {
            'uri': self.uri,
            'sha256': self.sha256,
        }


    def ensure_hash(self):
        """Ensures that the trusted file carries the sha256 sum.

        If not, this method will open the file and measure it.

        Returns:
            TrustedFile: self
        """
        if self.sha256 is None:
            with open(self.realpath, 'rb') as file:
                sha = hashlib.sha256()
                for chunk in iter(lambda: file.read(128 * sha.block_size), b''):
                    sha.update(chunk)
                self.sha256 = sha.hexdigest()
        return self


    def expand_directory(self, *, recursive=True, skip_inaccessible=True):
        """If this TrustedFile is a directory, iterate over its contents.

        If the TrustedFile instance is referring to a regular file, yield self and stop iteration.

        Args:
            recursive (bool): If :py:obj:`False`, will iterate only over direct descendants,
                yielding files and directories; if :py:obj:`True`, will recursively descend into all
                directories, yielding only regular files.
            skip_inaccessible (bool): If :py:obj:`True` (the default), will skip entries that are
                neither directories nor regular files, or fail ``os.access(realpath, os.R_OK)``. If
                :py:obj:`False`, will iterate over files that failed access test and will possibly
                error out on while measuring. This argument applies only while recursing into
                directory (if the instance is referring to a regular file, it will be yielded
                regardless).

        Yields:
            :py:class:`TrustedFile`: one object for each entry in the directory

        Raises:
            graminelibos.ManifestError: On errors in URIs, e.g. when directory does not have ``/``
                at the end or *vice versa*, or when directory has ``sha256`` value.
        """
        if self.uri.endswith('/'):
            if not self.realpath.is_dir():
                raise ManifestError(f'URI {self.uri!r} ends with "/" but is not a directory')
            if self.sha256 is not None:
                raise ManifestError(f'Directory URI ({self.uri!r}) has sha256 specified')

            for realpath in sorted(self.realpath.glob('*')):
                # this conditional could be one-lined, but please don't, it would be unreadable
                if skip_inaccessible:
                    if not realpath.is_file() and not realpath.is_dir():
                        continue
                    if not os.access(realpath, os.R_OK):
                        continue

                tf = type(self).from_realpath(realpath, chroot=self.chroot)

                if not recursive:
                    yield tf
                else:
                    if realpath.is_symlink() and realpath.is_dir():
                        # do not descend into symlinked directories
                        continue
                    yield from tf.expand_directory(
                        recursive=recursive, skip_inaccessible=skip_inaccessible)

        else:
            if self.realpath.is_dir():
                raise ManifestError(f'Directory URI ({self.uri!r}) does not end with "/"')
            yield self


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

        Returns a list of all expanded files, as included in the manifest.

        Args:
            chroot (pathlib.Path or None): Optional chroot directory. If specified, trusted files
                are expected to be found inside this directory, not in root of filesystem.

        Raises:
            graminelibos.ManifestError: There was an error with the format of some trusted files in
                the manifest or some of them could not be loaded from the filesystem.

        """
        trusted_files = {}
        for data in self['sgx']['trusted_files']:
            for tf in TrustedFile.from_manifest(data, chroot=chroot).expand_directory():
                if tf.uri in trusted_files:
                    # On duplicate entries, pick the one that is already measured, and if both don't
                    # have hashes, prefer existing one, to avoid dict insertion. Accept double
                    # (matching) sha256 deduplicating them, and error out on conflicting
                    # measurement.
                    tf_old = trusted_files[tf.uri]
                    if tf_old.sha256 is not None:
                        if tf.sha256 is not None and tf.sha256 != tf_old.sha256:
                            raise ManifestError(
                                f'Two different sha256 values ({tf_old.sha256} and {tf.sha256}) '
                                f'for the same URI {tf.uri!r}')
                        continue

                trusted_files[tf.uri] = tf

        for tf in trusted_files.values():
            tf.ensure_hash()

        self['sgx']['trusted_files'] = [tf.to_manifest() for tf in trusted_files.values()]
        return [tf.realpath for tf in trusted_files.values()]

    def get_dependencies(self):
        """Generate list of files which this manifest depends on.

        Collects all trusted files that are not yet expanded (do not have a hash in the entry) and
        returns them.

        Returns:
            list(pathlib.Path): List of paths to the files this manifest depends on.

        Raises:
            graminelibos.ManifestError: One of the found URIs is in an unsupported format.
        """
        deps = set()

        for tf in self['sgx']['trusted_files']:
            if not tf.get('sha256'):
                deps.add(uri2path(tf['uri']))

        return deps
