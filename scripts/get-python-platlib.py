#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (C) 2021 Intel Corporation
#                    Wojtek Porczyk <woju@invisiblethingslab.com>
#

'''
Statement of the problem
========================

Debian. The problem is Debian.

No, for real
------------

The problem is that Debian (and by induction, Ubuntu), change the install paths,
and also ``sys.path`` using ``site`` module.

Things that don't work
----------------------

- ``sysconfig`` - Debian doesn't touch this, so it returns wrong values
- ``import('python')`` or ``import('python3')`` in Meson - uses ``sysconfig``
  python module, so doesn't work for exactly the same reason
- ``distutils.sysconfig`` - haha no, but close: it has only major python version
  in path, but ``sys.path`` has ``major.minor``
- some functions from ``site`` - should work, right? isn't it the place where
  this change happens? not even close, you'd be condemned to sift through lists
  with traps like `/usr/local/local/*`

Solution
========

``distutils.command.install.INSTALL_SCHEMES`` and detection of corner case.

Things that can/will bite us, now or in the future
--------------------------------------------------

- ``site`` gates adding to path on ``os.path.exists``, so when reproducing, make
  sure to ``mkdir -p`` all suspected paths; that's also why we can't ``assert``
  that result is in ``sys.path``.
- PEP-632 deprecates ``distutils`` package (3.10-3.11 ``DeprecationWarning``,
  not installed in 3.12). UPDATE 26.09.2024: Ubuntu 24.04 has Python 3.12 with
  no ``distutils``, but setuptools ships vendored copy for now.

References
==========

- https://www.python.org/dev/peps/pep-0632/
- https://discuss.python.org/t/pep-632-deprecate-distutils-module/5134/122
  - https://salsa.debian.org/cpython-team/python3-stdlib/blob/master/debian/patches/3.8/distutils-install-layout.diff
  - https://github.com/fedora-python/cpython/commit/acba1a24b6ad5b894b4d6ef3223c2d174e225d21
- https://fedoraproject.org/wiki/Changes/Making_sudo_pip_safe
'''

import argparse
import pathlib
import sys
import sysconfig

try:
    import distutils.command.install as distutils_command_install
    import distutils.sysconfig as distutils_sysconfig
    import distutils.util as distutils_util
except ImportError:
    import setuptools._distutils.command.install as distutils_command_install
    import setuptools._distutils.sysconfig as distutils_sysconfig
    import setuptools._distutils.util as distutils_util

def get_platlib(prefix):
    is_debian = (
        'deb_system' in sysconfig.get_scheme_names() or
        'deb_system' in distutils_command_install.INSTALL_SCHEMES)

    # this takes care of `/` at the end, though not `/usr/../usr/local`
    is_usr_local = pathlib.PurePosixPath(prefix).as_posix() == '/usr/local'

    if is_debian and is_usr_local:
        # 1) try sysconfig; it works on bookworm and jammy
        try:
            platlib1 = sysconfig.get_path('platlib', 'deb_system')
        except KeyError:
            platlib1 = None

        if platlib1 in sys.path:
            return platlib1

        # 2) if system is too old for sysconfig, then distutils should work
        return distutils_util.subst_vars(
            distutils_command_install.INSTALL_SCHEMES['unix_local']['platlib'],
            {
                'platbase': '/usr',
                'py_version_short': '.'.join(map(str, sys.version_info[:2])),
            })

    return distutils_sysconfig.get_python_lib(plat_specific=True, prefix=prefix)


argparser = argparse.ArgumentParser()
argparser.add_argument('prefix')

def main(args=None):
    args = argparser.parse_args(args)
    print(get_platlib(args.prefix), end='')

if __name__ == '__main__':
    main()
