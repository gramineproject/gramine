'''Python support for Gramine'''

__version__ = '@VERSION@'

_CONFIG_PKGLIBDIR = '@PKGLIBDIR@'
_CONFIG_LIBDIR = '@LIBDIR@'

import os as _os

if __version__.startswith('@') and not _os.getenv('GRAMINE_IMPORT_ANYWAY_FOR_SPHINX') == '1':
    raise RuntimeError(
        'You are attempting to run the tools from repo, without installing. '
        'Please install Gramine before running Python tools. See '
        'https://gramine.readthedocs.io/en/latest/building.html.')
