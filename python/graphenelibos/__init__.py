'''Python support for Graphene'''

__version__ = '@VERSION@'

_CONFIG_PKGLIBDIR = '@PKGLIBDIR@'
_CONFIG_LIBDIR = '@LIBDIR@'

if __version__.startswith('@'):
    raise RuntimeError(
        'You are attempting to run the tools from repo, without installing. '
        'Please install graphene before running Python tools. See '
        'https://graphene.readthedocs.io/en/latest/building.html.')

if '@SGX_ENABLED@' == 'True': # please kill me
# pylint: disable=wrong-import-position
    from .manifest import Manifest
    from .sgx_get_token import get_token
    from .sgx_sign import get_mrenclave, get_tbssigstruct, sign_with_local_key
    from .sigstruct import Sigstruct
