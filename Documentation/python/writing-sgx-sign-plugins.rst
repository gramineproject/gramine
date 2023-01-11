.. default-domain:: py
.. highlight:: py

Writing plugins for signing SGX enclaves
========================================

SGX cryptosystem uses RSA-3072 with modulus 3 for signing SIGSTRUCT. However
there are different arrangements where suitable keys are kept and used for
operations. Keyfile is not always available (e.g. HSMs explicitly prevent users
from extracting keys), so we need adaptable ways of signing the enclaves. This
document describes how to implement a |~| plugin that allows Gramine to access
different APIs for signing SGX enclaves.

You need to provide a |~| click subcommand, which is a |~| Python function
wrapped in :func:`click.command` decorator. It will be called with
``standalone_mode=False``.

The command needs to return singing function that will be passed to
``Sigstruct.sign``. It returns 3-tuple:

- exponent (always ``3``)
- modulus (int)
- signature (int)

The signing function accepts a |~| single argument, the data to be signed. If
your signing function needs to accept additional arguments, use
:func:`functools.partial`.

In addition to the signing function, you can return an iterable of local files
that were accessed during signature generation (for the purpose of tracking
dependencies).

Your command can accept any command-line arguments you need to complete the
signing (like path to keyfile, URL to some external API, PIN to smartcard etc.).
It is strongly recommended that you provide ``--help-PLUGIN`` option (with
your plugin name substituted for ``PLUGIN``). Also consider prefixing your
options with ``--PLUGIN-`` to avoid conflicting with generic options.

Furthermore, your function needs to be packaged into Python distribution, which
will include an entry point from ``gramine.sgx_sign`` group. The entry point
needs to be named as your plugin and the callable it points to is the click
command.

.. seealso::

   https://setuptools.pypa.io/en/latest/userguide/entry_point.html#advertising-behavior
      Introduction to entrypoints

   https://packaging.python.org/en/latest/specifications/entry-points/
      Entrypoints specification

Example
-------

For full example, please see ``sgx_sign.py`` file (note that ``graminelibos``
package is not packaged with ``setuptools``, so metadata is provided manually).

The relevant parts are:

.. code-block:: python
   :caption: sgx_sign.py

   @click.command(add_help_option=False)
   @click.help_option('--help-file')
   @click.option('--key', '-k', metavar='FILE',
       type=click.Path(exists=True, dir_okay=False),
       default=os.fspath(SGX_RSA_KEY_PATH),
       help='specify signing key (.pem) file')
   def sign_with_file(key):
       return functools.partial(sign, key=key), [key]

   def sign(data, *, key):
       # sign data with key
       return exponent, modulus, signature

.. code-block:: python
   :caption: setup.py

   setuptools.setup(
       ...,
       entry_points={
           'gramine.sgx_sign': [
               'file = graminelibos.sgx_sign:sign_with_file',
           ]
       }
   )
