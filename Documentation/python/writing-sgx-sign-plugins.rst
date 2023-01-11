.. default-domain:: py
.. highlight:: py

Writing plugins for signing SGX enclaves
========================================

SGX cryptosystem uses RSA-3072 with modulus 3 for signing a SIGSTRUCT. However,
there are different arrangements where suitable keys are kept and used for
operations. A |~| keyfile is not always available (e.g., HSMs explicitly prevent
users from extracting keys), so we need adaptable ways of signing enclaves. This
document describes how to implement a |~| plugin that allows Gramine to access
different APIs for signing SGX enclaves.

You need to provide a |~| click subcommand, which is a |~| Python function
wrapped in :func:`click.command` decorator. This command can accept any
command-line arguments you need to complete the signing (like path to keyfile,
URL to some external API, PIN to smartcard). It is strongly recommended that you
provide ``--help-PLUGIN`` option (with your plugin name substituted for
``PLUGIN``). Also, consider prefixing your options with ``--PLUGIN-`` to avoid
conflicting with generic options.

Furthermore, your subcommand needs to be packaged into Python distribution,
which will include an entry point from ``gramine.sgx_sign`` group. The entry
point needs to be named as your plugin and the callable it points to needs to be
the click command.

The click command will be called with ``standalone_mode=False``. It needs to
return signing function that will be passed to ``Sigstruct.sign``. The signing
function should return a |~| 3-tuple:

- exponent (always ``3``)
- modulus (:class:`int`)
- signature (:class:`int`)

The signing function accepts a |~| single argument, the data to be signed. If
your signing function needs to accept additional arguments, use
:func:`functools.partial`.

Alternatively, the click command can return a |~| 2-tuple of:

- the signing function, as described above;
- iterable of local files that were accessed during signature generation, for
  the purpose of tracking dependencies

If you return just the function, it's equivalent to returning 2-tuple with empty
iterable, i.e. no dependent files.

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
