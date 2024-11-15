.. default-domain:: py
.. highlight:: py

Python API
==========

Introduction
------------

We expose a Python API for manifest and SIGSTRUCT management.

Examples
--------

To render a |~| manifest from a |~| jinja2 template::

   from graminelibos import Manifest

   with open('some_manifest_template_file', 'r') as f:
       template_string = f.read()

   manifest = Manifest.from_template(template_string, {'foo': 123})

   with open('some_output_file', 'w') as f:
       manifest.dump(f)

To create a |~| signed SIGSTRUCT file from a manifest::

    import datetime
    from graminelibos import get_tbssigstruct, sign_with_local_key

    today = datetime.date.today()
    # Manifest must be ready for signing, e.g. all trusted files must be already expanded.
    sigstruct = get_tbssigstruct('path_to_manifest', today, 'optional_path_to_libpal')
    sigstruct.sign(sign_with_local_key, 'path_to_private_key')

    with open('path_to_sigstruct', 'wb') as f:
        f.write(sigstruct.to_bytes())

API Reference
-------------

.. autoclass:: graminelibos.ManifestError

.. autoclass:: graminelibos.Manifest
   :members:

.. autoclass:: graminelibos.manifest.TrustedFile
   :members:
..
  TODO: enable this once we build Gramine on readthedocs
  .. autoclass:: graminelibos.Sigstruct
     :members:
  .. autofunction:: graminelibos.get_tbssigstruct
  .. autofunction:: graminelibos.sign_with_local_key
