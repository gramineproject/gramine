.. default-domain:: py
.. highlight:: py

Python API
==========

Introduction
------------

We expose a python API for manifest, SIGSTRUCT and SGX token management.

Examples
--------

To render a |~| manifest from a |~| template::

   from graminelibos import Manifest

   with open('some_manifest_template_file', 'r') as f:
       template_string = f.read()

   manifest = Manifest.from_template(template_string, {'foo': 123})

   with open('some_output_file', 'w') as f:
       manifest.dump(f)

API Reference
-------------

.. autoclass:: graminelibos.ManifestError

.. autoclass:: graminelibos.Manifest
   :members:

..
  TODO: enable this once we build Gramine on readthedocs
  .. autoclass:: graminelibos.Sigstruct
     :members:
  .. autofunction:: graminelibos.get_tbssigstruct
  .. autofunction:: graminelibos.sign_with_local_key
  .. autofunction:: graminelibos.get_token
