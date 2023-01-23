.. program:: gramine-sgx-sigstruct-view
.. _gramine-sgx-sigstruct-view:

==============================================================
:program:`gramine-sgx-sigstruct-view` -- Display SGX SIGSTRUCT
==============================================================

Synopsis
========

:command:`gramine-sgx-sigstruct-view` [*SIGSTRUCT-FILE*]

Description
===========

:program:`gramine-sgx-sigstruct-view` is used to display SIGSTRUCT fields of the
SGX enclave (MRENCLAVE, MRSIGNER, etc.), extracted from the ``.sig`` file.

Note that by default, the output is in plain text format, which is unstable and
should not be parsed. If the output should be parsed, consider
``--output-format=toml`` or ``--output-format=json``.

Command line arguments
======================

.. option:: --verbose, -v

    Print details to standard output.

.. option:: --output-format [text|toml|json]

    Output format: plain text, toml or json. Default: text.

Example
=======

.. code-block:: sh

   $ gramine-sgx-sigstruct-view --verbose --output-format=toml helloworld.sig
   mr_signer = "0dedbe47afb6955e5f6109637c1fbd9cc4b4e073e1396da8ce2091075e5b0a3b"
   mr_enclave = "81a675e9a408818b430be4b259f3e11e6f8cacdb4c971c3114ee79fe53076893"
   isv_prod_id = 0
   isv_svn = 0
   attribute_flags = "0x6"
   attribute_xfrms = "0x3"
   misc_select = "0x0"
   attribute_flags_mask = "0xffffffffffffffff"
   attribute_xfrm_mask = "0xfffffffffff9ff1b"
   misc_mask = "0xffffffff"
   date = "2023-02-20"
   debug_enclave = true
