.. _gramine-argv-serializer:

.. program:: gramine-argv-serializer

======================================================================
:program:`gramine-argv-serializer` -- Serialize command line arguments
======================================================================

Synopsis
========

:command:`gramine-argv-serializer` [*OPTION*] [*ARGS*]

Description
===========

`gramine-argv-serializer` serializes the command line arguments and displays it
to stdout. Typically the output is redirected to a file, which can be used as a
trusted or a protected file and the path is specified in
``loader.argv_src_file`` to pass the command line arguments to Gramine.
For more information on the usage, please refer to :doc:`../manifest-syntax`.

For an example on how to use this utility from Python, please refer to `this
file <https://github.com/gramineproject/gramine/blob/master/LibOS/shim/test/regression/test_libos.py>`__.

Command line arguments
======================

.. option:: -h, --help

   Display usage.

.. note::
   ``-h`` or ``--help`` option and the command line argument(s) are mutually
   exclusive.

Example
=======

.. code-block:: sh

   gramine-argv-serializer "binary_name" "arg1" "arg2" > gramine_secure_args.txt
