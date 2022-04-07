.. _gramine-argv-serializer:

.. program:: gramine-argv-serializer

======================================================================
:program:`gramine-argv-serializer` -- Serialize command line arguments
======================================================================

Synopsis
========

:command:`gramine-argv-serializer` [*ARGS*]

Description
===========

`gramine-argv-serializer` serializes the command line arguments and displays it
to stdout. Typically, the output is redirected to a file that can be used as a
trusted or a protected file and this file path can be pointed to
``loader.argv_src_file`` manifest option for passing command-line arguments to
Gramine.
For more information on the usage, please refer to :doc:`../manifest-syntax`.

For an example on how to use this utility from Python, please refer to `this
file <https://github.com/gramineproject/gramine/blob/master/LibOS/shim/test/regression/test_libos.py>`__.

Example
=======

.. code-block:: sh

   gramine-argv-serializer "binary_name" "arg1" "arg2" > gramine_secure_args.txt
