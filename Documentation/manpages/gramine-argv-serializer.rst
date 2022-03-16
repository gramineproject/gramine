.. program:: gramine-argv-serializer

======================================================================
:program:`gramine-argv-serializer` -- Serialize command line arguments
======================================================================

Synopsis
========

:command:`gramine-argv-serializer` [*OPTION*]

Description
===========

`gramine-argv-serializer` serializes the command line arguments and displays it
on the terminal. Typically the output is redirected to a file which can be
used as a trusted or a protected file. To use this file as a source of command
line arguments in Gramine, specify this file path in ``loader.argv_src_file``.
For more information on the usage, please refer to :doc:`../manifest-syntax`.

For an example on how to use this utility from Python, please refer to `this
file <https://github.com/gramineproject/gramine/blob/master/LibOS/shim/test/regression/test_libos.py>`__.

Command line arguments
======================

.. option:: -h, --help

   Display usage.

Example
=======

.. code-block:: sh

    $ gramine-argv-serializer Gramine says hi! > gramine_secure_args.txt
