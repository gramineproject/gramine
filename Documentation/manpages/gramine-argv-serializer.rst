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
used as a trusted or a protected file and point to ``loader.argv_src_file``. For
more information on the usage, please refer to :doc:`../manifest-syntax`.

Command line arguments
======================

.. option:: -h, --help

   Display usage.

Example
=======

.. code-block:: sh

    $ gramine-argv-serializer Gramine says hi!
    Graminesayshi!%
