.. program:: gramine-sgx-sign
.. _gramine-sgx-sign:

==============================================================
:program:`gramine-sgx-sign` -- Gramine ``SIGSTRUCT`` generator
==============================================================

Synopsis
========

:command:`gramine-sgx-sign` [*OPTION*]... --output output_manifest
--key key_file --manifest manifest_file

Description
===========

:program:`gramine-sgx-sign` is used to expand Trusted Files and generate
signature file for given input manifest and libpal file (main Gramine binary).

Command line arguments
======================

.. option:: --help, -h

    Show help and exit.

.. option:: --output output_manifest, -o output_manifest

    Path to the output manifest file (with Trusted Files expanded).

.. option:: --key key_file, -k key_file

    Path to the private key used for signing.

.. option:: --manifest manifest_file, -m manifest_file

    Input manifest file.

.. option:: --date <YYYY-MM-DD>|today

    Set specific date to be put into ``SIGSTRUCT``. If not given, or the value
    is literal ``today``, then current day according to system calendar is used.
    Otherwise expects ``<YYYY>-<MM>-<DD>``. The date needs not to be a |~| valid
    day, it will happily accept ``--date 0000-00-00``, e.g. for reproducible
    builds.

.. option:: --libpal libpal_path, -l libpal_path

    Path to libpal file (main Gramine binary).

.. option:: --sigfile sigfile, -s sigfile

    Path to the output file containing ``SIGSTRUCT``. If not provided,
    `manifest_file` will be used with ".manifest" (if present) removed from
    the end and with ".sig" appended.

.. option:: --depfile depfile

    Generate a file that describes the dependencies for the output manifest and
    ``SIGSTRUCT``, i.e. files that should trigger rebuilding if they're
    modified. The dependency file is in Makefile format, and is suitable for
    using in build systems (Make, Ninja).

.. option:: --chroot <path>

    When calculating cryptographic hashes of trusted files, measure files inside
    a |~| chroot instead of paths in root of the file system. Requires that all
    paths in manifest are absolute, and those will be interpreted as relative to
    the directory specified as the value of the option.

    Note you need to be very careful that the Gramine runtime binaries are
    exactly the same inside chroot as the ones used to execute
    :program:`gramine-sgx-sign`.

.. option:: --verbose, -v

    Print details to standard output. This is the default.

.. option:: --quiet, -q

    Don't print details to standard output.

.. option:: --with <plugin>

    Use plugin to perform actual signing. The default plugin is ``file``, which
    signs the ``SIGSTRUCT`` using PEM-encoded local file. The list of available
    plugins is at the end of :option:`--help` output.

    Each plugin may add its own set of options (usually in the form of
    ``--<plugin>-<option>``). To get help about those, use
    :command:`gramine-sgx-sign --with=<plugin> --help-<plugin>` and/or consult
    the documentation of the respective plugin.
