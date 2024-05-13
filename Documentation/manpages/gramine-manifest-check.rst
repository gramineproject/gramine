.. program:: gramine-manifest-check
.. _gramine-manifest-check:

======================================================================
:program:`gramine-manifest-check` -- Gramine manifest schema validator
======================================================================

Synopsis
========

:command:`gramine-manifest-check` [*MANIFEST-FILE*]

Description
===========

The program :program:`gramine-manifest-check` is used to check manifests for
compliance with builtin manifest schema.

If the manifest contains entries that are not parsed by Gramine itself (possibly
misspelled real options) or does not contain mandatory options,
:program:`gramine-manifest-check` exits non-zero and short diagnostics
describing the path into data structure will be output to standard error.
If the manifest is OK, nothing is printed and the tool exits with return code 0.

Note that options that are allowed and/or mandatory for default LibOS
implementation (``libsysdb.so``) are considered allowed/mandatory in schema.
Therefore, if you have another LibOS implementation (like it happens in PAL
test suite), the check may be wrong.

By default the check is already performed in :program:`gramine-manifest` (see
:option:`gramine-manifest --check`). This standalone tool may be useful for
example to validate existing manifests when updating Gramine version.
