.. program:: gramine-ratls
.. _gramine-ratls:

==========================================
:program:`gramine-ratls` -- RA-TLS wrapper
==========================================

Synopsis
========

:command:`gramine-ratls` [*OPTIONS*] <*CERTFILE*> <*KEYFILE*> [--] [*COMMAND* *ARGS* ...]

Description
===========

:program:`gramine-ratls` generates X.509 certificate and matching private key
using RA-TLS library. It saves those as files (by default PEM encoded, but see
option :option:`-D`) under paths given as first two CLI arguments. If further
arguments are passed, those are interpreted as a |~| command that is then
executed using ``execvp()``.

It is intended to launch standalone TLS (HTTPS) servers which require cert and
key passed as files.

Options
=======

.. option:: -D

    Write the certificate and key in DER format.

.. option:: -P

    Write the certificate and key in PEM format. This is the default, but can be
    used to override :option:`-D`.

.. option:: -h

    Show help and exit.

Example
=======

This manifest will run :program:`gramine-ratls` and write the contents of
certificate file to standard output using the :program:`cat` utility:

.. code-block:: jinja

    loader.entrypoint = "file:{{ gramine.libos }}"
    loader.argv = [
        "gramine-ratls", "/tmp/crt.der", "/tmp/key.der",
        "cat", "/tmp/crt.der",
    ]
    libos.entrypoint = "/gramine-ratls"

    loader.env.LD_LIBRARY_PATH = "/lib"

    fs.mounts = [
        { path = "/gramine-ratls", uri = "file:/usr/bin/gramine-ratls" },
        { path = "/lib", uri = "file:{{ gramine.runtimedir() }}" },
        { path = "/bin/cat", uri = "file:/bin/cat" },
        { path = "/tmp", type = "tmpfs" },
    ]

    sgx.remote_attestation = "dcap"

    sgx.debug = true

    sgx.trusted_files = [
        "file:{{ gramine.libos }}",
        "file:/usr/bin/gramine-ratls",
        "file:{{ gramine.runtimedir() }}/",
        "file:/bin/cat",
    ]
