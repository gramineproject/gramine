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

This tool is intended to be the "pre-main" executable that runs inside Gramine
before the actual application; therefore it must be specified as the entrypoint
in the Gramine manifest file. It **cannot** be used by itself.

This tool is intended to launch standalone TLS (HTTPS) servers which require
cert and key passed as files. For a real-world example of its usage with an
Nginx web server, see
https://github.com/gramineproject/gramine/tree/master/CI-Examples/ra-tls-nginx.

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

The below manifest will first run :program:`gramine-ratls` and then write the
contents of a certificate file to standard output using the :program:`cat`
utility:

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
