.. program:: gramine-ratls
.. _gramine-ratls:

==========================================
:program:`gramine-ratls` -- RA-TLS wrapper
==========================================

Synopsis
========

:command:`gramine-ratls` <*CERTFILE*> <*KEYFILE*> [*COMMAND* *ARGS* ...]

Description
===========

:program:`gramine-ratls` generates X.509 certificate and matching private key
using RA-TLS library. It saves those as DER-encoded files under paths given as
first two CLI arguments. If further arguments are passed, those are interpreted
as a |~| command that is then executed using ``execvp()``.

Example
=======

This manifest will run :program:`gramine-ratls` and write the contents of
certificate file to standard output:

.. code-block:: jinja

    loader.entrypoint = "file:{{ gramine.libos }}"
    loader.argv = [
        "gramine-ratls", "/tmp/crt.der", "/tmp/key.der",
        "cat", "/tmp/crt.der",
    ]
    libos.entrypoint = "/gramine-ratls"
    
    loader.env.LD_LIBRARY_PATH = "/lib"
    
    fs.mounts = [
        { path = "/lib", uri = "file:{{ gramine.runtimedir() }}" },
        { path = "/gramine-ratls", uri = "file:/usr/bin/gramine-ratls" },
        { path = "/tmp", type = "tmpfs" },
        { path = "/bin/cat", uri = "file:/bin/cat" },
    ]
    
    sgx.remote_attestation = "dcap"
    
    sgx.debug = true
    
    sgx.trusted_files = [
        "file:{{ gramine.libos }}",
        "file:/usr/bin/gramine-ratls-wrapper",
        "file:{{ gramine.runtimedir() }}/",
        "file:/bin/cat",
    ]

