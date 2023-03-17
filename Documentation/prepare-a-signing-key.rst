.. _prepare_a_signing_key

Prepare a signing key
---------------------

These instructions are only required for systems using SGX and have not already created a signing key.

   - If your system is not using SGX, skip to Run the sample application.

   - If your system is using SGX and you already created a signing key, skip to Run the sample application. 

   - If your system is using SGX and have not created a signing key, follow the instructions below. 

The following command generates an |~| RSA 3072 key suitable for signing SGX enclaves
and stores it in :file:`{HOME}/.config/gramine/enclave-key.pem`. Protect
this key and do not disclose it to anyone:: 

   gramine-sgx-gen-private-key


glibc vs musl
-------------

Most of the examples we provide use GNU C Library (glibc). If your application
is built against musl libc, you can pass ``'musl'`` to
:py:func:`gramine.runtimedir()` when generating the manifest from a template;
this will mount musl libc (instead of the default glibc).