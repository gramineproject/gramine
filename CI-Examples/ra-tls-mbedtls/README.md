# RA-TLS Minimal Example

This directory contains the Makefile, the template server manifest, and the
minimal server and client written against the mbedTLS library.

The server and client are based on `ssl_server.c` and `ssl_client1.c` example
programs shipped with mbedTLS. We modified them to allow using RA-TLS flows. In
particular, the server uses a self-signed RA-TLS cert with the SGX quote
embedded in it via `ra_tls_create_key_and_crt_der()`. The client uses an RA-TLS
verification callback to verify the server RA-TLS certificate via
`ra_tls_verify_callback_der()`.

This example uses the RA-TLS libraries `ra_tls_attest.so` for server and
`ra_tls_verify_epid.so`/ `ra_tls_verify_dcap.so` for client. These libraries are
installed together with Gramine (for DCAP version, you need `meson setup ...
-Ddcap=enabled`). For DCAP attestation, the DCAP software infrastructure must be
 installed and work correctly on the host.

The current example works with both EPID (IAS) and ECDSA (DCAP) remote
attestation schemes. For more documentation, refer to
https://gramine.readthedocs.io/en/stable/attestation.html.

## RA-TLS server

The server is supposed to run in the SGX enclave with Gramine and RA-TLS
dlopen-loaded. If the server is started not in the SGX enclave, then it falls
back to using normal X.509 PKI flows.

If server is run with a command-line argument ``--test-malicious-quote``, then
the server will maliciously modify the SGX quote before sending to the client.
This is useful for testing purposes.

## RA-TLS client

The client is supposed to run on a trusted machine (*not* in an SGX enclave). If
RA-TLS library `ra_tls_verify_epid.so` or `ra_tls_verify_dcap.so` is not
requested by user via `epid` or `dcap` command-line arguments respectively, the
client falls back to using normal X.509 PKI flows (specified as `native`
command-line argument).

It is also possible to run the client in an SGX enclave. This will create a
secure channel between two Gramine SGX processes, possibly running on different
machines. It can be used as an example of in-enclave remote attestation and
verification.

If client is run without additional command-line arguments, it uses default
RA-TLS verification callback that compares `MRENCLAVE`, `MRSIGNER`,
`ISV_PROD_ID` and `ISV_SVN` against the corresonding `RA_TLS_*` environment
variables. `MRENCLAVE`, `MRSIGNER` and `ISV_PROD_ID` are expected to match
`RA_TLS_*` ones. `ISV_SVN` is expected to be equal or greater than `RA_TLS_ISV_SVN`.
To run the client with its own verification callback, execute it with four
additional command-line arguments (see the source code for details).

Also, because this example builds and uses debug SGX enclaves (`sgx.debug` is
set to `true`), we use environment variable `RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE=1`.
Note that in production environments, you must *not* use this option!

Moreover, we set `RA_TLS_ALLOW_OUTDATED_TCB_INSECURE=1`,
`RA_TLS_ALLOW_HW_CONFIG_NEEDED=1` and `RA_TLS_ALLOW_SW_HARDENING_NEEDED=1` to
allow performing the tests when some of Intel's security advisories haven't been
addressed (for example, when the microcode or architectural enclaves aren't
fully up-to-date). Note that in production environments, you must carefully
analyze whether to use these options!

# Quick Start

In most of the examples below, you need to tell the client what values it should
expect for `MRENCLAVE`, `MRSIGNER`, `ISV_PROD_ID` and `ISV_SVN`. One way to
obtain them is to run `gramine-sgx-sigstruct-view server.sig`.

Moreover, for EPID-based (IAS) attestation, you will need to provide
an [SPID and the corresponding IAS API keys][spid].

[spid]: https://gramine.readthedocs.io/en/stable/sgx-intro.html#term-spid

For all examples, we set the following environment variables:
```sh
export RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE=1
export RA_TLS_ALLOW_OUTDATED_TCB_INSECURE=1
export RA_TLS_ALLOW_HW_CONFIG_NEEDED=1
export RA_TLS_ALLOW_SW_HARDENING_NEEDED=1
```

- Normal non-RA-TLS flows; without SGX and without Gramine:

```sh
make app
./server &
./client native
# client will successfully connect to the server via normal x.509 PKI flows
kill %%
```

- RA-TLS flows with SGX and with Gramine, EPID-based (IAS) attestation:

```sh
make clean
make app epid RA_TYPE=epid RA_CLIENT_SPID=<your SPID> \
    RA_CLIENT_LINKABLE=<1 if SPID is linkable, else 0>

gramine-sgx ./server &

RA_TLS_EPID_API_KEY=<your EPID API key> \
RA_TLS_MRENCLAVE=<MRENCLAVE of the server enclave> \
RA_TLS_MRSIGNER=<MRSIGNER of the server enclave> \
RA_TLS_ISV_PROD_ID=<ISV_PROD_ID of the server enclave> \
RA_TLS_ISV_SVN=<ISV_SVN of the server enclave> \
./client epid

# client will successfully connect to the server via RA-TLS/EPID flows
kill %%
```

- RA-TLS flows with SGX and with Gramine, ECDSA-based (DCAP) attestation:

```sh
make clean
make app dcap RA_TYPE=dcap

gramine-sgx ./server &

RA_TLS_MRENCLAVE=<MRENCLAVE of the server enclave> \
RA_TLS_MRSIGNER=<MRSIGNER of the server enclave> \
RA_TLS_ISV_PROD_ID=<ISV_PROD_ID of the server enclave> \
RA_TLS_ISV_SVN=<ISV_SVN of the server enclave> \
./client dcap

# client will successfully connect to the server via RA-TLS/DCAP flows
kill %%
```

- RA-TLS flows with SGX and with Gramine, client with its own verification callback:

```sh
make clean
make app dcap RA_TYPE=dcap

gramine-sgx ./server &

./client dcap \
    <MRENCLAVE of the server enclave> \
    <MRSIGNER of the server enclave> \
    <ISV_PROD_ID of the server enclave> \
    <ISV_SVN of the server enclave>

# client will successfully connect to the server via RA-TLS/DCAP flows
kill %%
```

- RA-TLS flows with SGX and with Gramine, server sends malicious SGX quote:

```sh
make clean
make app dcap RA_TYPE=dcap

gramine-sgx ./server --test-malicious-quote &
./client dcap

# client will fail to verify the malicious SGX quote and will *not* connect to the server
kill %%
```

- RA-TLS flows with SGX and with Gramine, running EPID client in SGX:

Note: you may need to add environment variables to `client.manifest.template`, such
as `RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE`, `RA_TLS_MRENCLAVE`, etc.

```sh
make clean
make app epid RA_TYPE=epid RA_CLIENT_SPID=<your SPID> \
    RA_CLIENT_LINKABLE=<1 if SPID is linkable, else 0>

gramine-sgx ./server &

RA_TLS_EPID_API_KEY=<your EPID API key> \
    gramine-sgx ./client_epid epid

# client will successfully connect to the server via RA-TLS/EPID flows
kill %%
```

- RA-TLS flows with SGX and with Gramine, running DCAP client in SGX:

```sh
make clean
make app dcap RA_TYPE=dcap

gramine-sgx ./server &

gramine-sgx ./client_dcap dcap \
    <MRENCLAVE of the server enclave> \
    <MRSIGNER of the server enclave> \
    <ISV_PROD_ID of the server enclave> \
    <ISV_SVN of the server enclave>

# client will successfully connect to the server via RA-TLS/DCAP flows
kill %%
```
