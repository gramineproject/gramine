# Secret Provisioning Minimal Examples

This directory contains a Makefile, template client manifests, and a few
examples of server and clients written against the Secret Provisioning
library.

These examples use the Secret Provisioning libraries `secret_prov_attest.so` for
the clients and `secret_prov_verify_epid.so`/`secret_prov_verify_dcap.so` for
the server. They are installed together with Gramine (but for DCAP version, you
need `meson setup ... -Ddcap=enabled`). Additionally, mbedTLS libraries are
required. For ECDSA/DCAP attestation, the DCAP software infrastructure must be
installed and work correctly on the host.

The current example works with both EPID (IAS) and ECDSA (DCAP) remote
attestation schemes. For more documentation, refer to
https://gramine.readthedocs.io/en/latest/attestation.html.

## Secret Provisioning server

The server is supposed to run on a trusted machine (not in an SGX enclave). The
server listens for client connections. For each connected client, the server
verifies the client's RA-TLS certificate and the embedded SGX quote and, if
verification succeeds, sends secrets back to the client (e.g. the master
key for encrypted files in `secret_prov_pf` example).

There are two versions of each the server: the EPID one and the DCAP one. Each
of them links against the corresponding EPID/DCAP secret-provisioning library
at build time.

Because this example builds and uses debug SGX enclaves (`sgx.debug` is set
to `true`), we use environment variable `RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE=1`.
Note that in production environments, you must *not* use this option!

Moreover, we set `RA_TLS_ALLOW_OUTDATED_TCB_INSECURE=1`, to allow performing
the tests when some of Intel's security advisories haven't been addressed (for
example, when the microcode or architectural enclaves aren't fully up-to-date).
As the name of this setting suggests, this is not secure and likewise should not
be used in production.

## Secret Provisioning clients

There are three clients in this example:

1. Minimal client. It relies on constructor-time secret provisioning and gets
   the first (and only) secret from the environment variable
   `SECRET_PROVISION_SECRET_STRING`.
2. Feature-rich client. It uses a programmatic C API to get two secrets from the
   server.
3. Encrypted-files client. Similarly to the minimal client, it relies on
   constructor-time secret provisioning and instructs Gramine to use the
   provisioned secret as the encryption key for the Encrypted Files feature.
   After the master key is applied, the client reads an encrypted file
   `input.txt`.

As part of secret provisioning flow, all clients create a self-signed RA-TLS
certificate with the embedded SGX quote, send it to the server for verification,
and expect secrets in return.

The minimal and the encrypted-files clients rely on the `LD_PRELOAD` trick that
preloads `libsecret_prov_attest.so` and runs it before the clients' main logic.
The feature-rich client links against `libsecret_prov_attest.so` explicitly at
build time.

# Quick Start

- Secret Provisioning flows, EPID-based (IAS) attestation (you will need to
  provide an [SPID and the corresponding IAS API keys][spid]):

[spid]: https://gramine.readthedocs.io/en/latest/sgx-intro.html#term-spid

```sh
make app epid RA_TYPE=epid RA_CLIENT_SPID=<your SPID> \
     RA_CLIENT_LINKABLE=<1 if SPID is linkable, else 0>

# test encrypted files client (other examples can be tested similarly)
cd secret_prov_pf
RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE=1 \
RA_TLS_ALLOW_OUTDATED_TCB_INSECURE=1 \
RA_TLS_EPID_API_KEY=<your EPID API key> \
./server_epid wrap_key &

# test minimal client
gramine-sgx ./client

kill %%
```

- Secret Provisioning flows, ECDSA-based (DCAP) attestation:

```sh
make app dcap RA_TYPE=dcap

# test encrypted files client (other examples can be tested similarly)
cd secret_prov_pf
RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE=1 \
RA_TLS_ALLOW_OUTDATED_TCB_INSECURE=1 \
./server_dcap wrap_key &

gramine-sgx ./client

kill %%
```
