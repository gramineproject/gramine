# Secret Provisioning Minimal Examples

This directory contains a Makefile, template client manifests, and a few
examples of servers and clients written against the Secret Provisioning
library.

These examples use the Secret Provisioning library `secret_prov_attest.so` for
the clients and `secret_prov_verify_epid.so`/`secret_prov_verify_dcap.so` for
the servers. These libraries are installed together with Gramine (but for DCAP
version, you need `meson setup ... -Ddcap=enabled`). For DCAP attestation, the
DCAP software infrastructure must be installed and work correctly on the host.

The current example works with both EPID (IAS) and ECDSA (DCAP) remote
attestation schemes. For more documentation, refer to
https://gramine.readthedocs.io/en/stable/attestation.html.

## Secret Provisioning servers

There are three server examples:

1. Minimal server (found under `secret_prov_minimal/`). It sends only one,
   hardcoded secret.
2. More complex server (found under `secret_prov/`), which uses the negotiated
   TLS connection to exchange more data with the client enclave.
3. Encrypted files server (found under `secret_prov_pf/`) - similarly to the
   minimal client, it sends only a single secret, but loads it from a file, with
   intended purpose of the secret being an encrypted files key to be provisioned
   to client enclaves.

The servers are supposed to run on trusted machines (not in SGX enclaves). The
servers listen for client connections. For each connected client, the servers
verify the client's RA-TLS certificate and the embedded SGX quote and, if
verification succeeds, sends secrets back to the client (e.g. the master key
for encrypted files in `secret_prov_pf` example).

There are two versions of each server: the EPID one and the DCAP one. Each of
them links against the corresponding EPID/DCAP secret-provisioning library at
build time.

Because this example builds and uses debug SGX enclaves (`sgx.debug` is set
to `true`), we use environment variable `RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE=1`.
Note that in production environments, you must *not* use this option!

Moreover, we set `RA_TLS_ALLOW_OUTDATED_TCB_INSECURE=1`,
`RA_TLS_ALLOW_HW_CONFIG_NEEDED=1` and `RA_TLS_ALLOW_SW_HARDENING_NEEDED=1` to
allow performing the tests when some of Intel's security advisories haven't been
addressed (for example, when the microcode or architectural enclaves aren't
fully up-to-date). Note that in production environments, you must carefully
analyze whether to use these options!

## Secret Provisioning clients

There are three client examples:

1. Minimal client (found under `secret_prov_minimal/`). It relies on
   constructor-time secret provisioning and gets the first (and only) secret
   from the environment variable `SECRET_PROVISION_SECRET_STRING`.
2. More complex client (found under `secret_prov/`). It uses a programmatic C
   API to get two secrets from the server.
3. Encrypted files client (found under `secret_prov_pf/`). Similarly to the
   minimal client, it relies on constructor-time secret provisioning and
   instructs Gramine to use the provisioned secret as the encryption key for the
   encrypted files feature. After the master key is applied, the client reads an
   encrypted file `input.txt`.

As part of secret provisioning flow, all clients create a self-signed RA-TLS
certificate with the embedded SGX quote, send it to the server for verification,
and expect secrets in return.

The minimal and the encrypted files clients rely on the `LD_PRELOAD` trick that
preloads `libsecret_prov_attest.so` and runs it before the clients' main logic.
The feature-rich client links against `libsecret_prov_attest.so` explicitly at
build time.

# Quick Start

For all examples, we set the following environment variables:
```sh
export RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE=1
export RA_TLS_ALLOW_OUTDATED_TCB_INSECURE=1
export RA_TLS_ALLOW_HW_CONFIG_NEEDED=1
export RA_TLS_ALLOW_SW_HARDENING_NEEDED=1
```

- Secret Provisioning flows, EPID-based (IAS) attestation (you will need to
  provide an [SPID and the corresponding IAS API keys][spid]):

[spid]: https://gramine.readthedocs.io/en/stable/sgx-intro.html#term-spid

```sh
make app epid RA_TYPE=epid RA_CLIENT_SPID=<your SPID> \
     RA_CLIENT_LINKABLE=<1 if SPID is linkable, else 0>

# test encrypted files client (other examples can be tested similarly)
cd secret_prov_pf
RA_TLS_EPID_API_KEY=<your EPID API key> \
./server_epid wrap_key &

gramine-sgx ./client

kill %%
```

- Secret Provisioning flows, ECDSA-based (DCAP) attestation:

```sh
make app dcap RA_TYPE=dcap

# test encrypted files client (other examples can be tested similarly)
cd secret_prov_pf
./server_dcap wrap_key &

gramine-sgx ./client

kill %%
```
