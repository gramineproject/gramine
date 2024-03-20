# Intel Trust Authority (ITA) Minimum Example

This directory contains a Makefile, a template app manifest,
and a minimum app which interacts with ITA pseudo files
to retrieve a token and/or a secret.
An ephemeral cryptographic keypair is generated on the fly in code
to illustrate how to provision a key for various purposes,
such as establishing a secure communication channel, wrapping secrets.

NOTE: this example was validated with ITA GA and KBS rc2.
      Sever-side TLS certificate authentication is not enabled.

# Quick Start

- Configuration

For token retrieval
```toml
# specify the endpoint of ITA appraisal service.
sgx.amber_url = "https://api.trustauthority.intel.com/appraisal/v1/"
# the default apikey, and it should be overwritten by
# a valid apikey through the `/dev/amber/endpoint_apikey` file
sgx.amber_apikey = "0000000"

```
For secret provisioning
```toml
# must be a IP address of the host set in sgx.kbs_url
sgx.kbs_ip = "<IP address>"
sgx.kbs_url = "https://localhost:443/appraisal/v1/"
# the default key id, and it should be overwritten by
# a valid keyid through the `/dev/amber/kbs_keyid` file
# sgx.kbs_keyid = ""
# a public key of a 2048-bit RSA key for secret wrapping
# sgx.amber_userdata = ""
```

- Run a workflow of ITA token retrieval; build with SGX enabled:

```sh
make clean
make SGX=1
gramine-sgx app

```
