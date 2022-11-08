# Project Amber Minimal Example

This directory contains a Makefile, a template app manifest, and a
minimal app which interact with project Amber pseudo files to retrieve a token and a secret.

NOTE: this example was validated with project Amber beta1 and the corresponding KBS.
      Sever-side TLS certificate authentication is not enabled.

# Quick Start

- Configuration

For token retrieval
```toml
# must be a IP address of the host set in sgx.amber_url
sgx.amber_ip = "<IP address>"
sgx.amber_url = "https://localhost:443/appraisal/v1/"
# the default apikey, and it should be overwritten by
# a valid apikey through the `/dev/amber/endpoint_apikey` file
sgx.amber_apikey = ""

```
For secret provisioning
```toml
# must be a IP address of the host set in sgx.kbs_url
sgx.kbs_ip = "<IP address>"
sgx.kbs_url = "https://localhost:443/appraisal/v1/"
# the default key id, and it should be overwritten by
# a valid keyid through the `/dev/amber/kbs_keyid` file
sgx.kbs_keyid = ""
# a public key of a 2048-bit RSA key for secret wrapping
sgx.amber_userdata = ""
```

- Run a workflow of project Amber token retrieval; build with SGX enabled:

```sh
make clean
make SGX=1
gramine-sgx ./app

```
