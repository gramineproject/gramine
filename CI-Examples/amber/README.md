# Project Amber Minimal Example

This directory contains the Makefile, the template app manifest, and the
minimal app which interact with project Amber pseudo files to retrieve Amber token.

# Quick Start

- Configuration

```toml
# must be IP address
sgx.amber_ip = "<IP address>"
sgx.amber_url = "https://<IP address>:443/appraisal/v1/"
# the default restricted apikey, and should be overridden by
# writing a proper apikey to /dev/amber/endpoint_apikey
sgx.amber_apikey = ""

```

- Run a workflow of project Amber token retrieval; build with SGX enabled:

```sh
make clean
make SGX=1
gramine-sgx ./app

```
