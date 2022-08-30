# KSS Hello World

This directory contains a Makefile and a manifest template for running a simple
"Hello World" program with KSS in Gramine. It is built with KSS support and non-zero
values for `isvextprodid` and `isvfamilyid`, which are printed by the enclave.
report.

This example is SGX-specific.

# Build

Run `make` (non-debug) or `make DEBUG=1` (debug) in the directory.

Remote attestation must be supported to run this test. Default attestation type is `dcap`.
It can be modified with the `RA_TYPE` flag in make. For example: `make RA_TYPE=epid`.

# Run

```sh
gramine-sgx ./kss-helloworld
```

Note that a platform with KSS support must be used, otherwise this example will not work.
Use `is-sgx-available` tool to determine if the platform supports KSS.
