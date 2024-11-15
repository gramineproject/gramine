# Busybox

This directory contains the Makefile and the template manifest for the most
recent version of Busybox (as of this writing, commit ac78f2ac96).

## Note on Ubuntu 24.04 and CentOS Stream 9

There is a known bug in Busybox: Busybox build fails on newer Linux
distributions such as Ubuntu 24.04 and CentOS Stream 9. Unfortunately no fix is
yet available. Be warned that this Busybox example will not build/work on these
newer Linux distros.

For details see https://github.com/gramineproject/gramine/issues/1909.

## Building without SGX remote attestation

By default, the example is built with [`dcap` attestation][attestation]. To
build *without* remote attestation (e.g. if you have SGX-capable hardware, but
not correctly provisioned yet), pass `RA_TYPE=none` argument to `make`
invocation below. When you build without attestation, most of pseudo-files in
`/dev/attestation` are not available.

[attestation]: https://gramine.readthedocs.io/en/stable/attestation.html

If you want to build the example for DCAP attestation, first make sure you have
a working DCAP setup. Then build the example as follows:
```
make SGX=1 RA_TYPE=dcap
```

# Quick Start

```sh
# build Busybox and the final manifest
make SGX=1

# run Busybox shell in non-SGX Gramine
gramine-direct busybox sh

# run Busybox shell in Gramine-SGX
gramine-sgx busybox sh

# now a shell session should be running e.g. typing:
ls
# should run program `ls` which lists current working directory
```
