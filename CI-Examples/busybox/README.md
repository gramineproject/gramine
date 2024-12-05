# Busybox

This directory contains the Makefile and the template manifest for the most
recent version of Busybox (as of this writing, commit ac78f2ac96).

## Note on Ubuntu 24.04 and CentOS Stream 9

There is a known bug in Busybox: Busybox build fails on newer Linux
distributions such as Ubuntu 24.04 and CentOS Stream 9. Unfortunately no fix is
yet available. Be warned that this Busybox example will not build/work on these
newer Linux distros.

For details see https://github.com/gramineproject/gramine/issues/1909.

## Building with SGX remote attestation

If you want to try out [`/dev/attestation/` files][attestation], you must build
the example with SGX remote attestation enabled. By default, the example is
built *without* remote attestation.

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
