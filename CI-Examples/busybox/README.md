# Busybox

This directory contains the Makefile and the template manifest for the most
recent version of Busybox (as of this writing, commit ac78f2ac96).

## Building with SGX remote attestation

If you want to try out `/dev/attestation/` files, you must build the example
with SGX remote attestation enabled. By default, the example is built *without*
remote attestation.

If you want to build the example for DCAP attestation, first make sure you have
a working DCAP setup. Then build the example as follows:
```
RA_TYPE=dcap make SGX=1
```

Otherwise, you will probably want to use EPID attestation. For this, you will
additionally need to provide an SPID and specify whether it is set up for
linkable quotes or not:
```
RA_TYPE=epid RA_CLIENT_SPID=12345678901234567890123456789012 RA_CLIENT_LINKABLE=0 make SGX=1
```

The above dummy values will suffice for simple experiments, but if you wish to
run `sgx-quote.py` and verify the output, you will need to provide an
[SPID recognized by Intel][spid].


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
