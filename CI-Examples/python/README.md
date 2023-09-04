# Python example

This directory contains an example for running Python 3 in Gramine, including
the Makefile and a template for generating the manifest.

# Generating the manifest

## Installing prerequisites

For generating the manifest and running the test scripts, please run the following
command to install the required packages (Ubuntu-specific):

    sudo apt-get install libnss-mdns python3-numpy python3-scipy

## Building for Linux

Run `make` (non-debug) or `make DEBUG=1` (debug) in the directory.

## Building for SGX

Run `make SGX=1` (non-debug) or `make SGX=1 DEBUG=1` (debug) in the directory.

If you want to run the `scripts/sgx-quote.py` script, you must build the example
with SGX remote attestation enabled. By default, the example is built *without*
remote attestation.

If you want to build the example for DCAP attestation, first make sure you have
a working DCAP setup. Then build the example as follows:
```
make SGX=1 RA_TYPE=dcap
```

Otherwise, you will probably want to use EPID attestation. For this, you will
additionally need to provide an SPID and specify whether it is set up for
linkable quotes or not:

```
make SGX=1 RA_TYPE=epid RA_CLIENT_SPID=12345678901234567890123456789012 \
    RA_CLIENT_LINKABLE=0
```

The above dummy values will suffice for simple experiments, but if you wish to
run `sgx-quote.py` and verify the output, you will need to provide an
[SPID recognized by Intel][spid].

[spid]: https://gramine.readthedocs.io/en/stable/sgx-intro.html#term-spid

# Run Python with Gramine

Here's an example of running Python scripts under Gramine:
```
gramine-sgx ./python scripts/helloworld.py
gramine-sgx ./python scripts/test-numpy.py
gramine-sgx ./python scripts/test-scipy.py
gramine-sgx ./python scripts/sgx-report.py
gramine-sgx ./python scripts/sgx-quote.py
```

You can also manually run included tests:
```
SGX=1 ./run-tests.sh
```

To run Gramine in non-SGX (direct) mode, replace `gramine-sgx` with
`gramine-direct` and remove `SGX=1` in the commands above.
