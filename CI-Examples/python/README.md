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

The `scripts/sgx-quote.py` script depends on working DCAP attestation, so first
make sure you have a&nbsp;working DCAP setup.

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
