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

## Using the KSS Feature
When KSS is enabled, you can set four values—ISV Family ID, ISV Extended Prod ID, Config ID, and Config SVN—and include them in the REPORT structure.

To enable KSS, modify the following section in python.manifest.template:  
```
sgx.kss = true  # Change to "false" to disable KSS
```

To set the ISV Family ID and ISV Extended Prod ID, modify the following lines:  
```
sgx.isvfamilyid = "0x00112233445566778899aabbccddeeff"
sgx.isvextprodid = "0xcafef00dcafef00df00dcafef00dcafe"
```

To set the Config ID and Config SVN, configure the following environment variables on the host OS before executing scripts:  
```
export SGX_CONFIG_ID=DEADBEEF12345678DEADBEEF12345678DEADBEEF12345678DEADBEEF12345678DEADBEEF12345678DEADBEEF12345678DEADBEEF12345678DEADBEEF12345678
export SGX_CONFIG_SVN=ABCD
```
You can check these values by running `sgx-report.py` or `sgx-quote.py`, as described in the next section.

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
