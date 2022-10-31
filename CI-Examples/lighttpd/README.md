# Lighttpd Example

This directory contains an example for running lighttpd in Gramine, including
the Makefile and a template for generating the manifest.

# Building lighttpd source

For this example, we build lighttpd from source instead of using an existing
binary. To build lighttpd on Ubuntu 20.04, please make sure that the following
packages are installed:

    sudo apt-get install -y build-essential libssl-dev zlib1g-dev

## Linux

Run `make` (non-debug) or `make DEBUG=1` (debug) in the directory.

## SGX

Run `make SGX=1` (non-debug) or `make SGX=1 DEBUG=1` (debug) in the directory to
prepare lighttpd to run on SGX.

# Running lighttpd

Execute one of the following commands to start lighttpd either natively
(non-Gramine), on Gramine or Gramine-SGX, respectively.

    make start-native-server
    make start-gramine-server
    SGX=1 make start-gramine-server

Because these commands will start the lighttpd server in the foreground, you
will need to open another console to run the client.

Once the server has started, you can test it with `wget` or `curl`

    wget http://127.0.0.1:8003/random/10K.1.html
    curl --compressed http://127.0.0.1:8003/random/10K.1.html -o 10K.1.html

You may also run the benchmark script using `wrk` (wrk2). Please refer to
https://github.com/giltene/wrk2 for more information.

    ../common_tools/benchmark-http.sh http://127.0.0.1:8003

Use Ctrl-C to terminate the server once you are finished testing lighttpd.
