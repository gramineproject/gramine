# Nginx

This directory contains the Makefile and the template manifest for the most
recent version of Nginx web server (as of this writing, version 1.16.1).

We build Nginx from the source code instead of using an existing installation.
On Ubuntu 20.04, please make sure that the following packages are installed:
```sh
sudo apt-get install -y build-essential libssl-dev zlib1g-dev
```

NOTE: The "benchmark-http.sh" script uses the wrk benchmark (wrk2) under the
hood. Please refer to https://github.com/giltene/wrk2.

# Quick Start

```sh
# build Nginx and the final manifest
make SGX=1

# run original Nginx against HTTP and HTTPS benchmarks (benchmark-http.sh, uses wrk2)
./install/sbin/nginx -c conf/nginx-gramine.conf &
../common_tools/benchmark-http.sh http://127.0.0.1:8002
../common_tools/benchmark-http.sh https://127.0.0.1:8444
kill -SIGINT %%

# Run Nginx in non-SGX Gramine against HTTP and HTTPS benchmarks.
# Note: The command-line arguments are passed using `loader.argv_src_file`
# manifest option.
gramine-direct ./nginx &
../common_tools/benchmark-http.sh http://127.0.0.1:8002
../common_tools/benchmark-http.sh https://127.0.0.1:8444
kill -SIGINT %%

# Run Nginx in Gramine-SGX against HTTP and HTTPS benchmarks.
# Note: The command-line arguments are securely passed using
# `loader.argv_src_file` manifest option.
gramine-sgx ./nginx &
../common_tools/benchmark-http.sh http://127.0.0.1:8002
../common_tools/benchmark-http.sh https://127.0.0.1:8444
kill -SIGINT %%

# you can also test the server using other utilities like wget
wget http://127.0.0.1:8002/random/10K.1.html
wget https://127.0.0.1:8444/random/10K.1.html
```

Alternatively, to run the Nginx server, use one of the following commands:

```
make start-native-server
make start-gramine-server
make SGX=1 start-gramine-server
```
