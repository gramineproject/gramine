# Rust example

This directory contains an example for running Rust in Gramine, including the
Makefile and a template for generating the manifest. The example application is
an HTTP server based on `hyper`, to also serve as a test for Gramine's `epoll`
implementation, as Rust's async runtimes used to trigger bugs in it.

The bind address and port are hardcoded in `src/main.rs`.

# Quick Start

NOTE: The "benchmark-http.sh" script uses the wrk benchmark (wrk2) under the
hood. Please refer to https://github.com/giltene/wrk2.

NOTE: The Tokio crate is known to require sufficiently new Rust compiler
(`rustc`). Such new version may not be installed by the OS distro Rust package.
In such case, please install the latest stable Rust compiler manually, e.g., via
https://rustup.rs/.

```sh
# build the program and the final manifest
make SGX=1

# run the server in Gramine-SGX against an HTTP benchmark
make SGX=1 start-gramine-server &
../common_tools/benchmark-http.sh http://127.0.0.1:3000
kill -SIGINT %%
```

To test with non-SGX Gramine instead, omit `SGX=1` in both commands.
