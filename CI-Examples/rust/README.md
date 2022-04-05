# Rust example

This directory contains an example for running Rust in Gramine, including the
Makefile and a template for generating the manifest. The example application is
an HTTP server based on `hyper`, to also serve as a test for Gramine's `epoll`
implementation, as Rust's async runtimes used to trigger bugs in it.
