# AMX test

This directory contains a Makefile and a manifest template for running a simple
AMX test in Gramine. The test performs 10,000,000 `sched_yield()` system calls.
This system call is chosen because it maps 1:1 to the actual host syscall in
case of Gramine. In other words, every `sched_yield()` in the test app results
in one EEXIT -> host `sched_yield` -> EENTER in Gramine-SGX.

Thus, this test app can be used as a micro-benchmark of latency of EEXIT/EENTER
and AEX/RESUME SGX flows, including the XSAVE/XRSTOR done as part of these
EEXIT/EENTER/AEX/ERESUME flows.

# Building

## Building for Linux

Run `make` (non-debug) or `make DEBUG=1` (debug) in the directory.

## Building for SGX

Run `make SGX=1` (non-debug) or `make SGX=1 DEBUG=1` (debug) in the directory.

# Run with Gramine

- Modify `sgx.cpu_features.amx` manifest option to enable/disable AMX feature
  inside the SGX enclave (i.e., hide the AMX feature from XSAVE/XRSTOR flows).

- Modify SSA frame size in Gramine to test different SSA sizes. For this, patch
  Gramine with a one-liner: `#define SSA_FRAME_SIZE (PRESET_PAGESIZE * 1)` and
  rebuild Gramine.

Don't forget to test with Gramine built *in release mode*!

Without SGX (shown for sanity, actually has no difference):
```sh
# run without initializing AMX feature (so-called XINUSE)
gramine-direct amxtest
# run with initializing AMX feature (argv[1] can be any string)
gramine-direct amxtest inuse
```

With SGX:
```sh
# run without initializing AMX feature (so-called XINUSE)
gramine-sgx amxtest
# run with initializing AMX feature (argv[1] can be any string)
gramine-sgx amxtest inuse
```
