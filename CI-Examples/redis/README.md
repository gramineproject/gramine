# Redis

This directory contains the Makefile and the template manifest for the most
recent version of Redis (as of this writing, version 6.0.5).

The Makefile and the template manifest contain extensive comments and are made
self-explanatory. Please review them to gain understanding of Gramine and
requirements for applications running under Gramine. If you want to contribute a
new example to Gramine and you take this Redis example as a template, we
recommend to remove the comments from your copies as they only add noise (see
e.g. Memcached for a "stripped-down" example).


# Quick Start

```sh
# build Redis and the final manifest
make SGX=1

# run original Redis against a benchmark (redis-benchmark supplied with Redis)
./redis-server --save '' &
src/src/redis-benchmark
kill %%

# run Redis in non-SGX Gramine against a benchmark (args are hardcoded in manifest)
gramine-direct redis-server &
src/src/redis-benchmark
kill %%

# run Redis in Gramine-SGX against a benchmark (args are hardcoded in manifest)
gramine-sgx redis-server &
src/src/redis-benchmark
kill %%
```

# Why this Redis configuration?

Notice that we run Redis with the `save ''` setting. This setting disables
saving DB to disk (both RDB snapshots and AOF logs). We use this setting
because:

- saving DB to disk is a slow operation (Redis uses fork internally which is
  implemented as a slow checkpoint-and-restore in Gramine and requires creating
  a new SGX enclave);
- saved RDB snapshots and AOF logs must be encrypted and integrity-protected for
  DB confidentiality reasons, which requires marking the corresponding
  directories and files as `encrypted` in Gramine manifest; we skip it for
  simplicity.

In Gramine case, this setting is hardcoded in the manifest file, see
`loader.argv` there.

# Redis with Select

By default, Redis uses the epoll mechanism of Linux to monitor client
connections. To test Redis with select, add `USE_SELECT=1`, e.g., `make SGX=1
USE_SELECT=1`.
