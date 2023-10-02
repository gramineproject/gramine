# Memcached

This directory contains the Makefile and the template manifest for the most
recent version of Memcached as of this writing (v1.6.21).

# Prerequisites

Please install `libevent-dev` package. If you want to benchmark with memcslap,
also install `libmemcached-tools`.

# Quick Start

```sh
# build Memcached and the final manifest
make SGX=1

# run original Memcached against a benchmark (memtier_benchmark,
# install the benchmark on your host OS first)
./memcached &
memtier_benchmark --port=11211 --protocol=memcache_binary --hide-histogram
kill %%

# run Memcached in non-SGX Gramine against a benchmark
gramine-direct memcached &
memtier_benchmark --port=11211 --protocol=memcache_binary --hide-histogram
kill %%

# run Memcached in Gramine-SGX against a benchmark
gramine-sgx memcached &
memtier_benchmark --port=11211 --protocol=memcache_binary --hide-histogram
kill %%
```
