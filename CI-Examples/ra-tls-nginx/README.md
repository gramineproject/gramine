# RA-TLS with Nginx

**NOTE:** This example requires SGX. It does not work with `gramine-direct`.

This example demonstrates how to attest a generic TLS server using RA-TLS. The
certificate and key files are saved to a tmpfs system inside Gramine using
`gramine-ratls` tool. Nginx is configured to use those files. This works because
while tmpfs is not shared between Gramine processes, Nginx is execve()'d from
`gramine-ratls`, so the tmpfs is kept intact.

```sh
make
gramine-sgx nginx
```

Then in another terminal:
```sh
curl --insecure https://localhost:8000
```

In this simplified example, `--insecure` argument to curl means that curl will
not check the TLS certificate. The `curl` command-line tool can't check it at
all, because RA-TLS certificate is self-signed and does not chain to any WebPKI
roots, so `curl` is currently unsuitable for production deployments. In
production, another HTTPS client performing remote attestation should be used.

See also `run.sh` script, which starts the enclave, performs a request, then
kills it and reports the status.

## EPID remote attestation

If you use EPID attestation, add those arguments to `make` invocation above:

```sh
make RA_TYPE=epid RA_CLIENT_SPID=... RA_CLIENT_LINKABLE=[0|1]
```
