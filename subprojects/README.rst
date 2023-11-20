Gramine uses the following third-party components:

- cJSON: used in RA-TLS/SecretProv libraries to parse JSON objects embedded in
  HTTPS requests (e.g. when communicating with Intel Attestation Service).
- curl: used in RA-TLS/SecretProv libraries to send/receive HTTPS
  requests/responses (e.g. when communicating with Intel Attestation Service).
- GCC: only the libgomp (OpenMP) library is used (unfortunately this library
  cannot be built separately from the whole GCC build); libgomp is patched to
  use Glibc wrapper ``futex()`` instead of the raw syscall. Purely for better
  performance.
- glibc/musl: used as the default libc library for applications; patched to use
  jump-into-Gramine functions instead of raw syscalls. Purely for better
  performance.
- mbedTLS: used for all crypto- and TLS-operations in Gramine and its tools:

  - crypto (``libmbedcrypto.a``) is used in Gramine core, e.g. AES-GCM on
    Encrypted Files and SHA256 on Trusted Files.
  - TLS (``libmbedtls.a`` and ``libmbedx509.a``) is used in RA-TLS/SecretProv
    libraries, to establish TLS connections and to create/verify X.509
    certificates.
- tomlc99: used in Gramine core to parse the manifest file (which is written in
  the TOML syntax).
- UTHash: used in Gramine core, in particular in Encrypted Files, to create a
  Least Recently Used (LRU) cache of blocks of encrypted files, as a performance
  optimization.

For security reasons, we strive to update glibc, musl, curl and mbedTLS as soon
as they release new versions that fix security vulnerabilities.
