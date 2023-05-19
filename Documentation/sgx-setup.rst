Set up the host environment
===========================

.. note ::
   Currently, Gramine has two backends: Linux (execution on the host Linux OS)
   and Linux-SGX (execution inside an SGX enclave). The Linux backend doesn't
   require any specific environment. Thus, this page describes how to set up the
   SGX environment on your platform.

Gramine with SGX support requires several features from your system:

- Intel SGX must be enabled in BIOS.
- Linux kernel version must be at least 5.11 (starting from this version, Linux
  has the FSGSBASE feature and the SGX driver required by Gramine).
- The Intel PSW must be installed.
- The Intel DCAP must be installed if DCAP-based attestation will be used.

If your system doesn't meet these requirements, please refer to more detailed
descriptions in :doc:`devel/building`.

Check for SGX compatibility
---------------------------

We supply a tool, :doc:`manpages/is-sgx-available` that checks the environment
for SGX compatibility. Use this tool to check your hardware and system. It is
installed together with the Gramine package.

Prepare a signing key
---------------------

Only for SGX, and if you haven't already, enter the following:

::

    gramine-sgx-gen-private-key

This command generates an RSA 3072 key suitable for signing SGX enclaves and
stores it in ``$HOME/.config/gramine/enclave-key.pem``. Protect this key and do
not disclose it to anyone. See also :doc:`manpages/gramine-sgx-gen-private-key`.

Signing an SGX enclave is a required step in Intel SGX. First, SGX platforms
only load signed enclave images. Second, the enclave's signed structure (called
SIGSTRUCT) includes a measurement of the enclave code (called MRENCLAVE), the
derivative of the public key (called MRSIGNER) and other metadata; thus, the
process of enclave signing binds together these measurements of the loaded
enclave, and subsequent SGX attestation can prove the genuineness of this
enclave based on these measurements.
