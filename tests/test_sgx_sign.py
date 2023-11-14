#!/usr/bin/python3
# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (C) 2023 Intel Corporation
#                    Mariusz Zaborski <oshogbo@invisiblethingslab.com>

import os
import tempfile

import pytest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

testdir = os.path.dirname(os.path.abspath(__file__))

class TempRSAKeyFile:
    def __init__(self, passphrase=None, key_size=3072):
        # pylint: disable=import-outside-toplevel
        from graminelibos.sgx_sign import SGX_RSA_PUBLIC_EXPONENT

        self.temp_file = tempfile.NamedTemporaryFile()

        key = rsa.generate_private_key(public_exponent=SGX_RSA_PUBLIC_EXPONENT, key_size=key_size)

        encryption_algorithm = serialization.NoEncryption()
        if passphrase:
            encryption_algorithm = serialization.BestAvailableEncryption(passphrase)

        private_key = key.private_bytes(encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8, encryption_algorithm=encryption_algorithm)

        self.temp_file.write(private_key)
        self.temp_file.flush()

    def __enter__(self):
        self.temp_file.seek(0)
        return self.temp_file

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.temp_file.close()

# pylint: disable=too-many-arguments
def verify_signature(data, exponent, modulus, signature, key_file, passphrase=None):
    # pylint: disable=import-outside-toplevel
    from graminelibos.sgx_sign import _cryptography_backend
    private_key = serialization.load_pem_private_key(key_file.read(), password=passphrase,
        backend=_cryptography_backend)

    public_key = private_key.public_key()

    numbers = public_key.public_numbers()
    assert numbers.e == exponent
    assert numbers.n == modulus
    signature_bytes = signature.to_bytes((signature.bit_length() + 7) // 8, byteorder='big')
    # This will raise a `cryptography.exceptions.InvalidSignature` exception
    # if signature verification fails.
    public_key.verify(signature_bytes, data, padding.PKCS1v15(), hashes.SHA256())


# This test is omitted when Gramine is installed without SGX support because graminelibos.sgx_sign
# is not installed in such case. This is also why we perform top-level import in this function.
@pytest.mark.sgx
def test_sign_from_pem_path():
    # pylint: disable=import-outside-toplevel
    from graminelibos.sgx_sign import sign_with_private_key_from_pem_path

    data = b'lorem ipsum dolor sit amet consectetur adipiscing elit'

    with TempRSAKeyFile() as key_file:
        exponent, modulus, signature = sign_with_private_key_from_pem_path(data, key_file.name)
        verify_signature(data, exponent, modulus, signature, key_file)

# This test is omitted when Gramine is installed without SGX support because graminelibos.sgx_sign
# is not installed in such case. This is also why we perform top-level import in this function.
@pytest.mark.sgx
def test_sign_from_pem_path_with_passphrase():
    # pylint: disable=import-outside-toplevel
    from graminelibos.sgx_sign import sign_with_private_key_from_pem_path

    data = b'lorem ipsum dolor sit amet consectetur adipiscing elit'
    passphrase = b'randompassphrase'

    with TempRSAKeyFile(passphrase=passphrase) as key_file:
        exponent, modulus, signature = sign_with_private_key_from_pem_path(data, key_file.name,
            passphrase)
        verify_signature(data, exponent, modulus, signature, key_file, passphrase)
