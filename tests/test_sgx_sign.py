#!/usr/bin/python3
# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (C) 2023 Intel Corporation
#                    Mariusz Zaborski <oshogbo@invisiblethingslab.com>

# pylint: disable=import-outside-toplevel

import pytest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

@pytest.fixture
def tmp_rsa_key(tmpdir):
    from graminelibos.sgx_sign import (SGX_RSA_KEY_SIZE, SGX_RSA_PUBLIC_EXPONENT,
        _cryptography_backend)
    def gen_rsa_key(passphrase=None, key_size=SGX_RSA_KEY_SIZE):
        # TODO: use `tmp_path` fixture after we drop support for distros (RHEL 8, CentOS Stream 8)
        # that have old pytest version (< 3.9.0) installed
        key_path = tmpdir.join('key.pem')
        with open(key_path, 'wb') as pfile:
            key = rsa.generate_private_key(public_exponent=SGX_RSA_PUBLIC_EXPONENT,
                key_size=key_size, backend=_cryptography_backend)

            encryption_algorithm = serialization.NoEncryption()
            if passphrase is not None:
                encryption_algorithm = serialization.BestAvailableEncryption(passphrase)

            private_key = key.private_bytes(encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8, encryption_algorithm=
                encryption_algorithm)
            pfile.write(private_key)
        return key_path
    return gen_rsa_key

# pylint: disable=too-many-arguments
def verify_signature(data, exponent, modulus, signature, key_file, passphrase=None):
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
# pylint: disable=redefined-outer-name
@pytest.mark.sgx
def test_sign_from_pem_path(tmp_rsa_key):
    from graminelibos.sgx_sign import sign_with_private_key_from_pem_path

    data = b'lorem ipsum dolor sit amet consectetur adipiscing elit'

    key_path = tmp_rsa_key()
    with open(key_path, 'rb') as key_file:
        exponent, modulus, signature = sign_with_private_key_from_pem_path(data, key_path)
        verify_signature(data, exponent, modulus, signature, key_file)

# This test is omitted when Gramine is installed without SGX support because graminelibos.sgx_sign
# is not installed in such case. This is also why we perform top-level import in this function.
# pylint: disable=redefined-outer-name
@pytest.mark.sgx
def test_sign_from_pem_path_with_passphrase(tmp_rsa_key):
    from graminelibos.sgx_sign import sign_with_private_key_from_pem_path

    data = b'lorem ipsum dolor sit amet consectetur adipiscing elit'
    passphrase = b'randompassphrase'

    key_path = tmp_rsa_key(passphrase)
    with open(key_path, 'rb') as key_file:
        exponent, modulus, signature = sign_with_private_key_from_pem_path(data, key_path,
            passphrase)
        verify_signature(data, exponent, modulus, signature, key_file, passphrase)
