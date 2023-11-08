#!/usr/bin/python3
# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (C) 2023 Intel Corporation
#                    Mariusz Zaborski <oshogbo@invisiblethingslab.com>

import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from graminelibos.sgx_sign import (
    _cryptography_backend,
    sign_with_private_key_from_pem_path,
)

testdir = os.path.dirname(os.path.abspath(__file__))

# pylint: disable=too-many-arguments
def verify_signature(data, exponent, modulus, signature, path, passphrase=None):
    with open(path, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(),
            password=passphrase, backend=_cryptography_backend)

    public_key = private_key.public_key()

    numbers = public_key.public_numbers()
    assert numbers.e == exponent
    assert numbers.n == modulus
    signature_bytes = signature.to_bytes((signature.bit_length() + 7) // 8,
        byteorder='big')
    # This will raise a `cryptography.exceptions.InvalidSignature` exception
    # if signature verification fails.
    public_key.verify(signature_bytes, data, padding.PKCS1v15(),
        hashes.SHA256())

def test_sign_from_pem_path():
    key_file = os.path.join(testdir, 'files/key.pem')
    data = b'lorem ipsum dolor sit amet consectetur adipiscing elit'

    exponent, modulus, signature = sign_with_private_key_from_pem_path(data,
        key_file)
    verify_signature(data, exponent, modulus, signature, key_file)

def test_sign_from_pem_path_with_passphrase():
    key_file = os.path.join(testdir, 'files/key_passphrase.pem')
    passphrase = b'oshogbo'
    data = b'lorem ipsum dolor sit amet consectetur adipiscing elit'

    exponent, modulus, signature = sign_with_private_key_from_pem_path(data,
        key_file, passphrase)
    verify_signature(data, exponent, modulus, signature, key_file, passphrase)
