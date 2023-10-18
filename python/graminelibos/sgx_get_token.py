# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (C) 2021 Intel Corporation
#                    Borys Popławski <borysp@invisiblethingslab.com>

import hashlib
import socket
import struct

import _graminelibos_offsets as offs # pylint: disable=import-error

def get_optional_sgx_features(sig):
    '''Set optional SGX features if they are available on this machine.'''
    optional_sgx_features = {
        offs.SGX_XFRM_AVX:      'avx',
        offs.SGX_XFRM_AVX512:   'avx512f',
        offs.SGX_XFRM_MPX:      'mpx',
        offs.SGX_XFRM_PKRU:     'pku', # "pku" is not a typo, that's how cpuinfo reports it
        offs.SGX_XFRM_AMX:      'amx_tile',
    }

    cpu_features = ''
    with open('/proc/cpuinfo', 'r') as file:
        for line in file:
            if line.startswith('flags'):
                cpu_features = line.split(':')[1].strip().split()
                break
        else:
            raise Exception('Failed to parse CPU flags')

    xfrms = sig['attribute_xfrms']
    xfrmmask = sig['attribute_xfrm_mask']

    new_xfrms = xfrms
    for (bits, feature) in optional_sgx_features.items():
        # check if SIGSTRUCT.ATTRIBUTEMASK.XFRM doesn't care whether an optional CPU feature is
        # enabled or not (XFRM mask should completely unset these bits); set these CPU features as
        # enabled if so and if the current system supports these features (for performance)
        if bits & xfrmmask == 0 and feature in cpu_features:
            new_xfrms |= bits

    return new_xfrms

def is_oot():
    '''Check if we're dealing with OOT driver.'''
    return hasattr(offs, 'CONFIG_SGX_DRIVER_OOT')

def p64(x):
    return x.to_bytes(8, byteorder='little')

def connect_aesmd(mrenclave, modulus, flags, xfrms):
    '''Connect with AESMD.'''

    from . import aesm_pb2 # pylint: disable=import-error,no-name-in-module,import-outside-toplevel

    req_msg = aesm_pb2.GetTokenReq()
    req_msg.req.signature = mrenclave
    req_msg.req.key = modulus
    req_msg.req.attributes = p64(flags) + p64(xfrms)
    req_msg.req.timeout = 10000

    req_msg_raw = req_msg.SerializeToString()

    aesm_service = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

    # Try to connect to all possible interfaces exposed by aesm service
    connections = (
        '/var/run/aesmd/aesm.socket',         # named socket (for PSW 1.8+)
        '\0sgx_aesm_socket_base' + '\0' * 87  # unnamed socket (for PSW 1.6/1.7)
    )

    for conn in connections:
        try:
            aesm_service.connect(conn)
        except socket.error:
            continue
        break
    else:
        raise socket.error('Cannot connect to the AESMD service')

    aesm_service.send(struct.pack('<I', len(req_msg_raw)))
    aesm_service.send(req_msg_raw)

    ret_msg_size = struct.unpack('<I', aesm_service.recv(4))[0]
    ret_msg = aesm_pb2.GetTokenRet()
    ret_msg_raw = aesm_service.recv(ret_msg_size)
    ret_msg.ParseFromString(ret_msg_raw)

    if ret_msg.ret.error != 0:
        raise Exception(f'Failed. (Error Code = {ret_msg.ret.error})')

    return ret_msg.ret.token

def get_token(sig, verbose=False):
    """Get SGX token (aka EINITTOKEN).

    Generates an SGX token from the given SIGSTRUCT. The resulting token might have some additional
    features enabled that were not required (but also not forbidden) by the input SIGSTRUCT. For
    example, if SIGSTRUCT did not have bit(s) corresponding to AVX512 set in
    `SIGSTRUCT.ATTRIBUTEMASK.XFRM` and the machine on which the token is generated (i.e. the one
    that will be running the enclave) supports AVX512, then the output token will have AVX512
    enabled.

    Args:
        sig (Sigstruct): SIGSTRUCT to generate the token for.
        verbose (bool): If true, print details to stdout.

    Returns:
        bytes: SGX token.
    """
    if not is_oot():
        raise RuntimeError('The upstream driver doesn\'t use EINITTOKEN')

    xfrms = get_optional_sgx_features(sig)

    # calculate MRSIGNER as sha256 hash over RSA public key's modulus
    mrsigner = hashlib.sha256()
    mrsigner.update(sig['modulus'])
    mrsigner = mrsigner.hexdigest()

    if verbose:
        print('Attributes:')
        print(f'    mr_enclave:  {sig["enclave_hash"].hex()}')
        print(f'    mr_signer:   {mrsigner}')
        print(f'    isv_prod_id: {sig["isv_prod_id"]}')
        print(f'    isv_svn:     {sig["isv_svn"]}')
        print(f'    attr.flags:  {sig["attribute_flags"]:016x}')
        print(f'    attr.xfrm:   {xfrms:016x}')
        print(f'    mask.flags:  {sig["attribute_flags_mask"]:016x}')
        print(f'    mask.xfrm:   {sig["attribute_xfrm_mask"]:016x}')
        print(f'    misc_select: {sig["misc_select"]:08x}')
        print(f'    misc_mask:   {sig["misc_mask"]:08x}')
        print(f'    modulus:     {sig["modulus"].hex()[:32]}...')
        print(f'    exponent:    {sig["exponent"]}')
        print(f'    signature:   {sig["signature"].hex()[:32]}...')
        print(f'    date:        {sig["date_year"]:04d}-{sig["date_month"]:02d}-'
              f'{sig["date_day"]:02d}')

    return connect_aesmd(sig['enclave_hash'], sig['modulus'], sig['attribute_flags'], xfrms)
