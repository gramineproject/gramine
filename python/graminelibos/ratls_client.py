#!/usr/bin/python3 -O
# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (C) 2023 Intel Corporation
#                    Wojtek Porczyk <woju@invisiblethingslab.com>

#
#   ┌─── DCAP
#   │┌── EPID
#   ││┌─ MAA
#   de$     VARIABLE
#    E€     VARIABLE (mandatory)
#     ¢     VARIABLE (output -- currently unsupported)
#
#   de$     RA_TLS_MRENCLAVE={any|<hex>}
#   de$     RA_TLS_MRSIGNER={any|<hex>}
#   de$     RA_TLS_ISV_PROD_ID={any|<dec>}
#   de$     RA_TLS_ISV_SVN={any|<dec>}
#   de$     RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE=1
#   de-     RA_TLS_ALLOW_OUTDATED_TCB_INSECURE=1
#   de-     RA_TLS_ALLOW_HW_CONFIG_NEEDED=1
#   de-     RA_TLS_ALLOW_SW_HARDENING_NEEDED=1
#   -E-     RA_TLS_EPID_API_KEY=<hex>
#   -e-     RA_TLS_IAS_REPORT_URL=<url>
#   -e-     RA_TLS_IAS_SIGRL_URL=<url>
#   -e-     RA_TLS_IAS_PUB_KEY_PEM=?
#   --€     RA_TLS_MAA_PROVIDER_URL=<url>
#   --$     RA_TLS_MAA_PROVIDER_API_VERSION=3
#   --¢     RA_TLS_MAA_JWT
#   --¢     RA_TLS_MAA_SET_OF_JWKS
#
# ref:
#   https://gramine.readthedocs.io/en/stable/attestation.html#ra-tls-verify-epid-so)
#   https://github.com/gramineproject/contrib/blob/master/Integrations/azure/ra_tls_maa/README.md
#


import ctypes
import os
import types
import http.client
import ssl
import urllib.parse


class AttestationError(Exception):
    pass


def request(method, url, *, verify_cb, headers=types.MappingProxyType({}), data=None):
    url = urllib.parse.urlsplit(url)
    if url.scheme != 'https':
        raise ValueError(f'needs https:// URI, found {url.scheme}://')

    context = ssl._create_unverified_context() #pylint: disable=protected-access
    conn = http.client.HTTPSConnection(url.netloc, context=context)
    conn.connect()
    try:
        # NEVER SEND ANYTHING TO THE SERVER BEFORE THIS LINE
        verify_cb(conn.sock.getpeercert(binary_form=True))
    except AttestationError:
        conn.close()
        raise

    path = url.path
    if url.query:
        path += url.query
    headers = {
        'host': url.hostname,
        **headers,
    }

    conn.request(method, path, headers=headers, body=data)
    return conn.getresponse()


def ra_tls_setenv(var, value, default=None):
    if value in (None, False):
        if default is None:
            try:
                del os.environ[var]
            except KeyError:
                pass
        else:
            os.environ[var] = default
    elif value is True:
        os.environ[var] = '1'
    else:
        os.environ[var] = value

def load_ra_tls_verify_callback_der(scheme):
    lib = ctypes.cdll.LoadLibrary(f'libra_tls_verify_{scheme}.so')
    func = lib.ra_tls_verify_callback_der # TODO extended
    func.argtypes = ctypes.c_char_p, ctypes.c_size_t
    func.restype = ctypes.c_int
    def ra_tls_verify_callback_der(der):
        ret = func(der, len(der))
        if ret < 0:
            raise AttestationError(ret)
    return ra_tls_verify_callback_der


def verify_dcap(cert, *,
    mrenclave=None, mrsigner=None, isv_prod_id=None, isv_svn=None,
    allow_debug_enclave_insecure=False, allow_outdated_tcb_insecure=False,
    allow_hw_config_needed=False, allow_sw_hardening_needed=False,
):
    if (mrenclave, mrsigner) == (None, None):
        raise TypeError('need at least one of: mrenclave, mrsigner')

    ra_tls_setenv('RA_TLS_MRENCLAVE', mrenclave, 'any')
    ra_tls_setenv('RA_TLS_MRSIGNER', mrsigner, 'any')
    ra_tls_setenv('RA_TLS_ISV_PROD_ID', isv_prod_id, 'any')
    ra_tls_setenv('RA_TLS_ISV_SVN', isv_svn, 'any')
    ra_tls_setenv('RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE', allow_debug_enclave_insecure)
    ra_tls_setenv('RA_TLS_ALLOW_OUTDATED_TCB_INSECURE', allow_outdated_tcb_insecure)
    ra_tls_setenv('RA_TLS_ALLOW_HW_CONFIG_NEEDED', allow_hw_config_needed)
    ra_tls_setenv('RA_TLS_ALLOW_SW_HARDENING_NEEDED', allow_sw_hardening_needed)

    load_ra_tls_verify_callback_der('dcap')(cert)


def verify_epid(cert, *,
    epid_api_key,
    mrenclave=None, mrsigner=None, isv_prod_id=None, isv_svn=None,
    allow_debug_enclave_insecure=False, allow_outdated_tcb_insecure=False,
    allow_hw_config_needed=False, allow_sw_hardening_needed=False, ias_report_url=None,
    ias_sigrl_url=None, ias_pub_key_pem=None,
):
    if (mrenclave, mrsigner) == (None, None):
        raise TypeError('need at least one of: mrenclave, mrsigner')

    ra_tls_setenv('RA_TLS_EPID_API_KEY', epid_api_key)
    ra_tls_setenv('RA_TLS_MRENCLAVE', mrenclave, 'any')
    ra_tls_setenv('RA_TLS_MRSIGNER', mrsigner, 'any')
    ra_tls_setenv('RA_TLS_ISV_PROD_ID', isv_prod_id, 'any')
    ra_tls_setenv('RA_TLS_ISV_SVN', isv_svn, 'any')
    ra_tls_setenv('RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE', allow_debug_enclave_insecure)
    ra_tls_setenv('RA_TLS_ALLOW_OUTDATED_TCB_INSECURE', allow_outdated_tcb_insecure)
    ra_tls_setenv('RA_TLS_ALLOW_HW_CONFIG_NEEDED', allow_hw_config_needed)
    ra_tls_setenv('RA_TLS_ALLOW_SW_HARDENING_NEEDED', allow_sw_hardening_needed)
    ra_tls_setenv('RA_TLS_IAS_REPORT_URL', ias_report_url)
    ra_tls_setenv('RA_TLS_IAS_SIGRL_URL', ias_sigrl_url)
    ra_tls_setenv('RA_TLS_IAS_PUB_KEY_PEM', ias_pub_key_pem)

    load_ra_tls_verify_callback_der('epid')(cert)


def verify_maa(cert, *,
    maa_provider_url,
    mrenclave=None, mrsigner=None, isv_prod_id=None, isv_svn=None,
    allow_debug_enclave_insecure=False, allow_outdated_tcb_insecure=False,
    allow_hw_config_needed=False, allow_sw_hardening_needed=False, maa_provider_api_version=None,
):
    if (mrenclave, mrsigner) == (None, None):
        raise TypeError('need at least one of: mrenclave, mrsigner')

    ra_tls_setenv('RA_TLS_MAA_PROVIDER_URL', maa_provider_url)
    ra_tls_setenv('RA_TLS_MRENCLAVE', mrenclave, 'any')
    ra_tls_setenv('RA_TLS_MRSIGNER', mrsigner, 'any')
    ra_tls_setenv('RA_TLS_ISV_PROD_ID', isv_prod_id, 'any')
    ra_tls_setenv('RA_TLS_ISV_SVN', isv_svn, 'any')
    ra_tls_setenv('RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE', allow_debug_enclave_insecure)
    ra_tls_setenv('RA_TLS_MAA_PROVIDER_API_VERSION', maa_provider_api_version)

    load_ra_tls_verify_callback_der('maa')(cert)
