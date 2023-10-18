# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (C) 2014 Stony Brook University
# Copyright (C) 2022 Intel Corporation
#                    Michał Kowalczyk <mkow@invisiblethingslab.com>
#                    Borys Popławski <borysp@invisiblethingslab.com>
#                    Wojtek Porczyk <woju@invisiblethingslab.com>
#

import functools
import hashlib
import os
import pathlib
import struct

import click

from cryptography.hazmat import backends
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

import elftools.elf.elffile

from . import _CONFIG_PKGLIBDIR
from .manifest import Manifest
from .sigstruct import Sigstruct

import _graminelibos_offsets as offs # pylint: disable=import-error,wrong-import-order

# TODO after deprecating 20.04: remove backend wrt
# https://cryptography.io/en/latest/faq/#what-happened-to-the-backend-argument
_cryptography_backend = backends.default_backend()

# Default / Architectural Options

ARCHITECTURE = 'amd64'

SGX_LIBPAL = os.path.join(_CONFIG_PKGLIBDIR, 'sgx/libpal.so')

SGX_RSA_PUBLIC_EXPONENT = 3
SGX_RSA_KEY_SIZE = 3072
_xdg_config_home = pathlib.Path(os.getenv('XDG_CONFIG_HOME',
    pathlib.Path.home() / '.config'))
SGX_RSA_KEY_PATH = _xdg_config_home / 'gramine' / 'enclave-key.pem'

# Utilities

ZERO_PAGE = bytes(offs.PAGESIZE)


def roundup(addr):
    remaining = addr % offs.PAGESIZE
    if remaining:
        return addr + (offs.PAGESIZE - remaining)
    return addr


def rounddown(addr):
    return addr - addr % offs.PAGESIZE


def parse_size(value):
    scale = 1
    if value.endswith('K'):
        scale = 1024
    elif value.endswith('M'):
        scale = 1024 * 1024
    elif value.endswith('G'):
        scale = 1024 * 1024 * 1024
    if scale != 1:
        value = value[:-1]
    return int(value, 0) * scale


# Loading Enclave Attributes


def collect_bits(manifest_sgx, options_dict):
    val = 0
    for opt, bits in options_dict.items():
        if manifest_sgx.get(opt) is True:
            val |= bits
    return val


def collect_cpu_feature_bits(manifest_cpu_features, options_dict, val, mask, security_hardening):
    for opt, bits in options_dict.items():
        if opt not in manifest_cpu_features:
            continue
        if manifest_cpu_features[opt] == "required":
            val |= bits
            mask |= bits
        elif manifest_cpu_features[opt] == "disabled":
            val &= ~bits
            mask |= bits
        elif security_hardening or manifest_cpu_features[opt] != "unspecified":
            raise KeyError(f'Manifest option `sgx.cpu_features.{opt}` has a disallowed value')
    return val, mask


def get_enclave_attributes(manifest_sgx):
    flags_dict = {
        'debug': offs.SGX_FLAGS_DEBUG,
    }
    flags = collect_bits(manifest_sgx, flags_dict)
    if ARCHITECTURE == 'amd64':
        flags |= offs.SGX_FLAGS_MODE64BIT

    # TODO: 'require_exinfo' was deprecated in release v1.6, should be removed in v1.7
    if 'require_exinfo' in manifest_sgx:
        if 'use_exinfo' in manifest_sgx:
            raise KeyError(f'`sgx.require_exinfo` cannot coexist with `sgx.use_exinfo`')
        manifest_sgx['use_exinfo'] = manifest_sgx.pop('require_exinfo')

    miscs_dict = {
        'use_exinfo': offs.SGX_MISCSELECT_EXINFO,
    }
    miscs = collect_bits(manifest_sgx, miscs_dict)

    # TODO: these were deprecated in release v1.6, so they should be removed in v1.7
    deprecated_xfrms_dict = {
        'require_avx': offs.SGX_XFRM_AVX,
        'require_avx512': offs.SGX_XFRM_AVX512,
        'require_mpx': offs.SGX_XFRM_MPX,
        'require_pkru': offs.SGX_XFRM_PKRU,
        'require_amx': offs.SGX_XFRM_AMX,
    }
    xfrms_dict = {
        'avx': offs.SGX_XFRM_AVX,
        'avx512': offs.SGX_XFRM_AVX512,
        'amx': offs.SGX_XFRM_AMX,
    }
    secure_xfrms_dict = {
        'mpx': offs.SGX_XFRM_MPX,
        'pkru': offs.SGX_XFRM_PKRU,
    }

    xfrms, xfrms_mask = offs.SGX_XFRM_LEGACY, offs.SGX_XFRM_MASK_CONST
    if manifest_sgx.get('cpu_features') is None:
        # collect deprecated `sgx.require_xxx` options; remove this in v1.7
        xfrms |= collect_bits(manifest_sgx, deprecated_xfrms_dict)
    else:
        for deprecated_key in deprecated_xfrms_dict:
            if deprecated_key in manifest_sgx:
                raise KeyError(f'`sgx.cpu_features` cannot coexist with `sgx.{deprecated_key}`')
        xfrms, xfrms_mask = collect_cpu_feature_bits(manifest_sgx['cpu_features'], xfrms_dict,
                                                     xfrms, xfrms_mask, security_hardening=False)
        xfrms, xfrms_mask = collect_cpu_feature_bits(manifest_sgx['cpu_features'],
                                                     secure_xfrms_dict, xfrms, xfrms_mask,
                                                     security_hardening=True)

    return flags, miscs, xfrms, xfrms_mask


# Populate Enclave Memory

PAGEINFO_R = 0x1
PAGEINFO_W = 0x2
PAGEINFO_X = 0x4
PAGEINFO_TCS = 0x100
PAGEINFO_REG = 0x200


def get_loadcmds(elf_filename):
    with open(elf_filename, 'rb') as file:
        for seg in elftools.elf.elffile.ELFFile(file).iter_segments():
            if seg.header.p_type != 'PT_LOAD':
                continue
            yield (
                seg.header.p_offset,
                seg.header.p_vaddr,
                seg.header.p_filesz,
                seg.header.p_memsz,
                seg.header.p_flags)


class MemoryArea:
    # pylint: disable=too-few-public-methods,too-many-instance-attributes
    def __init__(self, desc, elf_filename=None, content=None, addr=None, size=None,
                 flags=None, measure=True):
        # pylint: disable=too-many-arguments
        self.desc = desc
        self.elf_filename = elf_filename
        self.content = content
        self.addr = addr
        self.size = size
        self.flags = flags
        self.measure = measure

        if elf_filename:
            mapaddr = 0xffffffffffffffff
            mapaddr_end = 0
            for (_, addr_, _, memsize, _) in get_loadcmds(elf_filename):
                if rounddown(addr_) < mapaddr:
                    mapaddr = rounddown(addr_)
                if roundup(addr_ + memsize) > mapaddr_end:
                    mapaddr_end = roundup(addr_ + memsize)

            self.size = mapaddr_end - mapaddr
            if mapaddr > 0:
                self.addr = mapaddr

        if self.addr is not None:
            self.addr = rounddown(self.addr)
        if self.size is not None:
            self.size = roundup(self.size)


def get_memory_areas(attr, libpal):
    areas = []
    areas.append(
        MemoryArea('ssa',
                   size=attr['max_threads'] * offs.SSA_FRAME_SIZE * offs.SSA_FRAME_NUM,
                   flags=PAGEINFO_R | PAGEINFO_W | PAGEINFO_REG))
    areas.append(MemoryArea('tcs', size=attr['max_threads'] * offs.TCS_SIZE,
                            flags=PAGEINFO_TCS))
    areas.append(MemoryArea('tls', size=attr['max_threads'] * offs.PAGESIZE,
                            flags=PAGEINFO_R | PAGEINFO_W | PAGEINFO_REG))

    for _ in range(attr['max_threads']):
        areas.append(MemoryArea('stack', size=offs.ENCLAVE_STACK_SIZE,
                                flags=PAGEINFO_R | PAGEINFO_W | PAGEINFO_REG))
    for _ in range(attr['max_threads']):
        areas.append(MemoryArea('sig_stack', size=offs.ENCLAVE_SIG_STACK_SIZE,
                                flags=PAGEINFO_R | PAGEINFO_W | PAGEINFO_REG))

    areas.append(MemoryArea('pal', elf_filename=libpal, flags=PAGEINFO_REG))
    return areas


def find_areas(areas, desc):
    return [area for area in areas if area.desc == desc]


def find_area(areas, desc, allow_none=False):
    matching = find_areas(areas, desc)

    if not matching and allow_none:
        return None

    if len(matching) != 1:
        raise KeyError(f'Could not find exactly one MemoryArea {desc!r}')

    return matching[0]


def entry_point(elf_path):
    with open(elf_path, 'rb') as file:
        return elftools.elf.elffile.ELFFile(file).header.e_entry


def gen_area_content(attr, areas, enclave_base, enclave_heap_min):
    # pylint: disable=too-many-locals
    manifest_area = find_area(areas, 'manifest')
    pal_area = find_area(areas, 'pal')
    ssa_area = find_area(areas, 'ssa')
    tcs_area = find_area(areas, 'tcs')
    tls_area = find_area(areas, 'tls')
    stacks = find_areas(areas, 'stack')
    sig_stacks = find_areas(areas, 'sig_stack')

    tcs_data = bytearray(tcs_area.size)

    def set_tcs_field(t, offset, pack_fmt, value):
        struct.pack_into(pack_fmt, tcs_data, t * offs.TCS_SIZE + offset, value)

    tls_data = bytearray(tls_area.size)

    def set_tls_field(t, offset, value):
        struct.pack_into('<Q', tls_data, t * offs.PAGESIZE + offset, value)

    enclave_heap_max = pal_area.addr

    # Sanity check that we measure everything except the heap which is zeroed
    # on enclave startup.
    for area in areas:
        if (area.addr + area.size <= enclave_heap_min or
                area.addr >= enclave_heap_max):
            if not area.measure:
                raise ValueError('Memory area, which is not the heap, is not measured')
        elif area.desc != 'free':
            raise ValueError('Unexpected memory area is in heap range')

    for t in range(0, attr['max_threads']):
        ssa = ssa_area.addr + offs.SSA_FRAME_SIZE * offs.SSA_FRAME_NUM * t
        ssa_offset = ssa - enclave_base
        set_tcs_field(t, offs.TCS_OSSA, '<Q', ssa_offset)
        set_tcs_field(t, offs.TCS_NSSA, '<L', offs.SSA_FRAME_NUM)
        set_tcs_field(t, offs.TCS_OENTRY, '<Q',
                      pal_area.addr + entry_point(pal_area.elf_filename) - enclave_base)
        set_tcs_field(t, offs.TCS_OGS_BASE, '<Q', tls_area.addr - enclave_base + offs.PAGESIZE * t)
        set_tcs_field(t, offs.TCS_OFS_LIMIT, '<L', 0xfff)
        set_tcs_field(t, offs.TCS_OGS_LIMIT, '<L', 0xfff)

        set_tls_field(t, offs.SGX_COMMON_SELF, tls_area.addr + offs.PAGESIZE * t)
        set_tls_field(t, offs.SGX_COMMON_STACK_PROTECTOR_CANARY,
                      offs.STACK_PROTECTOR_CANARY_DEFAULT)
        set_tls_field(t, offs.SGX_ENCLAVE_SIZE, attr['enclave_size'])
        set_tls_field(t, offs.SGX_TCS_OFFSET, tcs_area.addr - enclave_base + offs.TCS_SIZE * t)
        set_tls_field(t, offs.SGX_INITIAL_STACK_ADDR, stacks[t].addr + stacks[t].size)
        set_tls_field(t, offs.SGX_SIG_STACK_LOW, sig_stacks[t].addr)
        set_tls_field(t, offs.SGX_SIG_STACK_HIGH, sig_stacks[t].addr + sig_stacks[t].size)
        set_tls_field(t, offs.SGX_SSA, ssa)
        set_tls_field(t, offs.SGX_GPR, ssa + offs.SSA_FRAME_SIZE - offs.SGX_GPR_SIZE)
        set_tls_field(t, offs.SGX_MANIFEST_SIZE, len(manifest_area.content))
        set_tls_field(t, offs.SGX_HEAP_MIN, enclave_heap_min)
        set_tls_field(t, offs.SGX_HEAP_MAX, enclave_heap_max)

    tcs_area.content = tcs_data
    tls_area.content = tls_data


def populate_memory_areas(attr, areas, enclave_base, enclave_heap_min):
    last_populated_addr = enclave_base + attr['enclave_size']

    for area in areas:
        if area.addr is not None:
            continue

        area.addr = last_populated_addr - area.size
        if area.addr < enclave_heap_min:
            raise Exception('Enclave size is not large enough')
        last_populated_addr = area.addr

    gen_area_content(attr, areas, enclave_base, enclave_heap_min)

    # Enclaves with EDMM do not add "free" memory at startup.
    if attr['edmm_enable']:
        return areas

    free_areas = []
    for area in areas:
        addr = area.addr + area.size
        if addr < last_populated_addr:
            flags = PAGEINFO_R | PAGEINFO_W | PAGEINFO_X | PAGEINFO_REG
            free_areas.append(
                MemoryArea('free', addr=addr, size=last_populated_addr - addr,
                           flags=flags, measure=False))
            last_populated_addr = area.addr

    if last_populated_addr > enclave_heap_min:
        flags = PAGEINFO_R | PAGEINFO_W | PAGEINFO_X | PAGEINFO_REG
        free_areas.append(
            MemoryArea('free', addr=enclave_heap_min,
                       size=last_populated_addr - enclave_heap_min, flags=flags,
                       measure=False))

    return areas + free_areas


def generate_measurement(enclave_base, attr, areas, verbose=False):
    # pylint: disable=too-many-statements,too-many-branches,too-many-locals

    def do_ecreate(digest, size):
        data = struct.pack('<8sLQ44s', b'ECREATE', offs.SSA_FRAME_SIZE // offs.PAGESIZE, size, b'')
        digest.update(data)

    def do_eadd(digest, offset, flags):
        assert offset < attr['enclave_size']
        data = struct.pack('<8sQQ40s', b'EADD', offset, flags, b'')
        digest.update(data)

    def do_eextend(digest, offset, content):
        assert offset < attr['enclave_size']

        if len(content) != 256:
            raise ValueError('Exactly 256 bytes expected')

        data = struct.pack('<8sQ48s', b'EEXTEND', offset, b'')
        digest.update(data)
        digest.update(content)

    def include_page(digest, addr, flags, content, measure):
        if len(content) != offs.PAGESIZE:
            raise ValueError('Exactly one page expected')

        do_eadd(digest, addr - enclave_base, flags)
        if measure:
            for i in range(0, offs.PAGESIZE, 256):
                do_eextend(digest, addr - enclave_base + i, content[i:i + 256])

    mrenclave = hashlib.sha256()
    do_ecreate(mrenclave, attr['enclave_size'])

    def print_area(addr, size, flags, desc, measured):
        assert verbose

        if flags & PAGEINFO_REG:
            type_ = 'REG'
        if flags & PAGEINFO_TCS:
            type_ = 'TCS'
        prot = ['-', '-', '-']
        if flags & PAGEINFO_R:
            prot[0] = 'R'
        if flags & PAGEINFO_W:
            prot[1] = 'W'
        if flags & PAGEINFO_X:
            prot[2] = 'X'
        prot = ''.join(prot)

        desc = f'({desc})'
        if measured:
            desc += ' measured'

        print(f'    {addr:016x}-{addr+size:016x} [{type_}:{prot}] {desc}')

    def load_file(digest, file, offset, addr, filesize, memsize, desc, flags):
        # pylint: disable=too-many-arguments
        f_addr = rounddown(offset)
        m_addr = rounddown(addr)
        m_size = roundup(addr + memsize) - m_addr

        if verbose:
            print_area(m_addr, m_size, flags, desc, True)

        for page in range(m_addr, m_addr + m_size, offs.PAGESIZE):
            start = page - m_addr + f_addr
            end = start + offs.PAGESIZE
            start_zero = b''
            if start < offset:
                if offset - start >= offs.PAGESIZE:
                    start_zero = ZERO_PAGE
                else:
                    start_zero = bytes(offset - start)
            end_zero = b''
            if end > offset + filesize:
                if end - offset - filesize >= offs.PAGESIZE:
                    end_zero = ZERO_PAGE
                else:
                    end_zero = bytes(end - offset - filesize)
            start += len(start_zero)
            end -= len(end_zero)
            if start < end:
                file.seek(start)
                data = file.read(end - start)
            else:
                data = b''
            if len(start_zero + data + end_zero) != offs.PAGESIZE:
                raise Exception('wrong calculation')

            include_page(digest, page, flags, start_zero + data + end_zero, True)

    if verbose:
        print('Memory:')

    for area in areas:
        if area.elf_filename is not None:
            with open(area.elf_filename, 'rb') as file:
                loadcmds = list(get_loadcmds(area.elf_filename))
                if loadcmds:
                    mapaddr = 0xffffffffffffffff
                    for (offset, addr, filesize, memsize,
                         prot) in loadcmds:
                        if rounddown(addr) < mapaddr:
                            mapaddr = rounddown(addr)
                baseaddr_ = area.addr - mapaddr
                for (offset, addr, filesize, memsize, prot) in loadcmds:
                    flags = area.flags
                    if prot & 4:
                        flags = flags | PAGEINFO_R
                    if prot & 2:
                        flags = flags | PAGEINFO_W
                    if prot & 1:
                        flags = flags | PAGEINFO_X

                    if flags & PAGEINFO_X:
                        desc = 'code'
                    else:
                        desc = 'data'
                    load_file(mrenclave, file, offset, baseaddr_ + addr, filesize, memsize,
                              desc, flags)
        else:
            for addr in range(area.addr, area.addr + area.size, offs.PAGESIZE):
                data = ZERO_PAGE
                if area.content is not None:
                    start = addr - area.addr
                    end = start + offs.PAGESIZE
                    data = area.content[start:end]
                    data += b'\0' * (offs.PAGESIZE - len(data)) # pad last page
                include_page(mrenclave, addr, area.flags, data, area.measure)

            if verbose:
                print_area(area.addr, area.size, area.flags, area.desc, area.measure)

    return mrenclave.digest()


def get_mrenclave_and_manifest(manifest_path, libpal, verbose=False):
    with open(manifest_path, 'rb') as f: # pylint: disable=invalid-name
        manifest_data = f.read()
    manifest = Manifest.loads(manifest_data.decode('utf-8'))

    manifest_sgx = manifest['sgx']
    attr = {
        'enclave_size': parse_size(manifest_sgx['enclave_size']),
        'edmm_enable': manifest_sgx.get('edmm_enable', False),
        'max_threads': manifest_sgx['max_threads'],
    }

    if verbose:
        print('Attributes (required for enclave measurement):')
        print(f'    size:        {attr["enclave_size"]:#x}')
        print(f'    edmm:        {attr["edmm_enable"]}')
        print(f'    max_threads: {attr["max_threads"]}')

        print('SGX remote attestation:')
        attestation_type = manifest_sgx.get('remote_attestation', 'none')
        if attestation_type == "none":
            print('    None')
        elif attestation_type == "dcap":
            print('    DCAP/ECDSA')
        elif attestation_type == "epid":
            spid = manifest_sgx.get('ra_client_spid', '')
            linkable = manifest_sgx.get('ra_client_linkable', False)
            print(f'    EPID (spid = `{spid}`, linkable = {linkable})')
        else:
            print('    <unrecognized>')

    # Populate memory areas
    memory_areas = get_memory_areas(attr, libpal)

    enclave_base = offs.DEFAULT_ENCLAVE_BASE
    enclave_heap_min = offs.MMAP_MIN_ADDR

    manifest_data += b'\0' # in-memory manifest needs NULL-termination

    memory_areas = [
        MemoryArea('manifest', content=manifest_data, size=len(manifest_data),
                   flags=PAGEINFO_R | PAGEINFO_REG)
        ] + memory_areas

    memory_areas = populate_memory_areas(attr, memory_areas, enclave_base, enclave_heap_min)

    # Generate measurement
    mrenclave = generate_measurement(enclave_base, attr, memory_areas, verbose=verbose)

    if verbose:
        print('Measurement:')
        print(f'    {mrenclave.hex()}')

    return mrenclave, manifest


def get_tbssigstruct(manifest_path, date, libpal=SGX_LIBPAL, verbose=False):
    """Generate To Be Signed Sigstruct (TBSSIGSTRUCT).

    Generates a Sigstruct object using the provided data with all required fields initialized (i.e.
    all except those corresponding to the signature itself).

    Args:
        manifest_path (str): Path to the manifest file.
        date (date): Date to put into SIGSTRUCT.
        libpal (:obj:`str`, optional): Path to the libpal file.
        verbose (:obj:`bool`, optional): If true, print details to stdout.

    Returns:
        Sigstruct: SIGSTRUCT generated from provided data.
    """

    mrenclave, manifest = get_mrenclave_and_manifest(manifest_path, libpal, verbose=verbose)

    manifest_sgx = manifest['sgx']

    sig = Sigstruct()

    sig['date_year'] = date.year
    sig['date_month'] = date.month
    sig['date_day'] = date.day
    sig['enclave_hash'] = mrenclave
    sig['isv_prod_id'] = manifest_sgx['isvprodid']
    sig['isv_svn'] = manifest_sgx['isvsvn']

    attribute_flags, misc_select, attribute_xfrms, xfrms_mask = get_enclave_attributes(manifest_sgx)
    sig['attribute_flags'] = attribute_flags
    sig['misc_select'] = misc_select
    sig['attribute_xfrms'] = attribute_xfrms
    sig['attribute_xfrm_mask'] = xfrms_mask

    return sig


@click.command(add_help_option=False)
@click.pass_context
@click.help_option('--help-file')
@click.option('--key', '-k', metavar='FILE',
    type=click.File('rb'),
    default=os.fspath(SGX_RSA_KEY_PATH),
    help='specify signing key (.pem) file')
# Explicit 'passphrase' below is for compatibility with click < 6.8 (supported on .el8),
# see https://github.com/pallets/click/issues/793 for more info.
# TODO after deprecating .el8: remove this workaround
@click.option('--passphrase', '--password', '-p', 'passphrase', metavar='PASSPHRASE',
    help='optional passphrase to decrypt the key')
def sign_with_file(ctx, key, passphrase):
    if passphrase is not None:
        passphrase = passphrase.encode()
    try:
        private_key = load_private_key_from_pem_file(key, passphrase)
    except InvalidKeyError as e:
        ctx.fail(str(e))

    return functools.partial(sign_with_private_key, private_key=private_key), [key.name]


class InvalidKeyError(Exception):
    pass


def load_private_key_from_pem_file(file, passphrase=None):
    with file:
        private_key = serialization.load_pem_private_key(
            file.read(), password=passphrase, backend=_cryptography_backend)

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise InvalidKeyError(
            f'Invalid key: expected RSA private key, found {type(private_key).__name__} instance')

    if private_key.key_size != SGX_RSA_KEY_SIZE:
        raise InvalidKeyError(
            f'Invalid RSA key: expected key size {SGX_RSA_KEY_SIZE}, got {private_key.key_size}')

    exponent = private_key.public_key().public_numbers().e

    if exponent != SGX_RSA_PUBLIC_EXPONENT:
        raise InvalidKeyError(
            f'Invalid RSA key: expected exponent {SGX_RSA_PUBLIC_EXPONENT}, got {exponent}')

    return private_key


def sign_with_private_key(data, private_key):
    """Signs *data* using *private_key*.

    Function used to generate an RSA signature over provided data using a 3072-bit private key with
    the public exponent of 3 (hard Intel SGX requirement on the key size and the exponent).
    Suitable to be used as a callback to :py:func:`graminelibos.Sigstruct.sign()`.

    Args:
        data (bytes): Data to calculate the signature over.
        private_key (cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey): RSA private key.

    Returns:
        (int, int, int): Tuple of exponent, modulus and signature respectively.

    See Also:
        :func:`sign_with_private_key_from_pem_file`
            This function also signs *data*, but the key argument is an already
            opened file.
        :func:`sign_with_private_key_from_pem_path`
            This function also signs *data*, but the key argument is path to a file, not a file-like
            object.
    """

    assert private_key.key_size == SGX_RSA_KEY_SIZE
    public_numbers = private_key.public_key().public_numbers()
    assert public_numbers.e == SGX_RSA_PUBLIC_EXPONENT

    # SDM vol. 3D pt. 4 38.13, description of SIGNATURE field:
    #   The (3072-bit integer) SIGNATURE should be an RSA signature, where:
    #   a) the RSA modulus (MODULUS) is a 3072-bit integer;
    #   b) the public exponent is set to 3;
    #   c) the signing procedure uses the EMSA-PKCS1-v1.5 format with DER encoding of the
    #      “DigestInfo” value as specified in of PKCS#1 v2.1/RFC 3447.
    # also see IACR 2016/086: section 6.5 and figure 76
    signature = private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())

    return public_numbers.e, public_numbers.n, int.from_bytes(signature, byteorder='big')


def sign_with_private_key_from_pem_file(data, file, passphrase=None):
    """Signs *data* using key loaded from *file*.

    Function used to generate an RSA signature over provided data using a 3072-bit private key with
    the public exponent of 3 (hard Intel SGX requirement on the key size and the exponent).
    Suitable to be used as a callback to :py:func:`graminelibos.Sigstruct.sign()`.

    Args:
        data (bytes): Data to calculate the signature over.
        file (file-like): File-like object, from which one can read RSA private key.
        passphrase (bytes or None): Optional passphrase.

    Returns:
        (int, int, int): Tuple of exponent, modulus and signature respectively.

    See Also:
        :func:`sign_with_private_key`
            This function also signs *data*, but the key argument is
            :class:`cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey` instance.
        :func:`sign_with_private_key_from_pem_path`
            This function also signs *data*, but the key argument is path to a file, not a file-like
            object.
    """
    return sign_with_private_key(data, load_private_key_from_pem_file(file, passphrase))


def sign_with_private_key_from_pem_path(data, path, passphrase=None):
    """Signs *data* using key loaded from *path*.

    Function used to generate an RSA signature over provided data using a 3072-bit private key with
    the public exponent of 3 (hard Intel SGX requirement on the key size and the exponent).
    Suitable to be used as a callback to :py:func:`graminelibos.Sigstruct.sign()`.

    Args:
        data (bytes): Data to calculate the signature over.
        path (path-like): Path to a file with RSA private key.
        passphrase (bytes or None): Optional passphrase.

    Returns:
        (int, int, int): Tuple of exponent, modulus and signature respectively.

    See Also:
        :func:`sign_with_private_key`
            This function also signs *data*, but the key argument is
            :class:`cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey` instance.
        :func:`sign_with_private_key_from_pem_file`
            This function also signs *data*, but the key argument is an already
            opened file.
    """

    with open(path, 'rb') as file:
        return sign_with_private_key_from_pem_file(data, file, passphrase)


# NOTE: the name and argument name of this function is kept for compatibility, *key* is path to
# a PEM-encoded file, not a key object from cryptography module
def sign_with_local_key(data, key):
    return sign_with_private_key_from_pem_path(data, key)


def generate_private_key():
    """Generate RSA key suitable for use with SGX.

    Returns:
        cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey: private key
    """
    return rsa.generate_private_key(
        public_exponent=SGX_RSA_PUBLIC_EXPONENT,
        key_size=SGX_RSA_KEY_SIZE,
        backend=_cryptography_backend)


def generate_private_key_pem():
    """Generate PEM-encoded RSA key suitable for use with SGX.

    Returns:
        bytes: PEM-encoded private key
    """
    return generate_private_key().private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption())
