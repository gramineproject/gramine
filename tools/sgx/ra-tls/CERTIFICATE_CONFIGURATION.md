# RA-TLS Certificate Generation Configuration Guide

This document describes how to configure RA-TLS certificate generation using environment variables and JSON configuration.

## Table of Contents

1. [Overview](#overview)
2. [Configuration Priority](#configuration-priority)
3. [Environment Variables](#environment-variables)
4. [JSON Configuration](#json-configuration)
5. [Certificate Types](#certificate-types)
6. [CA Certificate Support](#ca-certificate-support)
7. [Examples](#examples)
8. [Supported Algorithms](#supported-algorithms)

## Overview

RA-TLS (Remote Attestation TLS) certificate generation can be controlled through environment variables and JSON configuration. This allows you to customize:

- Key generation algorithms
- Certificate subject and validity period
- Signature algorithms
- CA certificate usage for certificate signing
- Certificate attributes (e.g., marking as CA certificate)

## Configuration Priority

Configuration is applied in the following priority order (highest to lowest):

1. **RA_TLS_CERT_ALGORITHM** environment variable (if set, JSON config is ignored)
2. **RA_TLS_CERT_CONFIG_B64** environment variable (base64-encoded JSON)
3. **Default values** (ECDSA with NIST P-384 curve)

## Environment Variables

### Simple Configuration

#### RA_TLS_CERT_ALGORITHM

Specifies the key generation algorithm. When set, all other configuration is ignored.

**Supported values:**
- `secp256r1` - ECDSA with NIST P-256 curve
- `secp384r1` - ECDSA with NIST P-384 curve (default)
- `secp521r1` - ECDSA with NIST P-521 curve
- `secp256k1` - ECDSA with secp256k1 curve
- `rsa2048` - RSA with 2048-bit key
- `rsa3072` - RSA with 3072-bit key
- `rsa4096` - RSA with 4096-bit key

**Example:**
```bash
export RA_TLS_CERT_ALGORITHM="secp256r1"
```

#### RA_TLS_CERT_TIMESTAMP_NOT_BEFORE

Certificate validity start time in format: `YYYYMMDDhhmmss`

**Default:** `20010101000000`

**Example:**
```bash
export RA_TLS_CERT_TIMESTAMP_NOT_BEFORE="20240101000000"
```

#### RA_TLS_CERT_TIMESTAMP_NOT_AFTER

Certificate validity end time in format: `YYYYMMDDhhmmss`

**Default:** `20301231235959`

**Example:**
```bash
export RA_TLS_CERT_TIMESTAMP_NOT_AFTER="20341231235959"
```

### Advanced Configuration

#### RA_TLS_CERT_CONFIG_B64

Base64-encoded JSON configuration for advanced certificate generation options.

**Example:**
```bash
export RA_TLS_CERT_CONFIG_B64=$(echo '{"algorithm":"secp256r1","subject":"CN=MyServer,O=MyOrg"}' | base64 -w 0)
```

## JSON Configuration

The JSON configuration (passed via `RA_TLS_CERT_CONFIG_B64`) supports the following fields:

### Key Configuration

| Field | Type | Description | Default |
|-------|------|-------------|---------|
| `key_file` | string | Path to existing private key file | Generate new key |
| `key_format` | string | Key file format: `"pem"` or `"der"` | `"pem"` |
| `algorithm` | string | Key generation algorithm (see list above) | `"secp384r1"` |

### Certificate Configuration

| Field | Type | Description | Default |
|-------|------|-------------|---------|
| `subject` | string | Certificate subject DN | `"CN=RATLS,O=GramineDevelopers,C=US"` |
| `not_before` | string | Validity start (YYYYMMDDhhmmss) | `"20010101000000"` |
| `not_after` | string | Validity end (YYYYMMDDhhmmss) | `"20301231235959"` |
| `signature_md` | string | Signature hash: `"sha256"`, `"sha384"`, `"sha512"` | `"sha256"` |
| `is_ca` | boolean | Mark certificate as CA certificate | `false` |

### CA Certificate Configuration

| Field | Type | Description | Default |
|-------|------|-------------|---------|
| `ca_key_file` | string | Path to CA private key file | None (self-signed) |
| `ca_key_format` | string | CA key format: `"pem"` or `"der"` | `"pem"` |
| `ca_cert_file` | string | Path to existing CA certificate file | None (generate if ca_key provided) |
| `ca_cert_format` | string | CA cert format: `"pem"` or `"der"` | `"pem"` |
| `ca_subject` | string | CA certificate subject DN | None |
| `ca_not_before` | string | CA validity start (YYYYMMDDhhmmss) | `"20010101000000"` |
| `ca_not_after` | string | CA validity end (YYYYMMDDhhmmss) | `"20301231235959"` |

## Certificate Types

### Self-Signed Certificate (Default)

When no CA configuration is provided, a self-signed certificate is generated.

**Characteristics:**
- Subject DN = Issuer DN
- Signed with the certificate's own private key
- No certificate chain

**Example:**
```bash
# Generate self-signed certificate with default settings
./my_app
```

### CA-Signed Certificate

When CA private key is provided, the certificate is signed by the CA.

**Characteristics:**
- Subject DN ≠ Issuer DN
- Signed with CA's private key
- Forms certificate chain with CA certificate
- CA certificate output to `ca.crt` (if generated)

## CA Certificate Support

### Three CA Usage Scenarios

#### Scenario 1: No CA (Self-Signed)

**Configuration:** Do not provide `ca_key_file`

**Result:** Self-signed certificate

**Example:**
```json
{
  "algorithm": "secp256r1",
  "subject": "CN=MyServer,O=MyOrg"
}
```

#### Scenario 2: Load Existing CA Certificate

**Configuration:** Provide both `ca_key_file` and `ca_cert_file`

**Process:**
1. Load CA certificate from file
2. Verify CA certificate matches CA private key
3. Verify CA certificate has CA attributes (CA:TRUE, KEY_CERT_SIGN)
4. Use CA to sign the RA-TLS certificate

**Example:**
```json
{
  "algorithm": "secp256r1",
  "subject": "CN=MyServer,O=MyOrg",
  "ca_key_file": "/path/to/ca-key.pem",
  "ca_cert_file": "/path/to/ca-cert.pem"
}
```

#### Scenario 3: Generate CA Certificate

**Configuration:** Provide `ca_key_file` and `ca_subject` (without `ca_cert_file`)

**Process:**
1. Generate CA certificate based on configuration
2. Mark CA certificate with CA:TRUE and KEY_CERT_SIGN
3. Use CA to sign the RA-TLS certificate
4. Output CA certificate to `ca.crt` file

**Example:**
```json
{
  "algorithm": "secp256r1",
  "subject": "CN=MyServer,O=MyOrg",
  "ca_key_file": "/path/to/ca-key.pem",
  "ca_subject": "CN=MyCA,O=MyOrg"
}
```

### Priority When Both ca_cert_file and ca_subject Are Provided

If both `ca_cert_file` and `ca_subject` are provided, **loading existing CA certificate takes priority** over generating a new one.

### Certificate Chain Formation

When a CA is used (Scenarios 2 or 3), the generated certificate forms a chain:

```
[User Certificate] -> [CA Certificate] -> NULL
```

**Certificate Chain Details:**
- User certificate contains:
  - User's public key
  - Issuer DN (matches CA's Subject DN)
  - Authority Key Identifier (AKI) pointing to CA
  - Signature created by CA's private key
- CA certificate is linked via `crt->next` in memory
- TLS handshake sends both certificates sequentially

**Client Verification:**
1. Match user cert's Issuer DN with CA cert's Subject DN
2. Verify user cert's AKI matches CA cert's SKI
3. Verify user cert's signature using CA's public key

## Examples

### Example 1: Simple Self-Signed Certificate

```bash
# Use default algorithm (secp384r1)
./my_app
```

### Example 2: Specify Algorithm via Environment Variable

```bash
export RA_TLS_CERT_ALGORITHM="secp256r1"
./my_app
```

### Example 3: Custom Subject and Validity

```bash
export RA_TLS_CERT_CONFIG_B64=$(echo '{
  "algorithm": "secp256r1",
  "subject": "CN=MyServer,O=MyOrganization,C=US",
  "not_before": "20240101000000",
  "not_after": "20341231235959"
}' | base64 -w 0)
./my_app
```

### Example 4: Load Existing Private Key

```bash
export RA_TLS_CERT_CONFIG_B64=$(echo '{
  "key_file": "/path/to/existing-key.pem",
  "key_format": "pem",
  "subject": "CN=MyServer,O=MyOrg"
}' | base64 -w 0)
./my_app
```

### Example 5: CA-Signed Certificate (Load Existing CA)

```bash
export RA_TLS_CERT_CONFIG_B64=$(echo '{
  "algorithm": "secp256r1",
  "subject": "CN=MyServer,O=MyOrg",
  "signature_md": "sha256",
  "ca_key_file": "/path/to/ca-key.pem",
  "ca_cert_file": "/path/to/ca-cert.pem"
}' | base64 -w 0)
./my_app
```

**Result:**
- User certificate signed by CA
- Certificate chain: User cert -> CA cert
- CA certificate loaded from file

### Example 6: CA-Signed Certificate (Generate CA)

```bash
export RA_TLS_CERT_CONFIG_B64=$(echo '{
  "algorithm": "secp256r1",
  "subject": "CN=MyServer,O=MyOrg",
  "signature_md": "sha256",
  "ca_key_file": "/path/to/ca-key.pem",
  "ca_subject": "CN=MyCA,O=MyOrg",
  "ca_not_before": "20240101000000",
  "ca_not_after": "20441231235959"
}' | base64 -w 0)
./my_app
```

**Result:**
- CA certificate generated and saved to `ca.crt`
- User certificate signed by generated CA
- Certificate chain: User cert -> CA cert

### Example 7: Generate CA Certificate

```bash
export RA_TLS_CERT_CONFIG_B64=$(echo '{
  "algorithm": "secp384r1",
  "subject": "CN=MyCA,O=MyOrganization,C=US",
  "is_ca": true,
  "ca_key_file": "/path/to/ca-key.pem",
  "ca_subject": "CN=MyCA,O=MyOrganization,C=US"
}' | base64 -w 0)
./my_app
```

**Result:**
- Certificate marked as CA (CA:TRUE)
- Can be used to sign other certificates

### Example 8: RSA Certificate with SHA-384

```bash
export RA_TLS_CERT_CONFIG_B64=$(echo '{
  "algorithm": "rsa3072",
  "signature_md": "sha384",
  "subject": "CN=MyServer,O=MyOrg"
}' | base64 -w 0)
./my_app
```

### Example 9: DER Format Key and Certificate

```bash
export RA_TLS_CERT_CONFIG_B64=$(echo '{
  "key_file": "/path/to/key.der",
  "key_format": "der",
  "subject": "CN=MyServer,O=MyOrg"
}' | base64 -w 0)
./my_app
```

## Supported Algorithms

### Elliptic Curve Algorithms

| Algorithm | Description | Key Size | Security Level |
|-----------|-------------|----------|----------------|
| `secp256r1` | NIST P-256 | 256-bit | 128-bit |
| `secp384r1` | NIST P-384 (default) | 384-bit | 192-bit |
| `secp521r1` | NIST P-521 | 521-bit | 256-bit |
| `secp256k1` | Bitcoin curve | 256-bit | 128-bit |

### RSA Algorithms

| Algorithm | Description | Key Size | Security Level |
|-----------|-------------|----------|----------------|
| `rsa2048` | RSA 2048-bit | 2048-bit | 112-bit |
| `rsa3072` | RSA 3072-bit | 3072-bit | 128-bit |
| `rsa4096` | RSA 4096-bit | 4096-bit | 152-bit |

### Signature Hash Algorithms

| Algorithm | Output Size | Security Level |
|-----------|-------------|----------------|
| `sha256` | 256-bit | 128-bit |
| `sha384` | 384-bit | 192-bit |
| `sha512` | 512-bit | 256-bit |

## Certificate Structure

### Self-Signed Certificate

```
Certificate:
  Subject: CN=MyServer,O=MyOrg
  Issuer: CN=MyServer,O=MyOrg (same as Subject)
  Public Key: [User's public key]
  Extensions:
    - Subject Key Identifier (SKI)
    - Authority Key Identifier (AKI) - points to self
    - SGX Quote (RA-TLS specific)
  Signature: [Signed with user's private key]
```

### CA-Signed Certificate

```
User Certificate:
  Subject: CN=MyServer,O=MyOrg
  Issuer: CN=MyCA,O=MyOrg (CA's Subject)
  Public Key: [User's public key]
  Extensions:
    - Subject Key Identifier (SKI)
    - Authority Key Identifier (AKI) - points to CA
    - SGX Quote (RA-TLS specific)
  Signature: [Signed with CA's private key]

CA Certificate (linked via crt->next):
  Subject: CN=MyCA,O=MyOrg
  Issuer: CN=MyCA,O=MyOrg (self-signed)
  Public Key: [CA's public key]
  Extensions:
    - Subject Key Identifier (SKI)
    - Authority Key Identifier (AKI) - points to self
    - Basic Constraints: CA:TRUE
    - Key Usage: KEY_CERT_SIGN, CRL_SIGN
  Signature: [Signed with CA's private key]
```

## Output Files

### Generated Certificate Files

- **User Certificate**: Returned via `ra_tls_create_key_and_crt_der()` in DER format
- **User Private Key**: Returned via `ra_tls_create_key_and_crt_der()` in DER format
- **CA Certificate**: Written to `ca.crt` (DER format) when CA is generated (Scenario 3)

### CA Certificate Output

The CA certificate is only written to `ca.crt` when:
- `ca_key_file` is provided
- `ca_cert_file` is NOT provided (CA is generated, not loaded)

This allows clients to install or distribute the CA certificate for trust verification.

## Security Considerations

### Private Key Protection

- Private keys should be stored securely with appropriate file permissions
- Never commit private keys to version control
- Use hardware security modules (HSMs) for production CA keys

### CA Certificate Verification

When loading an existing CA certificate, the system verifies:
1. CA certificate has `CA:TRUE` in Basic Constraints
2. CA certificate has `KEY_CERT_SIGN` in Key Usage
3. CA certificate's public key matches the provided CA private key

### Certificate Validity Period

- Choose appropriate validity periods based on your security policy
- Shorter validity periods reduce risk but require more frequent renewal
- CA certificates typically have longer validity than end-entity certificates

### Algorithm Selection

- ECDSA algorithms provide better performance than RSA
- Use at least 128-bit security level for production (secp256r1, rsa3072, or higher)
- Match signature hash algorithm strength to key algorithm strength

## Troubleshooting

### Common Issues

**Issue:** Certificate generation fails with "CA verification failed"

**Solution:** Ensure CA certificate file matches the CA private key and has proper CA attributes.

**Issue:** TLS handshake fails with "certificate chain incomplete"

**Solution:** Ensure CA certificate is properly linked and sent during TLS handshake.

**Issue:** Client cannot verify certificate

**Solution:** Ensure client has CA certificate installed in trust store (for CA-signed certificates).

## API Reference

### C API

```c
int ra_tls_create_key_and_crt_der(uint8_t** der_key, size_t* der_key_size,
                                  uint8_t** der_crt, size_t* der_crt_size);
```

Generates RA-TLS certificate and private key based on environment variable configuration.

**Returns:** 0 on success, negative error code on failure

**Output:**
- `der_key`: Private key in DER format (caller must free)
- `der_crt`: Certificate in DER format (caller must free)

### Environment Variables Used

- `RA_TLS_CERT_ALGORITHM` (highest priority)
- `RA_TLS_CERT_CONFIG_B64` (JSON configuration)
- `RA_TLS_CERT_TIMESTAMP_NOT_BEFORE` (fallback for validity start)
- `RA_TLS_CERT_TIMESTAMP_NOT_AFTER` (fallback for validity end)

## Additional Resources

- [Gramine RA-TLS Documentation](https://gramine.readthedocs.io/en/latest/attestation.html)
- [X.509 Certificate Standard](https://www.rfc-editor.org/rfc/rfc5280)
- [mbedTLS Documentation](https://mbed-tls.readthedocs.io/)

## Version History

- **v1.0** (2024): Initial CA certificate support with certificate chain formation
- **v0.9** (2024): Added `is_ca` configuration support
- **v0.8** (2024): Added configurable signature algorithms
- **v0.7** (2024): Initial JSON configuration support
