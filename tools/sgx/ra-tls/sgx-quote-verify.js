// sgx-quote-verifier.js
// 支持Web和Node.js环境的SGX Quote验证库

// 环境检测和依赖导入
const isBrowser = typeof window !== 'undefined';

// 第三方库导入
if (isBrowser) {
} else {
    // Node.js环境
    global.forge = require('node-forge');
    global.cbor = require('cbor');
    global.elliptic = require('elliptic');
    try {
        if (typeof fetch === 'undefined') {
            global.nodeFetch = require('node-fetch');
        }
    } catch (e) {
        console.log(e);
    }
}

const fetchFunc = isBrowser ? window.fetch : (typeof fetch !== 'undefined' ? fetch : nodeFetch);


const ByteUtils = {
    /**
     * 将各种输入转换为字节数组（Node中为Buffer，浏览器中为Uint8Array）
     */
    toBytes(input) {
        if (isBrowser) {
            if (input instanceof Uint8Array) return input;
            if (input instanceof ArrayBuffer) return new Uint8Array(input);
            if (typeof input === 'string') {
                const bytes = new Uint8Array(input.length);
                for (let i = 0; i < input.length; i++) {
                    bytes[i] = input.charCodeAt(i);
                }
                return bytes;
            }
            if (Array.isArray(input)) return new Uint8Array(input);
            throw new Error('Cannot convert to bytes');
        } else {
            if (Buffer.isBuffer(input)) return input;
            if (input instanceof Uint8Array) return Buffer.from(input);
            if (input instanceof ArrayBuffer) return Buffer.from(input);
            if (typeof input === 'string') return Buffer.from(input, 'binary');
            if (Array.isArray(input)) return Buffer.from(input);
            throw new Error('Cannot convert to bytes');
        }
    },

    /**
     * 从Base64字符串创建字节数组
     */
    fromBase64(base64Str) {
        if (isBrowser) {
            const binaryStr = atob(base64Str);
            const bytes = new Uint8Array(binaryStr.length);
            for (let i = 0; i < binaryStr.length; i++) {
                bytes[i] = binaryStr.charCodeAt(i);
            }
            return bytes;
        } else {
            return Buffer.from(base64Str, 'base64');
        }
    },

    /**
     * 转换为Base64字符串
     */
    toBase64(bytes) {
        if (isBrowser) {
            const binaryStr = this.toBinaryString(bytes);
            return btoa(binaryStr);
        } else {
            return Buffer.from(bytes).toString('base64');
        }
    },

    /**
     * 转换为十六进制字符串
     */
    toHex(bytes) {
        return Array.from(bytes)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    },

    /**
     * 从十六进制字符串创建字节数组
     */
    fromHex(hex) {
        const bytes = [];
        for (let i = 0; i < hex.length; i += 2) {
            bytes.push(parseInt(hex.slice(i, i + 2), 16));
        }
        return this.toBytes(bytes);
    },

    /**
     * 比较两个字节数组是否相等
     */
    equalBytes(a, b) {
        if (a.length !== b.length) return false;
        for (let i = 0; i < a.length; i++) {
            if (a[i] !== b[i]) return false;
        }
        return true;
    },

    /**
     * 切片操作
     */
    slice(bytes, start, end) {
        return bytes.slice(start, end);
    },

    /**
     * 创建DataView
     */
    dataView(bytes) {
        if (bytes.buffer) {
            return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
        }
        throw new Error('Cannot create DataView from input');
    },

    /**
     * 连接多个字节数组
     */
    concat(arrays) {
        const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
        if (isBrowser) {
            const result = new Uint8Array(totalLength);
            let offset = 0;
            for (const arr of arrays) {
                result.set(arr, offset);
                offset += arr.length;
            }
            return result;
        } else {
            return Buffer.concat(arrays);
        }
    },

    /**
     * 转换为二进制字符串（用于node-forge）
     */
    toBinaryString(bytes) {
        return Array.from(bytes)
            .map(b => String.fromCharCode(b))
            .join('');
    },

    /**
     * 从node-forge的二进制字符串转换
     */
    fromBinaryString(binaryStr) {
        const bytes = new Uint8Array(binaryStr.length);
        for (let i = 0; i < binaryStr.length; i++) {
            bytes[i] = binaryStr.charCodeAt(i);
        }
        return this.toBytes(bytes);
    }
};

// 常量定义 (基于sgx_attest.h)
const SGX_QUOTE_MAX_SIZE = 8192;
const SGX_REPORT_BODY_SIZE = 384;

// OID定义 (基于ra_tls_common.h)
const TCG_DICE_TAGGED_EVIDENCE_OID = '2.23.133.5.4.9';
const NON_STANDARD_INTEL_SGX_QUOTE_OID = '1.2.840.113741.1.13.1';
const LEGACY_QUOTE_OID_V1 = '0.6.9.42.840.113741.1337.6';
const LEGACY_QUOTE_OID = NON_STANDARD_INTEL_SGX_QUOTE_OID;
const TCG_DICE_TAGGED_EVIDENCE_CBOR_TAG = 60000;

// Quote验证结果枚举 (基于ra_tls_verify_dcap.c)
const SGX_QL_QV_RESULT = {
    OK: 0x0000,
    CONFIG_NEEDED: 0x0000A001,
    OUT_OF_DATE: 0x0000A002,
    OUT_OF_DATE_CONFIG_NEEDED: 0x0000A003,
    INVALID_SIGNATURE: 0x0000A004,
    REVOKED: 0x0000A005,
    UNSPECIFIED: 0x0000A006,
    SW_HARDENING_NEEDED: 0x0000A007,
    CONFIG_AND_SW_HARDENING_NEEDED: 0x0000A008
};

const INTEL_SGX_ROOT_CA_CERTS = {
    G1: `-----BEGIN CERTIFICATE-----
MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw
aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ
BgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG
A1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0
aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT
AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7
1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB
uzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ
MEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50
ZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV
Ur9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI
KoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg
AiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=
-----END CERTIFICATE-----`
};
INTEL_SGX_ROOT_CA_CERTS.G3=INTEL_SGX_ROOT_CA_CERTS.G1;
INTEL_SGX_ROOT_CA_CERTS.G4=INTEL_SGX_ROOT_CA_CERTS.G1;

function setFetchFunction(customFetch) {
    globalThis.fetch = customFetch;
}

/**
 * 主验证函数
 * @param {string|Buffer|Uint8Array} input - RA-TLS证书(PEM/DER)或base64编码的quote
 * @param {Object} options - 配置选项
 * @param {string} options.apiKey - Intel DCAP API密钥
 * @param {string} options.pccsUrl - PCCS服务地址(默认Intel官方)
 * @param {Function} options.cacheRead - 证书缓存读取回调 async (key) => data
 * @param {Function} options.cacheWrite - 证书缓存写入回调 async (key, data) => void
 * @param {boolean} options.allowOutdatedTcb - 允许过期TCB
 * @param {boolean} options.allowDebugEnclave - 允许调试enclave
 * @param {Array<string>} options.trustedRootCAs - 可信的根证书PEM数组（可选，默认使用所有Intel SGX Root CAs）
 * @param {string} options.expectedMrEnclave - 期望的MRENCLAVE值（十六进制字符串，可选）
 * @param {string} options.expectedMrSigner - 期望的MRSIGNER值（十六进制字符串，可选）
 * @param {number} options.expectedIsvProdId - 期望的ISV_PROD_ID值（可选）
 * @param {number} options.expectedIsvSvn - 期望的最小ISV_SVN值（可选）
 * @returns {Promise<Object>} 验证结果
 */
async function verifyQuote(input, options = {}) {
    const {
        apiKey,
        pccsUrl = 'https://api.trustedservices.intel.com/sgx/certification/v4',
        cacheRead = async (key) => isBrowser?localStorage.getItem(key):null,
        cacheWrite = async (key,data) => isBrowser?localStorage.setItem(key,typeof data===typeof""?data:JSON.stringify(data)):null,
        allowOutdatedTcb = false,
        allowDebugEnclave = false,
        allowHwConfigNeeded = false,
        allowSwHardeningNeeded = false,
        trustedRootCAs = null,
        expectedMrEnclave = null,
        expectedMrSigner = null,
        expectedIsvProdId = null,
        expectedIsvSvn = null
    } = options;

    const verificationDetails = {
        quoteExtraction: { verified: false, error: null },
        quoteStructureParsing: { verified: false, error: null },
        collateralFetch: { verified: false, error: null },
        tcbInfoSignature: { verified: false, error: null },
        qeIdentitySignature: { verified: false, error: null },
        certChainSignatures: { verified: false, error: null },
        certChainRevocation: { verified: false, error: null, details: null },
        raTlsBinding: { verified: false, error: null, skipped: false },
        quoteSignature: { verified: false, error: null },
        qeReportDataBinding: { verified: false, error: null },
        qeReportSignature: { verified: false, error: null },
        qeIdentityMatch: { verified: false, error: null },
        enclaveAttributes: { verified: false, error: null },
        tcbLevel: { verified: false, error: null, status: null },
        measurementPolicy: { verified: false, error: null }
    };

    let quoteData = null;
    let collateral = null;
    let tcbStatus = null;

    try {
        const { quote, quoteSize, certPem, claims } = await extractQuote(input);
        verificationDetails.quoteExtraction.verified = true;

        quoteData = parseQuoteStructure(quote);
        if (claims) {
            quoteData.claims = claims;
        }
        verificationDetails.quoteStructureParsing.verified = true;
        
        console.log('Quote parsed successfully - version:', quoteData.version, 'attestation key type:', quoteData.attestationKeyType);
        console.log('Certificate chain length:', quoteData.certChain ? quoteData.certChain.length : 0);

        collateral = await fetchCollateral(
            quoteData,
            pccsUrl,
            apiKey,
            cacheRead,
            cacheWrite
        );
        verificationDetails.collateralFetch.verified = true;

        try {
            await verifyCertChain(quoteData.certChain, collateral, trustedRootCAs);
            verificationDetails.certChainSignatures.verified = true;
            verificationDetails.certChainRevocation.verified = true;
            verificationDetails.tcbInfoSignature.verified = true;
            verificationDetails.qeIdentitySignature.verified = true;
        } catch (error) {
            verificationDetails.certChainSignatures.error = error.message;
            throw error;
        }

        if (certPem) {
            try {
                await verifyRaTlsBinding(certPem, quoteData);
                verificationDetails.raTlsBinding.verified = true;
            } catch (error) {
                verificationDetails.raTlsBinding.error = error.message;
                //throw error;
            }
        } else {
            verificationDetails.raTlsBinding.skipped = true;
        }

        try {
            tcbStatus = await verifyTCB(quoteData, collateral.tcbInfo);
            verificationDetails.tcbLevel.verified = true;
            verificationDetails.tcbLevel.status = tcbStatusToString(tcbStatus);
        } catch (error) {
            verificationDetails.tcbLevel.error = error.message;
            //throw error;
        }

        try {
            await verifyQuoteSignature(quoteData, collateral);
            verificationDetails.quoteSignature.verified = true;
            verificationDetails.qeReportDataBinding.verified = true;
            verificationDetails.qeReportSignature.verified = true;
            verificationDetails.qeIdentityMatch.verified = true;
        } catch (error) {
            verificationDetails.quoteSignature.error = error.message;
            //throw error;
        }

        try {
            verifyEnclaveAttributes(quoteData, allowDebugEnclave);
            verificationDetails.enclaveAttributes.verified = true;
        } catch (error) {
            verificationDetails.enclaveAttributes.error = error.message;
            //throw error;
        }

        const verificationResult = evaluateTcbStatus(
            tcbStatus,
            allowOutdatedTcb,
            allowHwConfigNeeded,
            allowSwHardeningNeeded
        );

        try {
            verifyMeasurementPolicy(quoteData, {
                expectedMrEnclave,
                expectedMrSigner,
                expectedIsvProdId,
                expectedIsvSvn
            });
            verificationDetails.measurementPolicy.verified = true;
        } catch (error) {
            verificationDetails.measurementPolicy.error = error.message;
            //throw error;
        }

        return {
            verified: true,
            verificationResult,
            verificationDetails,
            measurements: {
                mrenclave: ByteUtils.toHex(quoteData.mrenclave),
                mrsigner: ByteUtils.toHex(quoteData.mrsigner),
                isvProdId: quoteData.isvProdId,
                isvSvn: quoteData.isvSvn,
                attributes: ByteUtils.toHex(quoteData.attributes),
                attributesParsed: parseAttributes(quoteData.attributes),
                reportData: ByteUtils.toHex(quoteData.reportData)
            },
            tcbStatus: tcbStatusToString(tcbStatus),
            quoteVersion: quoteData.version,
            attestationKeyType: quoteData.attestationKeyType
        };
    } catch (error) {
        return {
            verified: false,
            error: error.message,
            stack: error.stack,
            verificationDetails,
            measurements: quoteData ? {
                mrenclave: ByteUtils.toHex(quoteData.mrenclave),
                mrsigner: ByteUtils.toHex(quoteData.mrsigner),
                isvProdId: quoteData.isvProdId,
                isvSvn: quoteData.isvSvn,
                attributes: quoteData.attributes,
                attributesParsed: parseAttributes(quoteData.attributes),
                reportData: ByteUtils.toHex(quoteData.reportData)
            } : null,
            tcbStatus: tcbStatus ? tcbStatusToString(tcbStatus) : null,
            quoteVersion: quoteData ? quoteData.version : null,
            attestationKeyType: quoteData ? quoteData.attestationKeyType : null
        };
    }
}

/**
 * 从证书或原始数据提取Quote
 * 基于ra_tls_verify_common.c:534-549
 */
async function extractQuote(input) {
    if (typeof input === 'string') {
        if (input.includes('-----BEGIN CERTIFICATE-----')) {
            const certChain = parsePemCertChain(input);
            for (const certPem of certChain) {
                try {
                    const result = extractQuoteFromCert(certPem);
                    return { ...result, certPem: certPem };
                } catch (error) {
                    continue;
                }
            }
            throw new Error('No certificate in the chain contains an RA-TLS quote extension');
        } else {
            const quote = ByteUtils.fromBase64(input);
            return { quote, quoteSize: quote.length, certPem: null };
        }
    } else if (input instanceof Uint8Array || (typeof Buffer !== 'undefined' && Buffer.isBuffer(input))) {
        try {
            const inputBytes = ByteUtils.toBytes(input);
            const binaryStr = ByteUtils.toBinaryString(inputBytes);
            const cert = forge.pki.certificateFromAsn1(
                forge.asn1.fromDer(forge.util.createBuffer(binaryStr))
            );
            return { ...extractQuoteFromParsedCert(cert), certPem: null };
        } catch {
            return { quote: ByteUtils.toBytes(input), quoteSize: input.length, certPem: null };
        }
    }

    throw new Error('Unsupported input format');
}

/**
 * 最小化DER TLV读取器 - 直接提取证书扩展（支持ECDSA证书）
 * node-forge的certificateFromPem对ECDSA证书支持有限，会抛出"OID is not RSA"错误
 * 这个函数使用最小化的DER解析来提取扩展，绕过完整的证书解析
 */
function getExtensionFromPemViaAsn1(pemCert, targetOid) {
    try {
        const pemMatch = pemCert.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/);
        if (!pemMatch) {
            throw new Error('No valid PEM certificate found');
        }

        const base64 = pemMatch[0]
            .replace(/-----BEGIN CERTIFICATE-----/, '')
            .replace(/-----END CERTIFICATE-----/, '')
            .replace(/\s/g, '');

        const derBuffer = ByteUtils.fromBase64(base64);

        const targetOidBytes = oidToBytes(targetOid);

        let extValue = extractExtensionByOid(derBuffer, targetOidBytes);

        if (extValue) {
            return extValue;
        }

        if (targetOid.startsWith('1.2.840.113741.1.13.1.')) {
            const sgxOidBytes = oidToBytes('1.2.840.113741.1.13.1');
            const sgxExtValue = extractExtensionByOid(derBuffer, sgxOidBytes);
            if (sgxExtValue) {
                extValue = extractSubExtensionByOid(sgxExtValue, targetOidBytes);
                return extValue;
            }
        }

        return null;
    } catch (error) {
        throw new Error(`Failed to extract extension via DER parsing: ${error.message}`);
    }
}

function extractSubExtensionByOid(extValueBytes, targetOidBytes) {
    const derBuffer = ByteUtils.toBytes(extValueBytes);
    let pos = 0;

    if (derBuffer[pos] !== 0x30) {
        return null;
    }
    pos++;

    let seqLength = derBuffer[pos++];
    if (seqLength & 0x80) {
        const numBytes = seqLength & 0x7f;
        seqLength = 0;
        for (let i = 0; i < numBytes; i++) {
            seqLength = (seqLength << 8) | derBuffer[pos++];
        }
    }

    const seqEnd = pos + seqLength;

    while (pos < seqEnd) {
        if (derBuffer[pos] !== 0x30) {
            break;
        }
        pos++;

        let subExtLength = derBuffer[pos++];
        if (subExtLength & 0x80) {
            const numBytes = subExtLength & 0x7f;
            subExtLength = 0;
            for (let i = 0; i < numBytes; i++) {
                subExtLength = (subExtLength << 8) | derBuffer[pos++];
            }
        }

        const subExtEnd = pos + subExtLength;

        if (derBuffer[pos] !== 0x06) {
            pos = subExtEnd;
            continue;
        }

        const oidTag = derBuffer[pos++];
        const oidLength = derBuffer[pos++];
        const oidBytes = new Uint8Array([oidTag, oidLength, ...derBuffer.slice(pos, pos + oidLength)]);
        pos += oidLength;

        let matches = true;
        if (oidBytes.length !== targetOidBytes.length) {
            matches = false;
        } else {
            for (let i = 0; i < oidBytes.length; i++) {
                if (oidBytes[i] !== targetOidBytes[i]) {
                    matches = false;
                    break;
                }
            }
        }

        if (matches) {
            if (pos < subExtEnd && derBuffer[pos] === 0x04) {
                pos++;
                const valueLength = derBuffer[pos++];
                const valueBytes = derBuffer.slice(pos, pos + valueLength);
                return ByteUtils.toBytes(valueBytes);
            }
        }

        pos = subExtEnd;
    }

    return null;
}

/**
 * 将OID字符串转换为DER编码字节
 */
function oidToBytes(oid) {
    const parts = oid.split('.').map(Number);
    if (parts.length < 2) {
        throw new Error('Invalid OID format');
    }

    const bytes = [parts[0] * 40 + parts[1]];

    for (let i = 2; i < parts.length; i++) {
        let value = parts[i];
        if (value === 0) {
            bytes.push(0);
            continue;
        }

        const encoded = [];
        while (value > 0) {
            encoded.unshift((value & 0x7F) | (encoded.length > 0 ? 0x80 : 0));
            value >>= 7;
        }
        bytes.push(...encoded);
    }

    return new Uint8Array([0x06, bytes.length, ...bytes]);
}

/**
 * 从DER编码的证书中提取指定OID的扩展值
 */
function extractExtensionByOid(derBuffer, targetOidBytes) {
    let pos = 0;

    const readLength = () => {
        if (pos >= derBuffer.length) {
            throw new Error('Unexpected end of DER data');
        }

        const first = derBuffer[pos++];
        if ((first & 0x80) === 0) {
            return first;
        }

        const numOctets = first & 0x7F;
        if (numOctets === 0 || numOctets > 4) {
            throw new Error('Invalid DER length encoding');
        }

        let length = 0;
        for (let i = 0; i < numOctets; i++) {
            if (pos >= derBuffer.length) {
                throw new Error('Unexpected end of DER data');
            }
            length = (length << 8) | derBuffer[pos++];
        }
        return length;
    };

    const skipValue = (length) => {
        pos += length;
        if (pos > derBuffer.length) {
            throw new Error('DER value extends beyond buffer');
        }
    };

    const readBytes = (length) => {
        if (pos + length > derBuffer.length) {
            throw new Error('Not enough bytes to read');
        }
        const bytes = derBuffer.slice(pos, pos + length);
        pos += length;
        return bytes;
    };

    const matchesOid = (oidBytes) => {
        if (oidBytes.length !== targetOidBytes.length) {
            return false;
        }
        for (let i = 0; i < oidBytes.length; i++) {
            if (oidBytes[i] !== targetOidBytes[i]) {
                return false;
            }
        }
        return true;
    };

    if (derBuffer[pos] !== 0x30) {
        throw new Error('Certificate must start with SEQUENCE tag');
    }
    pos++;
    const certLength = readLength();

    if (derBuffer[pos] !== 0x30) {
        throw new Error('TBSCertificate must be a SEQUENCE');
    }
    pos++;
    const tbsLength = readLength();
    const tbsEnd = pos + tbsLength;

    while (pos < tbsEnd) {
        const tag = derBuffer[pos];

        if (tag === 0xA3) {
            pos++;
            const extContainerLength = readLength();

            if (derBuffer[pos] !== 0x30) {
                throw new Error('Extensions must be a SEQUENCE');
            }
            pos++;
            const extensionsLength = readLength();
            const extensionsEnd = pos + extensionsLength;

            while (pos < extensionsEnd) {
                if (derBuffer[pos] !== 0x30) {
                    break;
                }
                pos++;
                const extLength = readLength();
                const extEnd = pos + extLength;

                if (derBuffer[pos] !== 0x06) {
                    pos = extEnd;
                    continue;
                }
                const oidTag = derBuffer[pos++];
                const oidLength = readLength();
                const oidBytes = new Uint8Array([oidTag, oidLength, ...readBytes(oidLength)]);

                let critical = false;
                if (pos < extEnd && derBuffer[pos] === 0x01) {
                    pos++;
                    const boolLength = readLength();
                    critical = readBytes(boolLength)[0] !== 0;
                }

                if (pos >= extEnd) {
                    pos = extEnd;
                    continue;
                }

                if (derBuffer[pos] !== 0x04) {
                    pos = extEnd;
                    continue;
                }
                pos++;
                const valueLength = readLength();
                const valueBytes = readBytes(valueLength);

                if (matchesOid(oidBytes)) {
                    return ByteUtils.toBytes(valueBytes);
                }

                pos = extEnd;
            }

            return null;
        } else {
            pos++;
            const length = readLength();
            skipValue(length);
        }
    }

    return null;
}

/**
 * 从X.509证书提取Quote
 * 基于ra_tls_verify_common.c:534-549
 * 支持RSA和ECDSA证书
 */
function extractQuoteFromCert(pemCert) {
    try {
        const cert = forge.pki.certificateFromPem(pemCert);
        return extractQuoteFromParsedCert(cert);
    } catch (error) {
        if (error.message && (error.message.includes('OID is not RSA') || error.message.includes('Too few bytes'))) {
            return extractQuoteFromParsedCertViaAsn1(pemCert);
        }
        throw error;
    }
}

/**
 * 使用ASN.1方式提取Quote（用于ECDSA证书）
 */
function extractQuoteFromParsedCertViaAsn1(pemCert) {
    let quoteData = getExtensionFromPemViaAsn1(pemCert, TCG_DICE_TAGGED_EVIDENCE_OID);
    if (quoteData) {
        return extractStandardQuoteFromExtension(quoteData);
    }

    quoteData = getExtensionFromPemViaAsn1(pemCert, LEGACY_QUOTE_OID);
    if (quoteData) {
        return extractLegacyQuoteFromExtension(quoteData);
    }

    quoteData = getExtensionFromPemViaAsn1(pemCert, LEGACY_QUOTE_OID_V1);
    if (quoteData) {
        return extractLegacyQuoteFromExtension(quoteData);
    }

    throw new Error('No SGX quote found in certificate');
}

/**
 * 从扩展数据中提取标准TCG DICE格式的Quote
 * 用于ASN.1方式提取的扩展数据
 */
function extractStandardQuoteFromExtension(extValue) {
    try {
        const cborData = cbor.decode(extValue);

        if (!cborData || cborData.tag !== TCG_DICE_TAGGED_EVIDENCE_CBOR_TAG) {
            throw new Error('Invalid CBOR tag for TCG DICE evidence');
        }

        const evidence = cborData.value;
        if (!Array.isArray(evidence) || evidence.length !== 2) {
            throw new Error('Invalid evidence structure');
        }

        const quote = evidence[0];
        const claimsBstr = evidence[1];

        if (!claimsBstr || !(claimsBstr instanceof Uint8Array || Buffer.isBuffer(claimsBstr))) {
            throw new Error('Invalid claims structure');
        }

        const claimsBytes = ByteUtils.toBytes(claimsBstr);
        const claimsBinaryStr = ByteUtils.toBinaryString(claimsBytes);

        const claimsHash = forge.md.sha256.create();
        claimsHash.update(claimsBinaryStr, 'raw');
        const expectedHash = claimsHash.digest().bytes();

        const quoteBuffer = ByteUtils.toBytes(quote);
        const reportDataOffset = 48 + 320;
        const actualHash = ByteUtils.slice(quoteBuffer, reportDataOffset, reportDataOffset + 32);

        const expectedHashBytes = ByteUtils.fromBinaryString(expectedHash);
        if (!ByteUtils.equalBytes(expectedHashBytes, actualHash)) {
            throw new Error('Claims hash does not match quote report_data');
        }

        return {
            quote: quoteBuffer,
            quoteSize: quoteBuffer.length,
            claims: claimsBytes
        };
    } catch (error) {
        throw new Error(`Failed to extract standard quote from extension: ${error.message}`);
    }
}

/**
 * 从扩展数据中提取遗留格式的Quote
 * 用于ASN.1方式提取的扩展数据
 * 传统格式包含：原始quote数据 + 嵌入的PCK证书链（PEM格式）
 */
function extractLegacyQuoteFromExtension(extValue) {
    const extBytes = ByteUtils.toBytes(extValue);

    if (extBytes.length < 436) {
        throw new Error('Extension value too short to contain a valid quote');
    }

    const view = ByteUtils.dataView(extBytes);
    const signatureDataLen = view.getUint32(432, true);
    const expectedQuoteSize = 432 + 4 + signatureDataLen;

    let quote;
    if (expectedQuoteSize <= extBytes.length) {
        quote = ByteUtils.slice(extBytes, 0, expectedQuoteSize);
    } else {
        quote = extBytes;
    }

    return {
        quote: quote,
        quoteSize: quote.length
    };
}

/**
 * 从解析后的证书提取Quote
 * 实现标准OID和遗留OID两种方式
 */
function extractQuoteFromParsedCert(cert) {
    // 首先尝试标准TCG DICE OID (基于extract_standard_quote_and_verify_claims)
    let quote = extractStandardQuote(cert);
    if (quote) {
        return quote;
    }

    // 回退到遗留OID (基于extract_legacy_quote_and_verify_pubkey)
    quote = extractLegacyQuote(cert);
    if (quote) {
        return quote;
    }

    throw new Error('No SGX quote found in certificate');
}

/**
 * 提取标准TCG DICE格式的Quote
 * 基于ra_tls_verify_common.c:326-502
 */
function extractStandardQuote(cert) {
    const ext = findExtension(cert, TCG_DICE_TAGGED_EVIDENCE_OID);
    if (!ext) return null;

    try {
        let extValue = ext.value;
        if (typeof extValue === 'string') {
            extValue = ByteUtils.fromBinaryString(extValue);
        } else {
            extValue = ByteUtils.toBytes(extValue);
        }

        const cborData = cbor.decode(extValue);

        if (!cborData || cborData.tag !== TCG_DICE_TAGGED_EVIDENCE_CBOR_TAG) {
            throw new Error('Invalid CBOR tag for TCG DICE evidence');
        }

        const evidence = cborData.value;
        if (!Array.isArray(evidence) || evidence.length !== 2) {
            throw new Error('Invalid evidence structure');
        }

        const quote = evidence[0];
        const claimsBstr = evidence[1];

        if (!claimsBstr || !(claimsBstr instanceof Uint8Array || Buffer.isBuffer(claimsBstr))) {
            throw new Error('Invalid claims structure');
        }

        const claimsBytes = ByteUtils.toBytes(claimsBstr);
        const claimsBinaryStr = ByteUtils.toBinaryString(claimsBytes);

        const claimsHash = forge.md.sha256.create();
        claimsHash.update(claimsBinaryStr, 'raw');
        const expectedHash = claimsHash.digest().bytes();

        const quoteBuffer = ByteUtils.toBytes(quote);
        const reportDataOffset = 48 + 320;  // Report body starts at 48, report_data is at offset 320 within report body
        const actualHash = ByteUtils.slice(quoteBuffer, reportDataOffset, reportDataOffset + 32);

        const expectedHashBytes = ByteUtils.fromBinaryString(expectedHash);
        if (!ByteUtils.equalBytes(expectedHashBytes, actualHash)) {
            throw new Error('Claims hash does not match quote report_data');
        }

        const claimsMap = cbor.decode(claimsBytes);

        if (claimsMap['pubkey-hash']) {
            const pubkeyHashValue = claimsMap['pubkey-hash'];
            let hashEntry;

            if (pubkeyHashValue instanceof Uint8Array || Buffer.isBuffer(pubkeyHashValue)) {
                hashEntry = cbor.decode(ByteUtils.toBytes(pubkeyHashValue));
            } else if (Array.isArray(pubkeyHashValue)) {
                hashEntry = pubkeyHashValue;
            } else {
                throw new Error('Invalid pubkey-hash format');
            }

            // hashEntry is [hashAlg, hashValue]
            if (!Array.isArray(hashEntry) || hashEntry.length !== 2) {
                throw new Error('Invalid pubkey-hash array format');
            }

            const hashAlg = hashEntry[0]; // 1=SHA-256, 7=SHA-384, 8=SHA-512
            const hashValue = hashEntry[1];

            if (hashAlg !== 1 && hashAlg !== 7 && hashAlg !== 8) {
                throw new Error(`Unsupported hash algorithm in pubkey-hash: ${hashAlg}`);
            }

            const certPubkey = cert.publicKey;
            const pubkeyAsn1 = forge.pki.publicKeyToAsn1(certPubkey);
            const pubkeyDer = forge.asn1.toDer(pubkeyAsn1).getBytes();

            let computedHash;
            if (hashAlg === 1) { // SHA-256
                const hash = forge.md.sha256.create();
                hash.update(pubkeyDer, 'raw');
                computedHash = ByteUtils.fromBinaryString(hash.digest().getBytes());
            } else if (hashAlg === 7) { // SHA-384
                const hash = forge.md.sha384.create();
                hash.update(pubkeyDer, 'raw');
                computedHash = ByteUtils.fromBinaryString(hash.digest().getBytes());
            } else if (hashAlg === 8) { // SHA-512
                const hash = forge.md.sha512.create();
                hash.update(pubkeyDer, 'raw');
                computedHash = ByteUtils.fromBinaryString(hash.digest().getBytes());
            }

            const hashValueBytes = ByteUtils.toBytes(hashValue);
            if (!ByteUtils.equalBytes(computedHash, hashValueBytes)) {
                throw new Error('Public key hash mismatch');
            }
        }

        return {
            quote: quoteBuffer,
            quoteSize: quoteBuffer.length
        };
    } catch (error) {
        throw new Error(`Failed to extract standard quote: ${error.message}`);
    }
}

/**
 * 提取遗留格式的Quote
 * 基于ra_tls_verify_common.c:504-532
 */
function extractLegacyQuote(cert) {
    const ext = findExtension(cert, NON_STANDARD_INTEL_SGX_QUOTE_OID);
    if (!ext) return null;

    let extValue = ext.value;
    if (typeof extValue === 'string') {
        extValue = ByteUtils.fromBinaryString(extValue);
    }
    const quote = ByteUtils.toBytes(extValue);

    // 验证公钥哈希匹配report_data
    const certPubkey = cert.publicKey;
    const pubkeyAsn1 = forge.pki.publicKeyToAsn1(certPubkey);
    const pubkeyDer = forge.asn1.toDer(pubkeyAsn1).getBytes();

    const hash = forge.md.sha256.create();
    hash.update(pubkeyDer, 'raw');
    const pubkeyHash = ByteUtils.fromBinaryString(hash.digest().getBytes());

    const reportDataOffset = 48 + 320;  // Report body starts at 48, report_data is at offset 320 within report body
    const reportData = ByteUtils.slice(quote, reportDataOffset, reportDataOffset + 64);

    if (!ByteUtils.equalBytes(pubkeyHash, ByteUtils.slice(reportData, 0, 32))) {
        throw new Error('Public key hash does not match report_data');
    }

    return {
        quote,
        quoteSize: quote.length
    };
}

/**
 * 查找证书扩展
 */
function findExtension(cert, oid) {
    if (!cert.extensions) return null;

    for (const ext of cert.extensions) {
        if (ext.id === oid) {
            return ext;
        }
    }
    return null;
}

/**
 * 解析Quote二进制结构
 * 基于sgx_attest.h中的sgx_quote3_t定义（DCAP格式）
 */
function parseQuoteStructure(quoteBuffer) {
    const view = ByteUtils.dataView(quoteBuffer);
    let offset = 0;

    const version = view.getUint16(offset, true); offset += 2;
    const attestationKeyType = view.getUint16(offset, true); offset += 2; // 2 = ECDSA-P256, 3 = ECDSA-P384
    const teeType = view.getUint32(offset, true); offset += 4; // 0x00000000 = SGX
    const qeSvn = view.getUint16(offset, true); offset += 2;
    const pceSvn = view.getUint16(offset, true); offset += 2;
    const qeVendorId = ByteUtils.slice(quoteBuffer, offset, offset + 16); offset += 16; // UUID
    const userData = ByteUtils.slice(quoteBuffer, offset, offset + 20); offset += 20; // User data

    // Report Body (384 bytes)
    const reportBodyStart = offset;
    const cpuSvn = ByteUtils.slice(quoteBuffer, offset, offset + 16); offset += 16;
    const miscSelect = view.getUint32(offset, true); offset += 4;
    offset += 28; // reserved
    const attributes = ByteUtils.slice(quoteBuffer, offset, offset + 16); offset += 16;
    const mrenclave = ByteUtils.slice(quoteBuffer, offset, offset + 32); offset += 32;
    offset += 32; // reserved
    const mrsigner = ByteUtils.slice(quoteBuffer, offset, offset + 32); offset += 32;
    offset += 96; // reserved
    const isvProdId = view.getUint16(offset, true); offset += 2;
    const isvSvn = view.getUint16(offset, true); offset += 2;
    offset += 60; // reserved
    const reportData = ByteUtils.slice(quoteBuffer, offset, offset + 64); offset += 64;

    const signatureSize = view.getUint32(offset, true); offset += 4;
    const signatureStart = offset;
    const signature = ByteUtils.slice(quoteBuffer, offset, offset + signatureSize);
    offset += signatureSize;

    let certChain = [];
    let qeAuthData = null;
    let certDataType = null;
    let ppid = null;
    let cpusvn = null;
    let pcesvn = null;
    let pceid = null;
    
    if (version === 3 || version === 4) {
        const sigResult = parseEcdsaSignatureData(signature, attestationKeyType);
        certChain = sigResult.certChain;
        qeAuthData = sigResult.qeAuthData;
        certDataType = sigResult.certDataType;
        ppid = sigResult.ppid;
        cpusvn = sigResult.cpusvn;
        pcesvn = sigResult.pcesvn;
        pceid = sigResult.pceid;
    }

    return {
        version,
        attestationKeyType,
        teeType,
        qeSvn,
        pceSvn,
        qeVendorId,
        userData,
        cpuSvn,
        miscSelect,
        attributes,
        mrenclave,
        mrsigner,
        isvProdId,
        isvSvn,
        reportData,
        signature,
        certChain,
        qeAuthData,
        certDataType,
        ppid,
        cpusvn,
        pcesvn,
        pceid,
        rawQuote: quoteBuffer
    };
}

/**
 * 解析ECDSA签名数据结构
 * 基于sgx_quote_3.h中的sgx_ql_ecdsa_sig_data_t
 */
function parseEcdsaSignatureData(sigData, attestationKeyType) {
    let offset = 0;
    const view = ByteUtils.dataView(sigData);

    const coordSize = attestationKeyType === 3 ? 48 : 32;
    const sigSize = coordSize * 2;
    const pubkeySize = coordSize * 2;

    const ecdsaSignature = ByteUtils.slice(sigData, offset, offset + sigSize); offset += sigSize;

    const attestationPubKey = ByteUtils.slice(sigData, offset, offset + pubkeySize); offset += pubkeySize;

    const qeReport = ByteUtils.slice(sigData, offset, offset + 384); offset += 384;

    const qeReportSignature = ByteUtils.slice(sigData, offset, offset + sigSize); offset += sigSize;

    const certChain = [];
    let qeAuthData = null;
    let certDataType = null;
    let ppid = null;
    let cpusvn = null;
    let pcesvn = null;
    let pceid = null;
    
    if (offset + 2 <= sigData.length) {
        const authDataSize = view.getUint16(offset, true); offset += 2;

        if (authDataSize > 0 && offset + authDataSize <= sigData.length) {
            qeAuthData = ByteUtils.slice(sigData, offset, offset + authDataSize);
            offset += authDataSize;
        }

        if (offset + 6 <= sigData.length) {
            const certData = ByteUtils.slice(sigData, offset);
            const certResult = parseCertificationData(certData);
            certChain.push(...certResult.certChain);
            certDataType = certResult.certDataType;
            ppid = certResult.ppid;
            cpusvn = certResult.cpusvn;
            pcesvn = certResult.pcesvn;
            pceid = certResult.pceid;
        }
    }

    return { certChain, qeAuthData, certDataType, ppid, cpusvn, pcesvn, pceid };
}

/**
 * 解析认证数据（Certification Data）
 * 基于sgx_quote_3.h中的sgx_ql_certification_data_t
 */
function parseCertificationData(authData) {
    const certChain = [];
    let offset = 0;
    const view = ByteUtils.dataView(authData);

    if (authData.length < 6) return { certChain, certDataType: null };

    const certDataType = view.getUint16(offset, true); offset += 2;
    const certDataSize = view.getUint32(offset, true); offset += 4;

    let actualCertDataSize = certDataSize;
    if (offset + certDataSize > authData.length) {
        actualCertDataSize = authData.length - offset;
    }

    const certData = ByteUtils.slice(authData, offset, offset + actualCertDataSize);
    
    const dataType = certDataType & 0xff;
    const keyType = (certDataType >> 8) & 0xff;
    
    if (dataType === 1 && certData.length > 6) {
        for (let i = 0; i < Math.min(128, certData.length - 6); i++) {
            const innerView = ByteUtils.dataView(certData);
            const innerType = innerView.getUint16(i, true);
            
            if (innerType === 5) {
                const innerSize = innerView.getUint32(i + 2, true);
                
                if (i + 6 + innerSize <= certData.length) {
                    const nestedCertData = ByteUtils.slice(certData, i + 6, i + 6 + innerSize);
                    const nestedDataStr = ByteUtils.toBinaryString(nestedCertData);
                    
                    if (nestedDataStr.indexOf('-----BEGIN CERTIFICATE-----') >= 0) {
                        const pemChain = parsePemCertChain(nestedDataStr);
                        return { certChain: pemChain, certDataType, dataType, innerType: 5 };
                    }
                }
            }
        }
    }

    if (dataType === 5) {
        const certDataStr = ByteUtils.toBinaryString(certData);
        if (certDataStr.indexOf('-----BEGIN CERTIFICATE-----') === 0) {
            const pemChain = parsePemCertChain(certDataStr);
            return { certChain: pemChain, certDataType, dataType };
        } else {
            const certView = ByteUtils.dataView(certData);
            let certOffset = 0;

            if (certData.length < 4) return { certChain, certDataType, dataType };

            const certCount = certView.getUint32(certOffset, true);
            certOffset += 4;

            for (let i = 0; i < certCount && certOffset < certData.length; i++) {
                if (certOffset + 4 > certData.length) break;

                const certSize = certView.getUint32(certOffset, true);
                certOffset += 4;

                if (certOffset + certSize > certData.length) break;

                const cert = ByteUtils.slice(certData, certOffset, certOffset + certSize);
                certChain.push(cert);
                certOffset += certSize;
            }
        }
        return { certChain, certDataType, dataType };
    }
    
    if (dataType === 1) {
        let certOffset = 0;
        const certView = ByteUtils.dataView(certData);
        
        if (certData.length < 36) {
            console.warn('[WARN] PPID-based cert data too small:', certData.length, 'bytes (expected at least 36)');
            return { certChain, certDataType, dataType };
        }
        
        const ppid = ByteUtils.slice(certData, certOffset, certOffset + 16); certOffset += 16;
        const cpusvn = ByteUtils.slice(certData, certOffset, certOffset + 16); certOffset += 16;
        const pcesvn = certView.getUint16(certOffset, true); certOffset += 2;
        const pceid = certView.getUint16(certOffset, true); certOffset += 2;
        
        return { 
            certChain, 
            certDataType, 
            dataType,
            ppid: ByteUtils.toHex(ppid),
            cpusvn: ByteUtils.toHex(cpusvn),
            pcesvn,
            pceid
        };
    }

    return { certChain, certDataType, dataType };
}

/**
 * 下载验证所需的材料
 * 基于DCAP协议从PCCS获取证书和TCB信息
 */
async function fetchCollateral(quoteData, pccsUrl, apiKey, cacheRead, cacheWrite) {
    const collateral = {
        pckCertChain: null,
        tcbInfo: null,
        tcbInfoRaw: null,  // 保存原始文本用于签名验证
        qeIdentity: null,
        qeIdentityRaw: null,  // 保存原始文本用于签名验证
        rootCaCrl: null,
        pckCrls: {
            processor: null,
            platform: null
        }
    };

    // 从quote中提取FMSPC和其他标识符
    const fmspc = extractFmspc(quoteData);
    const qeId = extractQeId(quoteData);

    // 1. 获取PCK证书链 (如果quote中没有嵌入)
    if (!quoteData.certChain || quoteData.certChain.length === 0) {
        const pckCertKey = `pck_cert_${fmspc}`;
        let pckCertChain = await cacheRead(pckCertKey);

        if (!pckCertChain) {
            const url = `${pccsUrl}/pckcert?fmspc=${fmspc}`;
            const headers = apiKey ? { 'Ocp-Apim-Subscription-Key': apiKey } : {};

            const response = await fetchFunc(url, { headers });
            if (!response.ok) {
                throw new Error(`Failed to fetch PCK cert: ${response.status}`);
            }

            pckCertChain = await response.text();
            await cacheWrite(pckCertKey, pckCertChain);
        }

        collateral.pckCertChain = parsePemCertChain(pckCertChain);
    } else {
        collateral.pckCertChain = quoteData.certChain;
    }

    const tcbInfoKey = `tcb_info_${fmspc}`;
    let tcbInfoText = await cacheRead(tcbInfoKey);
    let tcbInfoIssuerChain = null;

    if (!tcbInfoText) {
        const url = `${pccsUrl}/tcb?fmspc=${fmspc}`;
        const headers = apiKey ? { 'Ocp-Apim-Subscription-Key': apiKey } : {};

        const response = await fetchFunc(url, { headers });
        if (!response.ok) {
            throw new Error(`Failed to fetch TCB info: ${response.status}`);
        }

        tcbInfoText = await response.text();
        tcbInfoIssuerChain = response.headers.get('tcb-info-issuer-chain');
        if (tcbInfoIssuerChain) {
            tcbInfoIssuerChain = decodeURIComponent(tcbInfoIssuerChain);
        }
        await cacheWrite(tcbInfoKey, tcbInfoText);
        await cacheWrite(`${tcbInfoKey}_issuer_chain`, tcbInfoIssuerChain);
    } else {
        tcbInfoIssuerChain = await cacheRead(`${tcbInfoKey}_issuer_chain`);
    }

    collateral.tcbInfoRaw = tcbInfoText;
    collateral.tcbInfo = JSON.parse(tcbInfoText);
    collateral.tcbInfo.tcbInfoIssuerChain = tcbInfoIssuerChain;

    await verifyIntelSignedJson(collateral.tcbInfo, tcbInfoText, 'tcbInfo', 'tcbInfoIssuerChain');

    const qeIdentityKey = `qe_identity`;
    let qeIdentityText = await cacheRead(qeIdentityKey);
    let qeIdentityIssuerChain = null;

    if (!qeIdentityText) {
        const url = `${pccsUrl}/qe/identity`;
        const headers = apiKey ? { 'Ocp-Apim-Subscription-Key': apiKey } : {};

        const response = await fetchFunc(url, { headers });
        if (!response.ok) {
            throw new Error(`Failed to fetch QE identity: ${response.status}`);
        }

        qeIdentityText = await response.text();
        qeIdentityIssuerChain = response.headers.get('sgx-enclave-identity-issuer-chain');
        if (qeIdentityIssuerChain) {
            qeIdentityIssuerChain = decodeURIComponent(qeIdentityIssuerChain);
        }
        await cacheWrite(qeIdentityKey, qeIdentityText);
        await cacheWrite(`${qeIdentityKey}_issuer_chain`, qeIdentityIssuerChain);
    } else {
        qeIdentityIssuerChain = await cacheRead(`${qeIdentityKey}_issuer_chain`);
    }

    collateral.qeIdentityRaw = qeIdentityText;
    collateral.qeIdentity = JSON.parse(qeIdentityText);
    collateral.qeIdentity.enclaveIdentityIssuerChain = qeIdentityIssuerChain;

    await verifyIntelSignedJson(collateral.qeIdentity, qeIdentityText, 'enclaveIdentity', 'enclaveIdentityIssuerChain');

    // 4. 获取Root CA CRL
    const crlKey = 'root_ca_crl';
    let rootCaCrl = await cacheRead(crlKey);

    if (!rootCaCrl) {
        try {
            const url = `${pccsUrl}/rootcacrl`;
            const headers = apiKey ? { 'Ocp-Apim-Subscription-Key': apiKey } : {};

            const response = await fetchFunc(url, { headers });
            if (response.ok) {
                rootCaCrl = await response.text();
                await cacheWrite(crlKey, rootCaCrl);
            } else {
                console.warn(`WARNING: Failed to fetch root CA CRL: ${response.status} - CRL verification will be skipped`);
            }
        } catch (e) {
            console.warn('WARNING: Failed to fetch root CA CRL:', e.message, '- CRL verification will be skipped');
        }
    }

    collateral.rootCaCrl = rootCaCrl;

    if (collateral.pckCertChain && collateral.pckCertChain.length > 0) {
        const pckCert = collateral.pckCertChain[0];
        const issuerCN = getIssuerCN(pckCert);

        const processorCrlKey = `pck_crl_processor_${fmspc}`;
        let processorCrl = await cacheRead(processorCrlKey);

        if (!processorCrl) {
            try {
                const url = `${pccsUrl}/pckcrl?ca=processor`;
                const headers = apiKey ? { 'Ocp-Apim-Subscription-Key': apiKey } : {};
                const response = await fetchFunc(url, { headers });
                if (response.ok) {
                    processorCrl = await response.text();
                    await cacheWrite(processorCrlKey, processorCrl);
                }
            } catch (e) {
                console.warn('Failed to fetch processor CRL:', e.message);
            }
        }
        collateral.pckCrls.processor = processorCrl;

        const platformCrlKey = `pck_crl_platform_${fmspc}`;
        let platformCrl = await cacheRead(platformCrlKey);

        if (!platformCrl) {
            try {
                const url = `${pccsUrl}/pckcrl?ca=platform`;
                const headers = apiKey ? { 'Ocp-Apim-Subscription-Key': apiKey } : {};
                const response = await fetchFunc(url, { headers });
                if (response.ok) {
                    platformCrl = await response.text();
                    await cacheWrite(platformCrlKey, platformCrl);
                }
            } catch (e) {
                console.warn('Failed to fetch platform CRL:', e.message);
            }
        }
        collateral.pckCrls.platform = platformCrl;
    }

    return collateral;
}

/**
 * 验证Intel签名的JSON文档（TCB Info或QE Identity）
 * 完整实现Intel签名验证
 */
async function verifyIntelSignedJson(jsonObj, rawText, dataFieldName, issuerChainFieldName) {
    if (!jsonObj.signature) {
        throw new Error(`${dataFieldName} does not contain signature`);
    }

    if (!jsonObj[issuerChainFieldName]) {
        throw new Error(`${dataFieldName} does not contain ${issuerChainFieldName}`);
    }

    const issuerChainPem = jsonObj[issuerChainFieldName];
    const issuerCerts = parseCommaSeparatedPemChain(issuerChainPem);

    if (issuerCerts.length === 0) {
        throw new Error(`No certificates found in ${issuerChainFieldName}`);
    }

    await verifyIntelIssuerChain(issuerCerts);

    const signingCert = issuerCerts[0];
    
    let signatureBytes;
    if (jsonObj.signature.length === 128 && /^[0-9a-fA-F]+$/.test(jsonObj.signature)) {
        signatureBytes = ByteUtils.fromHex(jsonObj.signature);
    } else {
        signatureBytes = ByteUtils.fromBase64(jsonObj.signature);
    }
    
    let signingPubKeyBytes;
    try {
        const cert = forge.pki.certificateFromPem(signingCert);
        const pubKey = cert.publicKey;
        const pubKeyAsn1 = forge.pki.publicKeyToAsn1(pubKey);
        const pubKeyDer = forge.asn1.toDer(pubKeyAsn1).getBytes();
        signingPubKeyBytes = ByteUtils.fromBinaryString(pubKeyDer);
    } catch (error) {
        if (error.message && error.message.includes('OID is not RSA')) {
            signingPubKeyBytes = extractEcdsaPublicKeyFromPem(signingCert);
        } else {
            throw error;
        }
    }
    
    const signingCertDer = ByteUtils.fromBase64(
        signingCert.replace(/-----BEGIN CERTIFICATE-----/, '')
                   .replace(/-----END CERTIFICATE-----/, '')
                   .replace(/\s/g, '')
    );
    const signingCertSpki = extractSpkiFromCertDer(signingCertDer);
    const curveInfo = extractEcCurveFromSpki(signingCertSpki);
    
    const uncompressedMarker = signingPubKeyBytes.indexOf(0x04);
    if (uncompressedMarker === -1) {
        throw new Error('Cannot find uncompressed point marker in signing certificate public key');
    }
    
    const coordStart = uncompressedMarker + 1;
    const coordSize = curveInfo.coordSize;
    
    if (signingPubKeyBytes.length < coordStart + coordSize * 2) {
        throw new Error('Invalid signing certificate public key length');
    }
    
    const pubKeyX = ByteUtils.slice(signingPubKeyBytes, coordStart, coordStart + coordSize);
    const pubKeyY = ByteUtils.slice(signingPubKeyBytes, coordStart + coordSize, coordStart + coordSize * 2);
    
    const EC = elliptic.ec;
    const ec = new EC(curveInfo.ellipticName);
    
    const key = ec.keyFromPublic({
        x: ByteUtils.toHex(pubKeyX),
        y: ByteUtils.toHex(pubKeyY)
    }, 'hex');
    
    let r, s;
    try {
        const derSig = parseDerEcdsaSignature(signatureBytes);
        r = derSig.r;
        s = derSig.s;
    } catch (e) {
        if (signatureBytes.length === coordSize * 2 && signatureBytes[0] !== 0x30) {
            console.warn(`Failed to parse DER signature for ${dataFieldName}, trying raw format:`, e.message);
            r = null;
            s = null;
        } else {
            throw new Error(`Failed to parse signature for ${dataFieldName}: ${e.message}`);
        }
    }
    
    const dataFieldStartMarker = `"${dataFieldName}":`;
    const dataFieldStart = rawText.indexOf(dataFieldStartMarker);
    
    if (dataFieldStart === -1) {
        throw new Error(`Cannot find ${dataFieldName} field in raw JSON text`);
    }
    
    const dataStart = dataFieldStart + dataFieldStartMarker.length;
    let braceCount = 0;
    let inString = false;
    let escapeNext = false;
    let dataEnd = dataStart;
    
    for (let i = dataStart; i < rawText.length; i++) {
        const char = rawText[i];
        
        if (escapeNext) {
            escapeNext = false;
            continue;
        }
        
        if (char === '\\') {
            escapeNext = true;
            continue;
        }
        
        if (char === '"' && !escapeNext) {
            inString = !inString;
        }
        
        if (!inString) {
            if (char === '{') {
                braceCount++;
            } else if (char === '}') {
                braceCount--;
                if (braceCount === 0) {
                    dataEnd = i + 1;
                    break;
                }
            }
        }
    }
    
    const dataToVerify = rawText.substring(dataStart, dataEnd).trim();
    
    let dataHash;
    if (isBrowser) {
        dataHash = await window.crypto.subtle.digest('SHA-256', ByteUtils.toBytes(dataToVerify));
    } else {
        const cryptoModule = require('crypto');
        dataHash = await cryptoModule.webcrypto.subtle.digest('SHA-256', ByteUtils.toBytes(dataToVerify));
    }
    const dataHashArray = Array.from(new Uint8Array(dataHash));
    
    if (!r || !s) {
        if (signatureBytes.length !== coordSize * 2) {
            throw new Error(`Invalid raw signature length for ${dataFieldName}: expected ${coordSize * 2}, got ${signatureBytes.length}`);
        }
        r = ByteUtils.toHex(ByteUtils.slice(signatureBytes, 0, coordSize));
        s = ByteUtils.toHex(ByteUtils.slice(signatureBytes, coordSize, coordSize * 2));
    }
    
    const verified = key.verify(dataHashArray, { r, s });
    
    if (!verified) {
        throw new Error(`${dataFieldName} signature verification failed`);
    }
    
    console.info(`${dataFieldName} signature verified successfully`);

    const dataObj = jsonObj[dataFieldName];
    if (dataObj.issueDate && dataObj.nextUpdate) {
        const issueDate = new Date(dataObj.issueDate);
        const nextUpdate = new Date(dataObj.nextUpdate);
        const now = new Date();

        if (now < issueDate) {
            throw new Error(`${dataFieldName} not yet valid (issue date: ${dataObj.issueDate})`);
        }

        if (now > nextUpdate) {
            console.warn(`WARNING: ${dataFieldName} is outdated (next update: ${dataObj.nextUpdate})`);
        }
    }
}

/**
 * 解析逗号分隔的PEM证书链
 */
function parseCommaSeparatedPemChain(pemChainStr) {
    const certs = [];
    const certRegex = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g;
    const matches = pemChainStr.match(certRegex);

    if (matches) {
        for (const pemCert of matches) {
            certs.push(pemCert);
        }
    }

    return certs;
}

/**
 * 验证Intel issuer chain到Intel SGX Root CA
 * Verifies the Intel issuer certificate chain up to a trusted Intel SGX Root CA
 * @param {Array<string>} issuerCerts - Array of PEM certificates in leaf→root order
 */
async function verifyIntelIssuerChain(issuerCerts) {
    if (issuerCerts.length === 0) {
        throw new Error('Empty issuer certificate chain');
    }

    console.info('Verifying Intel issuer chain with', issuerCerts.length, 'certificates');

    for (let i = 0; i < issuerCerts.length - 1; i++) {
        const childCertPem = issuerCerts[i];
        const parentCertPem = issuerCerts[i + 1];
        
        try {
            const childCert = forge.pki.certificateFromPem(childCertPem);
            const parentCert = forge.pki.certificateFromPem(parentCertPem);
            
            const childIssuerDn = childCert.issuer.attributes.map(a => `${a.shortName}=${a.value}`).join(',');
            const parentSubjectDn = parentCert.subject.attributes.map(a => `${a.shortName}=${a.value}`).join(',');
            
            if (childIssuerDn !== parentSubjectDn) {
                throw new Error(`Certificate ${i} issuer does not match certificate ${i + 1} subject`);
            }
            
            const basicConstraints = parentCert.getExtension('basicConstraints');
            if (basicConstraints && !basicConstraints.cA) {
                throw new Error(`Certificate ${i + 1} is not a CA certificate`);
            }
            
            const now = new Date();
            if (now < parentCert.validity.notBefore) {
                throw new Error(`Certificate ${i + 1} not yet valid`);
            }
            if (now > parentCert.validity.notAfter) {
                throw new Error(`Certificate ${i + 1} has expired`);
            }
            
            const verified = parentCert.verify(childCert);
            if (!verified) {
                throw new Error(`Certificate ${i} signature verification failed using certificate ${i + 1}`);
            }
            
            console.info(`Intel issuer certificate ${i} verified by certificate ${i + 1}`);
        } catch (e) {
            if (e.message && e.message.includes('OID is not RSA')) {
                console.info(`Intel issuer certificate ${i} is ECDSA, verifying with elliptic.js`);
                
                const childCertDer = ByteUtils.fromBase64(
                    childCertPem.replace(/-----BEGIN CERTIFICATE-----/, '')
                              .replace(/-----END CERTIFICATE-----/, '')
                              .replace(/\s/g, '')
                );
                
                let offset = 0;
                if (childCertDer[offset] !== 0x30) {
                    throw new Error('Invalid certificate DER structure');
                }
                offset++;
                
                const readLength = (data, offset) => {
                    if (data[offset] < 0x80) {
                        return { length: data[offset], bytes: 1 };
                    }
                    const numBytes = data[offset] & 0x7f;
                    let length = 0;
                    for (let i = 0; i < numBytes; i++) {
                        length = (length << 8) | data[offset + 1 + i];
                    }
                    return { length, bytes: 1 + numBytes };
                };
                
                const certLen = readLength(childCertDer, offset);
                offset += certLen.bytes;
                
                const tbsCertStart = offset;
                if (childCertDer[offset] !== 0x30) {
                    throw new Error('Invalid TBSCertificate structure');
                }
                offset++;
                const tbsCertLen = readLength(childCertDer, offset);
                offset += tbsCertLen.bytes;
                const tbsCertEnd = offset + tbsCertLen.length;
                
                const tbsCert = ByteUtils.slice(childCertDer, tbsCertStart, tbsCertEnd);
                
                offset = tbsCertEnd;
                if (childCertDer[offset] !== 0x30) {
                    throw new Error('Invalid signatureAlgorithm structure');
                }
                offset++;
                const sigAlgLen = readLength(childCertDer, offset);
                offset += sigAlgLen.bytes + sigAlgLen.length;
                
                if (childCertDer[offset] !== 0x03) {
                    throw new Error('Invalid signature BIT STRING');
                }
                offset++;
                const sigLen = readLength(childCertDer, offset);
                offset += sigLen.bytes;
                
                if (childCertDer[offset] !== 0x00) {
                    throw new Error('Invalid BIT STRING padding');
                }
                offset++;
                
                const signatureDer = ByteUtils.slice(childCertDer, offset, offset + sigLen.length - 1);
                
                const derSig = parseDerEcdsaSignature(signatureDer);
                
                const parentCertDer = ByteUtils.fromBase64(
                    parentCertPem.replace(/-----BEGIN CERTIFICATE-----/, '')
                                .replace(/-----END CERTIFICATE-----/, '')
                                .replace(/\s/g, '')
                );
                const parentSpkiDer = extractSpkiFromCertDer(parentCertDer);
                const curveInfo = extractEcCurveFromSpki(parentSpkiDer);
                
                const childTbsAndSig = extractTbsAndSigFromCertDer(childCertDer);
                const hashAlg = sigAlgOidToHash(childTbsAndSig.sigAlgOid);
                
                let tbsCertHash;
                if (isBrowser) {
                    tbsCertHash = await window.crypto.subtle.digest(hashAlg, tbsCert);
                } else {
                    const cryptoModule = require('crypto');
                    tbsCertHash = await cryptoModule.webcrypto.subtle.digest(hashAlg, tbsCert);
                }
                const tbsCertHashArray = Array.from(new Uint8Array(tbsCertHash));
                
                const parentPubKeyBytes = extractEcdsaPublicKeyFromPem(parentCertPem);
                const uncompressedMarker = parentPubKeyBytes.indexOf(0x04);
                if (uncompressedMarker === -1) {
                    throw new Error('Cannot find uncompressed point marker in parent certificate public key');
                }
                
                const coordStart = uncompressedMarker + 1;
                const coordSize = curveInfo.coordSize;
                
                const pubKeyX = ByteUtils.slice(parentPubKeyBytes, coordStart, coordStart + coordSize);
                const pubKeyY = ByteUtils.slice(parentPubKeyBytes, coordStart + coordSize, coordStart + coordSize * 2);
                
                const EC = elliptic.ec;
                const ec = new EC(curveInfo.ellipticName);
                
                const key = ec.keyFromPublic({
                    x: ByteUtils.toHex(pubKeyX),
                    y: ByteUtils.toHex(pubKeyY)
                }, 'hex');
                
                const verified = key.verify(tbsCertHashArray, { r: derSig.r, s: derSig.s });
                
                if (!verified) {
                    throw new Error(`Intel issuer certificate ${i} ECDSA signature verification failed using certificate ${i + 1}`);
                }
                
                console.info(`Intel issuer certificate ${i} ECDSA signature verified by certificate ${i + 1}`);
            } else {
                throw e;
            }
        }
    }
    
    // Step 2: Verify trust anchor - the last certificate must be or be signed by a trusted Intel SGX Root CA
    const rootCandidate = issuerCerts[issuerCerts.length - 1];
    
    const trustedRootPems = [];
    for (const key in INTEL_SGX_ROOT_CA_CERTS) {
        trustedRootPems.push(INTEL_SGX_ROOT_CA_CERTS[key]);
    }
    
    const rootCandidateDer = ByteUtils.fromBase64(
        rootCandidate.replace(/-----BEGIN CERTIFICATE-----/, '')
                    .replace(/-----END CERTIFICATE-----/, '')
                    .replace(/\s/g, '')
    );
    
    let rootCandidateTbsAndSig;
    try {
        rootCandidateTbsAndSig = extractTbsAndSigFromCertDer(rootCandidateDer);
    } catch (e) {
        console.warn('Failed to extract TBS and signature from root candidate:', e.message);
        throw new Error('Intel issuer chain not anchored to trusted Intel SGX Root CA');
    }
    
    const hashAlg = sigAlgOidToHash(rootCandidateTbsAndSig.sigAlgOid);
    
    let isSelfSigned = false;
    let spkiMatchesTrustedRoot = false;
    
    try {
        isSelfSigned = await verifyCertSigNative(
            rootCandidateTbsAndSig.tbsCert,
            rootCandidateTbsAndSig.signature,
            rootCandidate,
            hashAlg
        );
        
        if (isSelfSigned) {
            const rootCandidateSpki = extractSpkiFromCertDer(rootCandidateDer);
            const rootCandidateSpkiHex = ByteUtils.toHex(rootCandidateSpki);
            
            for (const trustedRootPem of trustedRootPems) {
                try {
                    const trustedRootDer = ByteUtils.fromBase64(
                        trustedRootPem.replace(/-----BEGIN CERTIFICATE-----/, '')
                                    .replace(/-----END CERTIFICATE-----/, '')
                                    .replace(/\s/g, '')
                    );
                    const trustedRootSpki = extractSpkiFromCertDer(trustedRootDer);
                    const trustedRootSpkiHex = ByteUtils.toHex(trustedRootSpki);
                    
                    if (rootCandidateSpkiHex === trustedRootSpkiHex) {
                        spkiMatchesTrustedRoot = true;
                        break;
                    }
                } catch (e) {
                    console.warn('Failed to extract SPKI from trusted root:', e.message);
                    continue;
                }
            }
            
            if (!spkiMatchesTrustedRoot) {
                console.warn('Root candidate is self-signed but SPKI does not match any trusted Intel SGX Root CA');
            }
        }
    } catch (e) {
        console.warn('Self-signature verification failed:', e.message);
    }
    
    let signedByTrustedRoot = false;
    let akiSkiMatch = false;
    const rootCandidateAki = extractAuthorityKeyIdentifierFromCert(rootCandidate);
    
    for (const trustedRootPem of trustedRootPems) {
        try {
            let skiMatch = false;
            if (rootCandidateAki) {
                const trustedRootSki = extractSubjectKeyIdentifier(trustedRootPem);
                if (!trustedRootSki) {
                    const trustedRootComputedSki = computeSkiFromSpki(trustedRootPem);
                    if (trustedRootComputedSki) {
                        skiMatch = ByteUtils.equalBytes(rootCandidateAki, trustedRootComputedSki);
                    }
                } else {
                    skiMatch = ByteUtils.equalBytes(rootCandidateAki, trustedRootSki);
                }
                
                if (!skiMatch) {
                    continue;
                }
            }
            
            const verified = await verifyCertSigNative(
                rootCandidateTbsAndSig.tbsCert,
                rootCandidateTbsAndSig.signature,
                trustedRootPem,
                hashAlg
            );
            
            if (verified) {
                signedByTrustedRoot = true;
                akiSkiMatch = skiMatch;
                break;
            }
        } catch (e) {
            console.warn('Native crypto verification failed for trusted root:', e.message);
            continue;
        }
    }
    
    if (isSelfSigned && spkiMatchesTrustedRoot) {
        console.info('Intel issuer chain anchored to trusted Intel SGX Root CA (self-signed root with matching SPKI)');
        return true;
    }
    
    if (signedByTrustedRoot) {
        if (akiSkiMatch) {
            console.info('Intel issuer chain anchored to trusted Intel SGX Root CA (intermediate signed by trusted root, AKI/SKI match)');
        } else {
            console.info('Intel issuer chain anchored to trusted Intel SGX Root CA (intermediate signed by trusted root, signature verified)');
        }
        return true;
    }
    
    throw new Error('Intel issuer chain not anchored to trusted Intel SGX Root CA');
}

/**
 * 解析DER编码的ECDSA签名
 */
function parseDerEcdsaSignature(derBytes) {
    try {
        const binaryStr = ByteUtils.toBinaryString(derBytes);
        const asn1 = forge.asn1.fromDer(forge.util.createBuffer(binaryStr));

        if (asn1.type !== forge.asn1.Type.SEQUENCE || asn1.value.length !== 2) {
            throw new Error('Invalid DER ECDSA signature structure');
        }

        const rAsn1 = asn1.value[0];
        const sAsn1 = asn1.value[1];

        if (rAsn1.type !== forge.asn1.Type.INTEGER || sAsn1.type !== forge.asn1.Type.INTEGER) {
            throw new Error('Invalid DER ECDSA signature: r and s must be INTEGERs');
        }

        const rBytes = ByteUtils.fromBinaryString(rAsn1.value);
        const sBytes = ByteUtils.fromBinaryString(sAsn1.value);

        let rHex = ByteUtils.toHex(rBytes);
        let sHex = ByteUtils.toHex(sBytes);

        while (rHex.length > 64 && rHex.startsWith('00')) {
            rHex = rHex.substring(2);
        }
        while (sHex.length > 64 && sHex.startsWith('00')) {
            sHex = sHex.substring(2);
        }

        return { r: rHex, s: sHex };
    } catch (error) {
        throw new Error(`Failed to parse DER ECDSA signature: ${error.message}`);
    }
}

/**
 * Convert DER ECDSA signature to IEEE P1363 format (fixed-width r||s)
 * @param {Uint8Array} derSig - DER encoded signature
 * @param {number} coordSize - Coordinate size in bytes (32 for P-256, 48 for P-384, 66 for P-521)
 * @returns {Uint8Array} IEEE P1363 format signature
 */
function derSigToP1363(derSig, coordSize = 32) {
    const parsed = parseDerEcdsaSignature(derSig);
    
    const rHex = parsed.r.padStart(coordSize * 2, '0');
    const sHex = parsed.s.padStart(coordSize * 2, '0');
    
    const rBytes = ByteUtils.fromHex(rHex);
    const sBytes = ByteUtils.fromHex(sHex);
    
    return ByteUtils.concat([rBytes, sBytes]);
}

/**
 * Extract TBSCertificate and signature from certificate DER
 * @param {Uint8Array} certDer - Certificate in DER format
 * @returns {Object} {tbsCert: Uint8Array, signature: Uint8Array, sigAlgOid: string}
 */
function extractTbsAndSigFromCertDer(certDer) {
    const readLength = (data, offset) => {
        if (data[offset] < 0x80) {
            return { length: data[offset], bytes: 1 };
        }
        const numBytes = data[offset] & 0x7f;
        let length = 0;
        for (let i = 0; i < numBytes; i++) {
            length = (length << 8) | data[offset + 1 + i];
        }
        return { length, bytes: 1 + numBytes };
    };
    
    let offset = 0;
    if (certDer[offset] !== 0x30) {
        throw new Error('Invalid certificate DER structure');
    }
    offset++;
    
    const certLen = readLength(certDer, offset);
    offset += certLen.bytes;
    
    const tbsCertStart = offset;
    if (certDer[offset] !== 0x30) {
        throw new Error('Invalid TBSCertificate structure');
    }
    offset++;
    const tbsCertLen = readLength(certDer, offset);
    offset += tbsCertLen.bytes;
    const tbsCertEnd = offset + tbsCertLen.length;
    
    const tbsCert = ByteUtils.slice(certDer, tbsCertStart, tbsCertEnd);
    
    offset = tbsCertEnd;
    if (certDer[offset] !== 0x30) {
        throw new Error('Invalid signatureAlgorithm structure');
    }
    offset++;
    const sigAlgLen = readLength(certDer, offset);
    offset += sigAlgLen.bytes;
    
    const sigAlgStart = offset;
    if (certDer[offset] !== 0x06) {
        throw new Error('Expected OID in signatureAlgorithm');
    }
    offset++;
    const oidLen = certDer[offset];
    offset++;
    const oidBytes = ByteUtils.slice(certDer, offset, offset + oidLen);
    const sigAlgOid = ByteUtils.toHex(oidBytes);
    
    offset = sigAlgStart + sigAlgLen.length;
    
    if (certDer[offset] !== 0x03) {
        throw new Error('Invalid signature BIT STRING');
    }
    offset++;
    const sigLen = readLength(certDer, offset);
    offset += sigLen.bytes;
    
    if (certDer[offset] !== 0x00) {
        throw new Error('Invalid BIT STRING padding');
    }
    offset++;
    
    const signature = ByteUtils.slice(certDer, offset, offset + sigLen.length - 1);
    
    return { tbsCert, signature, sigAlgOid };
}

/**
 * Map signature algorithm OID to hash algorithm name
 * @param {string} oidHex - OID in hex format
 * @returns {string} Hash algorithm name (e.g., 'SHA-256', 'SHA-384', 'SHA-512')
 */
function sigAlgOidToHash(oidHex) {
    const oidMap = {
        '2a8648ce3d040302': 'SHA-256',  // ecdsa-with-SHA256 (1.2.840.10045.4.3.2)
        '2a8648ce3d040303': 'SHA-384',  // ecdsa-with-SHA384 (1.2.840.10045.4.3.3)
        '2a8648ce3d040304': 'SHA-512',  // ecdsa-with-SHA512 (1.2.840.10045.4.3.4)
        '2a864886f70d010105': 'SHA-1',  // sha1WithRSAEncryption (1.2.840.113549.1.1.5)
        '2a864886f70d01010b': 'SHA-256', // sha256WithRSAEncryption (1.2.840.113549.1.1.11)
        '2a864886f70d01010c': 'SHA-384', // sha384WithRSAEncryption (1.2.840.113549.1.1.12)
        '2a864886f70d01010d': 'SHA-512', // sha512WithRSAEncryption (1.2.840.113549.1.1.13)
    };
    
    return oidMap[oidHex] || 'SHA-256'; // Default to SHA-256
}

/**
 * Verify certificate signature using native Node.js crypto or WebCrypto
 * @param {Uint8Array} tbsCert - TBSCertificate bytes
 * @param {Uint8Array} signature - Signature bytes (DER format)
 * @param {string} parentPem - Parent certificate PEM
 * @param {string} hashAlg - Hash algorithm name (e.g., 'SHA-256')
 * @returns {Promise<boolean>} True if signature is valid
 */
async function verifyCertSigNative(tbsCert, signature, parentPem, hashAlg) {
    if (!isBrowser) {
        // Node.js environment
        const crypto = require('crypto');
        
        try {
            const webcrypto = crypto.webcrypto || crypto;
            
            const parentDer = ByteUtils.fromBase64(
                parentPem.replace(/-----BEGIN CERTIFICATE-----/, '')
                        .replace(/-----END CERTIFICATE-----/, '')
                        .replace(/\s/g, '')
            );
            
            const spkiDer = extractSpkiFromCertDer(parentDer);
            const curveInfo = extractEcCurveFromSpki(spkiDer);
            
            const parentKey = await webcrypto.subtle.importKey(
                'spki',
                spkiDer,
                { name: 'ECDSA', namedCurve: curveInfo.namedCurve },
                false,
                ['verify']
            );
            
            const sigP1363 = derSigToP1363(signature, curveInfo.coordSize);
            
            const verified = await webcrypto.subtle.verify(
                { name: 'ECDSA', hash: { name: hashAlg } },
                parentKey,
                sigP1363,
                tbsCert
            );
            
            return verified;
        } catch (e) {
            console.warn('WebCrypto verification failed, trying Node crypto.verify:', e.message);
            
            try {
                const verify = crypto.createVerify(hashAlg);
                verify.update(tbsCert);
                verify.end();
                
                const verified = verify.verify(parentPem, signature);
                return verified;
            } catch (e2) {
                console.warn('Node crypto.verify failed:', e2.message);
                return false;
            }
        }
    } else {
        try {
            const parentDer = ByteUtils.fromBase64(
                parentPem.replace(/-----BEGIN CERTIFICATE-----/, '')
                        .replace(/-----END CERTIFICATE-----/, '')
                        .replace(/\s/g, '')
            );
            
            const spkiDer = extractSpkiFromCertDer(parentDer);
            const curveInfo = extractEcCurveFromSpki(spkiDer);
            
            const parentKey = await window.crypto.subtle.importKey(
                'spki',
                spkiDer,
                { name: 'ECDSA', namedCurve: curveInfo.namedCurve },
                false,
                ['verify']
            );
            
            const sigP1363 = derSigToP1363(signature, curveInfo.coordSize);
            
            const verified = await window.crypto.subtle.verify(
                { name: 'ECDSA', hash: { name: hashAlg } },
                parentKey,
                sigP1363,
                tbsCert
            );
            
            return verified;
        } catch (e) {
            console.warn('Browser WebCrypto verification failed:', e.message);
            return false;
        }
    }
}

/**
 * Extract EC curve information from SPKI
 * @param {Uint8Array} spkiDer - SPKI in DER format
 * @returns {Object} {namedCurve: string, ellipticName: string, coordSize: number}
 */
function extractEcCurveFromSpki(spkiDer) {
    const readLength = (data, offset) => {
        if (data[offset] < 0x80) {
            return { length: data[offset], bytes: 1 };
        }
        const numBytes = data[offset] & 0x7f;
        let length = 0;
        for (let i = 0; i < numBytes; i++) {
            length = (length << 8) | data[offset + 1 + i];
        }
        return { length, bytes: 1 + numBytes };
    };
    
    let offset = 0;
    
    if (spkiDer[offset] !== 0x30) throw new Error('Invalid SPKI structure');
    offset++;
    const spkiLen = readLength(spkiDer, offset);
    offset += spkiLen.bytes;
    
    if (spkiDer[offset] !== 0x30) throw new Error('Expected AlgorithmIdentifier');
    offset++;
    const algIdLen = readLength(spkiDer, offset);
    offset += algIdLen.bytes;
    
    if (spkiDer[offset] !== 0x06) throw new Error('Expected algorithm OID');
    offset++;
    const algOidLen = spkiDer[offset];
    offset++;
    const algOidBytes = ByteUtils.slice(spkiDer, offset, offset + algOidLen);
    const algOidHex = ByteUtils.toHex(algOidBytes);
    offset += algOidLen;
    
    if (algOidHex !== '2a8648ce3d0201') {
        return { namedCurve: 'P-256', ellipticName: 'p256', coordSize: 32 };
    }
    
    if (spkiDer[offset] !== 0x06) throw new Error('Expected namedCurve OID');
    offset++;
    const curveOidLen = spkiDer[offset];
    offset++;
    const curveOidBytes = ByteUtils.slice(spkiDer, offset, offset + curveOidLen);
    const curveOidHex = ByteUtils.toHex(curveOidBytes);
    
    const curveMap = {
        '2a8648ce3d030107': { namedCurve: 'P-256', ellipticName: 'p256', coordSize: 32 },
        '2b81040022': { namedCurve: 'P-384', ellipticName: 'p384', coordSize: 48 },
        '2b81040023': { namedCurve: 'P-521', ellipticName: 'p521', coordSize: 66 }
    };
    
    return curveMap[curveOidHex] || { namedCurve: 'P-256', ellipticName: 'p256', coordSize: 32 };
}

/**
 * Extract SubjectPublicKeyInfo (SPKI) from certificate DER
 * @param {Uint8Array} certDer - Certificate in DER format
 * @returns {Uint8Array} SPKI in DER format
 */
function extractSpkiFromCertDer(certDer) {
    const readLength = (data, offset) => {
        if (data[offset] < 0x80) {
            return { length: data[offset], bytes: 1 };
        }
        const numBytes = data[offset] & 0x7f;
        let length = 0;
        for (let i = 0; i < numBytes; i++) {
            length = (length << 8) | data[offset + 1 + i];
        }
        return { length, bytes: 1 + numBytes };
    };
    
    let offset = 0;
    
    if (certDer[offset] !== 0x30) throw new Error('Invalid cert DER');
    offset++;
    const certLen = readLength(certDer, offset);
    offset += certLen.bytes;
    
    if (certDer[offset] !== 0x30) throw new Error('Invalid TBSCertificate');
    offset++;
    const tbsLen = readLength(certDer, offset);
    offset += tbsLen.bytes;
    
    if (certDer[offset] === 0xa0) {
        offset++;
        const versionLen = readLength(certDer, offset);
        offset += versionLen.bytes + versionLen.length;
    }
    
    if (certDer[offset] !== 0x02) throw new Error('Expected serialNumber');
    offset++;
    const serialLen = readLength(certDer, offset);
    offset += serialLen.bytes + serialLen.length;
    
    if (certDer[offset] !== 0x30) throw new Error('Expected signature algorithm');
    offset++;
    const sigAlgLen = readLength(certDer, offset);
    offset += sigAlgLen.bytes + sigAlgLen.length;
    
    if (certDer[offset] !== 0x30) throw new Error('Expected issuer');
    offset++;
    const issuerLen = readLength(certDer, offset);
    offset += issuerLen.bytes + issuerLen.length;
    
    if (certDer[offset] !== 0x30) throw new Error('Expected validity');
    offset++;
    const validityLen = readLength(certDer, offset);
    offset += validityLen.bytes + validityLen.length;
    
    if (certDer[offset] !== 0x30) throw new Error('Expected subject');
    offset++;
    const subjectLen = readLength(certDer, offset);
    offset += subjectLen.bytes + subjectLen.length;
    
    const spkiStart = offset;
    if (certDer[offset] !== 0x30) throw new Error('Expected SPKI');
    offset++;
    const spkiLen = readLength(certDer, offset);
    offset += spkiLen.bytes;
    
    const spkiEnd = offset + spkiLen.length;
    return ByteUtils.slice(certDer, spkiStart, spkiEnd);
}

/**
 * 获取证书的Issuer CN
 */
function getIssuerCN(cert) {
    if (!cert.issuer || !cert.issuer.attributes) {
        return '';
    }

    for (const attr of cert.issuer.attributes) {
        if (attr.shortName === 'CN' || attr.name === 'commonName') {
            return attr.value;
        }
    }

    return '';
}

/**
 * 从quote中提取FMSPC
 * FMSPC是平台的Family-Model-Stepping-Platform-CustomSKU标识符
 */
function extractFmspc(quoteData) {
    // 方法1: 从PCK证书扩展中提取
    if (quoteData.certChain && quoteData.certChain.length > 0) {
        try {
            const pckCertPem = quoteData.certChain[0];
            const fmspcExtValue = getExtensionFromPemViaAsn1(pckCertPem, '1.2.840.113741.1.13.1.4');

            if (fmspcExtValue) {
                const fmspcBytes = ByteUtils.toBytes(fmspcExtValue);
                return ByteUtils.toHex(fmspcBytes).toUpperCase();
            }
        } catch (error) {
            console.warn('Failed to extract FMSPC from PCK cert:', error.message);
        }
    }

    throw new Error('Cannot extract FMSPC from quote - PCK certificate not available or missing FMSPC extension');
}

/**
 * 从quote中提取QE ID
 */
function extractSubjectKeyIdentifier(certPem) {
    const certDer = ByteUtils.fromBase64(
        certPem.replace(/-----BEGIN CERTIFICATE-----/, '')
                  .replace(/-----END CERTIFICATE-----/, '')
                  .replace(/\s/g, '')
    );
    
    const skiOid = [0x55, 0x1d, 0x0e];
    
    try {
        const ski = extractExtensionByOid(certDer, skiOid);
        if (ski && ski.length > 2) {
            if (ski[0] === 0x04) {
                const skiLen = ski[1];
                return ByteUtils.slice(ski, 2, 2 + skiLen);
            }
        }
    } catch (e) {
    }
    
    return null;
}

/**
 * Extract Authority Key Identifier from certificate
 * @param {string} certPem - Certificate in PEM format
 * @returns {Uint8Array|null} AKI key identifier or null
 */
function extractAuthorityKeyIdentifierFromCert(certPem) {
    const certDer = ByteUtils.fromBase64(
        certPem.replace(/-----BEGIN CERTIFICATE-----/, '')
                  .replace(/-----END CERTIFICATE-----/, '')
                  .replace(/\s/g, '')
    );
    
    const akiOid = [0x55, 0x1d, 0x23];
    
    try {
        const aki = extractExtensionByOid(certDer, akiOid);
        if (!aki || aki.length < 4) {
            return null;
        }
        
        let offset = 0;
        if (aki[offset] !== 0x30) {
            return null;
        }
        offset++;
        
        const seqLen = aki[offset] < 0x80 ? aki[offset] : 
                      (aki[offset] === 0x81 ? aki[offset + 1] : 
                       ((aki[offset + 1] << 8) | aki[offset + 2]));
        offset += aki[offset] < 0x80 ? 1 : (aki[offset] === 0x81 ? 2 : 3);
        
        if (aki[offset] === 0x80) {
            offset++;
            const keyIdLen = aki[offset];
            offset++;
            return ByteUtils.slice(aki, offset, offset + keyIdLen);
        }
    } catch (e) {
    }
    
    return null;
}

function extractAuthorityKeyIdentifier(crlPem) {
    const crlDer = ByteUtils.fromBase64(
        crlPem.replace(/-----BEGIN X509 CRL-----/, '')
                  .replace(/-----END X509 CRL-----/, '')
                  .replace(/\s/g, '')
    );
    
    const parsed = parseCrlDer(crlDer);
    if (!parsed) {
        return null;
    }
    
    if (!parsed.extensions || parsed.extensions.length === 0) {
        return null;
    }
    
    const akiOid = [0x55, 0x1d, 0x23];
    for (const ext of parsed.extensions) {
        if (ByteUtils.equalBytes(ext.oid, akiOid)) {
            const value = ext.value;
            if (!value || value.length < 4) {
                continue;
            }
            
            let offset = 0;
            if (value[offset] !== 0x30) {
                continue;
            }
            offset++;
            
            const seqLen = value[offset] < 0x80 ? value[offset] : 
                          (value[offset] === 0x81 ? value[offset + 1] : 
                           ((value[offset + 1] << 8) | value[offset + 2]));
            offset += value[offset] < 0x80 ? 1 : (value[offset] === 0x81 ? 2 : 3);
            
            if (value[offset] === 0x80) {
                offset++;
                const keyIdLen = value[offset];
                offset++;
                return ByteUtils.slice(value, offset, offset + keyIdLen);
            } else if (value[offset] === 0xa0) {
                offset++;
                const constructedLen = value[offset];
                offset++;
                if (value[offset] === 0x04) {
                    offset++;
                    const keyIdLen = value[offset];
                    offset++;
                    return ByteUtils.slice(value, offset, offset + keyIdLen);
                }
            }
        }
    }
    
    return null;
}

function parseCrlDer(crlDer) {
    const readLength = (data, offset) => {
        if (data[offset] < 0x80) {
            return { length: data[offset], bytes: 1 };
        }
        const numBytes = data[offset] & 0x7f;
        let length = 0;
        for (let i = 0; i < numBytes; i++) {
            length = (length << 8) | data[offset + 1 + i];
        }
        return { length, bytes: 1 + numBytes };
    };
    
    let offset = 0;
    if (crlDer[offset] !== 0x30) return null;
    offset++;
    const outerLen = readLength(crlDer, offset);
    offset += outerLen.bytes;
    
    const tbsCertListStart = offset;
    if (crlDer[offset] !== 0x30) return null;
    offset++;
    const tbsCertListLen = readLength(crlDer, offset);
    offset += tbsCertListLen.bytes;
    const tbsCertListEnd = offset + tbsCertListLen.length;
    const tbsCertList = ByteUtils.slice(crlDer, tbsCertListStart, tbsCertListEnd);
    
    let currentOffset = offset;
    
    if (crlDer[currentOffset] === 0x02) {
        currentOffset++;
        const versionLen = readLength(crlDer, currentOffset);
        currentOffset += versionLen.bytes + versionLen.length;
    }
    
    if (crlDer[currentOffset] !== 0x30) return null;
    currentOffset++;
    const sigAlgLen = readLength(crlDer, currentOffset);
    currentOffset += sigAlgLen.bytes + sigAlgLen.length;
    
    if (crlDer[currentOffset] !== 0x30) return null;
    currentOffset++;
    const issuerLen = readLength(crlDer, currentOffset);
    currentOffset += issuerLen.bytes + issuerLen.length;
    
    if (crlDer[currentOffset] === 0x17 || crlDer[currentOffset] === 0x18) {
        currentOffset++;
        const thisUpdateLen = readLength(crlDer, currentOffset);
        currentOffset += thisUpdateLen.bytes + thisUpdateLen.length;
    }
    
    if (crlDer[currentOffset] === 0x17 || crlDer[currentOffset] === 0x18) {
        currentOffset++;
        const nextUpdateLen = readLength(crlDer, currentOffset);
        currentOffset += nextUpdateLen.bytes + nextUpdateLen.length;
    }
    
    const revokedCerts = [];
    if (currentOffset < tbsCertListEnd && crlDer[currentOffset] === 0x30) {
        currentOffset++;
        const revokedSeqLen = readLength(crlDer, currentOffset);
        currentOffset += revokedSeqLen.bytes;
        const revokedSeqEnd = currentOffset + revokedSeqLen.length;
        
        while (currentOffset < revokedSeqEnd) {
            if (crlDer[currentOffset] !== 0x30) break;
            currentOffset++;
            const entryLen = readLength(crlDer, currentOffset);
            currentOffset += entryLen.bytes;
            
            if (crlDer[currentOffset] === 0x02) {
                currentOffset++;
                const serialLen = readLength(crlDer, currentOffset);
                currentOffset += serialLen.bytes;
                const serialBytes = ByteUtils.slice(crlDer, currentOffset, currentOffset + serialLen.length);
                revokedCerts.push(normalizeSerial(serialBytes));
                currentOffset += serialLen.length;
            }
            
            currentOffset = Math.min(currentOffset + entryLen.length, revokedSeqEnd);
        }
    }
    
    const extensions = [];
    if (currentOffset < tbsCertListEnd && crlDer[currentOffset] === 0xa0) {
        currentOffset++;
        const extSeqLen = readLength(crlDer, currentOffset);
        currentOffset += extSeqLen.bytes;
        
        if (crlDer[currentOffset] === 0x30) {
            currentOffset++;
            const extListLen = readLength(crlDer, currentOffset);
            currentOffset += extListLen.bytes;
            const extListEnd = currentOffset + extListLen.length;
            
            while (currentOffset < extListEnd) {
                if (crlDer[currentOffset] !== 0x30) break;
                currentOffset++;
                const extLen = readLength(crlDer, currentOffset);
                currentOffset += extLen.bytes;
                const extEnd = currentOffset + extLen.length;
                
                if (crlDer[currentOffset] === 0x06) {
                    currentOffset++;
                    const oidLen = readLength(crlDer, currentOffset);
                    currentOffset += oidLen.bytes;
                    const oid = ByteUtils.slice(crlDer, currentOffset, currentOffset + oidLen.length);
                    currentOffset += oidLen.length;
                    
                    if (crlDer[currentOffset] === 0x01) {
                        currentOffset++;
                        const criticalLen = readLength(crlDer, currentOffset);
                        currentOffset += criticalLen.bytes + criticalLen.length;
                    }
                    
                    if (crlDer[currentOffset] === 0x04) {
                        currentOffset++;
                        const valueLen = readLength(crlDer, currentOffset);
                        currentOffset += valueLen.bytes;
                        const value = ByteUtils.slice(crlDer, currentOffset, currentOffset + valueLen.length);
                        extensions.push({ oid, value });
                    }
                }
                
                currentOffset = extEnd;
            }
        }
    }
    
    offset = tbsCertListEnd;
    if (crlDer[offset] !== 0x30) return null;
    offset++;
    const sigAlgLen2 = readLength(crlDer, offset);
    offset += sigAlgLen2.bytes + sigAlgLen2.length;
    
    if (crlDer[offset] !== 0x03) return null;
    offset++;
    const sigLen = readLength(crlDer, offset);
    offset += sigLen.bytes;
    if (crlDer[offset] !== 0x00) return null;
    offset++;
    const signature = ByteUtils.slice(crlDer, offset, offset + sigLen.length - 1);
    
    return {
        tbsCertList,
        signature,
        revokedCerts,
        extensions
    };
}

function getCertSerialHex(certPem) {
    const certDer = ByteUtils.fromBase64(
        certPem.replace(/-----BEGIN CERTIFICATE-----/, '')
                  .replace(/-----END CERTIFICATE-----/, '')
                  .replace(/\s/g, '')
    );
    
    const readLength = (data, offset) => {
        if (data[offset] < 0x80) {
            return { length: data[offset], bytes: 1 };
        }
        const numBytes = data[offset] & 0x7f;
        let length = 0;
        for (let i = 0; i < numBytes; i++) {
            length = (length << 8) | data[offset + 1 + i];
        }
        return { length, bytes: 1 + numBytes };
    };
    
    let offset = 0;
    if (certDer[offset] !== 0x30) return null;
    offset++;
    const certLen = readLength(certDer, offset);
    offset += certLen.bytes;
    
    if (certDer[offset] !== 0x30) return null;
    offset++;
    const tbsLen = readLength(certDer, offset);
    offset += tbsLen.bytes;
    
    if (certDer[offset] === 0xa0) {
        offset++;
        const versionLen = readLength(certDer, offset);
        offset += versionLen.bytes + versionLen.length;
    }
    
    if (certDer[offset] !== 0x02) return null;
    offset++;
    const serialLen = readLength(certDer, offset);
    offset += serialLen.bytes;
    const serialBytes = ByteUtils.slice(certDer, offset, offset + serialLen.length);
    
    return normalizeSerial(serialBytes);
}

function normalizeSerial(serialBytes) {
    let start = 0;
    while (start < serialBytes.length && serialBytes[start] === 0x00) {
        start++;
    }
    const normalized = ByteUtils.slice(serialBytes, start, serialBytes.length);
    return ByteUtils.toHex(normalized).toLowerCase();
}

function computeSkiFromSpki(certPem) {
    const certDer = ByteUtils.fromBase64(
        certPem.replace(/-----BEGIN CERTIFICATE-----/, '')
                  .replace(/-----END CERTIFICATE-----/, '')
                  .replace(/\s/g, '')
    );
    
    const readLength = (data, offset) => {
        if (data[offset] < 0x80) {
            return { length: data[offset], bytes: 1 };
        }
        const numBytes = data[offset] & 0x7f;
        let length = 0;
        for (let i = 0; i < numBytes; i++) {
            length = (length << 8) | data[offset + 1 + i];
        }
        return { length, bytes: 1 + numBytes };
    };
    
    let offset = 0;
    if (certDer[offset] !== 0x30) return null;
    offset++;
    const certLen = readLength(certDer, offset);
    offset += certLen.bytes;
    
    const tbsStart = offset;
    if (certDer[offset] !== 0x30) return null;
    offset++;
    const tbsLen = readLength(certDer, offset);
    offset += tbsLen.bytes;
    
    if (certDer[offset] === 0xa0) {
        offset++;
        const versionLen = readLength(certDer, offset);
        offset += versionLen.bytes + versionLen.length;
    }
    
    if (certDer[offset] !== 0x02) return null;
    offset++;
    const serialLen = readLength(certDer, offset);
    offset += serialLen.bytes + serialLen.length;
    
    if (certDer[offset] !== 0x30) return null;
    offset++;
    const sigAlgLen = readLength(certDer, offset);
    offset += sigAlgLen.bytes + sigAlgLen.length;
    
    if (certDer[offset] !== 0x30) return null;
    offset++;
    const issuerLen = readLength(certDer, offset);
    offset += issuerLen.bytes + issuerLen.length;
    
    if (certDer[offset] !== 0x30) return null;
    offset++;
    const validityLen = readLength(certDer, offset);
    offset += validityLen.bytes + validityLen.length;
    
    if (certDer[offset] !== 0x30) return null;
    offset++;
    const subjectLen = readLength(certDer, offset);
    offset += subjectLen.bytes + subjectLen.length;
    
    if (certDer[offset] !== 0x30) return null;
    const spkiStart = offset;
    offset++;
    const spkiLen = readLength(certDer, offset);
    offset += spkiLen.bytes;
    
    offset = spkiStart + 1;
    const spkiSeqLen = readLength(certDer, offset);
    offset += spkiSeqLen.bytes;
    
    if (certDer[offset] !== 0x30) return null;
    offset++;
    const algLen = readLength(certDer, offset);
    offset += algLen.bytes + algLen.length;
    
    if (certDer[offset] !== 0x03) return null;
    offset++;
    const pubKeyLen = readLength(certDer, offset);
    offset += pubKeyLen.bytes;
    if (certDer[offset] !== 0x00) return null;
    offset++;
    
    const subjectPublicKey = ByteUtils.slice(certDer, offset, offset + pubKeyLen.length - 1);
    
    if (isBrowser) {
        return window.crypto.subtle.digest('SHA-1', subjectPublicKey);
    } else {
        const crypto = require('crypto');
        const hash = crypto.createHash('sha1');
        hash.update(Buffer.from(subjectPublicKey));
        return Promise.resolve(hash.digest());
    }
}

function extractQeId(quoteData) {
    if (quoteData.certChain && quoteData.certChain.length > 0) {
        try {
            const pckCertPem = quoteData.certChain[0];
            const qeIdExtValue = getExtensionFromPemViaAsn1(pckCertPem, '1.2.840.113741.1.13.1.3');

            if (qeIdExtValue) {
                const qeIdBytes = ByteUtils.toBytes(qeIdExtValue);
                return ByteUtils.toHex(qeIdBytes);
            }
        } catch (error) {
            console.warn('Failed to extract QE ID from PCK cert:', error.message);
        }
    }

    if (quoteData.qeSvn !== undefined) {
        return `qe_svn_${quoteData.qeSvn}`;
    }

    return 'default';
}

/**
 * 解析PEM格式的证书链
 */
function parsePemCertChain(pemChain) {
    const certs = [];
    const certRegex = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g;
    const matches = pemChain.match(certRegex);

    if (matches) {
        for (const pemCert of matches) {
            certs.push(pemCert);
        }
    }

    if (certs.length === 0) {
        throw new Error('No valid certificates found in PEM chain');
    }

    return certs;
}

/**
 * 验证证书链
 * 使用node-forge的证书验证API，支持多根证书
 */
async function verifyCertChain(certChain, collateral, trustedRootCAs = null) {
    // 步骤1: 确保有证书链可用
    if (!certChain || certChain.length === 0) {
        if (collateral && collateral.pckCertChain) {
            certChain = collateral.pckCertChain;
        } else {
            throw new Error('No certificate chain available');
        }
    }

    if (!certChain || certChain.length === 0) {
        throw new Error('Certificate chain is empty after fallback');
    }

    let rootCerts = [];
    let rootCertPems = [];
    try {
        if (trustedRootCAs && Array.isArray(trustedRootCAs)) {
            rootCertPems = trustedRootCAs;
        } else {
            // 使用默认的Intel SGX Root CA
            for (const key in INTEL_SGX_ROOT_CA_CERTS) {
                rootCertPems.push(INTEL_SGX_ROOT_CA_CERTS[key]);
            }
        }
        
        for (const rootPem of rootCertPems) {
            try {
                rootCerts.push(forge.pki.certificateFromPem(rootPem));
            } catch (e) {
                if (e.message && e.message.includes('OID is not RSA')) {
                    console.info('Intel SGX Root CA is ECDSA, will use elliptic.js for CRL verification if needed');
                } else {
                    console.warn('Failed to parse root CA:', e.message);
                }
            }
        }
    } catch (e) {
        console.warn('Failed to initialize root certificates:', e.message);
    }

    console.info('Certificate chain present with', certChain.length, 'certificates');
    
    for (let i = 0; i < certChain.length - 1; i++) {
        const childCertPem = certChain[i];
        const parentCertPem = certChain[i + 1];
        
        try {
            const childCert = forge.pki.certificateFromPem(childCertPem);
            const parentCert = forge.pki.certificateFromPem(parentCertPem);
            
            const verified = parentCert.verify(childCert);
            if (!verified) {
                throw new Error(`Certificate ${i} signature verification failed using certificate ${i + 1}`);
            }
            
            console.info(`Certificate ${i} signature verified by certificate ${i + 1}`);
        } catch (e) {
            if (e.message && e.message.includes('OID is not RSA')) {
                const childPubKeyBytes = extractEcdsaPublicKeyFromPem(childCertPem);
                const parentPubKeyBytes = extractEcdsaPublicKeyFromPem(parentCertPem);
                
                console.info(`Certificate ${i} is ECDSA, verifying with elliptic.js`);
                
                const childCertDer = ByteUtils.fromBase64(
                    childCertPem.replace(/-----BEGIN CERTIFICATE-----/, '')
                              .replace(/-----END CERTIFICATE-----/, '')
                              .replace(/\s/g, '')
                );
                
                let offset = 0;
                if (childCertDer[offset] !== 0x30) {
                    throw new Error('Invalid certificate DER structure');
                }
                offset++;
                
                const readLength = (data, offset) => {
                    if (data[offset] < 0x80) {
                        return { length: data[offset], bytes: 1 };
                    }
                    const numBytes = data[offset] & 0x7f;
                    let length = 0;
                    for (let i = 0; i < numBytes; i++) {
                        length = (length << 8) | data[offset + 1 + i];
                    }
                    return { length, bytes: 1 + numBytes };
                };
                
                const certLen = readLength(childCertDer, offset);
                offset += certLen.bytes;
                
                const tbsCertStart = offset;
                if (childCertDer[offset] !== 0x30) {
                    throw new Error('Invalid TBSCertificate structure');
                }
                offset++;
                const tbsCertLen = readLength(childCertDer, offset);
                offset += tbsCertLen.bytes;
                const tbsCertEnd = offset + tbsCertLen.length;
                
                const tbsCert = ByteUtils.slice(childCertDer, tbsCertStart, tbsCertEnd);
                
                offset = tbsCertEnd;
                if (childCertDer[offset] !== 0x30) {
                    throw new Error('Invalid signatureAlgorithm structure');
                }
                offset++;
                const sigAlgLen = readLength(childCertDer, offset);
                offset += sigAlgLen.bytes + sigAlgLen.length;
                
                if (childCertDer[offset] !== 0x03) {
                    throw new Error('Invalid signature BIT STRING');
                }
                offset++;
                const sigLen = readLength(childCertDer, offset);
                offset += sigLen.bytes;
                
                if (childCertDer[offset] !== 0x00) {
                    throw new Error('Invalid BIT STRING padding');
                }
                offset++;
                
                const signatureDer = ByteUtils.slice(childCertDer, offset, offset + sigLen.length - 1);
                
                let derSig;
                try {
                    derSig = parseDerEcdsaSignature(signatureDer);
                } catch (parseError) {
                    throw new Error(`Failed to parse certificate signature: ${parseError.message}`);
                }
                
                // Extract curve info from parent certificate
                const parentCertDer = ByteUtils.fromBase64(
                    parentCertPem.replace(/-----BEGIN CERTIFICATE-----/, '')
                              .replace(/-----END CERTIFICATE-----/, '')
                              .replace(/\s/g, '')
                );
                const parentSpki = extractSpkiFromCertDer(parentCertDer);
                const curveInfo = extractEcCurveFromSpki(parentSpki);
                
                const childTbsAndSig = extractTbsAndSigFromCertDer(childCertDer);
                const hashAlg = sigAlgOidToHash(childTbsAndSig.sigAlgOid);
                
                let tbsCertHash;
                if (isBrowser) {
                    tbsCertHash = await window.crypto.subtle.digest(hashAlg, tbsCert);
                } else {
                    const cryptoModule = require('crypto');
                    tbsCertHash = await cryptoModule.webcrypto.subtle.digest(hashAlg, tbsCert);
                }
                const tbsCertHashArray = Array.from(new Uint8Array(tbsCertHash));
                
                const uncompressedMarker = parentPubKeyBytes.indexOf(0x04);
                if (uncompressedMarker === -1) {
                    throw new Error('Cannot find uncompressed point marker in parent certificate public key');
                }
                
                const coordStart = uncompressedMarker + 1;
                const coordSize = curveInfo.coordSize;
                
                const pubKeyX = ByteUtils.slice(parentPubKeyBytes, coordStart, coordStart + coordSize);
                const pubKeyY = ByteUtils.slice(parentPubKeyBytes, coordStart + coordSize, coordStart + coordSize * 2);
                
                const EC = elliptic.ec;
                const ec = new EC(curveInfo.ellipticName);
                
                const key = ec.keyFromPublic({
                    x: ByteUtils.toHex(pubKeyX),
                    y: ByteUtils.toHex(pubKeyY)
                }, 'hex');
                
                const verified = key.verify(tbsCertHashArray, { r: derSig.r, s: derSig.s });
                
                if (!verified) {
                    throw new Error(`Certificate ${i} ECDSA signature verification failed using certificate ${i + 1}`);
                }
                
                console.info(`Certificate ${i} ECDSA signature verified by certificate ${i + 1}`);
            } else {
                throw e;
            }
        }
    }
    
    console.info('Certificate chain signatures verified successfully');

    if (collateral && collateral.rootCaCrl) {
        console.info('Performing Root CA CRL verification');

        try {
            const crl = forge.pki.certificateRevocationListFromPem(collateral.rootCaCrl);

            let crlVerified = false;
            
            for (const rootCa of rootCerts) {
                try {
                    const verified = rootCa.publicKey.verify(
                        crl.tbsCertList,
                        crl.signature
                    );
                    if (verified) {
                        crlVerified = true;
                        console.info('Root CA CRL signature verified (RSA)');
                        break;
                    }
                } catch (e) {
                }
            }
            
            if (!crlVerified && rootCertPems.length > 0) {
                for (const rootPem of rootCertPems) {
                    try {
                        const rootPubKeyBytes = extractEcdsaPublicKeyFromPem(rootPem);
                        
                        const rootCertDer = ByteUtils.fromBase64(
                            rootPem.replace(/-----BEGIN CERTIFICATE-----/, '')
                                  .replace(/-----END CERTIFICATE-----/, '')
                                  .replace(/\s/g, '')
                        );
                        const rootSpki = extractSpkiFromCertDer(rootCertDer);
                        const curveInfo = extractEcCurveFromSpki(rootSpki);
                        
                        const uncompressedMarker = rootPubKeyBytes.indexOf(0x04);
                        if (uncompressedMarker === -1) {
                            continue;
                        }
                        
                        const coordStart = uncompressedMarker + 1;
                        const coordSize = curveInfo.coordSize;
                        
                        const pubKeyX = ByteUtils.slice(rootPubKeyBytes, coordStart, coordStart + coordSize);
                        const pubKeyY = ByteUtils.slice(rootPubKeyBytes, coordStart + coordSize, coordStart + coordSize * 2);
                        
                        const EC = elliptic.ec;
                        const ec = new EC(curveInfo.ellipticName);
                        
                        const key = ec.keyFromPublic({
                            x: ByteUtils.toHex(pubKeyX),
                            y: ByteUtils.toHex(pubKeyY)
                        }, 'hex');
                        
                        const crlDer = ByteUtils.fromBase64(
                            collateral.rootCaCrl.replace(/-----BEGIN X509 CRL-----/, '')
                                              .replace(/-----END X509 CRL-----/, '')
                                              .replace(/\s/g, '')
                        );
                        
                        let offset = 0;
                        if (crlDer[offset] !== 0x30) {
                            continue;
                        }
                        offset++;
                        
                        const readLength = (data, offset) => {
                            if (data[offset] < 0x80) {
                                return { length: data[offset], bytes: 1 };
                            }
                            const numBytes = data[offset] & 0x7f;
                            let length = 0;
                            for (let i = 0; i < numBytes; i++) {
                                length = (length << 8) | data[offset + 1 + i];
                            }
                            return { length, bytes: 1 + numBytes };
                        };
                        
                        const crlLen = readLength(crlDer, offset);
                        offset += crlLen.bytes;
                        
                        const tbsCertListStart = offset;
                        if (crlDer[offset] !== 0x30) {
                            continue;
                        }
                        offset++;
                        const tbsCertListLen = readLength(crlDer, offset);
                        offset += tbsCertListLen.bytes;
                        const tbsCertListEnd = offset + tbsCertListLen.length;
                        
                        const tbsCertList = ByteUtils.slice(crlDer, tbsCertListStart, tbsCertListEnd);
                        
                        offset = tbsCertListEnd;
                        if (crlDer[offset] !== 0x30) {
                            continue;
                        }
                        offset++;
                        const sigAlgLen = readLength(crlDer, offset);
                        offset += sigAlgLen.bytes + sigAlgLen.length;
                        
                        if (crlDer[offset] !== 0x03) {
                            continue;
                        }
                        offset++;
                        const sigLen = readLength(crlDer, offset);
                        offset += sigLen.bytes;
                        
                        if (crlDer[offset] !== 0x00) {
                            continue;
                        }
                        offset++;
                        
                        const signatureDer = ByteUtils.slice(crlDer, offset, offset + sigLen.length - 1);
                        
                        let derSig;
                        try {
                            derSig = parseDerEcdsaSignature(signatureDer);
                        } catch (parseError) {
                            continue;
                        }
                        
                        const hashAlg = coordSize === 32 ? 'SHA-256' : coordSize === 48 ? 'SHA-384' : 'SHA-512';
                        
                        let tbsCertListHash;
                        if (isBrowser) {
                            tbsCertListHash = await window.crypto.subtle.digest(hashAlg, tbsCertList);
                        } else {
                            const cryptoModule = require('crypto');
                            tbsCertListHash = await cryptoModule.webcrypto.subtle.digest(hashAlg, tbsCertList);
                        }
                        const tbsCertListHashArray = Array.from(new Uint8Array(tbsCertListHash));
                        
                        const verified = key.verify(tbsCertListHashArray, { r: derSig.r, s: derSig.s });
                        
                        if (verified) {
                            crlVerified = true;
                            console.info('Root CA CRL signature verified (ECDSA)');
                            break;
                        }
                    } catch (e) {
                    }
                }
            }

            if (!crlVerified) {
                throw new Error('Root CA CRL signature verification failed with all root CAs');
            }

            const now = new Date();
            if (crl.thisUpdate && now < crl.thisUpdate) {
                throw new Error(`CRL is not yet valid (thisUpdate: ${crl.thisUpdate})`);
            }
            if (crl.nextUpdate && now > crl.nextUpdate) {
                console.warn(`WARNING: CRL is outdated (nextUpdate: ${crl.nextUpdate})`);
            }

            for (let i = 0; i < certChain.length; i++) {
                const cert = certChain[i];
                const revokedCert = crl.getRevokedCertificate(cert.serialNumber);

                if (revokedCert) {
                    throw new Error(
                        `Certificate ${i} (serial: ${cert.serialNumber}) has been revoked. ` +
                        `Revocation date: ${revokedCert.revocationDate}`
                    );
                }
            }

            console.info('Root CA CRL verification completed successfully');
        } catch (error) {
            throw new Error(`Root CA CRL verification failed: ${error.message}`);
        }
    } else {
        console.warn('WARNING: No Root CA CRL provided, skipping root revocation check');
    }

    if (collateral && collateral.pckCrls) {
        console.info('Performing PCK CRL verification');

        const pckCertPem = certChain[0];
        const issuerCertPem = certChain.length > 1 ? certChain[1] : null;

        if (!issuerCertPem) {
            console.warn('WARNING: No issuer certificate available for PCK CRL verification');
        } else {
            try {
                let issuerSki = extractSubjectKeyIdentifier(issuerCertPem);
                if (!issuerSki) {
                    const skiHash = await computeSkiFromSpki(issuerCertPem);
                    issuerSki = Array.from(new Uint8Array(skiHash));
                }
                
                const crlCandidates = [
                    { pem: collateral.pckCrls.processor, type: 'Processor' },
                    { pem: collateral.pckCrls.platform, type: 'Platform' }
                ];

                let matchedCrl = null;
                let matchedType = '';

                for (const candidate of crlCandidates) {
                    if (!candidate.pem) {
                        continue;
                    }

                    try {
                        const crlAki = extractAuthorityKeyIdentifier(candidate.pem);
                        
                        if (crlAki && issuerSki && ByteUtils.equalBytes(crlAki, issuerSki)) {
                            matchedCrl = candidate.pem;
                            matchedType = candidate.type;
                            console.info(`Matched ${candidate.type} PCK CRL via SKI/AKI`);
                            break;
                        }
                    } catch (e) {
                    }
                }

                if (!matchedCrl) {
                    const certDer = ByteUtils.fromBase64(
                        issuerCertPem.replace(/-----BEGIN CERTIFICATE-----/, '')
                                      .replace(/-----END CERTIFICATE-----/, '')
                                      .replace(/\s/g, '')
                    );
                    
                    const readLength = (data, offset) => {
                        if (data[offset] < 0x80) {
                            return { length: data[offset], bytes: 1 };
                        }
                        const numBytes = data[offset] & 0x7f;
                        let length = 0;
                        for (let i = 0; i < numBytes; i++) {
                            length = (length << 8) | data[offset + 1 + i];
                        }
                        return { length, bytes: 1 + numBytes };
                    };
                    
                    try {
                        let offset = 0;
                        if (certDer[offset] !== 0x30) throw new Error('Invalid cert');
                        offset++;
                        const certLen = readLength(certDer, offset);
                        offset += certLen.bytes;
                        
                        if (certDer[offset] !== 0x30) throw new Error('Invalid TBS');
                        offset++;
                        const tbsLen = readLength(certDer, offset);
                        offset += tbsLen.bytes;
                        
                        if (certDer[offset] === 0xa0) {
                            offset++;
                            const versionLen = readLength(certDer, offset);
                            offset += versionLen.bytes + versionLen.length;
                        }
                        
                        if (certDer[offset] !== 0x02) throw new Error('Expected serial');
                        offset++;
                        const serialLen = readLength(certDer, offset);
                        offset += serialLen.bytes + serialLen.length;
                        
                        if (certDer[offset] !== 0x30) throw new Error('Expected sig alg');
                        offset++;
                        const sigAlgLen = readLength(certDer, offset);
                        offset += sigAlgLen.bytes + sigAlgLen.length;
                        
                        if (certDer[offset] !== 0x30) throw new Error('Expected issuer');
                        offset++;
                        const issuerLen = readLength(certDer, offset);
                        offset += issuerLen.bytes + issuerLen.length;
                        
                        if (certDer[offset] !== 0x30) throw new Error('Expected validity');
                        offset++;
                        const validityLen = readLength(certDer, offset);
                        offset += validityLen.bytes + validityLen.length;
                        
                        if (certDer[offset] !== 0x30) throw new Error('Expected subject');
                        offset++;
                        const subjectLen = readLength(certDer, offset);
                        offset += subjectLen.bytes;
                        const subjectEnd = offset + subjectLen.length;
                        
                        let issuerCN = '';
                        const cnOid = [0x55, 0x04, 0x03];
                        
                        while (offset < subjectEnd) {
                            if (certDer[offset] !== 0x31) break;
                            offset++;
                            const setLen = readLength(certDer, offset);
                            offset += setLen.bytes;
                            const setEnd = offset + setLen.length;
                            
                            if (certDer[offset] === 0x30) {
                                offset++;
                                const seqLen = readLength(certDer, offset);
                                offset += seqLen.bytes;
                                
                                if (certDer[offset] === 0x06) {
                                    offset++;
                                    const oidLen = readLength(certDer, offset);
                                    offset += oidLen.bytes;
                                    
                                    let isMatch = true;
                                    for (let i = 0; i < cnOid.length; i++) {
                                        if (certDer[offset + i] !== cnOid[i]) {
                                            isMatch = false;
                                            break;
                                        }
                                    }
                                    offset += oidLen.length;
                                    
                                    if (isMatch && (certDer[offset] === 0x0c || certDer[offset] === 0x13)) {
                                        offset++;
                                        const valueLen = readLength(certDer, offset);
                                        offset += valueLen.bytes;
                                        
                                        const cnBytes = ByteUtils.slice(certDer, offset, offset + valueLen.length);
                                        issuerCN = String.fromCharCode(...cnBytes);
                                        break;
                                    }
                                }
                            }
                            
                            offset = setEnd;
                        }
                        
                        if (issuerCN.includes('Processor') && collateral.pckCrls.processor) {
                            matchedCrl = collateral.pckCrls.processor;
                            matchedType = 'Processor';
                            console.info('Matched Processor PCK CRL via CN fallback');
                        } else if (issuerCN.includes('Platform') && collateral.pckCrls.platform) {
                            matchedCrl = collateral.pckCrls.platform;
                            matchedType = 'Platform';
                            console.info('Matched Platform PCK CRL via CN fallback');
                        }
                    } catch (e) {
                    }
                }

                if (matchedCrl) {
                    const parsed = parseCrlDer(
                        ByteUtils.fromBase64(
                            matchedCrl.replace(/-----BEGIN X509 CRL-----/, '')
                                        .replace(/-----END X509 CRL-----/, '')
                                        .replace(/\s/g, '')
                        )
                    );

                    if (!parsed) {
                        throw new Error(`Failed to parse ${matchedType} CRL`);
                    }

                    const issuerCertDer = ByteUtils.fromBase64(
                        issuerCertPem.replace(/-----BEGIN CERTIFICATE-----/, '')
                                  .replace(/-----END CERTIFICATE-----/, '')
                                  .replace(/\s/g, '')
                    );
                    const issuerSpki = extractSpkiFromCertDer(issuerCertDer);
                    const curveInfo = extractEcCurveFromSpki(issuerSpki);
                    
                    const issuerPubKeyBytes = extractEcdsaPublicKeyFromPem(issuerCertPem);
                    let issuerPubKeyHex = ByteUtils.toHex(issuerPubKeyBytes);
                    if (!issuerPubKeyHex.startsWith('04')) {
                        issuerPubKeyHex = '04' + issuerPubKeyHex;
                    }
                    const EC = isBrowser?elliptic.ec:require('elliptic').ec;
                    const ec = new EC(curveInfo.ellipticName);
                    const issuerKey = ec.keyFromPublic(issuerPubKeyHex, 'hex');

                    const derSig = parseDerEcdsaSignature(parsed.signature);

                    const hashAlg = curveInfo.coordSize === 32 ? 'SHA-256' : curveInfo.coordSize === 48 ? 'SHA-384' : 'SHA-512';
                    
                    let tbsCertListHash;
                    if (isBrowser) {
                        tbsCertListHash = await window.crypto.subtle.digest(hashAlg, parsed.tbsCertList);
                    } else {
                        const cryptoModule = require('crypto');
                        tbsCertListHash = await cryptoModule.webcrypto.subtle.digest(hashAlg, parsed.tbsCertList);
                    }
                    const tbsCertListHashArray = Array.from(new Uint8Array(tbsCertListHash));

                    const verified = issuerKey.verify(tbsCertListHashArray, { r: derSig.r, s: derSig.s });

                    if (!verified) {
                        throw new Error(`${matchedType} PCK CRL signature verification failed`);
                    }

                    console.info(`${matchedType} PCK CRL signature verified`);

                    const pckSerialHex = getCertSerialHex(pckCertPem);
                    if (!pckSerialHex) {
                        throw new Error('Failed to extract PCK certificate serial number');
                    }

                    const isRevoked = parsed.revokedCerts.includes(pckSerialHex);
                    if (isRevoked) {
                        throw new Error(
                            `PCK certificate (serial: ${pckSerialHex}) has been revoked`
                        );
                    }

                    console.info(`${matchedType} PCK CRL verification completed successfully - certificate not revoked`);
                } else {
                    console.warn('WARNING: No appropriate PCK CRL found for verification');
                }
            } catch (error) {
                throw new Error(`PCK CRL verification failed: ${error.message}`);
            }
        }
    } else {
        console.warn('WARNING: No PCK CRLs provided, skipping PCK revocation check');
    }

    console.info('Certificate chain verification completed successfully');
}

/**
 * 验证TCB级别
 * 基于ra_tls_verify_dcap.c:182-229的TCB验证逻辑
 */
async function verifyTCB(quoteData, tcbInfo) {
    const tcbInfoObj = typeof tcbInfo === 'string' ? JSON.parse(tcbInfo) : tcbInfo;

    if (!tcbInfoObj.tcbInfo || !tcbInfoObj.tcbInfo.tcbLevels) {
        throw new Error('Invalid TCB Info structure');
    }

    const tcbLevels = tcbInfoObj.tcbInfo.tcbLevels;

    // 从quote中提取TCB组件
    const quoteTcb = {
        cpuSvn: Array.from(quoteData.cpuSvn),
        pceSvn: quoteData.pceSvn
    };

    // 查找匹配的TCB级别
    let matchedTcbLevel = null;
    for (const tcbLevel of tcbLevels) {
        if (!tcbLevel.tcb) {
            console.warn('TCB level missing tcb field, skipping');
            continue;
        }

        const tcbComponents = tcbLevel.tcb.sgxtcbcomponents || tcbLevel.tcb.sgxtcbcomp;

        if (!tcbComponents || !Array.isArray(tcbComponents) || tcbComponents.length < 16) {
            console.warn('TCB level has invalid sgxtcbcomponents, skipping');
            continue;
        }

        // 检查所有TCB组件是否匹配或更高
        let allMatch = true;
        for (let i = 0; i < 16; i++) {
            const componentSvn = tcbComponents[i].svn !== undefined ? tcbComponents[i].svn : 0;
            if (quoteTcb.cpuSvn[i] < componentSvn) {
                allMatch = false;
                break;
            }
        }

        const tcbPceSvn = tcbLevel.tcb.pcesvn !== undefined ? tcbLevel.tcb.pcesvn : 0;
        if (allMatch && quoteTcb.pceSvn >= tcbPceSvn) {
            matchedTcbLevel = tcbLevel;
            break;
        }
    }

    if (!matchedTcbLevel) {
        throw new Error('No matching TCB level found');
    }

    // 返回TCB状态
    return matchedTcbLevel.tcbStatus || 'Unknown';
}

/**
 * 验证Quote签名
 * 使用ECDSA P-256/P-384验证
 */
async function verifyRaTlsBinding(certPem, quoteData) {
    const certDer = ByteUtils.fromBase64(
        certPem.replace(/-----BEGIN CERTIFICATE-----/, '')
                .replace(/-----END CERTIFICATE-----/, '')
                .replace(/\s/g, '')
    );
    
    const readLength = (data, offset) => {
        if (data[offset] < 0x80) {
            return { length: data[offset], bytes: 1 };
        }
        const numBytes = data[offset] & 0x7f;
        let length = 0;
        for (let i = 0; i < numBytes; i++) {
            length = (length << 8) | data[offset + 1 + i];
        }
        return { length, bytes: 1 + numBytes };
    };
    
    let offset = 0;
    if (certDer[offset] !== 0x30) {
        throw new Error('Invalid certificate DER structure');
    }
    offset++;
    const certLen = readLength(certDer, offset);
    offset += certLen.bytes;
    
    if (certDer[offset] !== 0x30) {
        throw new Error('Invalid TBSCertificate structure');
    }
    offset++;
    const tbsCertLen = readLength(certDer, offset);
    offset += tbsCertLen.bytes;
    
    let currentOffset = offset;
    
    if (certDer[currentOffset] === 0xa0) {
        currentOffset++;
        const versionLen = readLength(certDer, currentOffset);
        currentOffset += versionLen.bytes + versionLen.length;
    }
    
    if (certDer[currentOffset] !== 0x02) {
        throw new Error('Expected serial number INTEGER');
    }
    currentOffset++;
    const serialLen = readLength(certDer, currentOffset);
    currentOffset += serialLen.bytes + serialLen.length;
    
    if (certDer[currentOffset] !== 0x30) {
        throw new Error('Expected signature algorithm SEQUENCE');
    }
    currentOffset++;
    const sigAlgLen = readLength(certDer, currentOffset);
    currentOffset += sigAlgLen.bytes + sigAlgLen.length;
    
    if (certDer[currentOffset] !== 0x30) {
        throw new Error('Expected issuer SEQUENCE');
    }
    currentOffset++;
    const issuerLen = readLength(certDer, currentOffset);
    currentOffset += issuerLen.bytes + issuerLen.length;
    
    if (certDer[currentOffset] !== 0x30) {
        throw new Error('Expected validity SEQUENCE');
    }
    currentOffset++;
    const validityLen = readLength(certDer, currentOffset);
    currentOffset += validityLen.bytes + validityLen.length;
    
    if (certDer[currentOffset] !== 0x30) {
        throw new Error('Expected subject SEQUENCE');
    }
    currentOffset++;
    const subjectLen = readLength(certDer, currentOffset);
    currentOffset += subjectLen.bytes + subjectLen.length;
    
    if (certDer[currentOffset] !== 0x30) {
        throw new Error('Expected SubjectPublicKeyInfo SEQUENCE');
    }
    const spkiStart = currentOffset;
    currentOffset++;
    const spkiLen = readLength(certDer, currentOffset);
    currentOffset += spkiLen.bytes;
    const spkiEnd = currentOffset + spkiLen.length;
    
    const spkiDer = ByteUtils.slice(certDer, spkiStart, spkiEnd);
    
    if (quoteData.claims) {
        console.log('[DEBUG] Standard RA-TLS: verifying against CBOR claims');
        const claims = cbor.decode(quoteData.claims);
        
        if (!claims || typeof claims !== 'object') {
            throw new Error('Invalid CBOR claims structure');
        }
        
        let pubkeyHashEntry = null;
        for (const [key, value] of Object.entries(claims)) {
            if (key === 'pubkey-hash') {
                pubkeyHashEntry = value;
                break;
            }
        }
        
        if (!pubkeyHashEntry) {
            throw new Error('No pubkey-hash entry found in CBOR claims');
        }
        
        const hashEntryDecoded = cbor.decode(pubkeyHashEntry);
        if (!Array.isArray(hashEntryDecoded) || hashEntryDecoded.length !== 2) {
            throw new Error('Invalid pubkey-hash entry structure');
        }
        
        const hashAlgId = hashEntryDecoded[0];
        const expectedHashBytes = ByteUtils.toBytes(hashEntryDecoded[1]);
        
        let hashAlgName;
        let expectedHashSize;
        if (hashAlgId === 1) {
            hashAlgName = 'SHA-256';
            expectedHashSize = 32;
        } else if (hashAlgId === 7) {
            hashAlgName = 'SHA-384';
            expectedHashSize = 48;
        } else if (hashAlgId === 8) {
            hashAlgName = 'SHA-512';
            expectedHashSize = 64;
        } else {
            throw new Error(`Unsupported hash algorithm ID: ${hashAlgId}`);
        }
        
        let computedHash;
        if (isBrowser) {
            computedHash = await window.crypto.subtle.digest(hashAlgName, spkiDer);
        } else {
            const cryptoModule = require('crypto');
            computedHash = await cryptoModule.webcrypto.subtle.digest(hashAlgName, spkiDer);
        }
        
        const computedHashArray = Array.from(new Uint8Array(computedHash));
        
        console.log('[DEBUG] Hash Algorithm:', hashAlgName);
        console.log('[DEBUG] Expected Hash (from claims):', ByteUtils.toHex(expectedHashBytes));
        console.log('[DEBUG] Computed Hash (SPKI DER):', ByteUtils.toHex(computedHashArray));
        
        if (!ByteUtils.equalBytes(expectedHashBytes, computedHashArray)) {
            throw new Error(`RA-TLS TLS key binding verification failed: ${hashAlgName} of SPKI DER does not match pubkey-hash in claims`);
        }
        
        console.info(`RA-TLS TLS key binding verified (${hashAlgName} of SPKI DER matches claims)`);
    } else {
        console.log('[DEBUG] Legacy RA-TLS: verifying against report_data');
        
        let hash1, hash2, hash3;
        if (isBrowser) {
            hash1 = await window.crypto.subtle.digest('SHA-256', spkiDer);
        } else {
            const cryptoModule = require('crypto');
            hash1 = await cryptoModule.webcrypto.subtle.digest('SHA-256', spkiDer);
        }
        
        const hash1Array = Array.from(new Uint8Array(hash1));
        const reportData32 = ByteUtils.slice(quoteData.reportData, 0, 32);
        
        console.log('[DEBUG] Report Data (first 32 bytes):', ByteUtils.toHex(reportData32));
        console.log('[DEBUG] SHA256(SPKI DER):', ByteUtils.toHex(hash1Array));
        
        if (!ByteUtils.equalBytes(reportData32, hash1Array)) {
            throw new Error('RA-TLS TLS key binding verification failed: SHA256 of SPKI DER does not match quote report_data');
        }
        
        console.info('RA-TLS TLS key binding verified (SHA256 of SPKI DER matches report_data)');
    }
}

async function verifyQuoteSignature(quoteData, collateral) {
    
    if (quoteData.version !== 3 && quoteData.version !== 4) {
        throw new Error(`Unsupported quote version: ${quoteData.version}`);
    }

    if (quoteData.attestationKeyType !== 2 && quoteData.attestationKeyType !== 3) {
        throw new Error(
            `Unsupported attestation key type: ${quoteData.attestationKeyType}. ` +
            `SGX DCAP only supports type 2 (ECDSA-P256) and type 3 (ECDSA-P384)`
        );
    }

    const sigData = quoteData.signature;

    // attestationKeyType: 2 = ECDSA-P256 (32-byte coordinates), 3 = ECDSA-P384 (48-byte coordinates)
    const coordSize = quoteData.attestationKeyType === 3 ? 48 : 32;
    const sigSize = coordSize * 2;
    const minSigDataSize = sigSize + sigSize + 384 + sigSize; // sig + pubkey + qe_report + qe_report_sig

    if (!sigData || sigData.length < minSigDataSize) {
        throw new Error(`Invalid signature data: expected at least ${minSigDataSize} bytes, got ${sigData ? sigData.length : 0}`);
    }

    let offset = 0;
    const ecdsaSignature = ByteUtils.slice(sigData, offset, offset + sigSize); offset += sigSize;
    const attestationPubKey = ByteUtils.slice(sigData, offset, offset + sigSize); offset += sigSize;

    // 验证Quote主签名
    const headerSize = 48;
    const reportBodySize = 384;
    const signedDataSize = headerSize + reportBodySize;
    const signedData = ByteUtils.slice(quoteData.rawQuote, 0, signedDataSize);

    const curveName = quoteData.attestationKeyType === 3 ? 'p384' : 'p256';
    const hashAlgorithm = quoteData.attestationKeyType === 3 ? 'SHA-384' : 'SHA-256';
    const EC = elliptic.ec;
    const ec = new EC(curveName);

    try {
        const pubKeyX = ByteUtils.slice(attestationPubKey, 0, coordSize);
        const pubKeyY = ByteUtils.slice(attestationPubKey, coordSize, coordSize * 2);

        const key = ec.keyFromPublic({
            x: ByteUtils.toHex(pubKeyX),
            y: ByteUtils.toHex(pubKeyY)
        }, 'hex');

        let hashBuffer;
        if (isBrowser) {
            hashBuffer = await window.crypto.subtle.digest(hashAlgorithm, signedData);
        } else {
            const cryptoModule = require('crypto');
            hashBuffer = await cryptoModule.webcrypto.subtle.digest(hashAlgorithm, signedData);
        }
        const hashArray = Array.from(new Uint8Array(hashBuffer));

        const r = ByteUtils.toHex(ByteUtils.slice(ecdsaSignature, 0, coordSize));
        const s = ByteUtils.toHex(ByteUtils.slice(ecdsaSignature, coordSize, coordSize * 2));

        const verified = key.verify(hashArray, { r, s });

        if (!verified) {
            throw new Error('Quote ECDSA signature verification failed');
        }

        console.info('Quote signature verified successfully');

        await verifyQeReportSignature(quoteData, sigData, collateral);

    } catch (error) {
        throw new Error(`Quote signature verification failed: ${error.message}`);
    }
}

/**
 * 从PEM格式的ECDSA证书中提取公钥（返回完整的SubjectPublicKeyInfo DER编码）
 */
function extractEcdsaPublicKeyFromPem(pemCert) {
    const pemMatch = pemCert.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/);
    if (!pemMatch) {
        throw new Error('No valid PEM certificate found');
    }
    
    const base64 = pemMatch[0]
        .replace(/-----BEGIN CERTIFICATE-----/, '')
        .replace(/-----END CERTIFICATE-----/, '')
        .replace(/\s/g, '');
    
    const derBuffer = ByteUtils.fromBase64(base64);
    
    const readLength = (buffer, pos) => {
        let length = buffer[pos++];
        if (length & 0x80) {
            const numBytes = length & 0x7f;
            length = 0;
            for (let i = 0; i < numBytes; i++) {
                length = (length << 8) | buffer[pos++];
            }
        }
        return { length, newPos: pos };
    };
    
    let pos = 0;
    if (derBuffer[pos] !== 0x30) {
        throw new Error('Invalid certificate structure');
    }
    pos++;
    let result = readLength(derBuffer, pos);
    pos = result.newPos;
    
    if (derBuffer[pos] !== 0x30) {
        throw new Error('Invalid TBSCertificate structure');
    }
    pos++;
    result = readLength(derBuffer, pos);
    pos = result.newPos;
    
    if (derBuffer[pos] === 0xA0) {
        pos++;
        result = readLength(derBuffer, pos);
        pos = result.newPos + result.length;
    }
    
    if (derBuffer[pos] !== 0x02) {
        throw new Error('Invalid serial number');
    }
    pos++;
    result = readLength(derBuffer, pos);
    pos = result.newPos + result.length;
    
    if (derBuffer[pos] !== 0x30) {
        throw new Error('Invalid signature algorithm');
    }
    pos++;
    result = readLength(derBuffer, pos);
    pos = result.newPos + result.length;
    
    if (derBuffer[pos] !== 0x30) {
        throw new Error('Invalid issuer');
    }
    pos++;
    result = readLength(derBuffer, pos);
    pos = result.newPos + result.length;
    
    if (derBuffer[pos] !== 0x30) {
        throw new Error('Invalid validity');
    }
    pos++;
    result = readLength(derBuffer, pos);
    pos = result.newPos + result.length;
    
    if (derBuffer[pos] !== 0x30) {
        throw new Error('Invalid subject');
    }
    pos++;
    result = readLength(derBuffer, pos);
    pos = result.newPos + result.length;
    
    if (derBuffer[pos] !== 0x30) {
        throw new Error('Invalid SubjectPublicKeyInfo');
    }
    
    pos++;
    result = readLength(derBuffer, pos);
    pos = result.newPos;
    
    if (derBuffer[pos] !== 0x30) {
        throw new Error('Invalid algorithm identifier');
    }
    pos++;
    result = readLength(derBuffer, pos);
    pos = result.newPos + result.length;
    
    if (derBuffer[pos] !== 0x03) {
        throw new Error('Invalid public key BIT STRING');
    }
    pos++;
    result = readLength(derBuffer, pos);
    pos = result.newPos;
    
    const unusedBits = derBuffer[pos];
    pos++;
    
    const pubKeyLength = result.length - 1; // Subtract 1 for unused bits byte
    return ByteUtils.slice(derBuffer, pos, pos + pubKeyLength);
}

/**
 * 验证QE Report签名
 */
async function verifyQeReportSignature(quoteData, sigData, collateral) {
    const coordSize = quoteData.attestationKeyType === 3 ? 48 : 32;
    const sigSize = coordSize * 2;
    const pubkeySize = coordSize * 2; // X||Y without 0x04 prefix in DCAP sig data

    // QE Report在签名数据的固定偏移位置
    let offset = sigSize + pubkeySize; // sig + pubkey
    const qeReportSize = 384;

    if (sigData.length < offset + qeReportSize) {
        throw new Error('QE Report not available in signature data');
    }

    const qeReport = ByteUtils.slice(sigData, offset, offset + qeReportSize);
    offset += qeReportSize;

    const qeReportView = ByteUtils.dataView(qeReport);
    let reportOffset = 0;

    const qeCpuSvn = ByteUtils.slice(qeReport, reportOffset, reportOffset + 16); reportOffset += 16;
    const qeMiscSelect = qeReportView.getUint32(reportOffset, true); reportOffset += 4;
    reportOffset += 28; // reserved
    const qeAttributes = ByteUtils.slice(qeReport, reportOffset, reportOffset + 16); reportOffset += 16;
    const qeMrenclave = ByteUtils.slice(qeReport, reportOffset, reportOffset + 32); reportOffset += 32;
    reportOffset += 32; // reserved
    const qeMrsigner = ByteUtils.slice(qeReport, reportOffset, reportOffset + 32); reportOffset += 32;
    reportOffset += 96; // reserved
    const qeIsvProdId = qeReportView.getUint16(reportOffset, true); reportOffset += 2;
    const qeIsvSvn = qeReportView.getUint16(reportOffset, true); reportOffset += 2;
    reportOffset += 60; // reserved
    const qeReportData = ByteUtils.slice(qeReport, reportOffset, reportOffset + 64);

    // 步骤1: 验证QE Report的report_data包含attestation key的哈希
    const attestationKeyOffset = sigSize;
    const attestationPubKey = ByteUtils.slice(sigData, attestationKeyOffset, attestationKeyOffset + pubkeySize);
    
    const reportDataHash = ByteUtils.slice(qeReportData, 0, 32);
    
    const cryptoModule = isBrowser ? null : require('crypto');
    
    const computeHash = async (data) => {
        if (isBrowser) {
            return new Uint8Array(await window.crypto.subtle.digest('SHA-256', data));
        } else {
            return new Uint8Array(await cryptoModule.webcrypto.subtle.digest('SHA-256', data));
        }
    };
    
    const h1 = await computeHash(attestationPubKey);
    
    let attestationKeyWithPrefix = new Uint8Array(pubkeySize + 1);
    attestationKeyWithPrefix[0] = 0x04;
    attestationKeyWithPrefix.set(attestationPubKey, 1);
    const h2 = await computeHash(attestationKeyWithPrefix);
    
    const reverse32 = (bytes) => {
        const reversed = new Uint8Array(bytes.length);
        for (let i = 0; i < bytes.length; i++) {
            reversed[i] = bytes[bytes.length - 1 - i];
        }
        return reversed;
    };
    
    const x = ByteUtils.slice(attestationPubKey, 0, coordSize);
    const y = ByteUtils.slice(attestationPubKey, coordSize, coordSize * 2);
    const xRev = reverse32(x);
    const yRev = reverse32(y);
    const xyRev = ByteUtils.concat([xRev, yRev]);
    const h3 = await computeHash(xyRev);
    
    let xyRevWithPrefix = new Uint8Array(pubkeySize + 1);
    xyRevWithPrefix[0] = 0x04;
    xyRevWithPrefix.set(xyRev, 1);
    const h4 = await computeHash(xyRevWithPrefix);
    
    let h5, h6;
    if (quoteData.qeAuthData && quoteData.qeAuthData.length > 0) {
        const xyWithAuth = ByteUtils.concat([attestationPubKey, quoteData.qeAuthData]);
        h5 = await computeHash(xyWithAuth);
        
        const xyPrefixWithAuth = ByteUtils.concat([attestationKeyWithPrefix, quoteData.qeAuthData]);
        h6 = await computeHash(xyPrefixWithAuth);
    }
    
    let matchedHash = null;
    if (ByteUtils.equalBytes(h1, reportDataHash)) {
        matchedHash = 'H1 (X||Y)';
    } else if (ByteUtils.equalBytes(h2, reportDataHash)) {
        matchedHash = 'H2 (0x04||X||Y)';
    } else if (ByteUtils.equalBytes(h3, reportDataHash)) {
        matchedHash = 'H3 (reverse32(X)||reverse32(Y))';
    } else if (ByteUtils.equalBytes(h4, reportDataHash)) {
        matchedHash = 'H4 (0x04||reverse32(X)||reverse32(Y))';
    } else if (h5 && ByteUtils.equalBytes(h5, reportDataHash)) {
        matchedHash = 'H5 (X||Y||qeAuthData)';
    } else if (h6 && ByteUtils.equalBytes(h6, reportDataHash)) {
        matchedHash = 'H6 (0x04||X||Y||qeAuthData)';
    }
    
    if (!matchedHash) {
        throw new Error(
            'QE Report data verification failed: report_data does not match any expected attestation key hash format'
        );
    }
    
    console.info('QE Report data verification successful');

    // 步骤2: 验证QE Report签名
    if (sigData.length < offset + sigSize) {
        throw new Error('QE Report signature not available');
    }

    const qeReportSignature = ByteUtils.slice(sigData, offset, offset + sigSize);

    let pckCertPem;
    if (quoteData.certChain && quoteData.certChain.length > 0) {
        if (typeof quoteData.certChain[0] === 'string') {
            pckCertPem = quoteData.certChain[0];
        } else {
            throw new Error('Unexpected PCK certificate format in quote data');
        }
    } else if (collateral && collateral.pckCertChain && collateral.pckCertChain.length > 0) {
        pckCertPem = collateral.pckCertChain[0];
    } else {
        throw new Error('No PCK certificate chain available for QE Report verification');
    }

    let pubKeyBytes;
    try {
        const pckCert = forge.pki.certificateFromPem(pckCertPem);
        const pckPubKey = pckCert.publicKey;
        const pckPubKeyAsn1 = forge.pki.publicKeyToAsn1(pckPubKey);
        const pckPubKeyDer = forge.asn1.toDer(pckPubKeyAsn1).getBytes();
        pubKeyBytes = ByteUtils.fromBinaryString(pckPubKeyDer);
    } catch (error) {
        if (error.message && error.message.includes('OID is not RSA')) {
            console.info('PCK certificate is ECDSA, extracting public key via ASN.1 parsing');
            pubKeyBytes = extractEcdsaPublicKeyFromPem(pckCertPem);
        } else {
            throw error;
        }
    }

    const pckCertDer = ByteUtils.fromBase64(
        pckCertPem.replace(/-----BEGIN CERTIFICATE-----/, '')
                  .replace(/-----END CERTIFICATE-----/, '')
                  .replace(/\s/g, '')
    );
    const pckSpki = extractSpkiFromCertDer(pckCertDer);
    const curveInfo = extractEcCurveFromSpki(pckSpki);
    
    const uncompressedMarker = pubKeyBytes.indexOf(0x04);
    
    if (uncompressedMarker === -1) {
        throw new Error('Cannot find uncompressed point marker in PCK public key');
    }

    const pckCoordSize = curveInfo.coordSize;
    const coordStart = uncompressedMarker + 1;

    if (pubKeyBytes.length < coordStart + pckCoordSize * 2) {
        throw new Error('Invalid PCK public key length');
    }

    const pckPubKeyX = ByteUtils.slice(pubKeyBytes, coordStart, coordStart + pckCoordSize);
    const pckPubKeyY = ByteUtils.slice(pubKeyBytes, coordStart + pckCoordSize, coordStart + pckCoordSize * 2);

    const EC = elliptic.ec;
    const ec = new EC(curveInfo.ellipticName);

    try {
        const key = ec.keyFromPublic({
            x: ByteUtils.toHex(pckPubKeyX),
            y: ByteUtils.toHex(pckPubKeyY)
        }, 'hex');

        // 计算QE Report的哈希
        let qeReportHash;
        if (isBrowser) {
            qeReportHash = await window.crypto.subtle.digest('SHA-256', qeReport);
        } else {
            const cryptoModule = require('crypto');
            qeReportHash = await cryptoModule.webcrypto.subtle.digest('SHA-256', qeReport);
        }
        const qeReportHashArray = Array.from(new Uint8Array(qeReportHash));

        // 提取签名的r和s分量
        const r = ByteUtils.toHex(ByteUtils.slice(qeReportSignature, 0, pckCoordSize));
        const s = ByteUtils.toHex(ByteUtils.slice(qeReportSignature, pckCoordSize, pckCoordSize * 2));

        // 验证签名
        const verified = key.verify(qeReportHashArray, { r, s });

        if (!verified) {
            throw new Error('QE Report signature verification failed');
        }

        console.info('QE Report signature verified successfully');

        // 步骤3: 验证QE Identity
        if (collateral && collateral.qeIdentity) {
            await verifyQeIdentity(qeMrenclave, qeMrsigner, qeIsvProdId, qeIsvSvn, collateral.qeIdentity);
        }

    } catch (error) {
        throw new Error(`QE Report signature verification failed: ${error.message}`);
    }
}

/**
 * 验证QE Identity
 * 基于Intel发布的QE Identity验证QE的度量值
 */
async function verifyQeIdentity(qeMrenclave, qeMrsigner, qeIsvProdId, qeIsvSvn, qeIdentity) {
    if (!qeIdentity) {
        console.warn('QE Identity not available, skipping QE identity verification');
        return;
    }

    const qeIdObj = typeof qeIdentity === 'string' ? JSON.parse(qeIdentity) : qeIdentity;

    if (!qeIdObj.enclaveIdentity) {
        throw new Error('Invalid QE Identity structure: missing enclaveIdentity field');
    }

    const enclaveIdentity = qeIdObj.enclaveIdentity;

    // 1. 验证MRSIGNER (必须匹配)
    if (!enclaveIdentity.mrsigner) {
        throw new Error('QE Identity missing mrsigner field');
    }

    const expectedMrsigner = ByteUtils.fromHex(enclaveIdentity.mrsigner);
    const qeMrsignerBytes = ByteUtils.toBytes(qeMrsigner);

    if (!ByteUtils.equalBytes(qeMrsignerBytes, expectedMrsigner)) {
        throw new Error(
            `QE MRSIGNER mismatch: expected ${enclaveIdentity.mrsigner}, ` +
            `got ${ByteUtils.toHex(qeMrsignerBytes)}`
        );
    }

    // 2. 验证ISV_PROD_ID (必须匹配)
    if (enclaveIdentity.isvprodid === undefined) {
        throw new Error('QE Identity missing isvprodid field');
    }

    if (qeIsvProdId !== enclaveIdentity.isvprodid) {
        throw new Error(
            `QE ISV_PROD_ID mismatch: expected ${enclaveIdentity.isvprodid}, ` +
            `got ${qeIsvProdId}`
        );
    }

    // 3. 验证ISV_SVN (QE的版本必须大于等于TCB level中的最小要求)
    if (enclaveIdentity.tcbLevels && enclaveIdentity.tcbLevels.length > 0) {
        let tcbStatus = 'OutOfDate';
        for (const level of enclaveIdentity.tcbLevels) {
            if (level.tcb && level.tcb.isvsvn !== undefined) {
                if (qeIsvSvn >= level.tcb.isvsvn) {
                    tcbStatus = level.tcbStatus || 'UpToDate';
                    break;
                }
            }
        }
        console.info(`QE ISV_SVN TCB status: ${tcbStatus}`);
    } else {
        console.warn('WARNING: QE Identity tcbLevels not available, skipping ISV_SVN verification');
    }

    console.info('QE Identity verification successful');
    console.info(`  MRSIGNER: ${ByteUtils.toHex(qeMrsignerBytes)}`);
    console.info(`  ISV_PROD_ID: ${qeIsvProdId}`);
    console.info(`  ISV_SVN: ${qeIsvSvn}`);
}

/**
 * 验证测量值策略
 * 基于Gramine的verify_quote_body_against_envvar_measurements逻辑
 */
function verifyMeasurementPolicy(quoteData, policy) {
    const { expectedMrEnclave, expectedMrSigner, expectedIsvProdId, expectedIsvSvn } = policy;

    if (expectedMrEnclave) {
        const actualMrEnclave = ByteUtils.toHex(quoteData.mrenclave).toLowerCase();
        const expectedMrEnclaveNorm = expectedMrEnclave.toLowerCase();
        if (actualMrEnclave !== expectedMrEnclaveNorm) {
            throw new Error(
                `MRENCLAVE mismatch: expected ${expectedMrEnclaveNorm}, got ${actualMrEnclave}`
            );
        }
    }

    if (expectedMrSigner) {
        const actualMrSigner = ByteUtils.toHex(quoteData.mrsigner).toLowerCase();
        const expectedMrSignerNorm = expectedMrSigner.toLowerCase();
        if (actualMrSigner !== expectedMrSignerNorm) {
            throw new Error(
                `MRSIGNER mismatch: expected ${expectedMrSignerNorm}, got ${actualMrSigner}`
            );
        }
    }

    if (expectedIsvProdId !== null && expectedIsvProdId !== undefined) {
        if (quoteData.isvProdId !== expectedIsvProdId) {
            throw new Error(
                `ISV_PROD_ID mismatch: expected ${expectedIsvProdId}, got ${quoteData.isvProdId}`
            );
        }
    }

    if (expectedIsvSvn !== null && expectedIsvSvn !== undefined) {
        if (quoteData.isvSvn < expectedIsvSvn) {
            throw new Error(
                `ISV_SVN too low: minimum required ${expectedIsvSvn}, got ${quoteData.isvSvn}`
            );
        }
    }

    if (!expectedMrEnclave && !expectedMrSigner) {
        console.warn('WARNING: Neither expectedMrEnclave nor expectedMrSigner are specified. ' +
                     'This will accept any enclave and provides no security whatsoever.');
    }
}

/**
 * 解析SGX Enclave属性
 * 将16字节的attributes字段解析为可读的flags和xfrm结构
 * @param {Buffer|Uint8Array} attributes - 16字节的attributes数据
 * @returns {Object} 包含解析后的flags和xfrm信息
 */
function parseAttributes(attributes) {
    if (!attributes || attributes.length < 16) {
        throw new Error('Invalid enclave attributes: must be 16 bytes');
    }

    const view = ByteUtils.dataView(attributes);
    
    // Attributes结构: flags(8 bytes) + xfrm(8 bytes)
    const flags = view.getBigUint64(0, true);
    const xfrm = view.getBigUint64(8, true);

    const hasFlag = (bit) => ((flags >> BigInt(bit)) & 1n) === 1n;
    const hasXfrm = (bit) => ((xfrm >> BigInt(bit)) & 1n) === 1n;

    const flagsHex = '0x' + flags.toString(16).padStart(16, '0');
    const xfrmHex = '0x' + xfrm.toString(16).padStart(16, '0');

    return {
        raw: ByteUtils.toHex(attributes),
        flags: {
            value: flagsHex,
            initted: hasFlag(0),           // SGX_FLAGS_INITTED - Enclave已初始化
            debug: hasFlag(1),             // SGX_FLAGS_DEBUG - 调试模式
            mode64bit: hasFlag(2),         // SGX_FLAGS_MODE64BIT - 64位模式
            provisionKey: hasFlag(4),      // SGX_FLAGS_PROVISION_KEY - 可访问Provisioning Key
            einittokenKey: hasFlag(5),     // SGX_FLAGS_EINITTOKEN_KEY - 可访问EINIT Token Key
            kss: hasFlag(7)                // SGX_FLAGS_KSS - Key Separation and Sharing支持
        },
        xfrm: {
            value: xfrmHex,
            x87: hasXfrm(0),               // x87 FPU状态
            sse: hasXfrm(1),               // SSE状态
            avx: hasXfrm(2),               // AVX状态
            bndreg: hasXfrm(3),            // MPX BNDREGS状态
            bndcsr: hasXfrm(4),            // MPX BNDCSR状态
            opmask: hasXfrm(5),            // AVX-512 opmask状态
            zmm_hi256: hasXfrm(6),         // AVX-512 ZMM_Hi256状态
            hi16_zmm: hasXfrm(7),          // AVX-512 Hi16_ZMM状态
            pkru: hasXfrm(9),              // PKRU状态
            legacyX87SSE: hasXfrm(0) && hasXfrm(1)  // Legacy x87+SSE (必须设置)
        }
    };
}

/**
 * 验证Enclave属性
 * 基于ra_tls_verify_dcap.c:237-241
 */
function verifyEnclaveAttributes(quoteData, allowDebugEnclave) {
    const attributes = quoteData.attributes;
    if (!attributes || attributes.length < 16) {
        throw new Error('Invalid enclave attributes');
    }

    const view = ByteUtils.dataView(attributes);

    // Attributes结构: flags(8 bytes) + xfrm(8 bytes)
    const flags = view.getBigUint64(0, true);
    const xfrm = view.getBigUint64(8, true);

    // 检查关键标志位 (基于sgx_arch.h中的定义)
    const SGX_FLAGS_INITTED = 0x01n;
    const SGX_FLAGS_DEBUG = 0x02n;
    const SGX_FLAGS_MODE64BIT = 0x04n;

    // INIT标志必须设置
    if ((flags & SGX_FLAGS_INITTED) === 0n) {
        throw new Error('Enclave not initialized (INIT flag not set)');
    }

    // 64位模式必须设置
    if ((flags & SGX_FLAGS_MODE64BIT) === 0n) {
        throw new Error('Enclave must be in 64-bit mode');
    }

    // 检查DEBUG标志
    const isDebug = (flags & SGX_FLAGS_DEBUG) !== 0n;
    if (isDebug && !allowDebugEnclave) {
        throw new Error('Debug enclave not allowed (DEBUG flag is set)');
    }

    // 验证XFRM (扩展特性请求掩码)
    const SGX_XFRM_LEGACY = 0x03n; // x87 + SSE (必须设置)

    // Legacy特性(x87 + SSE)必须设置
    if ((xfrm & SGX_XFRM_LEGACY) !== SGX_XFRM_LEGACY) {
        throw new Error('Enclave must have x87 and SSE support (XFRM legacy bits not set)');
    }

    console.info('Enclave attributes verified successfully');
}

/**
 * 评估TCB状态
 * 基于ra_tls_verify_dcap.c:182-229
 */
function evaluateTcbStatus(tcbStatus, allowOutdatedTcb, allowHwConfigNeeded, allowSwHardeningNeeded) {
    const statusMap = {
        'UpToDate': SGX_QL_QV_RESULT.OK,
        'OutOfDate': SGX_QL_QV_RESULT.OUT_OF_DATE,
        'ConfigurationNeeded': SGX_QL_QV_RESULT.CONFIG_NEEDED,
        'OutOfDateConfigurationNeeded': SGX_QL_QV_RESULT.OUT_OF_DATE_CONFIG_NEEDED,
        'SWHardeningNeeded': SGX_QL_QV_RESULT.SW_HARDENING_NEEDED,
        'ConfigurationAndSWHardeningNeeded': SGX_QL_QV_RESULT.CONFIG_AND_SW_HARDENING_NEEDED,
        'Revoked': SGX_QL_QV_RESULT.REVOKED
    };

    const result = statusMap[tcbStatus] || SGX_QL_QV_RESULT.UNSPECIFIED;

    // 检查是否允许该状态
    switch (result) {
        case SGX_QL_QV_RESULT.OK:
            return "SGX_QL_QV_RESULT_OK";

        case SGX_QL_QV_RESULT.CONFIG_NEEDED:
            if (!allowHwConfigNeeded) {
                throw new Error(`TCB status ${tcbStatus} not allowed (hardware configuration needed)`);
            }
            return "SGX_QL_QV_RESULT_CONFIG_NEEDED";

        case SGX_QL_QV_RESULT.OUT_OF_DATE:
            if (!allowOutdatedTcb) {
                throw new Error(`TCB status ${tcbStatus} not allowed (TCB is out of date)`);
            }
            return "SGX_QL_QV_RESULT_OUT_OF_DATE";

        case SGX_QL_QV_RESULT.OUT_OF_DATE_CONFIG_NEEDED:
            if (!allowOutdatedTcb || !allowHwConfigNeeded) {
                throw new Error(`TCB status ${tcbStatus} not allowed (out of date and config needed)`);
            }
            return "SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED";

        case SGX_QL_QV_RESULT.SW_HARDENING_NEEDED:
            if (!allowSwHardeningNeeded) {
                throw new Error(`TCB status ${tcbStatus} not allowed (software hardening needed)`);
            }
            return "SGX_QL_QV_RESULT_SW_HARDENING_NEEDED";

        case SGX_QL_QV_RESULT.CONFIG_AND_SW_HARDENING_NEEDED:
            if (!allowHwConfigNeeded || !allowSwHardeningNeeded) {
                throw new Error(`TCB status ${tcbStatus} not allowed (config and SW hardening needed)`);
            }
            return "SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED";

        case SGX_QL_QV_RESULT.REVOKED:
            throw new Error(`TCB status ${tcbStatus} indicates platform is revoked`);

        case SGX_QL_QV_RESULT.UNSPECIFIED:
        default:
            throw new Error(`TCB status ${tcbStatus} indicates verification failure (unspecified)`);
    }
}

/**
 * 将TCB状态转换为字符串
 * 基于ra_tls_verify_dcap.c:74-96中的sgx_ql_qv_result_to_str函数
 */
function tcbStatusToString(tcbStatus) {
    if (typeof tcbStatus === 'string') {
        return tcbStatus;
    }

    if (typeof tcbStatus === 'number') {
        switch (tcbStatus) {
            case SGX_QL_QV_RESULT.OK:
                return 'OK';
            case SGX_QL_QV_RESULT.CONFIG_NEEDED:
                return 'CONFIG_NEEDED';
            case SGX_QL_QV_RESULT.OUT_OF_DATE:
                return 'OUT_OF_DATE';
            case SGX_QL_QV_RESULT.OUT_OF_DATE_CONFIG_NEEDED:
                return 'OUT_OF_DATE_CONFIG_NEEDED';
            case SGX_QL_QV_RESULT.SW_HARDENING_NEEDED:
                return 'SW_HARDENING_NEEDED';
            case SGX_QL_QV_RESULT.CONFIG_AND_SW_HARDENING_NEEDED:
                return 'CONFIG_AND_SW_HARDENING_NEEDED';
            case SGX_QL_QV_RESULT.INVALID_SIGNATURE:
                return 'INVALID_SIGNATURE';
            case SGX_QL_QV_RESULT.REVOKED:
                return 'REVOKED';
            case SGX_QL_QV_RESULT.UNSPECIFIED:
                return 'UNSPECIFIED';
            default:
                return 'UNKNOWN';
        }
    }

    return 'Unknown';
}

// 导出主函数和辅助类型
if (typeof module !== 'undefined' && module.exports) {
    // Node.js环境
    module.exports = {
        verifyQuote,
        SGX_QL_QV_RESULT,
        INTEL_SGX_ROOT_CA_CERTS,
        parseQuoteStructure,
        extractQuote,
        parseAttributes,
        ByteUtils,
        setFetchFunction
    };
} else {
    // 浏览器环境
    window.SGXQuoteVerifier = {
        verifyQuote,
        SGX_QL_QV_RESULT,
        INTEL_SGX_ROOT_CA_CERTS,
        parseQuoteStructure,
        extractQuote,
        parseAttributes,
        ByteUtils,
        setFetchFunction
    };
}
