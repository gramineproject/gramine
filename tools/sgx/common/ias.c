/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Invisible Things Lab
 *                    Rafal Wojdyla <omeg@invisiblethingslab.com>
 */

#define _GNU_SOURCE

#include "ias.h"

#include <assert.h>
#include <ctype.h>
#include <curl/curl.h>
#include <errno.h>
#include <mbedtls/base64.h>
#include <mbedtls/pk.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#ifdef HAVE_INTERNAL_CJSON
/* here we -I the cJSON's repo root, which directly contains the header */
#include <cJSON.h>
#else
#include <cjson/cJSON.h>
#endif

#include "util.h"

/*! This is the public RSA key of the IAS (PEM). It's used to verify IAS report signatures. */
const char* g_ias_public_key_pem =
    "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqXot4OZuphR8nudFrAFi\n"
    "aGxxkgma/Es/BA+tbeCTUR106AL1ENcWA4FX3K+E9BBL0/7X5rj5nIgX/R/1ubhk\n"
    "KWw9gfqPG3KeAtIdcv/uTO1yXv50vqaPvE1CRChvzdS/ZEBqQ5oVvLTPZ3VEicQj\n"
    "lytKgN9cLnxbwtuvLUK7eyRPfJW/ksddOzP8VBBniolYnRCD2jrMRZ8nBM2ZWYwn\n"
    "XnwYeOAHV+W9tOhAImwRwKF/95yAsVwd21ryHMJBcGH70qLagZ7Ttyt++qO/6+KA\n"
    "XJuKwZqjRlEtSEz8gZQeFfVYgcwSfo96oSMAzVr7V0L6HSDLRnpb6xxmbPdqNol4\n"
    "tQIDAQAB\n"
    "-----END PUBLIC KEY-----\n";

#define CURL_FAIL(action, ret)                                                 \
    (((ret) == CURLE_OK) ? false : ({                                          \
        ERROR("curl call (%s) failed: %s\n", action, curl_easy_strerror(ret)); \
        true;                                                                  \
    }))

/*! Context used in ias_*() calls */
struct ias_context_t {
    CURL* curl;                 /*!< CURL context for this session */
    char* ias_verify_url;       /*!< URL for IAS attestation verification API */
    char* ias_sigrl_url;        /*!< URL for IAS "Retrieve SigRL" API */
    struct curl_slist* headers; /*!< Request headers sent to IAS */
};

/*! IAS response with attestation evidence or signature revocation list */
struct ias_request_resp {
    char* signature;          /*!< X-IASReport-Signature data, NULL terminated string */
    size_t signature_size;    /*!< size of \p signature string */
    char* certificate;        /*!< x-iasreport-signing-certificate data, NULL terminated string */
    size_t certificate_size;  /*!< size of \p certificate string */
    char* data;               /*!< response data */
    size_t data_size;         /*!< size of \p data field */
};

/*!
 * \brief Decode %-sequences ("URL encoding").
 *
 * \param      src  NULL-terminated URL-encoded input.
 * \param[out] dst  Buffer to write decoded output to. Can be the same as \p src.
 */
static void urldecode(const char* src, char* dst) {
    char a, b;
    while (*src) {
        if (*src == '%' && (a = src[1]) && (b = src[2]) && isxdigit(a) && isxdigit(b)) {
            if (a >= 'a')
                a -= 'a' - 'A';

            if (a >= 'A')
                a -= ('A' - 10);
            else
                a -= '0';

            if (b >= 'a')
                b -= 'a' - 'A';

            if (b >= 'A')
                b -= ('A' - 10);
            else
                b -= '0';

            *dst++ = 16 * a + b;
            src += 3;
        } else if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else {
            *dst++ = *src++;
        }
    }
    *dst++ = '\0';
}

/*!
 * \brief Parse response headers to get report signature and other metadata.
 *
 * \param buffer   Single HTTP header.
 * \param size     Together with \p count a size of \p buffer.
 * \param count    Size of \p buffer, in \p size units.
 * \param context  User data pointer (ias_request_resp).
 *
 * \returns \p size * \p count
 *
 * See cURL documentation at https://curl.haxx.se/libcurl/c/CURLOPT_HEADERFUNCTION.html
 */
static size_t header_callback(char* buffer, size_t size, size_t count, void* context) {
    const char* sig_hdr = "x-iasreport-signature: "; // header containing IAS signature
    const char* cert_hdr = "x-iasreport-signing-certificate: "; // header containing IAS certificate
    size_t total_size = size * count;
    struct ias_request_resp* resp_data = context;
    char** save_to;
    size_t* save_to_size;
    size_t hdr_len;

    assert(context);

    if (!strncasecmp(buffer, sig_hdr, strlen(sig_hdr))) {
        save_to = &resp_data->signature;
        save_to_size = &resp_data->signature_size;
        hdr_len = strlen(sig_hdr);
    } else if (!strncasecmp(buffer, cert_hdr, strlen(cert_hdr))) {
        save_to = &resp_data->certificate;
        save_to_size = &resp_data->certificate_size;
        hdr_len = strlen(cert_hdr);
    } else {
        /* don't save */
        return total_size;
    }

    /* keep only last value */
    if (*save_to) {
        free(*save_to);
    }
    *save_to = strndup(buffer + hdr_len, total_size - hdr_len);

    if (!*save_to) {
        ERROR("Out of memory\n");
        exit(-ENOMEM); // no way to gracefully recover
    }
    *save_to_size = total_size - hdr_len;

    /* drop already stored data - seeing headers after some data means it's additional response
     * - store only the last one */
    if (resp_data->data) {
        free(resp_data->data);
        resp_data->data = NULL;
        resp_data->data_size = 0;
    }

    return total_size;
}

/*!
 * \brief Add HTTP body chunk to internal buffer.
 *
 * \param buffer   Chunk containing HTTP body.
 * \param size     Together with \p count a size of \p buffer.
 * \param count    Size of \p buffer, in \p size units.
 * \param context  User data pointer (ias_request_resp).
 *
 * \returns \p size * \p count
 *
 * See cURL documentation at https://curl.haxx.se/libcurl/c/CURLOPT_WRITEFUNCTION.html
 */
static size_t body_callback(char* buffer, size_t size, size_t count, void* context) {
    size_t total_size = size * count;
    struct ias_request_resp* resp_data = context;

    assert(context);

    /* make space for the data, plus terminating \0 */
    resp_data->data = realloc(resp_data->data, resp_data->data_size + total_size + 1);
    if (!resp_data->data) {
        ERROR("Out of memory\n");
        exit(-ENOMEM); // no way to gracefully recover
    }

    /* append the data (buffer) to resp_data->data */
    memcpy(resp_data->data + resp_data->data_size, buffer, total_size);
    resp_data->data_size += total_size;

    /* add terminating \0, but don't count it in resp_data->data_size to ease appending next chunk */
    resp_data->data[resp_data->data_size] = '\0';

    return total_size;
}

struct ias_context_t* ias_init(const char* ias_api_key, const char* ias_verify_url,
                               const char* ias_sigrl_url) {
    int ret = -1;
    struct ias_context_t* context = NULL;
    const char* api_key_hdr_start = "Ocp-Apim-Subscription-Key: ";
    char* api_key_hdr = NULL;
    size_t api_key_hdr_size;

    // can be called multiple times
    CURLcode curl_ret = curl_global_init(CURL_GLOBAL_ALL);
    if (CURL_FAIL("global cURL init", curl_ret))
        goto out;

    context = calloc(1, sizeof(*context));
    if (!context)
        goto out;

    context->curl = curl_easy_init();
    if (!context->curl || !ias_api_key)
        goto out;

    api_key_hdr_size = strlen(api_key_hdr_start) + strlen(ias_api_key) + 1;
    api_key_hdr = malloc(api_key_hdr_size);
    if (!api_key_hdr)
        goto out;
    snprintf(api_key_hdr, api_key_hdr_size, "%s%s", api_key_hdr_start, ias_api_key);

    // set IAS URLs
    context->ias_verify_url = strdup(ias_verify_url);
    context->ias_sigrl_url = strdup(ias_sigrl_url);

    if (get_verbose())
        curl_easy_setopt(context->curl, CURLOPT_VERBOSE, 1L);

    // IAS requires TLS 1.2 minimum
    curl_ret = curl_easy_setopt(context->curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
    if (CURL_FAIL("set CURLOPT_SSLVERSION", curl_ret))
        goto out;

    curl_ret = curl_easy_setopt(context->curl, CURLOPT_SSL_VERIFYPEER, 1L);
    if (CURL_FAIL("set CURLOPT_SSL_VERIFYPEER", curl_ret))
        goto out;

    // set IAS API key in headers
    context->headers = curl_slist_append(context->headers, api_key_hdr);

    // set Content-Type header (required)
    context->headers = curl_slist_append(context->headers, "Content-Type: application/json");
    curl_ret = curl_easy_setopt(context->curl, CURLOPT_HTTPHEADER, context->headers);
    if (CURL_FAIL("set CURLOPT_HTTPHEADER", curl_ret))
        goto out;

    // callbacks to store response and headers (headers contain IAS report signature)
    curl_ret = curl_easy_setopt(context->curl, CURLOPT_HEADERFUNCTION, header_callback);
    if (CURL_FAIL("set CURLOPT_HEADERFUNCTION", curl_ret))
        goto out;

    curl_ret = curl_easy_setopt(context->curl, CURLOPT_WRITEFUNCTION, body_callback);
    if (CURL_FAIL("set CURLOPT_WRITEFUNCTION", curl_ret))
        goto out;

    ret = 0;
out:
    free(api_key_hdr);
    if (ret != 0) {
        free(context);
        context = NULL;
    }

    return context;
}

void ias_cleanup(struct ias_context_t* context) {
    assert(context);

    if (context->headers)
        curl_slist_free_all(context->headers);

    curl_easy_cleanup(context->curl);
    free(context->ias_sigrl_url);
    free(context->ias_verify_url);
    free(context);

    // every curl_global_init() must have a corresponding curl_global_cleanup()
    curl_global_cleanup();
}

int ias_get_sigrl(struct ias_context_t* context, uint8_t gid[4], size_t* sigrl_size, void** sigrl) {
    struct ias_request_resp* ias_resp = NULL;
    int ret = -1;
    long response_code;
    char* url = NULL;
    size_t url_size = 0;
    CURLcode curl_ret;

    ias_resp = calloc(1, sizeof(*ias_resp));
    if (!ias_resp)
        goto out;

    /* format request URL */
    url_size = strlen(context->ias_sigrl_url) + 1 + 8 + 1; /* slash, 8 chars for gid, NULL */
    url = malloc(url_size);
    if (!url)
        goto out;

    /* gid must be big-endian */
    snprintf(url, url_size, "%s/%02x%02x%02x%02x", context->ias_sigrl_url, gid[3], gid[2], gid[1],
             gid[0]);

    DBG("IAS URL: %s\n", url);

    curl_ret = curl_easy_setopt(context->curl, CURLOPT_URL, url);
    if (CURL_FAIL("set CURLOPT_URL", curl_ret))
        goto out;

    /* disable POST for curl */
    curl_ret = curl_easy_setopt(context->curl, CURLOPT_POST, 0L);
    if (CURL_FAIL("set CURLOPT_POST", curl_ret))
        goto out;

    /* place to store result */
    curl_ret = curl_easy_setopt(context->curl, CURLOPT_HEADERDATA, ias_resp);
    if (CURL_FAIL("set CURLOPT_HEADERDATA", curl_ret))
        goto out;

    curl_ret = curl_easy_setopt(context->curl, CURLOPT_WRITEDATA, ias_resp);
    if (CURL_FAIL("set CURLOPT_WRITEDATA", curl_ret))
        goto out;

    /* perform the request, callbacks will store result in ias_resp */
    curl_ret = curl_easy_perform(context->curl);
    if (CURL_FAIL("SigRL IAS request", curl_ret))
        goto out;

    curl_ret = curl_easy_getinfo(context->curl, CURLINFO_RESPONSE_CODE, &response_code);
    if (CURL_FAIL("get response", curl_ret))
        goto out;

    if (response_code != 200) {
        ERROR("SigRL IAS request failed: code %ld\n", response_code);
        goto out;
    }

    /* SigRL is base64-encoded, decode if not empty. */
    *sigrl_size = 0;
    if (ias_resp->data) {
        ret = mbedtls_base64_decode(/*dst=*/NULL, /*dlen=*/0, sigrl_size, (uint8_t*)ias_resp->data,
                                    strlen(ias_resp->data));
        if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
            ERROR("Failed to get size for base64 decoding of SigRL\n");
            goto out;
        }

        *sigrl = malloc(*sigrl_size);
        if (!*sigrl) {
            ERROR("No memory\n");
            goto out;
        }

        ret = mbedtls_base64_decode(*sigrl, *sigrl_size, sigrl_size, (uint8_t*)ias_resp->data,
                                    strlen(ias_resp->data));
        if (ret < 0 || !*sigrl_size) {
            ERROR("Failed to base64 decode SigRL\n");
            goto out;
        }
    }
    ret = 0;

out:
    free(url);
    if (ias_resp) {
        free(ias_resp->data);
        free(ias_resp);
    }

    return ret;
}

/*! Send request to IAS and save response in \p ias_resp; caller is responsible for its cleanup */
static int ias_send_request(struct ias_context_t* context, struct ias_request_resp* ias_resp,
                            const void* quote, size_t quote_size, const char* nonce) {
    int ret = -1;
    long response_code;
    char* quote_b64 = NULL;
    size_t quote_b64_size = 0;
    char* quote_json = NULL;
    size_t quote_json_size = 0;
    const char* json_fmt = nonce ? "{\"isvEnclaveQuote\":\"%s\",\"nonce\":\"%s\"}"
                                 : "{\"isvEnclaveQuote\":\"%s\"}";

    if (nonce && strlen(nonce) > 32) {
        ERROR("Nonce too long\n");
        goto out;
    }

    /* get needed base64 buffer size */
    ret = mbedtls_base64_encode(/*dest=*/NULL, /*dlen=*/0, &quote_b64_size, quote, quote_size);
    if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
        ERROR("Failed to get size for base64 encoding of the quote\n");
        goto out;
    }

    quote_b64 = malloc(quote_b64_size);
    ret = mbedtls_base64_encode((uint8_t*)quote_b64, quote_b64_size, &quote_b64_size, quote,
                                quote_size);
    if (ret < 0) {
        ERROR("Failed to base64 encode the quote\n");
        goto out;
    }

    /* this is not exactly accurate but should always be enough for the json string */
    quote_json_size = quote_b64_size + strlen(json_fmt);
    if (nonce)
        quote_json_size += strlen(nonce);

    quote_json = malloc(quote_json_size);
    if (!quote_json) {
        ERROR("Failed to allocate memory for IAS request\n");
        goto out;
    }

    if (nonce)
        snprintf(quote_json, quote_json_size, json_fmt, quote_b64, nonce);
    else
        snprintf(quote_json, quote_json_size, json_fmt, quote_b64);

    DBG("IAS request:\n%s\n", quote_json);

    CURLcode curl_ret;
    ret = -1;

    /* request URL */
    curl_ret = curl_easy_setopt(context->curl, CURLOPT_URL, context->ias_verify_url);
    if (CURL_FAIL("set CURLOPT_URL", curl_ret))
        goto out;

    /* request data */
    curl_ret = curl_easy_setopt(context->curl, CURLOPT_POSTFIELDS, quote_json);
    if (CURL_FAIL("set CURLOPT_POSTFIELDS", curl_ret))
        goto out;

    /* place to store result */
    curl_ret = curl_easy_setopt(context->curl, CURLOPT_HEADERDATA, ias_resp);
    if (CURL_FAIL("set CURLOPT_HEADERDATA", curl_ret))
        goto out;

    curl_ret = curl_easy_setopt(context->curl, CURLOPT_WRITEDATA, ias_resp);
    if (CURL_FAIL("set CURLOPT_WRITEDATA", curl_ret))
        goto out;

    /* perform the request, callbacks will store result in ias_resp */
    curl_ret = curl_easy_perform(context->curl);
    if (CURL_FAIL("Attestation IAS request", curl_ret))
        goto out;

    curl_ret = curl_easy_getinfo(context->curl, CURLINFO_RESPONSE_CODE, &response_code);
    if (CURL_FAIL("get response", curl_ret))
        goto out;

    if (response_code != 200) {
        ERROR("Attestation IAS request failed: code %ld\n", response_code);
        goto out;
    }

    DBG("IAS response: %ld\n", response_code);

    if (!ias_resp->signature || !ias_resp->data) {
        /* XXX should it be fatal? */
        ERROR("IAS response: missing headers or data\n");
        goto out;
    }

    ret = 0;

out:
    /* cleanup */
    free(quote_b64);
    free(quote_json);

    return ret;
}

int ias_send_quote_get_report(struct ias_context_t* context, const void* quote, size_t quote_size,
                              const char* nonce, const char* report_path, const char* sig_path,
                              const char* cert_path) {
    int ret;
    struct ias_request_resp ias_resp = {0};

    ret = ias_send_request(context, &ias_resp, quote, quote_size, nonce);
    if (ret < 0) {
        ERROR("Failed to send request to IAS and receive its response\n");
        goto out;
    }

    if (report_path) {
        ret = write_file(report_path, ias_resp.data_size, ias_resp.data);
        if (ret != 0) {
            ERROR("Failed to write IAS report to %s: %s\n", report_path, strerror(errno));
            goto out;
        }
        DBG("IAS report saved to: %s\n", report_path);
    }

    if (sig_path) {
        ret = write_file(sig_path, ias_resp.signature_size, ias_resp.signature);
        if (ret != 0) {
            ERROR("Failed to write IAS signature to %s: %s\n", sig_path, strerror(errno));
            goto out;
        }
        DBG("IAS report signature saved to: %s\n", sig_path);
    }

    if (cert_path) {
        urldecode(ias_resp.certificate, ias_resp.certificate);
        ias_resp.certificate_size = strlen(ias_resp.certificate);
        ret = write_file(cert_path, ias_resp.certificate_size, ias_resp.certificate);
        if (ret != 0) {
            ERROR("Failed to write IAS certificate to %s: %s\n", cert_path, strerror(errno));
            goto out;
        }
        DBG("IAS certificate saved to: %s\n", cert_path);
    }

    /* body_callback and header_callback always add terminating \0, but
     * don't count it in respective resp_data->*_size, finalize the process
     */
    ias_resp.data_size++;
    ias_resp.signature_size++;

    ret = 0;

out:
    /* cleanup */
    free(ias_resp.signature);
    free(ias_resp.certificate);
    free(ias_resp.data);

    return ret;
}

int ias_send_quote_get_report_raw(struct ias_context_t* context, const void* quote,
                                  size_t quote_size, const char* nonce, char** report_data_ptr,
                                  size_t* report_data_size, char** sig_data_ptr,
                                  size_t* sig_data_size, char** cert_data_ptr,
                                  size_t* cert_data_size) {
    int ret;
    struct ias_request_resp ias_resp = {0};

    char* report_data   = NULL;
    char* sig_data      = NULL;
    char* cert_data     = NULL;

    ret = ias_send_request(context, &ias_resp, quote, quote_size, nonce);
    if (ret < 0) {
        ERROR("Failed to send request to IAS and receive its response\n");
        goto out;
    }

    /* body_callback and header_callback always add terminating \0, but
     * don't count it in respective resp_data->*_size, finalize the process
     */
    ias_resp.data_size++;
    ias_resp.signature_size++;

    ret = -1;

    if (report_data_ptr) {
        assert(report_data_size);

        report_data = malloc(ias_resp.data_size);
        if (!report_data) {
            ERROR("Failed to allocate memory for IAS report\n");
            goto out;
        }
        memcpy(report_data, ias_resp.data, ias_resp.data_size);

        *report_data_ptr  = report_data;
        *report_data_size = ias_resp.data_size;
    }

    if (sig_data_ptr) {
        assert(sig_data_size);

        sig_data = malloc(ias_resp.signature_size);
        if (!sig_data) {
            ERROR("Failed to allocate memory for IAS signature\n");
            goto out;
        }
        memcpy(sig_data, ias_resp.signature, ias_resp.signature_size);

        *sig_data_ptr  = sig_data;
        *sig_data_size = ias_resp.signature_size;
    }

    if (cert_data_ptr) {
        assert(cert_data_size);

        urldecode(ias_resp.certificate, ias_resp.certificate);
        ias_resp.certificate_size = strlen(ias_resp.certificate) + 1;

        cert_data = malloc(ias_resp.certificate_size);
        if (!cert_data) {
            ERROR("Failed to allocate memory for IAS certificate\n");
            goto out;
        }
        memcpy(cert_data, ias_resp.certificate, ias_resp.certificate_size);

        *cert_data_ptr  = cert_data;
        *cert_data_size = ias_resp.certificate_size;
    }

    ret = 0;

out:
    /* cleanup */
    free(ias_resp.signature);
    free(ias_resp.certificate);
    free(ias_resp.data);

    if (ret < 0) {
        free(report_data);
        free(sig_data);
        free(cert_data);
    }

    return ret;
}

int ias_verify_report_extract_quote(const uint8_t* ias_report, size_t ias_report_size,
                                    uint8_t* ias_sig_b64, size_t ias_sig_b64_size,
                                    bool allow_outdated_tcb, const char* nonce,
                                    const char* ias_pub_key_pem, uint8_t** out_quote,
                                    size_t* out_quote_size) {
    mbedtls_pk_context ias_pub_key;
    int ret = -1;
    uint8_t* ias_sig = NULL;
    uint8_t* report_quote = NULL;
    cJSON* json = NULL;

    // Load the IAS public key
    mbedtls_pk_init(&ias_pub_key);

    if (!ias_pub_key_pem)
        ias_pub_key_pem = g_ias_public_key_pem;

    ret = mbedtls_pk_parse_public_key(&ias_pub_key, (const unsigned char*)ias_pub_key_pem,
                                      strlen(ias_pub_key_pem) + 1);
    if (ret != 0) {
        ERROR("Failed to parse IAS public key: %d\n", ret);
        goto out;
    }

    DBG("IAS key: %s, %zu bits\n", mbedtls_pk_get_name(&ias_pub_key),
        mbedtls_pk_get_bitlen(&ias_pub_key));

    if (!mbedtls_pk_can_do(&ias_pub_key, MBEDTLS_PK_RSA)) {
        ret = -1;
        ERROR("IAS public key is not an RSA key\n");
        goto out;
    }

    size_t ias_sig_size = 0;

    // Drop trailing newlines
    if (ias_sig_b64_size == 0) {
        ret = -1;
        ERROR("Invalid signature size\n");
        goto out;
    }

    while (ias_sig_b64[ias_sig_b64_size - 1] == '\n' || ias_sig_b64[ias_sig_b64_size - 1] == '\r')
        ias_sig_b64[--ias_sig_b64_size] = '\0';

    ret = mbedtls_base64_decode(/*dest=*/NULL, /*dlen=*/0, &ias_sig_size, ias_sig_b64,
                                ias_sig_b64_size);
    if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
        ERROR("Failed to get size for base64 decoding of IAS signature\n");
        goto out;
    }

    ias_sig = malloc(ias_sig_size);
    if (!ias_sig) {
        ret = -1;
        ERROR("No memory\n");
        goto out;
    }

    ret = mbedtls_base64_decode(ias_sig, ias_sig_size, &ias_sig_size, ias_sig_b64,
                                ias_sig_b64_size);
    if (ret < 0) {
        ERROR("Failed to base64 decode IAS signature\n");
        goto out;
    }

    DBG("Decoded IAS signature size: %zu bytes\n", ias_sig_size);

    // Calculate report hash
    uint8_t report_hash[32];
    ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (const unsigned char*)ias_report,
                     ias_report_size, report_hash);
    if (ret != 0) {
        ERROR("Failed to compute IAS report hash: %d\n", ret);
        goto out;
    }

    // Verify signature
    ret = mbedtls_pk_verify(&ias_pub_key, MBEDTLS_MD_SHA256, (const unsigned char*)report_hash,
                            sizeof(report_hash), ias_sig, ias_sig_size);
    if (ret != 0) {
        ERROR("Failed to verify IAS report signature: %d\n", ret);
        goto out;
    }

    INFO("IAS report: signature verified correctly\n");

    // Check quote status
    ret = -1;
    json = cJSON_Parse((const char*)ias_report);
    if (!json) {
        ERROR("Failed to parse IAS report\n");
        goto out;
    }

    cJSON* node = cJSON_GetObjectItem(json, "isvEnclaveQuoteStatus");
    if (!node) {
        ERROR("IAS report: failed to read quote status\n");
        goto out;
    }

    if (node->type != cJSON_String) {
        ERROR("IAS report: quote status is not a string\n");
        goto out;
    }

    if (strcmp("OK", node->valuestring) == 0) {
        ret = 0;
        INFO("IAS report: quote status OK\n");
    } else if (allow_outdated_tcb && (
               strcmp("GROUP_OUT_OF_DATE", node->valuestring) == 0
            || strcmp("CONFIGURATION_NEEDED", node->valuestring) == 0
            || strcmp("SW_HARDENING_NEEDED", node->valuestring) == 0
            || strcmp("CONFIGURATION_AND_SW_HARDENING_NEEDED", node->valuestring) == 0
            )) {
        ret = 0;
        INFO("IAS report: allowing quote status %s\n", node->valuestring);

        cJSON* url_node = cJSON_GetObjectItem(json, "advisoryURL");
        if (url_node && url_node->type == cJSON_String)
            INFO("            [ advisory URL: %s ]\n", url_node->valuestring);

        cJSON* ids_node = cJSON_GetObjectItem(json, "advisoryIDs");
        if (ids_node && ids_node->type == cJSON_Array) {
            char* ids_str = cJSON_Print(ids_node);
            if (!ids_str) {
                ERROR("IAS report: out-of-memory during reading advisoryIDs\n");
                ret = -1;
                goto out;
            }
            INFO("            [ advisory IDs: %s ]\n", ids_str);
            free(ids_str);
        }
    }

    if (ret != 0) {
        ERROR("IAS report: quote status is not OK (%s)\n", node->valuestring);
        goto out;
    }

    ret = -1;
    // Verify nonce if required
    if (nonce) {
        cJSON* node = cJSON_GetObjectItem(json, "nonce");
        if (!node) {
            ERROR("IAS report: failed to read nonce\n");
            goto out;
        }

        if (node->type != cJSON_String) {
            ERROR("IAS report: nonce is not a string\n");
            goto out;
        }

        if (strcmp(nonce, node->valuestring) != 0) {
            ERROR("IAS report: invalid nonce '%s', expected '%s'\n", node->valuestring, nonce);
            goto out;
        }

        DBG("IAS report: nonce OK\n");
    }

    // Extract quote from the report
    node = cJSON_GetObjectItem(json, "isvEnclaveQuoteBody");
    if (!node) {
        ERROR("IAS report: failed to get quote\n");
        goto out;
    }

    if (node->type != cJSON_String) {
        ERROR("IAS report: quote is not a string\n");
        goto out;
    }

    size_t quote_size = 0;
    ret = mbedtls_base64_decode(/*dest=*/NULL, /*dlen=*/0, &quote_size, (uint8_t*)node->valuestring,
                                strlen(node->valuestring));
    if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
        ERROR("IAS report: failed to get size for base64 decoding of report quote\n");
        goto out;
    }

    report_quote = malloc(quote_size);
    if (!report_quote) {
        ret = -1;
        ERROR("No memory\n");
        goto out;
    }

    ret = mbedtls_base64_decode(report_quote, quote_size, &quote_size, (uint8_t*)node->valuestring,
                                strlen(node->valuestring));
    if (ret < 0) {
        ERROR("IAS report: failed to decode report quote\n");
        goto out;
    }

    DBG("IAS report: quote decoded, size %zu bytes\n", quote_size);
    *out_quote      = report_quote;
    *out_quote_size = quote_size;
    ret = 0;
out:
    if (ret) {
        free(report_quote);
    }
    if (json)
        cJSON_Delete(json);
    mbedtls_pk_free(&ias_pub_key);
    free(ias_sig);
    return ret ? -1 : 0;
}
