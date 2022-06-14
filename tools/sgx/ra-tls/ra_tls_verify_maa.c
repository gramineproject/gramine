/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Labs */

/*!
 * \file
 *
 * This file contains the implementation of a verification callback for TLS libraries. The callback
 * verifies the correctness of a self-signed RA-TLS certificate with an SGX quote embedded in it.
 * The callback accesses a specific attestation provider of the Microsoft Azure Attestation (MAA)
 * for MAA-based attestation as part of the verification process. In particular, the callback sends
 * the Attestation request (JSON string that embeds the SGX quote + Enclave Held Data) to MAA via
 * HTTPS and receives an Attestation response (a JSON Web Token, or JWT, with claims). To ensure
 * authenticity of the Attestation response, the callback also obtains a set of JSON Web Keys, or
 * JWKs, from MAA and verifies the signature of JWT with the corresponding JWK's public key.
 *
 * The HTTPS Attestation request is sent to the URL in the format:
 *     POST {instanceUrl}/attest/SgxEnclave?api-version=2022-08-01
 *
 * The HTTPS "Get set of JWKs" request is sent to the URL in the format:
 *     POST {instanceUrl}/certs/
 *
 * {instanceUrl} is the attestation provider URL, e.g. `shareduks.uks.attest.azure.net`.
 *
 * This file is part of the RA-TLS verification library which is typically linked into client
 * applications. This library is *not* thread-safe.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>

#include <mbedtls/base64.h>
#include <mbedtls/md.h>
#include <mbedtls/x509_crt.h>

#ifdef HAVE_INTERNAL_CJSON
/* here we -I the cJSON's repo root, which directly contains the header */
#include <cJSON.h>
#else
#include <cjson/cJSON.h>
#endif

#include "quote.h"
#include "ra_tls.h"
#include "sgx_arch.h"
#include "sgx_attest.h"
#include "util.h"

extern verify_measurements_cb_t g_verify_measurements_cb;

#define MAA_URL_MAX_SIZE 256

/** MAA "Attest SGX Enclave" API endpoint. */
#define MAA_URL_ATTEST_ENDPOINT "attest/SgxEnclave"

/** MAA "Get Signing Certificates" API endpoint. */
#define MAA_URL_CERTS_ENDPOINT "certs"

/** Default API version for MAA API endpoints. */
#define DEFAULT_MAA_PROVIDER_API_VERSION "2022-08-01"

static char* g_maa_base_url = NULL;
static char* g_maa_api_version = NULL;

/*! Context used in maa_*() calls */
struct maa_context_t {
    bool curl_global_init_done;
    CURL* curl;                 /*!< CURL context for this session */
    struct curl_slist* headers; /*!< Request headers sent to MAA attestation provider */
};

/*! MAA response (JWT token for `attest/` API, set of Signing keys for `certs/` API) */
struct maa_response {
    char* data;              /*!< response (JSON string) */
    size_t data_size;        /*!< size of \a token string */
};

static void replace_char(uint8_t* buf, size_t buf_size, char find, char replace) {
    while (*buf && buf_size > 0) {
        if (*buf == find)
            *buf = replace;
        buf++;
        buf_size--;
    }
}

/* mbedTLS currently doesn't implement base64url but only base64, so we introduce helpers */
static int mbedtls_base64url_encode(uint8_t* dst, size_t dlen, size_t* olen, const uint8_t* src,
                                    size_t slen) {
    int ret = mbedtls_base64_encode(dst, dlen, olen, src, slen);
    if (ret < 0 || dlen == 0)
        return ret;

    /* dst contains base64-encoded string; replace `+` -> `-`, `/` -> `_`, `=` -> `\0` */
    replace_char(dst, dlen, '+', '-');
    replace_char(dst, dlen, '/', '_');
    replace_char(dst, dlen, '=', '\0');
    return 0;
}

static int mbedtls_base64url_decode(uint8_t* dst, size_t dlen, size_t* olen, const uint8_t* src,
                                    size_t slen) {
    if (!src || slen == 0) {
        /* that's what mbedtls_base64_decode() does in this case */
        *olen = 0;
        return 0;
    }

    size_t copied_slen = slen + (3 - (slen - 1) % 4); /* account for 4-byte padding */
    uint8_t* copied_src = calloc(1, copied_slen + 1);
    memcpy(copied_src, src, slen);

    /* src contains base64url-encoded string; replace `-` -> `+`, `_` -> `/` and pad with `=` */
    replace_char(copied_src, copied_slen, '-', '+');
    replace_char(copied_src, copied_slen, '_', '/');
    memset(copied_src + slen, '=', copied_slen - slen);

    int ret = mbedtls_base64_decode(dst, dlen, olen, copied_src, copied_slen);
    free(copied_src);
    return ret;
}

static int init_from_env(char** ptr, const char* env_name, const char* default_val) {
    assert(ptr == &g_maa_base_url || ptr == &g_maa_api_version);

    if (*ptr) {
        /* already initialized */
        return 0;
    }

    char* env_val = getenv(env_name);
    if (!env_val) {
        if (!default_val)
            return MBEDTLS_ERR_X509_BAD_INPUT_DATA;

        *ptr = strdup(default_val);
        if (!*ptr)
            return MBEDTLS_ERR_X509_ALLOC_FAILED;

        return 0;
    }

    size_t env_val_size = strlen(env_val) + 1;
    *ptr = malloc(env_val_size);
    if (!*ptr)
        return MBEDTLS_ERR_X509_ALLOC_FAILED;

    memcpy(*ptr, env_val, env_val_size);
    return 0;
}

/*!
 * \brief Parse response headers of the MAA attestation response (currently none).
 *
 * \param[in] buffer   Single HTTP header.
 * \param[in] size     Together with \a count a size of \a buffer.
 * \param[in] count    Size of \a buffer, in \a size units.
 * \param[in] context  User data pointer (of type struct maa_response).
 *
 * \returns \a size * \a count
 *
 * \details See cURL documentation at
 *          https://curl.haxx.se/libcurl/c/CURLOPT_HEADERFUNCTION.html
 */
static size_t header_callback(char* buffer, size_t size, size_t count, void* context) {
    /* unused callback, always return success */
    (void)buffer;
    (void)context;
    return size * count;
}

/*!
 * \brief Add HTTP body chunk to internal buffer (contains JSON string).
 *
 * \param[in] buffer   Chunk containing HTTP body.
 * \param[in] size     Together with \a count a size of \a buffer.
 * \param[in] count    Size of \a buffer, in \a size units.
 * \param[in] context  User data pointer (of type struct maa_response).
 *
 * \returns \a size * \a count
 *
 * \details See cURL documentation at
 *          https://curl.haxx.se/libcurl/c/CURLOPT_WRITEFUNCTION.html
 */
static size_t body_callback(char* buffer, size_t size, size_t count, void* context) {
    size_t total_size = size * count;

    struct maa_response* response = context;
    assert(response);

    /* make space for the data, plus terminating \0 */
    response->data = realloc(response->data, response->data_size + total_size + 1);
    if (!response->data) {
        exit(-ENOMEM); // no way to gracefully recover
    }

    /* append the data (buffer) to response->data */
    memcpy(response->data + response->data_size, buffer, total_size);
    response->data_size += total_size;

    /* add terminating `\0`, but don't count it in response->data_size to ease appending a next
     * chunk (if any) */
    response->data[response->data_size] = '\0';

    return total_size;
}

static void response_cleanup(struct maa_response* response) {
    free(response->data);
    free(response);
}

static void maa_cleanup(struct maa_context_t* context) {
    if (!context)
        return;

    if (context->headers)
        curl_slist_free_all(context->headers);

    if (context->curl)
        curl_easy_cleanup(context->curl);

    /* every curl_global_init() must have a corresponding curl_global_cleanup() */
    if (context->curl_global_init_done)
        curl_global_cleanup();

    free(context);
}

static int maa_init(struct maa_context_t** out_context) {
    int ret;

    struct maa_context_t* context = calloc(1, sizeof(*context));
    if (!context) {
        ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
        goto out;
    }

    /* can be called multiple times */
    CURLcode curl_ret = curl_global_init(CURL_GLOBAL_ALL);
    if (curl_ret != CURLE_OK) {
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        goto out;
    }
    context->curl_global_init_done = true;

    context->curl = curl_easy_init();
    if (!context->curl) {
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        goto out;
    }

    curl_ret = curl_easy_setopt(context->curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
    if (curl_ret != CURLE_OK) {
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        goto out;
    }

    curl_ret = curl_easy_setopt(context->curl, CURLOPT_SSL_VERIFYPEER, 1L);
    if (curl_ret != CURLE_OK) {
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        goto out;
    }

    context->headers = curl_slist_append(context->headers, "Content-Type: application/json");
    if (!context->headers) {
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        goto out;
    }

    curl_ret = curl_easy_setopt(context->curl, CURLOPT_HTTPHEADER, context->headers);
    if (curl_ret != CURLE_OK) {
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        goto out;
    }

    curl_ret = curl_easy_setopt(context->curl, CURLOPT_HEADERFUNCTION, header_callback);
    if (curl_ret != CURLE_OK) {
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        goto out;
    }

    curl_ret = curl_easy_setopt(context->curl, CURLOPT_WRITEFUNCTION, body_callback);
    if (curl_ret != CURLE_OK) {
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        goto out;
    }

    *out_context = context;
    ret = 0;
out:
    if (ret < 0) {
        maa_cleanup(context);
    }
    return ret;
}

/*! Send GET request (empty) to MAA attestation provider's `certs/` API endpoint and save the
 * resulting set of JWKs \a out_set_of_jwks; caller is responsible for its cleanup */
static int maa_get_signing_certs(struct maa_context_t* context, char** out_set_of_jwks) {
    int ret;

    char* request_url = NULL;
    struct maa_response* response = NULL;

    /* prepare sending "GET certs" to MAA and receiving a response (using Curl) */
    response = calloc(1, sizeof(*response));
    if (!response) {
        ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
        goto out;
    }

    request_url = malloc(MAA_URL_MAX_SIZE);
    if (!request_url) {
        ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
        goto out;
    }

    ret = snprintf(request_url, MAA_URL_MAX_SIZE, "%s/%s/", g_maa_base_url, MAA_URL_CERTS_ENDPOINT);
    if (ret < 0 || (size_t)ret >= MAA_URL_MAX_SIZE) {
        ret = MBEDTLS_ERR_X509_BUFFER_TOO_SMALL;
        goto out;
    }

    CURLcode curl_ret;
    curl_ret = curl_easy_setopt(context->curl, CURLOPT_URL, request_url);
    if (curl_ret != CURLE_OK) {
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        goto out;
    }

    curl_ret = curl_easy_setopt(context->curl, CURLOPT_HTTPGET, 1);
    if (curl_ret != CURLE_OK) {
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        goto out;
    }

    curl_ret = curl_easy_setopt(context->curl, CURLOPT_HEADERDATA, response);
    if (curl_ret != CURLE_OK) {
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        goto out;
    }

    curl_ret = curl_easy_setopt(context->curl, CURLOPT_WRITEDATA, response);
    if (curl_ret != CURLE_OK) {
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        goto out;
    }

    /* send the "GET certs" request, callbacks will store results in `response` */
    curl_ret = curl_easy_perform(context->curl);
    if (curl_ret != CURLE_OK) {
        ERROR("Failed to send the MAA \"GET certs\" request to `%s`\n", request_url);
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        goto out;
    }

    long response_code;
    curl_ret = curl_easy_getinfo(context->curl, CURLINFO_RESPONSE_CODE, &response_code);
    if (curl_ret != CURLE_OK) {
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        goto out;
    }

    if (response_code != 200) {
        ERROR("MAA \"GET certs\" request failed with code %ld and message `%s`\n", response_code,
              response->data);
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        goto out;
    }

    if (!response->data) {
        ERROR("MAA \"GET certs\" response doesn't have the set of JSON Web Keys (JWKs)\n");
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        goto out;
    }

    char* set_of_jwks = strdup(response->data);
    if (!set_of_jwks) {
        ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
        goto out;
    }

    *out_set_of_jwks = set_of_jwks;
    ret = 0;
out:
    response_cleanup(response);
    free(request_url);
    return ret;
}

/*! Send request (with \a quote embedded in it) to MAA attestation provider's `attest/` API endpoint
 * and save response in \a out_maa_response; caller is responsible for its cleanup */
static int maa_send_request(struct maa_context_t* context, const void* quote, size_t quote_size,
                            const void* runtime_data, size_t runtime_data_size,
                            struct maa_response** out_maa_response) {
    int ret;

    char* quote_b64        = NULL;
    char* runtime_data_b64 = NULL;
    char* request_json     = NULL;
    char* request_url      = NULL;

    struct maa_response* response = NULL;

    /* get needed base64url buffer size for quote, allocate it and encode the quote */
    size_t quote_b64_size = 0;
    ret = mbedtls_base64url_encode(/*dest=*/NULL, /*dlen=*/0, &quote_b64_size, quote, quote_size);
    if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
        goto out;
    }

    quote_b64 = malloc(quote_b64_size);
    if (!quote_b64) {
        ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
        goto out;
    }

    ret = mbedtls_base64url_encode((uint8_t*)quote_b64, quote_b64_size, &quote_b64_size, quote,
                                   quote_size);
    if (ret < 0) {
        goto out;
    }

    /* get needed base64url buffer size for runtime data, allocate it and encode the runtime data */
    size_t runtime_data_b64_size = 0;
    ret = mbedtls_base64url_encode(/*dest=*/NULL, /*dlen=*/0, &runtime_data_b64_size, runtime_data,
                                   runtime_data_size);
    if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
        goto out;
    }

    runtime_data_b64 = malloc(runtime_data_b64_size);
    if (!runtime_data_b64) {
        ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
        goto out;
    }

    ret = mbedtls_base64url_encode((uint8_t*)runtime_data_b64, runtime_data_b64_size,
                                   &runtime_data_b64_size, runtime_data, runtime_data_size);
    if (ret < 0) {
        goto out;
    }

    /* construct JSON string with the attestation request to MAA */
    const char* request_json_fmt = "{\"quote\": \"%s\", \"runtimeData\": "
                           "  {\"data\": \"%s\", \"dataType\": \"Binary\"}  }";

    size_t request_json_size = strlen(request_json_fmt) + 1 + quote_b64_size +
                               runtime_data_b64_size;
    request_json = malloc(request_json_size);
    if (!request_json) {
        ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
        goto out;
    }

    ret = snprintf(request_json, request_json_size, request_json_fmt, quote_b64, runtime_data_b64);
    if (ret < 0 || (size_t)ret >= request_json_size) {
        ret = MBEDTLS_ERR_X509_BUFFER_TOO_SMALL;
        goto out;
    }

    /* prepare sending attestation request to MAA and receiving a response (using Curl) */
    response = calloc(1, sizeof(*response));
    if (!response) {
        ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
        goto out;
    }

    request_url = malloc(MAA_URL_MAX_SIZE);
    if (!request_url) {
        ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
        goto out;
    }

    ret = snprintf(request_url, MAA_URL_MAX_SIZE, "%s/" MAA_URL_ATTEST_ENDPOINT "?api-version=%s",
                   g_maa_base_url, g_maa_api_version);
    if (ret < 0 || (size_t)ret >= MAA_URL_MAX_SIZE) {
        ret = MBEDTLS_ERR_X509_BUFFER_TOO_SMALL;
        goto out;
    }

    CURLcode curl_ret;
    curl_ret = curl_easy_setopt(context->curl, CURLOPT_URL, request_url);
    if (curl_ret != CURLE_OK) {
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        goto out;
    }

    curl_ret = curl_easy_setopt(context->curl, CURLOPT_POST, 1);
    if (curl_ret != CURLE_OK) {
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        goto out;
    }

    curl_ret = curl_easy_setopt(context->curl, CURLOPT_POSTFIELDS, request_json);
    if (curl_ret != CURLE_OK) {
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        goto out;
    }

    curl_ret = curl_easy_setopt(context->curl, CURLOPT_HEADERDATA, response);
    if (curl_ret != CURLE_OK) {
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        goto out;
    }

    curl_ret = curl_easy_setopt(context->curl, CURLOPT_WRITEDATA, response);
    if (curl_ret != CURLE_OK) {
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        goto out;
    }

    /* send the attestation request, callbacks will store results in `response` */
    curl_ret = curl_easy_perform(context->curl);
    if (curl_ret != CURLE_OK) {
        ERROR("Failed to send the MAA Attestation request to `%s`\n", request_url);
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        goto out;
    }

    long response_code;
    curl_ret = curl_easy_getinfo(context->curl, CURLINFO_RESPONSE_CODE, &response_code);
    if (curl_ret != CURLE_OK) {
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        goto out;
    }

    if (response_code != 200) {
        ERROR("MAA Attestation request failed with code %ld and message `%s`\n", response_code,
              response->data);
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        goto out;
    }

    if (!response->data) {
        ERROR("MAA Attestation response doesn't have the JSON Web Token (JWT)\n");
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        goto out;
    }

    *out_maa_response = response;
    ret = 0;

out:
    if (ret < 0 && response) {
        response_cleanup(response);
    }
    free(quote_b64);
    free(runtime_data_b64);
    free(request_json);
    free(request_url);
    return ret;
}

/*! Verify the attestation response from MAA (the JWT token) and create a dummy SGX quote populated
 * with the SGX-enclave measurements from this response in \a out_quote_body; caller is responsible
 * for its cleanup */
static int maa_verify_response_output_quote(struct maa_response* response, const char* set_of_jwks,
                                            sgx_quote_body_t** out_quote_body) {
    int ret;

    sgx_quote_body_t* quote_body = NULL;

    char* maa_certs_url = NULL;

    cJSON* json_response      = NULL;
    cJSON* json_token_header  = NULL;
    cJSON* json_token_payload = NULL;
    cJSON* json_jwks          = NULL;

    char* token_b64_header    = NULL;
    char* token_b64_payload   = NULL;
    char* token_b64_signature = NULL;

    char* token_header    = NULL;
    char* token_payload   = NULL;
    char* token_signature = NULL;

    char* token_signing_x509cert_b64 = NULL; /* not allocated, so no need to free it */
    char* token_signing_x509cert     = NULL;

    mbedtls_md_context_t md_context;
    mbedtls_md_init(&md_context);

    mbedtls_x509_crt token_signing_crt;
    mbedtls_x509_crt_init(&token_signing_crt);

    json_response = cJSON_Parse(response->data);
    if (!json_response) {
        ERROR("MAA Attestation response is not proper JSON\n");
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        goto out;
    }

    cJSON* token_b64 = cJSON_GetObjectItem(json_response, "token");
    if (!cJSON_IsString(token_b64)) {
        ERROR("MAA Attestation response doesn't contain the `token` string key (JWT)\n");
        ret = MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT;
        goto out;
    }

    /* JWT tokens are strings in the format: xxx.yyy.zzz where xxx, yyy, zzz are the header, the
     * payload, and the signature correspondingly (each base64url encoded) */
    char* header_begin_in_token_b64 = token_b64->valuestring;
    char* header_end_in_token_b64   = strchr(header_begin_in_token_b64, '.');
    if (!header_end_in_token_b64) {
        ERROR("MAA JWT is incorrectly formatted (cannot find the header)\n");
        ret = MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT;
        goto out;
    }

    token_b64_header = calloc(1, header_end_in_token_b64 - header_begin_in_token_b64 + 1);
    if (!token_b64_header) {
        ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
        goto out;
    }
    memcpy(token_b64_header, header_begin_in_token_b64,
           header_end_in_token_b64 - header_begin_in_token_b64);

    char* payload_begin_in_token_b64 = header_end_in_token_b64 + 1;
    char* payload_end_in_token_b64   = strchr(payload_begin_in_token_b64, '.');
    if (!payload_end_in_token_b64) {
        ERROR("MAA JWT is incorrectly formatted (cannot find the payload)\n");
        ret = MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT;
        goto out;
    }

    token_b64_payload = calloc(1, payload_end_in_token_b64 - payload_begin_in_token_b64 + 1);
    if (!token_b64_payload) {
        ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
        goto out;
    }
    memcpy(token_b64_payload, payload_begin_in_token_b64,
           payload_end_in_token_b64 - payload_begin_in_token_b64);

    char* signature_begin_in_token_b64 = payload_end_in_token_b64 + 1;
    token_b64_signature = strdup(signature_begin_in_token_b64);
    if (!token_b64_signature) {
        ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
        goto out;
    }

    size_t token_header_size;
    ret = mbedtls_base64url_decode(/*dest=*/NULL, /*dlen=*/0, &token_header_size,
                                   (const uint8_t*)token_b64_header, strlen(token_b64_header));
    if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
        goto out;
    }

    token_header = calloc(1, token_header_size + 1);
    if (!token_header) {
        ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
        goto out;
    }

    ret = mbedtls_base64url_decode((uint8_t*)token_header, token_header_size, &token_header_size,
                                   (const uint8_t*)token_b64_header, strlen(token_b64_header));
    if (ret < 0) {
        ERROR("MAA JWT is incorrectly formatted (the header is not Base64Url encoded)\n");
        goto out;
    }

    size_t token_payload_size;
    ret = mbedtls_base64url_decode(/*dest=*/NULL, /*dlen=*/0, &token_payload_size,
                                   (const uint8_t*)token_b64_payload, strlen(token_b64_payload));
    if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
        goto out;
    }

    token_payload = calloc(1, token_payload_size + 1);
    if (!token_payload) {
        ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
        goto out;
    }

    ret = mbedtls_base64url_decode((uint8_t*)token_payload, token_payload_size, &token_payload_size,
                                   (const uint8_t*)token_b64_payload, strlen(token_b64_payload));
    if (ret < 0) {
        ERROR("MAA JWT is incorrectly formatted (the payload is not Base64Url encoded)\n");
        goto out;
    }

    size_t token_signature_size;
    ret = mbedtls_base64url_decode(/*dest=*/NULL, /*dlen=*/0, &token_signature_size,
                                   (const uint8_t*)token_b64_signature,
                                   strlen(token_b64_signature));
    if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
        goto out;
    }

    token_signature = calloc(1, token_signature_size + 1);
    if (!token_signature) {
        ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
        goto out;
    }

    ret = mbedtls_base64url_decode((uint8_t*)token_signature, token_signature_size,
                                   &token_signature_size, (const uint8_t*)token_b64_signature,
                                   strlen(token_b64_signature));
    if (ret < 0) {
        ERROR("MAA JWT is incorrectly formatted (the signature is not Base64Url encoded)\n");
        goto out;
    }

    /* at this point, we parsed JWT into three decoded strings: token_header, token_payload,
     * token_signature; the first two are JSON strings */
    json_token_header = cJSON_Parse(token_header);
    if (!json_token_header) {
        ERROR("MAA JWT is incorrectly formatted (the header is not proper JSON)\n");
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        goto out;
    }

    cJSON* token_header_alg = cJSON_GetObjectItem(json_token_header, "alg");
    cJSON* token_header_kid = cJSON_GetObjectItem(json_token_header, "kid");
    cJSON* token_header_typ = cJSON_GetObjectItem(json_token_header, "typ");
    cJSON* token_header_jku = cJSON_GetObjectItem(json_token_header, "jku");

    /* currently only support JWTs with RSA-SHA256 signing */
    if (!cJSON_IsString(token_header_alg) || strcmp(token_header_alg->valuestring, "RS256") ||
            !cJSON_IsString(token_header_typ) || strcmp(token_header_typ->valuestring, "JWT") ||
            !cJSON_IsString(token_header_kid)) {
        ERROR("MAA JWT header's `alg`, `typ` and/or `kid` fields contain unrecognized values\n");
        ret = MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT;
        goto out;
    }

    /* verify that we got the set of JWKs from the same endpoint as contained in `jku`; note that
     * `jku` field doesn't have the trailing slash */
    maa_certs_url = malloc(MAA_URL_MAX_SIZE);
    if (!maa_certs_url) {
        ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
        goto out;
    }

    ret = snprintf(maa_certs_url, MAA_URL_MAX_SIZE, "%s/%s", g_maa_base_url,
                   MAA_URL_CERTS_ENDPOINT);
    if (ret < 0 || (size_t)ret >= MAA_URL_MAX_SIZE) {
        ret = MBEDTLS_ERR_X509_BUFFER_TOO_SMALL;
        goto out;
    }

    if (!cJSON_IsString(token_header_jku) || strcmp(token_header_jku->valuestring, maa_certs_url)) {
        ERROR("MAA JWT header's `jku` field contains an unexpected URL (got `%s`, expected `%s`)\n",
              token_header_jku->valuestring, maa_certs_url);
        ret = MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT;
        goto out;
    }

    json_token_payload = cJSON_Parse(token_payload);
    if (!json_token_payload) {
        ERROR("MAA JWT is incorrectly formatted (the payload is not proper JSON)\n");
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        goto out;
    }

    /* json_token_header["kid"] contains an ID that should be found in `set_of_jwks`, so let's parse
     * the latter, find the corresponding array item and extract the X.509 cert from `x5c` field */
    json_jwks = cJSON_Parse(set_of_jwks);
    if (!json_jwks) {
        ERROR("MAA set of JWKs is incorrectly formatted (the set is not proper JSON)\n");
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        goto out;
    }

    cJSON* keys_json_array = cJSON_GetObjectItem(json_jwks, "keys");
    if (!cJSON_IsArray(keys_json_array)) {
        ERROR("MAA set of JWKs doesn't contain the `keys` JSON array\n");
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        goto out;
    }

    token_signing_x509cert_b64 = NULL; /* for sanity */
    const cJSON* key_json = NULL;
    cJSON_ArrayForEach(key_json, keys_json_array) {
        /* in practice, the `certs/` API endpoint doesn't have `use` and `alg` fields */
        cJSON* key_kty = cJSON_GetObjectItem(key_json, "kty");
        cJSON* key_kid = cJSON_GetObjectItem(key_json, "kid");
        cJSON* key_x5c = cJSON_GetObjectItem(key_json, "x5c");

        /* currently only support RSA keys */
        if (!cJSON_IsString(key_kty) || strcmp(key_kty->valuestring, "RSA")) {
            ERROR("MAA JWK's `kty` field contains an unexpected value (got `%s`, expected `%s`)\n",
                    key_kty->valuestring, "RSA");
            ret = MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT;
            goto out;
        }

        if (!cJSON_IsString(key_kid) || !cJSON_IsArray(key_x5c) || !cJSON_GetArraySize(key_x5c)) {
            ERROR("MAA JWK's `kid` and/or `x5c` fields have incorrect types\n");
            ret = MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT;
            goto out;
        }

        /* compare kid from the set of JWKs with the one in JWT */
        if (!strcmp(key_kid->valuestring, token_header_kid->valuestring)) {
            cJSON* key_first_x509cert = cJSON_GetArrayItem(key_x5c, 0);
            if (!cJSON_IsString(key_first_x509cert)) {
                ERROR("MAA JWK's `x5c` is not an array of string-value X.509 certificates\n");
                ret = MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT;
                goto out;
            }

            token_signing_x509cert_b64 = key_first_x509cert->valuestring;
            break;
        }
    }

    if (!token_signing_x509cert_b64) {
        ERROR("Failed to find a corresponding JWK for the JWT received from MAA\n");
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        goto out;
    }

    /* note that "x5c" field is *not* base64url encoded */
    size_t token_signing_x509cert_size = 0;
    ret = mbedtls_base64_decode(/*dest=*/NULL, /*dlen=*/0, &token_signing_x509cert_size,
                                (const uint8_t*)token_signing_x509cert_b64,
                                strlen(token_signing_x509cert_b64));
    if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
        goto out;
    }

    token_signing_x509cert = malloc(token_signing_x509cert_size);
    if (!token_signing_x509cert) {
        ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
        goto out;
    }

    ret = mbedtls_base64_decode((uint8_t*)token_signing_x509cert, token_signing_x509cert_size,
                                &token_signing_x509cert_size,
                                (const uint8_t*)token_signing_x509cert_b64,
                                strlen(token_signing_x509cert_b64));
    if (ret < 0) {
        ERROR("MAA JWK's certificate is incorrectly formatted (not Base64 encoded)\n");
        goto out;
    }

    ret = mbedtls_x509_crt_parse(&token_signing_crt, (const uint8_t*)token_signing_x509cert,
                                 token_signing_x509cert_size);
    if (ret < 0) {
        ERROR("MAA JWK's certificate is incorrectly formatted (not a proper X.509 cert)\n");
        goto out;
    }

    /* perform signature verification of attestation token using the public key from the self-signed
     * certificate obtained from `certs/` MAA API endpoint */
    uint8_t md_sha256[32];
    mbedtls_md_setup(&md_context, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), /*hmac=*/0);
    mbedtls_md_starts(&md_context);
    mbedtls_md_update(&md_context, (const uint8_t*)token_b64_header, strlen(token_b64_header));
    mbedtls_md_update(&md_context, (const uint8_t*)".", 1);
    mbedtls_md_update(&md_context, (const uint8_t*)token_b64_payload,
                      strlen(token_b64_payload));
    mbedtls_md_finish(&md_context, md_sha256);

    ret = mbedtls_pk_verify(&token_signing_crt.pk, MBEDTLS_MD_SHA256, md_sha256, sizeof(md_sha256),
                            (const uint8_t*)token_signature, token_signature_size);
    if (ret < 0) {
        ERROR("Failed signature verification of JWT using the JWK's certificate\n");
        goto out;
    }

    /* we verified the header and the signature of the received JWT, can trust its payload */
    cJSON* x_ms_ver  = cJSON_GetObjectItem(json_token_payload, "x-ms-ver");
    cJSON* x_ms_type = cJSON_GetObjectItem(json_token_payload, "x-ms-attestation-type");

    cJSON* sgx_is_debuggable = cJSON_GetObjectItem(json_token_payload, "x-ms-sgx-is-debuggable");
    cJSON* sgx_mrenclave     = cJSON_GetObjectItem(json_token_payload, "x-ms-sgx-mrenclave");
    cJSON* sgx_mrsigner      = cJSON_GetObjectItem(json_token_payload, "x-ms-sgx-mrsigner");
    cJSON* sgx_product_id    = cJSON_GetObjectItem(json_token_payload, "x-ms-sgx-product-id");
    cJSON* sgx_svn           = cJSON_GetObjectItem(json_token_payload, "x-ms-sgx-svn");
    cJSON* sgx_report_data   = cJSON_GetObjectItem(json_token_payload, "x-ms-sgx-report-data");

    /* XXX: we currently do not use/verify the following fields: x-ms-sgx-ehd, x-ms-sgx-config-id,
     *      x-ms-sgx-config-svn, x-ms-sgx-isv-extended-product-id, x-ms-sgx-isv-family-id,
     *      x-ms-sgx-collateral, x-ms-policy-hash */

    if (!cJSON_IsString(x_ms_ver) || strcmp(x_ms_ver->valuestring, "1.0") ||
            !cJSON_IsString(x_ms_type) || strcmp(x_ms_type->valuestring, "sgx")) {
        ERROR("MAA JWT payload's `x-ms-ver` and/or `x-ms-attestation-type` fields contain "
              "unrecognized values\n");
        ret = MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT;
        goto out;
    }

    if (!cJSON_IsBool(sgx_is_debuggable) || !cJSON_IsString(sgx_mrenclave) ||
            !cJSON_IsString(sgx_mrsigner) || !cJSON_IsNumber(sgx_product_id) ||
            !cJSON_IsNumber(sgx_svn) || !cJSON_IsString(sgx_report_data)) {
        ERROR("MAA JWT payload's `x-ms-sgx-is-debuggable`, `x-ms-sgx-mrenclave`, "
              "`x-ms-sgx-mrsigner`, `x-ms-sgx-product-id`, `x-ms-sgx-svn` and/or "
              "`x-ms-sgx-report-data` fields have incorrect types\n");
        ret = MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT;
        goto out;
    }

    /* construct a dummy SGX quote (body) with contents takes from the JWT payload; this is for
     * convenience because other functions in RA-TLS library operate on an SGX quote */
    quote_body = calloc(1, sizeof(*quote_body));
    if (!quote_body) {
        ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
        goto out;
    }

    quote_body->version = 3; /* DCAP; not strictly needed, just for sanity */

    quote_body->report_body.attributes.flags = SGX_FLAGS_INITIALIZED | SGX_FLAGS_MODE64BIT;
    if (cJSON_IsTrue(sgx_is_debuggable))
        quote_body->report_body.attributes.flags |= SGX_FLAGS_DEBUG;

    ret = parse_hex(sgx_mrenclave->valuestring, &quote_body->report_body.mr_enclave,
                    sizeof(quote_body->report_body.mr_enclave), /*mask=*/NULL);
    if (ret < 0) {
        ERROR("MAA JWT payload's `x-ms-sgx-mrenclave` field is not hex encoded\n");
        ret = MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT;
        goto out;
    }

    ret = parse_hex(sgx_mrsigner->valuestring, &quote_body->report_body.mr_signer,
                    sizeof(quote_body->report_body.mr_signer), /*mask=*/NULL);
    if (ret < 0) {
        ERROR("MAA JWT payload's `x-ms-sgx-mrsigner` field is not hex encoded\n");
        ret = MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT;
        goto out;
    }

    if (sgx_product_id->valueint == INT_MAX || sgx_product_id->valueint == INT_MIN) {
        ERROR("MAA JWT payload's `x-ms-sgx-product-id` field is not an integer\n");
        ret = MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT;
        goto out;
    }
    quote_body->report_body.isv_prod_id = sgx_product_id->valueint;

    if (sgx_svn->valueint == INT_MAX || sgx_svn->valueint == INT_MIN) {
        ERROR("MAA JWT payload's `x-ms-sgx-svn` field is not an integer\n");
        ret = MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT;
        goto out;
    }
    quote_body->report_body.isv_svn = sgx_svn->valueint;

    ret = parse_hex(sgx_report_data->valuestring, &quote_body->report_body.report_data,
                    sizeof(quote_body->report_body.report_data), /*mask=*/NULL);
    if (ret < 0) {
        ERROR("MAA JWT payload's `x-ms-sgx-report-data` field is not hex encoded\n");
        ret = MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT;
        goto out;
    }

    *out_quote_body = quote_body;
    ret = 0;
out:
    if (ret < 0) {
        free(quote_body);
    }

    if (json_response)
        cJSON_Delete(json_response);
    if (json_token_header)
        cJSON_Delete(json_token_header);
    if (json_token_payload)
        cJSON_Delete(json_token_payload);
    if (json_jwks)
        cJSON_Delete(json_jwks);

    free(token_b64_header);
    free(token_b64_payload);
    free(token_b64_signature);

    free(token_header);
    free(token_payload);
    free(token_signature);

    free(maa_certs_url);
    free(token_signing_x509cert);
    mbedtls_x509_crt_free(&token_signing_crt);
    mbedtls_md_free(&md_context);
    return ret;
}

/*! parse the public key \p pk into DER format and copy it into \p pk_der */
static int parse_pk(mbedtls_pk_context* pk, uint8_t* out_pk_der) {
    /* below function writes data at the end of the buffer */
    int pk_der_size_byte = mbedtls_pk_write_pubkey_der(pk, out_pk_der, PUB_KEY_SIZE_MAX);
    if (pk_der_size_byte != RSA_PUB_3072_KEY_DER_LEN)
        return MBEDTLS_ERR_PK_INVALID_PUBKEY;

    /* move the data to the beginning of the buffer, to avoid pointer arithmetic later */
    memmove(out_pk_der, out_pk_der + PUB_KEY_SIZE_MAX - pk_der_size_byte, pk_der_size_byte);
    return 0;
}

int ra_tls_verify_callback(void* data, mbedtls_x509_crt* crt, int depth, uint32_t* flags) {
    (void)data;

    int ret;

    struct maa_context_t* context = NULL;
    struct maa_response* response = NULL;
    char* set_of_jwks             = NULL;

    sgx_quote_body_t* quote_from_maa = NULL;

    if (depth != 0) {
        /* the cert chain in RA-TLS consists of single self-signed cert, so we expect depth 0 */
        return MBEDTLS_ERR_X509_INVALID_FORMAT;
    }

    if (flags) {
        /* mbedTLS sets flags to signal that the cert is not to be trusted (e.g., it is not
         * correctly signed by a trusted CA; since RA-TLS uses self-signed certs, we don't care
         * what mbedTLS thinks and ignore internal cert verification logic of mbedTLS */
        *flags = 0;
    }

    ret = init_from_env(&g_maa_base_url, RA_TLS_MAA_PROVIDER_URL, /*default_val=*/NULL);
    if (ret < 0) {
        ERROR("Failed to read the environment variable RA_TLS_MAA_PROVIDER_URL\n");
        goto out;
    }

    ret = init_from_env(&g_maa_api_version, RA_TLS_MAA_PROVIDER_API_VERSION,
                        DEFAULT_MAA_PROVIDER_API_VERSION);
    if (ret < 0) {
        ERROR("Failed to read the environment variable RA_TLS_MAA_PROVIDER_API_VERSION\n");
        goto out;
    }

    /* extract SGX quote from "quote" OID extension from crt */
    sgx_quote_t* quote;
    size_t quote_size;
    ret = find_oid(crt->v3_ext.p, crt->v3_ext.len, quote_oid, quote_oid_len, (uint8_t**)&quote,
                   &quote_size);
    if (ret < 0)
        goto out;

    if (quote_size < sizeof(*quote)) {
        ret = MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
        goto out;
    }

    /* compare public key's hash from cert against quote's report_data */
    ret = cmp_crt_pk_against_quote_report_data(crt, quote);
    if (ret < 0)
        goto out;

    /* parse the public key of the received certificate into DER format -- it should be put into the
     * Attestation request's `runtimeData` field (MAA will take a SHA256 hash over it and verify
     * against the first 32 bytes of the SGX quote's report_data field) */
    uint8_t pk_der[PUB_KEY_SIZE_MAX] = {0};
    ret = parse_pk(&crt->pk, pk_der);
    if (ret < 0)
        goto out;

    /* initialize the MAA context, get the set of JWKs from the `certs/` MAA API endpoint, send the
     * SGX quote to the `attest/` MAA API endpoint, and finally receive and verify the attestation
     * response (JWT) */
    ret = maa_init(&context);
    if (ret < 0) {
        goto out;
    }

    /* a set of JWKs may change over time, so we better get them every time */
    ret = maa_get_signing_certs(context, &set_of_jwks);
    if (ret < 0) {
        goto out;
    }

    ret = maa_send_request(context, quote, quote_size, pk_der, RSA_PUB_3072_KEY_DER_LEN, &response);
    if (ret < 0) {
        goto out;
    }
    assert(response && response->data);

    /* The attestation response is JWT -- we need to verify its signature using one of the set of
     * JWKs, as well as verify its header and payload, and construct an SGX quote from the
     * JWT-payload values to be used in further `verify_*` functions */
    ret = maa_verify_response_output_quote(response, set_of_jwks, &quote_from_maa);
    if (ret < 0) {
        ret = MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
        goto out;
    }

    /* verify that the SGX quote sent to MAA has the same measurements as the constructed from the
     * MAA's JWT payload -- just for sanity */
    sgx_report_body_t* orig_body = &quote->body.report_body;
    sgx_report_body_t* maa_body  = &quote_from_maa->report_body;
    if (memcmp(&orig_body->report_data, &maa_body->report_data, sizeof(orig_body->report_data)) ||
            memcmp(&orig_body->mr_enclave, &maa_body->mr_enclave, sizeof(orig_body->mr_enclave)) ||
            memcmp(&orig_body->mr_signer, &maa_body->mr_signer, sizeof(orig_body->mr_signer))) {
        ERROR("Failed verification of JWT's SGX measurements against the original SGX quote's "
              "measurements (for sanity)\n");
        ret = MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
        goto out;
    }

    /* verify enclave attributes from the SGX quote body, including the user-supplied verification
     * parameter "allow debug enclave"; NOTE: "allow outdated TCB" parameter is not used in MAA */
    ret = verify_quote_body_enclave_attributes(quote_from_maa, getenv_allow_debug_enclave());
    if (ret < 0) {
        ERROR("Failed verification of JWT's SGX enclave attributes\n");
        ret = MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
        goto out;
    }

    /* verify other relevant enclave information from the SGX quote */
    if (g_verify_measurements_cb) {
        /* use user-supplied callback to verify measurements */
        ret = g_verify_measurements_cb((const char*)&quote_from_maa->report_body.mr_enclave,
                                       (const char*)&quote_from_maa->report_body.mr_signer,
                                       (const char*)&quote_from_maa->report_body.isv_prod_id,
                                       (const char*)&quote_from_maa->report_body.isv_svn);
    } else {
        /* use default logic to verify measurements */
        ret = verify_quote_body_against_envvar_measurements(quote_from_maa);
    }
    if (ret < 0) {
        ERROR("Failed verification of JWT's SGX measurements\n");
        ret = MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
        goto out;
    }

    ret = 0;
out:
    if (context)
        maa_cleanup(context);

    if (response)
        response_cleanup(response);

    free(set_of_jwks);
    free(quote_from_maa);
    return ret;
}
