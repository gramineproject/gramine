/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel */

/*!
 * \file
 *
 * This file contains the implementation of Amber client via
 * `/dev/amber/{keyid, token, secret, status, renew}` pseudo-files.
 *
 * The Amber client logic uses DkAttestationQuote() to support
 * the workflows of quote verification, token issuance/renew and
 * secret provisioning.
 *
 * This pseudo-FS interface is not thread-safe.
 * It is the responsibility of the application to
 * correctly synchronize concurrent accesses to the pseudo-files.
 * We expect amber flows to be generally single-threaded
 * and therefore do not introduce synchronization here.
 */

#include "https.h"
#include "jsmn.h"
// #include "picohttpparser.h" /*cause conflict with a type defined in shim */
#include "libos_fs_encrypted.h"
#include "libos_fs_pseudo.h"
#include "log.h"
#include "toml_utils.h"
#include "hex.h"

/* the prefix strings for amber status messages */
#define AMBER_STATUS_INFO  "[INFO]"
#define AMBER_STATUS_ERROR "[ERROR]"
/* the predefine status messages for amber client */
#define AMBER_STATUS_UNINITIALIZED      "uninitialized"
#define AMBER_STATUS_INITIALIZED        "initialized"
#define AMBER_STATUS_PROVISIONED        "provisioned"
#define AMBER_STATUS_RENEWED            "renewed"
#define AMBER_STATUS_RENEW_FAILED       "renew failed"
#define AMBER_STATUS_PROVISION_FAILED   "provision failed"
#define AMBER_STATUS_PROVISION_REJECTED "provision rejected"

const char* CA_CHAIN =
"-----BEGIN CERTIFICATE----- \n\
MIIF5DCCBMygAwIBAgIRAPM1n7EbS5uSEFsviUcuYSswDQYJKoZIhvcNAQELBQAw\n\
RjELMAkGA1UEBhMCVVMxIjAgBgNVBAoTGUdvb2dsZSBUcnVzdCBTZXJ2aWNlcyBM\n\
TEMxEzARBgNVBAMTCkdUUyBDQSAxQzMwHhcNMjMwODA3MTIyMjQ4WhcNMjMxMDMw\n\
MTIyMjQ3WjAVMRMwEQYDVQQDEwpkbnMuZ29vZ2xlMIIBIjANBgkqhkiG9w0BAQEF\n\
AAOCAQ8AMIIBCgKCAQEA1+yKwM4lh44fEmarP/7TnOqBht16/mQbKAtSIc5tlUM8\n\
I4+peY5/gopsW+re3G+dnQJjFzV+bhWt4CjYAJcA54thdeNKkRIk2xPrsOgbyAZ0\n\
lk1CsHHzGeRgR8xpEa1qU5Bn0mw7wV4NrbnDcWO3sbRkm3qgnYqOEHP+p14R6KAm\n\
e4a96TsT8OdLAnqKkwAzJtWSffRFpgPBHRQIWMDJ0ELtwbQTq0kmgGxg2rip5WyV\n\
PewpdZraTcsC1n0stJyiAcdY3A2LttGiG00oDr/yYXwWADkv2VsgNXEzG0vctCcj\n\
q4j6ZY5SMXKwkJ8MInVHyWdK8kNqbU99cr3sp8fsMQIDAQABo4IC/DCCAvgwDgYD\n\
VR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAw\n\
HQYDVR0OBBYEFAmZaHVDVFtCV4Jf49YVl2jOTx7fMB8GA1UdIwQYMBaAFIp0f6+F\n\
ze6VzT2c0OJGFPNxNR0nMGoGCCsGAQUFBwEBBF4wXDAnBggrBgEFBQcwAYYbaHR0\n\
cDovL29jc3AucGtpLmdvb2cvZ3RzMWMzMDEGCCsGAQUFBzAChiVodHRwOi8vcGtp\n\
Lmdvb2cvcmVwby9jZXJ0cy9ndHMxYzMuZGVyMIGsBgNVHREEgaQwgaGCCmRucy5n\n\
b29nbGWCDmRucy5nb29nbGUuY29tghAqLmRucy5nb29nbGUuY29tggs4ODg4Lmdv\n\
b2dsZYIQZG5zNjQuZG5zLmdvb2dsZYcECAgICIcECAgEBIcQIAFIYEhgAAAAAAAA\n\
AACIiIcQIAFIYEhgAAAAAAAAAACIRIcQIAFIYEhgAAAAAAAAAABkZIcQIAFIYEhg\n\
AAAAAAAAAAAAZDAhBgNVHSAEGjAYMAgGBmeBDAECATAMBgorBgEEAdZ5AgUDMDwG\n\
A1UdHwQ1MDMwMaAvoC2GK2h0dHA6Ly9jcmxzLnBraS5nb29nL2d0czFjMy9RcUZ4\n\
Ymk5TTQ4Yy5jcmwwggEFBgorBgEEAdZ5AgQCBIH2BIHzAPEAdgDoPtDaPvUGNTLn\n\
Vyi8iWvJA9PL0RFr7Otp4Xd9bQa9bgAAAYnQKiSNAAAEAwBHMEUCIQCQ0Zikdh80\n\
0dPQg0QknWetB0rhX8JYKC2LbFtBT/bL0AIgA0O34HK8rNmOvYory8aMaSGmPgXY\n\
Vh2aEyuiIHQs2U4AdwC3Pvsk35xNunXyOcW6WPRsXfxCz3qfNcSeHQmBJe20mQAA\n\
AYnQKiSfAAAEAwBIMEYCIQDLXpNYPkrEy1aYJoUKt69VZnEb0TT2ifbgZEwdZzHX\n\
mgIhAI+wJrKIOiMhwgVH+YEUhS8DUwpvkCaR6MqR5YRN67+JMA0GCSqGSIb3DQEB\n\
CwUAA4IBAQDn7bk66zmcQxJ1p3lBnpIVZAAaAJ0sq0AfQmHRlGa8pATPaAfVzt6+\n\
CY+4+/3SvwwCdWJeblk9+RB/zDUsKMxgD/ubZMyqX1Gn2RYKdlFajs0a10s8G3IG\n\
x/yA5ZlPJLXu9z158WEJCE5EQmG9zg0q5l3XRoimLDypx2OnNW1EYKKonghgJ5yj\n\
2V8x+nPP96O1gyBw4EjJ4T5fhj96MTUI+iU9UpcTkN0p16wNp2lq0456h1gVyFgQ\n\
LK3rsI3xbyYdeMH2aW2R9slJ4emPH4htELje+SlNds3sEFqCQA4gH3Lh3PYYETez\n\
L6XZjeoWV5K2UTj0JAI0gIAUMdPObqZK\n\
-----END CERTIFICATE-----";

/* the amber status functions */
static size_t amber_status_info(const char* fmt, ...);
static size_t amber_status_error(const char* fmt, ...);
void debug_base64_bytes(const char* label, const char *base64_encoded,
                        const unsigned char *base64_decoded, size_t base64_decoded_sz);

/* the macros defined here to reduce the code duplication */
#define amber_save_func(name) \
    static int amber_##name##_save(struct libos_dentry* dent, const char* data, size_t size) { \
        __UNUSED(dent); \
        int ret; \
        size_t sz = set_amber_##name(data, size); \
        if (sz != size) { \
            return -EACCES; \
        } \
        amber_status_info("%s saved", #name); \
        ret = amber_##name##_save_event(); \
        return ret; \
    }

#define amber_load_func(name) \
    static int amber_##name##_load(struct libos_dentry* dent, char** out_data, size_t* out_size) { \
        __UNUSED(dent); \
        log_global_vars(); \
        *out_data = NULL; \
        *out_size = 0; \
        int ret = amber_##name##_load_event(); \
        if (ret < 0) { \
            return ret; \
        } \
        *out_data = get_amber_##name(); \
        if (*out_data) { \
            *out_size = g_amber_##name##_size; \
        } else { \
            *out_data = calloc(1, 1); \
        } \
        return 0; \
    }

#define get_amber_func(name) \
    static char* get_amber_##name(void) { \
        return get_buffer_content(g_amber_##name, g_amber_##name##_size); \
    }

#define set_amber_func(name, ucname) \
    static size_t set_amber_##name(const char* data, size_t size) { \
        if (!data) { \
            log_debug("<<< set_amber_%s: (null) : sz: %ld", #name, size); \
            return 0; \
        } \
        log_debug("<<< set_amber_%s: %s : sz: %ld", #name, data, size); \
        g_amber_##name##_size = \
            update_buffer(g_amber_##name, AMBER_##ucname##_MAX_SIZE, data, size); \
        if (g_amber_##name##_size != size) { \
            amber_status_error("The content truncated to %zu bytes", g_amber_##name##_size); \
        } \
        log_debug(">>> set_amber_%s: %s : sz: %ld", #name, g_amber_##name, g_amber_##name##_size); \
        return g_amber_##name##_size; \
    }

#define amber_var(name, ucname, maxsize) \
    static const size_t AMBER_##ucname##_MAX_SIZE = maxsize; \
    static char g_amber_##name[maxsize] = {0}; \
    static size_t g_amber_##name##_size = 0; \

#define amber_dev_rw(name) \
    struct pseudo_node* amber_node_##name = \
        pseudo_add_str(amber, #name, &amber_##name##_load); \
        amber_node_##name->perm     = PSEUDO_PERM_FILE_RW; \
        amber_node_##name->str.save = &amber_##name##_save;

#define amber_dev_ro(name) \
        pseudo_add_str(amber, #name, &amber_##name##_load);

static int g_amber_client_initialized = FALSE;

/* all amber variables defined here for referencing by associated functions*/
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#pragma GCC diagnostic ignored "-Wunused-const-variable"
amber_var(endpoint_ip, ENDPOINT_IP, 64);
amber_var(endpoint_url, ENDPOINT_URL, 2048);
amber_var(kbs_ip, KBS_IP, 64);
amber_var(kbs_url, KBS_URL, 2048);
amber_var(endpoint_apikey, ENDPOINT_APIKEY, 512);
amber_var(kbs_keyid, KBS_KEYID, 1024);
amber_var(renew, RENEW, 256);
amber_var(userdata, USERDATA, 8192);
amber_var(quote, QUOTE, 8192);
amber_var(user_report_data, USER_REPORT_DATA, 256);
amber_var(token, TOKEN, 4096);
amber_var(secret, SECRET, 2048);
amber_var(status, STATUS, 1024);
amber_var(cacerts, CACERTS, 10240);
#pragma GCC diagnostic pop

/* the code for debug purpose */
static void log_global_vars(void) {
    log_debug("g_amber_endpoint_ip sz: %ld = %s", g_amber_endpoint_ip_size, g_amber_endpoint_ip);
    log_debug("g_amber_endpoint_url sz: %ld = %s", g_amber_endpoint_url_size, g_amber_endpoint_url);
    log_debug("g_amber_kbs_ip sz: %ld = %s", g_amber_kbs_ip_size, g_amber_kbs_ip);
    log_debug("g_amber_kbs_url sz: %ld = %s", g_amber_kbs_url_size, g_amber_kbs_url);
    log_debug("g_amber_endpoint_apikey sz: %ld = %s", g_amber_endpoint_apikey_size,
              g_amber_endpoint_apikey);
    log_debug("g_amber_kbs_keyid sz: %ld = %s", g_amber_kbs_keyid_size, g_amber_kbs_keyid);
    log_debug("g_amber_renew sz: %ld = %s", g_amber_renew_size, g_amber_renew);
    log_debug("g_amber_userdata sz: %ld = %s", g_amber_userdata_size, g_amber_userdata);
    log_debug("g_amber_quote sz: %ld", g_amber_quote_size);
    log_debug("g_amber_token sz: %ld = %s", g_amber_token_size, g_amber_token);
    log_debug("g_amber_secret sz: %ld = %s", g_amber_secret_size, g_amber_secret);
    log_debug("g_amber_status sz: %ld = %s", g_amber_status_size, g_amber_status);
    log_debug("g_amber_cacerts sz: %ld = %s", g_amber_cacerts_size, g_amber_cacerts);
}

static int jsoneq(const char* json, jsmntok_t* tok, const char* s) {
    if (tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start &&
        strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
        return 0;
    }
    return -1;
}

/* Write at most `max_size` bytes of data to the buffer, padding the rest with zeroes. */
static size_t update_buffer(char* buffer, size_t max_size, const char* data, size_t size) {
    if (max_size == 0 || size == 0 || data == NULL || buffer == NULL) {
        return 0;
    }

    memset(buffer, '\0', max_size);
    if (size >= max_size) {
        size = max_size - 1;
        log_warning("Buffer overflow, truncating to %zu bytes", size);
    }
    memcpy(buffer, data, size);
    return size;
}

static char* get_buffer_content(const char* data, size_t size) {
    char* ret = NULL;
    if (size > 0 && data != NULL) {
        ret = calloc(1, size + 1);
        if (ret) {
            memcpy(ret, data, size);
        } else {
            log_debug("Failed to allocate memory for buffer content");
        }
    }
    return ret;
}

/* define get function for each amber variable */
get_amber_func(endpoint_ip)
get_amber_func(endpoint_url)
get_amber_func(kbs_ip)
get_amber_func(kbs_url)
get_amber_func(endpoint_apikey)
get_amber_func(kbs_keyid)
get_amber_func(renew)
get_amber_func(userdata)
get_amber_func(token)
get_amber_func(secret)
get_amber_func(status)
get_amber_func(cacerts)

/* define set function for each amber variable */
set_amber_func(endpoint_ip, ENDPOINT_IP)
set_amber_func(endpoint_url, ENDPOINT_URL)
set_amber_func(kbs_ip, KBS_IP)
set_amber_func(kbs_url, KBS_URL)
set_amber_func(endpoint_apikey, ENDPOINT_APIKEY)
set_amber_func(kbs_keyid, KBS_KEYID)
set_amber_func(renew, RENEW)
set_amber_func(userdata, USERDATA)
set_amber_func(quote, QUOTE)
set_amber_func(token, TOKEN)
set_amber_func(secret, SECRET)
set_amber_func(status, STATUS)
set_amber_func(cacerts, CACERTS)

static size_t amber_status_write(const char* prefix, const char* fmt, va_list ap, const char* suffix) {
    char msgbuf[256];
    snprintf(msgbuf, sizeof(msgbuf), "%s ", prefix);
    size_t len = strlen(msgbuf);
    log_debug("prefix length: %ld", len);
    vsnprintf(msgbuf + len, sizeof(msgbuf) - len, fmt, ap);
    len = strlen(msgbuf);
    snprintf(msgbuf + len, sizeof(msgbuf) - len, "%s", suffix);
    return set_amber_status(msgbuf, strlen(msgbuf));
}

static size_t amber_status_info(const char* fmt, ...) {
    size_t ret;
    va_list ap;
    va_start(ap, fmt);
    ret = amber_status_write(AMBER_STATUS_INFO, fmt, ap, "\n");
    va_end(ap);
    return ret;
}

static size_t amber_status_error(const char* fmt, ...) {
    size_t ret;
    va_list ap;
    va_start(ap, fmt);
    ret = amber_status_write(AMBER_STATUS_ERROR, fmt, ap, "\n");
    va_end(ap);
    return ret;
}

static char* amber_getaddr_secure(const char* dn);
static int update_ipaddr(const char *ipaddr, char *src_url);

static int init_amber_client(void) {
    int ret = 0;
    if (g_amber_client_initialized) {
        /* already initialized, nothing to do here */
        return 0;
    }
    amber_status_info(AMBER_STATUS_UNINITIALIZED);
    log_debug("########### Initializing Amber client ###############");

    char* ip  = NULL, *kbs_ip = NULL;
    char* url = NULL, *kbs_url = NULL;
    char* apikey = NULL, *userdata = NULL, *kbs_keyid = NULL;
    char* cacerts = NULL;
    if (g_pal_public_state) {
        ret = toml_string_in(g_pal_public_state->manifest_root, "sgx.amber_ip", &ip);
        if (ret < 0) {
            log_warning("'sgx.amber_ip' not found, it will be automatically detected.");
        }
        ret = toml_string_in(g_pal_public_state->manifest_root, "sgx.amber_url", &url);
        if (ret < 0) {
            log_error("Cannot parse 'sgx.amber_url'");
            return -PAL_ERROR_INVAL;
        }
        ret = toml_string_in(g_pal_public_state->manifest_root, "sgx.amber_apikey", &apikey);
        if (ret < 0) {
            log_error("Cannot parse 'sgx.amber_apikey'");
            return -PAL_ERROR_INVAL;
        }
        ret = toml_string_in(g_pal_public_state->manifest_root, "sgx.amber_cacerts", &cacerts);
        if (ret < 0) {
            log_warning("'sgx.amber_cacerts' not found, the TLS verify will be skipped");
        }
        ret = toml_string_in(g_pal_public_state->manifest_root, "sgx.amber_userdata", &userdata);
        if (ret < 0) {
            log_error("Cannot parse 'sgx.amber_userdata'");
            return -PAL_ERROR_INVAL;
        }
        ret = toml_string_in(g_pal_public_state->manifest_root,
                             "sgx.kbs_url", &kbs_url);
        if (ret < 0) {
            log_warning("'sgx.kbs_url' is not configured, skipped");
        } else {
            ret = toml_string_in(g_pal_public_state->manifest_root,
                            "sgx.kbs_ip", &kbs_ip);
            if (ret < 0) {
                log_error("Cannot parse 'sgx.kbs_ip'");
                return -PAL_ERROR_INVAL;
            } else {
                ret = toml_string_in(g_pal_public_state->manifest_root, "sgx.kbs_keyid", &kbs_keyid);
                if (ret < 0) {
                    log_error("Cannot parse 'sgx.kbs_keyid'");
                    return -PAL_ERROR_INVAL;
                }
            }
        }
    } else {
        log_error("Global state is NULL");
        return -PAL_ERROR_INVAL;
    }

    log_debug("Amber default values:\namber_ip: %s\namber_url: %s\namber_apikey: %s",
              ip, url, apikey);

    if (url) {
        // set initialization values.
        set_amber_endpoint_ip(ip, ip ? strlen(ip) : 0);
        set_amber_endpoint_url(url, url ? strlen(url) : 0);
        update_ipaddr(ip, url);
        set_amber_endpoint_apikey(apikey, apikey ? strlen(apikey) : 0);
        set_amber_userdata(userdata, userdata ? strlen(userdata) : 0);
        set_amber_token("", 0);
        set_amber_secret("", 0);
        set_amber_renew("", 0);

        if (kbs_url) {
            set_amber_kbs_ip(kbs_ip, kbs_ip ? strlen(kbs_ip) : 0);
            set_amber_kbs_url(kbs_url, kbs_url ? strlen(kbs_url) : 0);
            set_amber_kbs_keyid(kbs_keyid, kbs_keyid ? strlen(kbs_keyid) : 0);
        }

        if (cacerts) {
            set_amber_cacerts(cacerts, cacerts ? strlen(cacerts) : 0);
        }

        g_amber_client_initialized = TRUE;
        amber_status_info(AMBER_STATUS_INITIALIZED);
        log_global_vars();
        return 0;
    }
    return -PAL_ERROR_INVAL;
}

static int amber_DoH_resolve(const char* dn, char* response, size_t resp_size) {
    int ret = -1;
    char* url = NULL;
    HTTP_INFO hi;
    const char* resolver = "https://dns.google/resolve?name=%s&type=a&do=1";

    if (dn) {
        size_t sz = strlen(resolver) + strlen(dn) + 1;
        url = calloc(1, sz);
        if (!url)
            return -ENOMEM;
        snprintf(url, sz, resolver, dn);
    } else {
        return ret;
    }

    hi.initialized = FALSE;
    // init https connection
    http_init(&hi, FALSE);
    // send https request and get https response.
    ret = http_get(&hi, "8.8.8.8", url, response, resp_size, CA_CHAIN, strlen(CA_CHAIN) + 1);
    free(url);
    http_close(&hi);

    return ret;
}

static int update_ipaddr(const char *ipaddr, char *src_url) {
    int ret = -1;
    HTTP_URL url_info;
    if (ipaddr == NULL || strlen(ipaddr) == 0) {
        log_always("IP address is not set, it will be auto. detected.");
        ret = parse_url(ipaddr, src_url, &url_info);
        if (ret == 0) {
            char* ip = amber_getaddr_secure(url_info.host);
            if (ip) {
                set_amber_endpoint_ip(ip, ip ? strlen(ip) : 0);
                free(ip);
                log_always("The auto detected IP is %s", g_amber_endpoint_ip);
            } else {
                log_error("%s cannot be resolved.", url_info.host);
                return -1;
            }
        } else {
            log_error("Parse %s failed.", src_url);
            return ret;
        }
    }
    return 0;
}

static int amber_http_get(const char* path, char* response, size_t resp_size) {
    int ret = -1;
    HTTP_INFO hi;
    hi.initialized = FALSE;
    http_init(&hi, g_amber_cacerts_size > 0);

    char* url = g_amber_endpoint_url;
    char* apikey = g_amber_endpoint_apikey;
    size_t sz = 0;

    if (g_amber_endpoint_url_size > 0 && g_amber_endpoint_apikey_size > 0) {
        if (path) {
            sz = strlen(url) + strlen(path) + 1;
            url = calloc(1, sz);
            if (!url)
                return -ENOMEM;
            snprintf(url, sz, "%s%s", g_amber_endpoint_url, path);
        }
        snprintf(hi.request.ext_headers, H_FIELD_SIZE,
                 "Accept: application/json\r\n"
                 "x-api-key: %s\r\n", apikey);
        log_debug("HTTP GET (%s): %s with apikey: %s", g_amber_endpoint_ip, url, apikey);
        ret = http_get(&hi, g_amber_endpoint_ip, url, response, resp_size, g_amber_cacerts, g_amber_cacerts_size);
        if (path && url)
            free(url);
    } else {
        log_warning("Amber HTTP POST with URL: %s, APIKEY: %s, is invalid", url, apikey);
    }

    log_debug("HTTP GET return code: %d \n", ret);
    log_debug("HTTP GET return body: %s \n", response);
    http_close(&hi);
    return ret;
}

static int amber_http_post(const char* path, const char* post_data, char* response, size_t resp_size) {
    int ret = -1;
    HTTP_INFO hi;
    hi.initialized = FALSE;
    http_init(&hi, g_amber_cacerts_size > 0);

    char* url = g_amber_endpoint_url;
    char* apikey = g_amber_endpoint_apikey;
    size_t sz = 0;

    if (g_amber_endpoint_url_size > 0 && g_amber_endpoint_apikey_size > 0) {
        if (path) {
            sz = strlen(url) + strlen(path) + 1;
            url = calloc(1, sz);
            if (!url)
                return -ENOMEM;
            snprintf(url, sz, "%s%s", g_amber_endpoint_url, path);
        }
        snprintf(hi.request.ext_headers, H_FIELD_SIZE,
                 "Accept: application/json\r\n"
                 "Content-Type: application/json\r\n"
                 "x-api-key: %s\r\n", apikey);
        log_debug("HTTP POST (%s): %s with apikey: %s", g_amber_endpoint_ip, url, apikey);
        ret = http_post(&hi, g_amber_endpoint_ip, url, (char*)post_data, response, resp_size, g_amber_cacerts, g_amber_cacerts_size);
        if (path && url)
            free(url);
    } else {
        log_warning("Amber HTTP POST with URL: %s, APIKEY: %s, is invalid", url, apikey);
    }

    log_debug("HTTP POST return code: %d \n", ret);
    log_debug("HTTP POST return body: %s \n", response);
    http_close(&hi);
    return ret;
}

static int kbs_http_post(const char* path, const char* post_data, char* response, size_t resp_size) {
    int ret = -1;
    HTTP_INFO hi;
    hi.initialized = FALSE;
    http_init(&hi, FALSE);

    char* url = NULL;
    char* keyid = g_amber_kbs_keyid;
    size_t sz = 0;

    if (g_amber_kbs_url_size > 0 && g_amber_kbs_keyid_size > 0) {
        sz = g_amber_kbs_url_size + g_amber_kbs_keyid_size + 2;
        if (path) {
            sz += strlen(path);
        }
        url = calloc(1, sz);
        if (!url)
            return -ENOMEM;
        snprintf(url, sz, "%s%s/%s", g_amber_kbs_url, keyid, path);
        snprintf(hi.request.ext_headers, H_FIELD_SIZE,
                 "Accept: application/json\r\n"
                 "Content-Type: application/json\r\n");
        log_debug("HTTP POST (%s): %s with keyid: %s", g_amber_kbs_ip, url, keyid);
        ret = http_post(&hi, g_amber_kbs_ip, url, (char*)post_data, response, resp_size, g_amber_cacerts, g_amber_cacerts_size);
        if (url)
            free(url);
    } else {
        log_warning("The KBS settings are invalid");
    }

    log_debug("HTTP POST return code: %d \n", ret);
    log_debug("HTTP POST return body: %s \n", response);
    http_close(&hi);
    return ret;
}

static int amber_json_parse(const char* jdata, jsmntok_t token_array[], int token_array_size){
    int ret = -1;
    jsmn_parser p;
    jsmn_init(&p);
    ret = jsmn_parse(&p, jdata, strlen(jdata), token_array, token_array_size);
    if (ret < 0) {
        log_debug("Failed to parse JSON: %d\n", ret);
    }
    return ret;
}

static int amber_json_query(const char* jdata, jsmntok_t token_array[], int count, const char* key) {
    int i = -1;
    /* Assume the top-level element is an object */
    if (count < 1 || token_array[0].type != JSMN_OBJECT) {
        log_debug("Json object expected\n");
        return -1;
    }
    for (i = 1; i < count; i++) {
        if (jsoneq(jdata, &token_array[i], key) == 0) {
            /* We may use strndup() to fetch string value */
            i++;
            break;
        }
    }
    return i;
}

static char* amber_getaddr_secure(const char* dn) {
    char* ret = NULL;
    size_t resp_sz = 2048;
    char* response = NULL;
    jsmntok_t t[128];
    int idx_val;
    int count = 0;

    response = (char*) calloc(1, resp_sz);
    if (!response) {
        log_error("Memory insufficient.");
        return ret;
    }

    if (amber_DoH_resolve(dn, response, resp_sz) > 0) {
        int cnt = amber_json_parse(response, t, sizeof(t)/sizeof(t[0]));
        if (cnt >= 0) {
            idx_val = amber_json_query(response, t, cnt, "Answer");
            if (idx_val < 0 || t[idx_val].type != JSMN_ARRAY) {
                log_error("Json array expected\n");
                free(response);
                return NULL;
            }
            log_debug("getaddr Answer - query val idx: %d \n", idx_val);
            count = t[idx_val].size;
            jsmntok_t *item = &t[idx_val + 1];
            bool flag_found = false;
            for (int j = 0; j < count; j++, item++) {
                if (item->type != JSMN_OBJECT) {
                    log_error("Json object expected\n");
                    free(response);
                    return NULL;
                }
                int obj_sz = item->size;
                for (int i = 0; i < obj_sz; i++) {
                    item++;
                    if (jsoneq(response, item, "type") == 0) {
                        /* We may use strndup() to fetch string value */
                        item++; // value
                        if (item->type != JSMN_PRIMITIVE) {
                            log_error("Json primitive expected\n");
                            free(response);
                            return NULL;
                        }
                        flag_found = response[item->start] == '1';
                    } else {
                        if (flag_found && jsoneq(response, item, "data") == 0) {
                            item++;
                            size_t len = item->end - item->start;
                            char* addr = calloc(1, len + 1);
                            if (!addr) {
                                log_error("Memory insufficient.");
                                free(response);
                                return NULL;
                            }
                            memcpy(addr, &response[item->start], len);
                            free(response);
                            return addr;
                        } else {
                            item++; //skip val.
                        }
                    }
                }
            }
        }
    }
    free(response);
    return ret;
}

static int amber_endpoint_ip_save_event(void) {
    return 0;
}

static int amber_endpoint_ip_load_event(void) {
    return 0;
}

static int amber_endpoint_url_save_event(void) {
    return 0;
}

static int amber_endpoint_url_load_event(void) {
    return 0;
}

static int amber_kbs_ip_save_event(void) {
    return 0;
}

static int amber_kbs_ip_load_event(void) {
    return 0;
}

static int amber_kbs_url_save_event(void) {
    return 0;
}

static int amber_kbs_url_load_event(void) {
    return 0;
}

static int amber_endpoint_apikey_save_event(void) {
    return 0;
}

static int amber_endpoint_apikey_load_event(void) {
    return 0;
}

static int update_quote(void) {
    int ret = -1;
    size_t quote_size = sizeof(g_amber_quote);
    char* quote = calloc(1, quote_size);
    if (!quote)
        return -ENOMEM;
    // MUST be sizeof(sgx_report_data_t) == 64
    ret = PalAttestationQuote(&g_amber_user_report_data, g_amber_user_report_data_size, quote, &quote_size);
    if (ret < 0) {
        free(quote);
        return -EACCES;
    }
    size_t sz = set_amber_quote(quote, quote_size);
    free(quote);
    if (sz <= 0 && sz != quote_size) {
        amber_status_error("The QUOTE content truncated to %zu bytes", sz);
    } else {
        amber_status_info("QUOTE updated");
        ret = 0;
    }
    return ret;
}

static int amber_get_nonce(char* resp_buf, size_t resp_bufsz, unsigned char* nonce_buf, size_t* nonce_bufsz) {
    int ret = -1;
    ret = amber_http_get("nonce", resp_buf, resp_bufsz);
    if (ret == 200) {
        ret = -1;
        jsmntok_t t[128];
        int sz_val, sz_iat;
        int idx_val, idx_iat;
        int cnt = amber_json_parse(resp_buf, t, 128);
        log_debug("nonce - amber_json_parse found count: %d \n", cnt);
        if (cnt >= 0) {
            idx_val = amber_json_query(resp_buf, t, cnt, "val");
            log_debug("nonce[val] - query val idx: %d \n", idx_val);
            idx_iat = amber_json_query(resp_buf, t, cnt, "iat");
            log_debug("nonce[iat] - query iat idx: %d \n", idx_iat);
            if (idx_val >= 0 && idx_iat >= 0 && idx_val != idx_iat) {
                size_t sz_decoded_val, sz_decoded_iat;

                sz_val = t[idx_val].end - t[idx_val].start;
                log_debug("- JSON NONCE[VAL]: %.*s\n", sz_val,
                            resp_buf + t[idx_val].start);
                ret = mbedtls_base64_decode((unsigned char*)nonce_buf, *nonce_bufsz, &sz_decoded_val, (unsigned char*)(resp_buf + t[idx_val].start), sz_val);
                if (ret != 0) {
                    amber_status_error("Base64 decode of nonce[val] failed");
                }
                debug_base64_bytes("nonce[val]", "--", nonce_buf, sz_decoded_val);

                sz_iat = t[idx_iat].end - t[idx_iat].start;
                log_debug("- JSON NONCE[IAT]: %.*s\n", sz_iat,
                            resp_buf + t[idx_iat].start);
                ret = mbedtls_base64_decode((unsigned char*)nonce_buf + sz_decoded_val, *nonce_bufsz - sz_decoded_val, &sz_decoded_iat, (unsigned char*)(resp_buf + t[idx_iat].start), sz_iat);
                if (ret != 0) {
                    amber_status_error("Base64 decode of nonce[iat] failed");
                }
                debug_base64_bytes("nonce[iat]", "--", nonce_buf + sz_decoded_val, sz_decoded_iat);

                if (*nonce_bufsz < sz_decoded_val + sz_decoded_iat) {
                    log_error("nonce buffer is insufficient");
                    ret = -1;
                } else {
                    *nonce_bufsz = sz_decoded_val + sz_decoded_iat;
                    debug_base64_bytes("nonce[val + iat]", "--", nonce_buf, *nonce_bufsz);
                }
            } else {
                amber_status_error("Nonce not found in response");
            }
        }
    } else {
        amber_status_error("HTTP GET nonce failed with return code: %d", ret);
    }
    return ret;
}

static int amber_post_appraise(char* data, char* resp_buf, size_t resp_bufsz) {
    int ret = -1;
    ret = amber_http_post("attest", data, resp_buf, resp_bufsz);
    if (ret == 200) {
        ret = 0;
    } else {
        amber_status_error("HTTP POST appraise failed with return code: %d", ret);
        log_error("amber_post_appraise, HTTP error code %d", ret);
    }
    return ret;
}

static int kbs_post_transfer(char* data, char* resp_buf, size_t resp_bufsz) {
    int ret = -1;
    ret = kbs_http_post("transfer", data, resp_buf, resp_bufsz);
    if (ret == 200) {
        ret = 0;
    } else {
        amber_status_error("HTTP POST appraise failed with return code: %d", ret);
        log_error("kbs_post_transfer, HTTP error code %d", ret);
    }
    return ret;
}

void debug_base64_bytes(const char* label, const char *base64_encoded,
                        const unsigned char *base64_decoded, size_t base64_decoded_sz) {
    size_t hex_buf_sz = base64_decoded_sz * 2 + 1;
    char *hex_buf = calloc(1, hex_buf_sz);
    if (!hex_buf) {
        log_debug("calloc failed.");
    }
    log_debug("%s:\nbase64_encoded: %s\nbase64_decoded: %s\n",
                label, base64_encoded, bytes2hex(base64_decoded, base64_decoded_sz, hex_buf, hex_buf_sz));
    free(hex_buf);
}

/* this function define the workflow of the Amber token retrieval and update */
static int amber_update_token(void) {
    int ret = -1;
    char response[4096];
    char* keyid = get_amber_kbs_keyid();
    const char *inp_udata = g_amber_userdata;
    size_t inp_udata_sz = g_amber_userdata_size; // strlen(inp_udata);

    size_t udata_b64_outsz, udata_b64_sz = inp_udata_sz * 2;
    char *udata_b64 = calloc(1, udata_b64_sz);
    if (!udata_b64)
        return ret;

    ret = mbedtls_base64_encode((unsigned char*)udata_b64, udata_b64_sz,
                        &udata_b64_outsz,
                        (unsigned char*)inp_udata, inp_udata_sz);
    if (ret != 0) {
        amber_status_error("Base64 encode of user data failed");
        free(udata_b64);
        return ret;
    }
    udata_b64[udata_b64_outsz] = '\0';
    udata_b64_sz = udata_b64_outsz;

    unsigned char nonce[256];
    size_t nonce_sz = sizeof(nonce);
    ret = amber_get_nonce(response, sizeof(response), nonce, &nonce_sz);
    if (ret == 0) {
        log_debug("GET NONCE response: %s", response);

        size_t cudata_sz = nonce_sz + inp_udata_sz;
        void *cudata = calloc(1,cudata_sz);
        if (!cudata)
            return -ENOMEM;

        // memcpy(cudata, nonce, nonce_sz);
        // memcpy(cudata + nonce_sz, udata, udata_sz);
        // this code just consider user data only
        memcpy(cudata, inp_udata, inp_udata_sz);
        cudata_sz = inp_udata_sz;

        log_debug("nonce size: %ld\nudata_b64 size: %ld\ncudata size: %ld\n",
                    nonce_sz, udata_b64_sz, cudata_sz);
        debug_base64_bytes("user data", udata_b64, (unsigned char*)inp_udata, inp_udata_sz);
        debug_base64_bytes("nonce", "--", nonce, nonce_sz);
        debug_base64_bytes("Combined", "--", cudata, cudata_sz);
    
        ret = mbedtls_sha256(cudata, cudata_sz,
                             (unsigned char*)g_amber_user_report_data, 0);
        // ret = mbedtls_sha256(udata, udata_sz,
        //                          (unsigned char*)g_amber_user_report_data, 0);
        // ret = mbedtls_sha256(nonce, nonce_sz,
        //                          (unsigned char*)g_amber_user_report_data, 0);
        free(cudata);
        if (ret < 0) {
            log_error("NONCE SHA265 operation failed");
            return -EACCES;
        }

        g_amber_user_report_data_size = 64;
        memset(g_amber_user_report_data + 32, 0, 32);

        debug_base64_bytes("Quote report data", "--", (unsigned char*)g_amber_user_report_data, g_amber_user_report_data_size);

        ret = update_quote();
        if (ret < 0) {
            free(keyid);
            return ret;
        }
        
        size_t qb64_size = 20480, qb64_outsz = 0;
        unsigned char* qb64 = calloc(1, qb64_size);
        if (!qb64) {
            free(keyid);
            return -ENOMEM;
        }

        ret = mbedtls_base64_encode(qb64, qb64_size, &qb64_outsz,
                            (unsigned char*)g_amber_quote, g_amber_quote_size);
        if (ret != 0) {
            amber_status_error("Base64 encode of quote failed");
            free(qb64);
            free(keyid);
            return ret;
        }
        qb64[qb64_outsz] = '\0';

        
        size_t data_bufsz = qb64_outsz + inp_udata_sz + sizeof(response) + 200;
        char* data_buf = calloc(1, data_bufsz);
        if (!data_buf) {
            free(qb64);
            free(keyid);
            return -ENOMEM;
        }

        if (inp_udata_sz > 0) {
            // snprintf(data_buf, data_bufsz,
            // "{\"quote\":\"%s\", \"nonce\":%s, \"user_data\":\"%s\"}",
            //         qb64, response, inp_udata);
            snprintf(data_buf, data_bufsz,
            "{\"quote\":\"%s\", \"runtime_data\":\"%s\"}",
                    qb64, udata_b64);
        } else {
            // snprintf(data_buf, data_bufsz,
            // "{\"quote\":\"%s\", \"nonce\":%s}",
            //         qb64, response);
            snprintf(data_buf, data_bufsz,
            "{\"quote\":\"%s\"}", qb64);
            log_debug("#### >>>> no user data supplied");
        }
        // log_error("%s\n -+++--- %ld", data_buf, strlen(data_buf));
        // snprintf(data_buf, data_bufsz, "{\"quote\":\"%s\", \"user_data\":\"%s\"}", qb64, inp_udata);
        // snprintf(data_buf, data_bufsz, "{\"quote\":\"%s\"}", qb64);
        free(qb64);
        free(keyid);

        log_debug(">>> APPRAISE Req. JSON DATA: %s", data_buf);

        jsmntok_t t[10];
        int sz;
        int idx;
        int cnt;
        ret = amber_post_appraise(data_buf, response, sizeof(response));
        free(data_buf);
        if (ret == 0) {
            log_debug(">>> APPRAISE Resp. JSON DATA: %s", response);
            cnt = amber_json_parse(response, t, 10);
            if (cnt > 0) {
                idx = amber_json_query(response, t, cnt, "token");
                if (idx >= 0) {
                    sz = t[idx].end - t[idx].start;
                    set_amber_token(response + t[idx].start, sz);
                    amber_status_info("token saved");
                } else {
                    amber_status_error("There is no token found");
                }
            } else {
                amber_status_error("The response doesn't contain any fields");
            }
        } else {
            set_amber_token("", 0);
            cnt = amber_json_parse(response, t, 10);
            log_debug("APPRAISE error - amber_json_parse found count: %d \n", cnt);
            if (cnt > 0) {
                idx = amber_json_query(response, t, cnt, "error");
                if (idx > 0 && idx < cnt) {
                    sz = t[idx].end - t[idx].start;
                    amber_status_error("Token retrieval failed with error: %.*s", sz,
                                response + t[idx].start);
                } else {
                    idx = amber_json_query(response, t, cnt, "message");
                    if (idx > 0 && idx < cnt) {
                        sz = t[idx].end - t[idx].start;
                        amber_status_error("Token retrieval failed with message: %.*s", sz,
                                    response + t[idx].start);
                    }
                }
            } else {
                amber_status_error("Token retrieval failed with no response info");
            }
        }
        return ret;
    }

    return ret;
}

static int kbs_update_secret(void) {
    int ret = -1;
    char response[4096];
    if (g_amber_token_size == 0) {
        amber_status_error("Secret cannot be retrieved due to empty token");
        log_debug("Secret cannot be retrieved due to empty token");
        return ret;
    }
    if (g_amber_kbs_url_size == 0 || g_amber_kbs_keyid_size == 0) {
        amber_status_error("Secret cannot be retrieved as KBS is not configured properly");
        log_debug("Secret cannot be retrieved as KBS is not configured properly");
        return ret;
    }
    log_debug("Updating the secret with the key id: %s", g_amber_kbs_keyid);
    char *jt = calloc(1, g_amber_token_size + 128);
    if (!jt)
        return -ENOMEM;
    snprintf(jt, g_amber_token_size + 128, "{\"attestation_token\": \"%s\"}", g_amber_token);
    ret = kbs_post_transfer(jt, response, sizeof(response));
    free(jt);
    if (ret == 0) {
        log_debug(">>> KBS Resp. JSON DATA: %s", response);
        set_amber_secret(response, strlen(response));
        amber_status_info("secret saved");
    } else {
        set_amber_secret("", 0);
        amber_status_error("Secret retrieval failed");
    }
    return ret;
}

static int amber_kbs_keyid_save_event(void) {
    log_debug("<--- keyid save event");
    int ret = amber_update_token();
    log_debug("---> keyid save event");
    return ret;
}

static int amber_kbs_keyid_load_event(void) {
    return 0;
}

static int amber_renew_save_event(void) {
    int ret;
    const char* renew_token = "token";
    const char* renew_secret = "secret";
    if (strncasecmp(g_amber_renew, renew_token, strlen(renew_token)) == 0) {
        ret = amber_update_token();
        if (!ret)
            amber_status_info("Token renewed successfully");
        else
            amber_status_error("Token renewal failed");
    } else {
        if (strncasecmp(g_amber_renew, renew_secret, strlen(renew_secret)) == 0) {
            ret = kbs_update_secret();
            if (!ret)
                amber_status_info("Secret renew successfully");
            else
                amber_status_error("Secret renewal failed");
        } else {
            amber_status_error("%s renew Unsupported", g_amber_renew);
        }
    }
    return 0;
}

static int amber_renew_load_event(void) {
    return 0;
}

static int amber_userdata_save_event(void) {
    return 0;
}

static int amber_userdata_load_event(void) {
    return 0;
}

static int amber_token_load_event(void) {
    amber_update_token();
    return 0;
}

static int amber_secret_load_event(void) {
    kbs_update_secret();
    return 0;
}

static int amber_status_load_event(void) {
    return 0;
}

static int amber_cacerts_load_event(void) {
    return 0;
}

/*
 *  Define save event here for each amber pseudo-files
 */
amber_save_func(endpoint_ip)

amber_save_func(endpoint_url)

amber_save_func(kbs_ip)

amber_save_func(kbs_url)

amber_save_func(endpoint_apikey)

amber_save_func(kbs_keyid)

amber_save_func(renew)

amber_save_func(userdata)

/*
 *  Define load event here for each amber pseudo-files
 */
amber_load_func(endpoint_ip)

amber_load_func(endpoint_url)

amber_load_func(kbs_ip)

amber_load_func(kbs_url)

amber_load_func(endpoint_apikey)

amber_load_func(kbs_keyid)

amber_load_func(renew)

amber_load_func(userdata)

amber_load_func(token)

amber_load_func(secret)

amber_load_func(status)

amber_load_func(cacerts)

int init_amber(struct pseudo_node* dev) {

    if (!strcmp(g_pal_public_state->host_type, "Linux-SGX")) {

        log_debug("Initializing Amber.");

        int ret = init_amber_client();
        if (ret) {
            log_warning("Amber is not configured properly, skipped.");
            return 0;
        }

        log_always(
            "host is Linux-SGX, adding SGX-specific /dev/amber pseudo files: "
            "endpoint_url, token, etc.");

        /* construct amber pseudo-files here */
        struct pseudo_node* amber = pseudo_add_dir(dev, "amber");
        amber_dev_rw(endpoint_ip)
        amber_dev_rw(endpoint_url)
        amber_dev_rw(endpoint_apikey)
        amber_dev_rw(kbs_ip)
        amber_dev_rw(kbs_url)
        amber_dev_rw(kbs_keyid)
        amber_dev_rw(renew)
        amber_dev_rw(userdata)
        amber_dev_ro(token)
        amber_dev_ro(secret)
        amber_dev_ro(status)
        amber_dev_ro(cacerts)

    }

    return 0;
}
