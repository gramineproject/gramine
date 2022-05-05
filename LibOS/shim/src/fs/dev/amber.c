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
#include "shim_fs_encrypted.h"
#include "shim_fs_pseudo.h"
#include "toml_utils.h"

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

/* the amber status functions */
static size_t amber_status_info(const char* fmt, ...);
static size_t amber_status_error(const char* fmt, ...);

/* the macros defined here to reduce the code duplication */
#define amber_save_func(name) \
    static int amber_##name##_save(struct shim_dentry* dent, const char* data, size_t size) { \
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
    static int amber_##name##_load(struct shim_dentry* dent, char** out_data, size_t* out_size) { \
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
        log_debug("<<< set_amber_%s: %s : sz: %ld", #name, data, size); \
        g_amber_##name##_size = \
            update_buffer(g_amber_##name, AMBER_##ucname##_MAX_SIZE, data, size); \
        if (g_amber_##name##_size != size) { \
            amber_status_error("The content truncated to %zu bytes", g_amber_##name##_size); \
        } \
        log_debug(">>> set_amber_%s: %s : sz: %ld", #name, data, size); \
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
amber_var(endpoint_ip, ENDPOINT_IP, 64);
amber_var(endpoint_url, ENDPOINT_URL, 2048);
amber_var(endpoint_apikey, ENDPOINT_APIKEY, 2048);
amber_var(keyid, KEYID, 256);
amber_var(renew, RENEW, 256);
amber_var(quote, QUOTE, 8192);
amber_var(user_report_data, USER_REPORT_DATA, 256);
amber_var(token, TOKEN, 4096);
amber_var(secret, SECRET, 2048);
amber_var(status, STATUS, 1024);

/* the code for debug purpose */
static void log_global_vars(void) {
    log_debug("g_amber_endpoint_ip sz: %ld = %s", g_amber_endpoint_ip_size, g_amber_endpoint_ip);
    log_debug("g_amber_endpoint_url sz: %ld = %s", g_amber_endpoint_url_size, g_amber_endpoint_url);
    log_debug("g_amber_endpoint_apikey sz: %ld = %s", g_amber_endpoint_apikey_size,
              g_amber_endpoint_apikey);
    log_debug("g_amber_keyid sz: %ld = %s", g_amber_keyid_size, g_amber_keyid);
    log_debug("g_amber_renew sz: %ld = %s", g_amber_renew_size, g_amber_renew);
    log_debug("g_amber_quote sz: %ld = %s", g_amber_quote_size, g_amber_quote);
    log_debug("g_amber_token sz: %ld = %s", g_amber_token_size, g_amber_token);
    log_debug("g_amber_secret sz: %ld = %s", g_amber_secret_size, g_amber_secret);
    log_debug("g_amber_status sz: %ld = %s", g_amber_status_size, g_amber_status);
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
        log_debug("Buffer overflow, truncating to %zu bytes", size);
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
get_amber_func(endpoint_apikey)
get_amber_func(keyid)
get_amber_func(renew)
get_amber_func(token)
get_amber_func(secret)
get_amber_func(status)

/* define set function for each amber variable */
set_amber_func(endpoint_ip, ENDPOINT_IP)
set_amber_func(endpoint_url, ENDPOINT_URL)
set_amber_func(endpoint_apikey, ENDPOINT_APIKEY)
set_amber_func(keyid, KEYID)
set_amber_func(renew, RENEW)
set_amber_func(quote, QUOTE)
set_amber_func(token, TOKEN)
set_amber_func(secret, SECRET)
set_amber_func(status, STATUS)

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

static int init_amber_client(void) {
    int ret = 0;
    if (g_amber_client_initialized) {
        /* already initialized, nothing to do here */
        return 0;
    }
    amber_status_info(AMBER_STATUS_UNINITIALIZED);
    log_debug("########### Initializing Amber client ###############");

    char* ip  = NULL;
    char* url = NULL;
    char* apikey = NULL;
    if (g_pal_public_state) {
        ret = toml_string_in(g_pal_public_state->manifest_root, "sgx.amber_ip", &ip);
        if (ret < 0) {
            log_error("Cannot parse 'sgx.amber_ip'");
            return -PAL_ERROR_INVAL;
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
    } else {
        log_error("Global state is NULL");
        return -PAL_ERROR_INVAL;
    }

    log_debug("Amber default values:\namber_ip: %s\namber_url: %s\namber_apikey: %s",
              ip, url, apikey);

    if (url) {
        if (ip)
            set_amber_endpoint_ip(ip, strlen(ip));
        set_amber_endpoint_url(url, strlen(url));
        set_amber_endpoint_apikey(apikey, strlen(apikey));
        set_amber_status("", 0);
        set_amber_token("", 0);
        set_amber_secret("", 0);
        set_amber_renew("", 0);

        g_amber_client_initialized = TRUE;
        amber_status_info(AMBER_STATUS_INITIALIZED);
        log_global_vars();
        return 0;
    }
    return -PAL_ERROR_INVAL;
}

static int amber_http_get(const char* path, char* response, size_t resp_size) {
    int ret = -1;
    HTTP_INFO hi;
    hi.initialized = FALSE;
    http_init(&hi, FALSE);

    char* url = g_amber_endpoint_url;
    char* apikey = g_amber_endpoint_apikey;
    size_t sz = 0;

    if (strlen(url) > 0) {
        if (path) {
            sz = strlen(url) + strlen(path) + 1;
            url = calloc(1, sz);
            if (!url)
                return -ENOMEM;
            snprintf(url, sz, "%s%s", g_amber_endpoint_url, path);
        }
        if (strlen(apikey) > 0) {
            snprintf(hi.request.ext_headers, H_FIELD_SIZE, "x-api-key: %s\r\n", apikey);
        }
        log_debug("HTTP GET (%s): %s with apikey: %s", g_amber_endpoint_ip, url, apikey);
        ret = http_get(&hi, g_amber_endpoint_ip, url, response, resp_size);
        if (path && url)
            free(url);
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
    http_init(&hi, FALSE);

    char* url = g_amber_endpoint_url;
    char* apikey = g_amber_endpoint_apikey;
    size_t sz = 0;

    if (strlen(url) > 0) {
        if (path) {
            sz = strlen(url) + strlen(path) + 1;
            url = calloc(1, sz);
            if (!url)
                return -ENOMEM;
            snprintf(url, sz, "%s%s", g_amber_endpoint_url, path);
        }
        if (strlen(apikey) > 0) {
            snprintf(hi.request.ext_headers, H_FIELD_SIZE, "x-api-key: %s\r\n", apikey);
        }
        log_debug("HTTP POST (%s): %s with apikey: %s", g_amber_endpoint_ip, url, apikey);
        ret = http_post(&hi, g_amber_endpoint_ip, url, (char*)post_data, response, resp_size);
        if (path && url)
            free(url);
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
        log_debug("Object expected\n");
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
    ret = DkAttestationQuote(&g_amber_user_report_data, 64, quote, &quote_size);
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

static int amber_get_nonce(char* resp_buf, size_t resp_bufsz, char* nonce_buf, size_t* nonce_bufsz) {
    int ret = -1;
    ret = amber_http_get("nonce", resp_buf, resp_bufsz);
    if (ret == 200) {
        ret = -1;
        jsmntok_t t[128];
        int sz;
        int idx;
        int cnt = amber_json_parse(resp_buf, t, 128);
        log_debug("nonce - amber_json_parse found count: %d \n", cnt);
        if (cnt >= 0) {
            idx = amber_json_query(resp_buf, t, cnt, "nonce");
            log_debug("nonce - query nonce idx: %d \n", idx);
            if (idx >= 0) {
                sz = t[idx].end - t[idx].start;
                log_debug("- JSON NONCE: %.*s\n", sz,
                            resp_buf + t[idx].start);
                ret = mbedtls_base64_decode((unsigned char*)nonce_buf, *nonce_bufsz, nonce_bufsz,
                                            (unsigned char*)(resp_buf + t[idx].start), sz);
                if (ret != 0) {
                    amber_status_error("Base64 decode of nonce failed");
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
    ret = amber_http_post("appraise", data, resp_buf, resp_bufsz);
    if (ret == 200) {
        ret = 0;
    } else {
        amber_status_error("HTTP POST appraise failed with return code: %d", ret);
        log_error("amber_post_appraise, HTTP error code %d", ret);
    }
    return ret;
}

/* this function define the workflow of the Amber token retrieval and update */
static int amber_update_token(void) {
    int ret = -1;
    char response[4096];
    char* keyid = get_amber_keyid();

    char nonce[256];
    size_t nonce_sz = sizeof(nonce);
    ret = amber_get_nonce(response, sizeof(response), nonce, &nonce_sz);
    if (ret == 0) {
        log_debug("GET NONCE response: %s", response);

        ret = mbedtls_sha256_ret((unsigned char*)nonce, nonce_sz,
                                 (unsigned char*)g_amber_user_report_data, 0);
        g_amber_user_report_data_size = 64;
        if (ret < 0) {
            log_error("NONCE SHA265 operation failed");
            return -EACCES;
        }

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

        size_t data_bufsz = qb64_outsz + strlen(response) + 200;
        char* data_buf = calloc(1, data_bufsz);
        if (!data_buf) {
            free(qb64);
            free(keyid);
            return -ENOMEM;
        }

        snprintf(data_buf, data_bufsz, "{\"quote\":\"%s\", \"signed_nonce\":%s}", qb64, response);
        free(qb64);
        free(keyid);

        log_debug(">>> APPRAISE Req. JSON DATA: %s", data_buf);

        ret = amber_post_appraise(data_buf, response, sizeof(response));
        free(data_buf);
        if (ret == 0) {
            log_debug(">>> APPRAISE Resp. JSON DATA: %s", response);
            set_amber_token(response, strlen(response));
            amber_status_info("token saved");
        } else {
            set_amber_token("", 0);
            jsmntok_t t[10];
            int sz;
            int idx;
            int cnt = amber_json_parse(response, t, 10);
            log_debug("APPRAISE error - amber_json_parse found count: %d \n", cnt);
            if (cnt > 0) {
                idx = amber_json_query(response, t, cnt, "error");
                if (idx >= 0) {
                    sz = t[idx].end - t[idx].start;
                    amber_status_error("Token retrieval failed: %.*s", sz,
                                response + t[idx].start);
                } else {
                    amber_status_error("Token retrieval failed with no error info");
                }
            } else {
                amber_status_error("Token retrieval failed with no response info");
            }
        }
        return ret;
    }

    return ret;
}

static int amber_keyid_save_event(void) {
    log_debug("<--- keyid save event");
    int ret = amber_update_token();
    log_debug("---> keyid save event");
    return ret;
}

static int amber_keyid_load_event(void) {
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
            amber_status_error("Secret renew unsupported");
        } else {
            amber_status_error("%s renew Unsupported", g_amber_renew);
        }
    }
    return 0;
}

static int amber_renew_load_event(void) {
    return 0;
}

static int amber_token_load_event(void) {
    amber_update_token();
    return 0;
}

static int amber_secret_load_event(void) {
    return 0;
}

static int amber_status_load_event(void) {
    return 0;
}

/*
 *  Define save event here for each amber pseudo-files
 */
amber_save_func(endpoint_ip)

amber_save_func(endpoint_url)

amber_save_func(endpoint_apikey)

amber_save_func(keyid)

amber_save_func(renew)

/*
 *  Define load event here for each amber pseudo-files
 */
amber_load_func(endpoint_ip)

amber_load_func(endpoint_url)

amber_load_func(endpoint_apikey)

amber_load_func(keyid)

amber_load_func(renew)

amber_load_func(token)

amber_load_func(secret)

amber_load_func(status)

int init_amber(struct pseudo_node* dev) {

    if (!strcmp(g_pal_public_state->host_type, "Linux-SGX")) {

        log_debug("Initializing Amber.");

        int ret = init_amber_client();
        if (ret) {
            log_debug("Amber is not configured properly, skipped.");
            return 0;
        }

        log_debug(
            "host is Linux-SGX, adding SGX-specific /dev/amber files: "
            "input, token, etc.");

        /* construct amber pseudo-files here */
        struct pseudo_node* amber = pseudo_add_dir(dev, "amber");
        amber_dev_rw(endpoint_ip)
        amber_dev_rw(endpoint_url)
        amber_dev_rw(endpoint_apikey)
        amber_dev_rw(keyid)
        amber_dev_rw(renew)
        amber_dev_ro(token)
        amber_dev_ro(secret)
        amber_dev_ro(status)

    }

    return 0;
}
