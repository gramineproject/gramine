#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* POSIX string functions (strcasecmp) */
#include <strings.h>

/* Dynamic linking API (dlsym, dlopen, dlclose, dladdr, dlerror) */
#include <dlfcn.h>

/* File status and permissions (chmod) */
#include <sys/stat.h>
#include <pthread.h>
#include <stdint.h>
#include <limits.h>
#include <link.h>

/* Include TLS library headers for type definitions only - no linking */
#define HAVE_MBEDTLS_HEADERS 1
#ifdef HAVE_MBEDTLS_HEADERS
#include <mbedtls/ssl.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/sha256.h>
#else
/* Forward declarations if headers not available */
typedef struct mbedtls_ssl_context mbedtls_ssl_context;
typedef struct mbedtls_ssl_config mbedtls_ssl_config;
typedef struct mbedtls_x509_crt mbedtls_x509_crt;
#endif
#include <ra_tls.h>

/* OpenSSL forward declarations (avoid including headers to prevent conflicts) */
typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_st SSL;
typedef struct x509_st X509;
typedef struct x509_store_ctx_st X509_STORE_CTX;

#include "ra_tls.h"

/* Environment variable names */
#define ENV_RATLS_KEY_PATH "RATLS_KEY_PATH"
#define ENV_RATLS_CERT_PATH "RATLS_CERT_PATH"
#define ENV_RATLS_WHITELIST_CONFIG "RATLS_WHITELIST_CONFIG"
#define ENV_RATLS_ENABLE_VERIFY "RATLS_ENABLE_VERIFY"
#define ENV_RATLS_REQUIRE_PEER_CERT "RATLS_REQUIRE_PEER_CERT"

/* Default paths */
#define DEFAULT_KEY_PATH "/tmp/priv.key"
#define DEFAULT_CERT_PATH "/tmp/crt.crt"

/* Maximum whitelist entries per measurement type */
#define MAX_WHITELIST_ENTRIES 256

/* PEM headers for certificate and key (standard format for compatibility) */
#define PEM_KEY_HEADER "-----BEGIN EC PRIVATE KEY-----\n"
#define PEM_KEY_FOOTER "-----END EC PRIVATE KEY-----\n"
#define PEM_CERT_HEADER "-----BEGIN CERTIFICATE-----\n"
#define PEM_CERT_FOOTER "-----END CERTIFICATE-----\n"

/* Base64 encoding table */
static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* User's measurement callback storage */
static verify_measurements_cb_t g_user_measurements_cb = NULL;
static pthread_mutex_t g_user_measurements_cb_mutex = PTHREAD_MUTEX_INITIALIZER;

/* OpenSSL helper functions - resolved lazily in callbacks */
static int (*openssl_i2d_X509)(X509 *cert, unsigned char **out) = NULL;
static X509 *(*openssl_X509_STORE_CTX_get0_cert)(X509_STORE_CTX *ctx) = NULL;
static void (*openssl_X509_STORE_CTX_set_error)(X509_STORE_CTX *ctx, int error) = NULL;
static int (*openssl_SSL_get_ex_data_X509_STORE_CTX_idx)(void) = NULL;
static void *(*openssl_X509_STORE_CTX_get_ex_data)(X509_STORE_CTX *ctx, int idx) = NULL;
static void *(*openssl_SSL_get_SSL_CTX)(void *ssl) = NULL;
static int (*openssl_X509_STORE_CTX_get_error_depth)(X509_STORE_CTX *ctx) = NULL;

/* wolfSSL helper functions - resolved lazily in callbacks */
static void *(*wolfssl_X509_STORE_CTX_get_current_cert)(void *ctx) = NULL;
static int (*wolfssl_i2d_X509)(void *cert, unsigned char **out) = NULL;
static void (*wolfssl_X509_STORE_CTX_set_error)(void *ctx, int error) = NULL;
static int (*wolfssl_SSL_get_ex_data_X509_STORE_CTX_idx)(void) = NULL;
static void *(*wolfssl_X509_STORE_CTX_get_ex_data)(void *ctx, int idx) = NULL;
static void *(*wolfssl_SSL_get_SSL_CTX)(void *ssl) = NULL;
static int (*wolfssl_X509_STORE_CTX_get_error_depth)(void *ctx) = NULL;

/* Real dlopen/dlmopen function pointers */
static void *(*real_dlopen)(const char *filename, int flags) = NULL;
static void *(*real_dlmopen)(long lmid, const char *filename, int flags) = NULL;
static int (*real_dlclose)(void *handle) = NULL;

/* Callback tracking structures */
#define MAX_CALLBACK_ENTRIES 1024

/* OpenSSL callback tracking */
typedef struct
{
    void *key; /* SSL_CTX* or SSL* */
    int (*verify_callback)(int, X509_STORE_CTX *);
    int verify_mode;
    int installed_ours_verify; /* Flag: our verify callback is installed */
    int (*cert_verify_callback)(X509_STORE_CTX *, void *);
    void *cert_verify_arg;
    int installed_ours_cert; /* Flag: our cert verify callback is installed */
} openssl_callback_entry_t;

static openssl_callback_entry_t g_openssl_ctx_callbacks[MAX_CALLBACK_ENTRIES];
static openssl_callback_entry_t g_openssl_ssl_callbacks[MAX_CALLBACK_ENTRIES];
static size_t g_openssl_ctx_count = 0;
static size_t g_openssl_ssl_count = 0;
static pthread_mutex_t g_openssl_callback_mutex = PTHREAD_MUTEX_INITIALIZER;

/* mbedTLS callback tracking */
typedef struct
{
    void *key; /* mbedtls_ssl_config* */
    int (*verify_callback)(void *, mbedtls_x509_crt *, int, uint32_t *);
    void *verify_p;
    int installed_ours; /* Flag: our verify callback is installed */
} mbedtls_callback_entry_t;

static mbedtls_callback_entry_t g_mbedtls_callbacks[MAX_CALLBACK_ENTRIES];
static size_t g_mbedtls_count = 0;
static pthread_mutex_t g_mbedtls_callback_mutex = PTHREAD_MUTEX_INITIALIZER;

/* wolfSSL callback tracking */
typedef struct
{
    void *key; /* WOLFSSL_CTX* or WOLFSSL* */
    void *verify_callback;
    int verify_mode;
    int installed_ours; /* Flag: our verify callback is installed */
} wolfssl_callback_entry_t;

static wolfssl_callback_entry_t g_wolfssl_ctx_callbacks[MAX_CALLBACK_ENTRIES];
static wolfssl_callback_entry_t g_wolfssl_ssl_callbacks[MAX_CALLBACK_ENTRIES];
static size_t g_wolfssl_ctx_count = 0;
static size_t g_wolfssl_ssl_count = 0;
static pthread_mutex_t g_wolfssl_callback_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Handle registry for tracking dlopen handles and reference counts */
#define MAX_HANDLE_ENTRIES 256

typedef struct
{
    void *handle;
    char path[PATH_MAX];
    int refcount;
    int is_openssl;
    int is_mbedtls;
    int is_wolfssl;
} handle_registry_entry_t;

static handle_registry_entry_t g_handle_registry[MAX_HANDLE_ENTRIES];
static size_t g_handle_count = 0;
static pthread_mutex_t g_handle_registry_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Forward declarations for handle registry functions */
static int register_handle(void *handle, const char *path);
static handle_registry_entry_t *decrement_handle_refcount_locked(void *handle);
static void remove_handle_locked(void *handle);

/* Initialization flags */
static pthread_once_t g_init_once = PTHREAD_ONCE_INIT;
static int g_ratls_verify_initialized = 0;

/* Reentrancy guard to prevent storing our own callbacks as user callbacks */
static _Thread_local int g_installing_ours = 0;

/* Thread-local storage for platform instance ID extracted from quote */
static _Thread_local char g_platform_instance_id[129] = {0}; /* 64 bytes = 128 hex chars + null */
static _Thread_local int g_platform_instance_id_valid = 0;

/**
 * Helper functions to read environment variables in real-time
 */
static inline int is_ratls_enabled(void)
{
    const char *val = getenv(ENV_RATLS_ENABLE_VERIFY);
    return (val && strcmp(val, "1") == 0);
}

static inline int is_require_peer_cert_enabled(void)
{
    const char *val = getenv(ENV_RATLS_REQUIRE_PEER_CERT);
    return (val && strcmp(val, "1") == 0);
}

/**
 * Helper functions for callback tracking
 */

/* OpenSSL callback map helpers */
static openssl_callback_entry_t *find_openssl_ctx_callback(void *ctx)
{
    for (size_t i = 0; i < g_openssl_ctx_count; i++)
    {
        if (g_openssl_ctx_callbacks[i].key == ctx)
        {
            return &g_openssl_ctx_callbacks[i];
        }
    }
    return NULL;
}

static openssl_callback_entry_t *find_openssl_ssl_callback(void *ssl)
{
    for (size_t i = 0; i < g_openssl_ssl_count; i++)
    {
        if (g_openssl_ssl_callbacks[i].key == ssl)
        {
            return &g_openssl_ssl_callbacks[i];
        }
    }
    return NULL;
}

static void store_openssl_ctx_callback(void *ctx, int (*cb)(int, X509_STORE_CTX *), int mode,
                                       int (*cert_cb)(X509_STORE_CTX *, void *), void *arg)
{
    pthread_mutex_lock(&g_openssl_callback_mutex);

    openssl_callback_entry_t *entry = find_openssl_ctx_callback(ctx);
    if (!entry && g_openssl_ctx_count < MAX_CALLBACK_ENTRIES)
    {
        entry = &g_openssl_ctx_callbacks[g_openssl_ctx_count++];
        entry->key = ctx;
        entry->installed_ours_verify = 0;
        entry->installed_ours_cert = 0;
    }

    if (entry)
    {
        entry->verify_callback = cb;
        entry->verify_mode = mode;
        entry->cert_verify_callback = cert_cb;
        entry->cert_verify_arg = arg;
    }

    pthread_mutex_unlock(&g_openssl_callback_mutex);
}

static void store_openssl_ssl_callback(void *ssl, int (*cb)(int, X509_STORE_CTX *), int mode,
                                       int (*cert_cb)(X509_STORE_CTX *, void *), void *arg)
{
    pthread_mutex_lock(&g_openssl_callback_mutex);

    openssl_callback_entry_t *entry = find_openssl_ssl_callback(ssl);
    if (!entry && g_openssl_ssl_count < MAX_CALLBACK_ENTRIES)
    {
        entry = &g_openssl_ssl_callbacks[g_openssl_ssl_count++];
        entry->key = ssl;
        entry->installed_ours_verify = 0;
        entry->installed_ours_cert = 0;
    }

    if (entry)
    {
        entry->verify_callback = cb;
        entry->verify_mode = mode;
        entry->cert_verify_callback = cert_cb;
        entry->cert_verify_arg = arg;
    }

    pthread_mutex_unlock(&g_openssl_callback_mutex);
}

static void remove_openssl_ctx_callback(void *ctx)
{
    pthread_mutex_lock(&g_openssl_callback_mutex);

    for (size_t i = 0; i < g_openssl_ctx_count; i++)
    {
        if (g_openssl_ctx_callbacks[i].key == ctx)
        {
            if (i < g_openssl_ctx_count - 1)
            {
                g_openssl_ctx_callbacks[i] = g_openssl_ctx_callbacks[g_openssl_ctx_count - 1];
            }
            g_openssl_ctx_count--;
            break;
        }
    }

    pthread_mutex_unlock(&g_openssl_callback_mutex);
}

static void remove_openssl_ssl_callback(void *ssl)
{
    pthread_mutex_lock(&g_openssl_callback_mutex);

    for (size_t i = 0; i < g_openssl_ssl_count; i++)
    {
        if (g_openssl_ssl_callbacks[i].key == ssl)
        {
            if (i < g_openssl_ssl_count - 1)
            {
                g_openssl_ssl_callbacks[i] = g_openssl_ssl_callbacks[g_openssl_ssl_count - 1];
            }
            g_openssl_ssl_count--;
            break;
        }
    }

    pthread_mutex_unlock(&g_openssl_callback_mutex);
}

/* mbedTLS callback map helpers */
static mbedtls_callback_entry_t *find_mbedtls_callback(void *conf)
{
    for (size_t i = 0; i < g_mbedtls_count; i++)
    {
        if (g_mbedtls_callbacks[i].key == conf)
        {
            return &g_mbedtls_callbacks[i];
        }
    }
    return NULL;
}

static void store_mbedtls_callback(void *conf, int (*cb)(void *, mbedtls_x509_crt *, int, uint32_t *), void *p)
{
    pthread_mutex_lock(&g_mbedtls_callback_mutex);

    mbedtls_callback_entry_t *entry = find_mbedtls_callback(conf);
    if (!entry && g_mbedtls_count < MAX_CALLBACK_ENTRIES)
    {
        entry = &g_mbedtls_callbacks[g_mbedtls_count++];
        entry->key = conf;
        entry->installed_ours = 0;
    }

    if (entry)
    {
        entry->verify_callback = cb;
        entry->verify_p = p;
    }

    pthread_mutex_unlock(&g_mbedtls_callback_mutex);
}

static void remove_mbedtls_callback(void *conf)
{
    pthread_mutex_lock(&g_mbedtls_callback_mutex);

    for (size_t i = 0; i < g_mbedtls_count; i++)
    {
        if (g_mbedtls_callbacks[i].key == conf)
        {
            if (i < g_mbedtls_count - 1)
            {
                g_mbedtls_callbacks[i] = g_mbedtls_callbacks[g_mbedtls_count - 1];
            }
            g_mbedtls_count--;
            break;
        }
    }

    pthread_mutex_unlock(&g_mbedtls_callback_mutex);
}

/* wolfSSL callback map helpers */
static wolfssl_callback_entry_t *find_wolfssl_ctx_callback(void *ctx)
{
    for (size_t i = 0; i < g_wolfssl_ctx_count; i++)
    {
        if (g_wolfssl_ctx_callbacks[i].key == ctx)
        {
            return &g_wolfssl_ctx_callbacks[i];
        }
    }
    return NULL;
}

static wolfssl_callback_entry_t *find_wolfssl_ssl_callback(void *ssl)
{
    for (size_t i = 0; i < g_wolfssl_ssl_count; i++)
    {
        if (g_wolfssl_ssl_callbacks[i].key == ssl)
        {
            return &g_wolfssl_ssl_callbacks[i];
        }
    }
    return NULL;
}

static void store_wolfssl_ctx_callback(void *ctx, void *cb, int mode)
{
    pthread_mutex_lock(&g_wolfssl_callback_mutex);

    wolfssl_callback_entry_t *entry = find_wolfssl_ctx_callback(ctx);
    if (!entry && g_wolfssl_ctx_count < MAX_CALLBACK_ENTRIES)
    {
        entry = &g_wolfssl_ctx_callbacks[g_wolfssl_ctx_count++];
        entry->key = ctx;
        entry->installed_ours = 0;
    }

    if (entry)
    {
        entry->verify_callback = cb;
        entry->verify_mode = mode;
    }

    pthread_mutex_unlock(&g_wolfssl_callback_mutex);
}

static void store_wolfssl_ssl_callback(void *ssl, void *cb, int mode)
{
    pthread_mutex_lock(&g_wolfssl_callback_mutex);

    wolfssl_callback_entry_t *entry = find_wolfssl_ssl_callback(ssl);
    if (!entry && g_wolfssl_ssl_count < MAX_CALLBACK_ENTRIES)
    {
        entry = &g_wolfssl_ssl_callbacks[g_wolfssl_ssl_count++];
        entry->key = ssl;
        entry->installed_ours = 0;
    }

    if (entry)
    {
        entry->verify_callback = cb;
        entry->verify_mode = mode;
    }

    pthread_mutex_unlock(&g_wolfssl_callback_mutex);
}

static void remove_wolfssl_ctx_callback(void *ctx)
{
    pthread_mutex_lock(&g_wolfssl_callback_mutex);

    for (size_t i = 0; i < g_wolfssl_ctx_count; i++)
    {
        if (g_wolfssl_ctx_callbacks[i].key == ctx)
        {
            if (i < g_wolfssl_ctx_count - 1)
            {
                g_wolfssl_ctx_callbacks[i] = g_wolfssl_ctx_callbacks[g_wolfssl_ctx_count - 1];
            }
            g_wolfssl_ctx_count--;
            break;
        }
    }

    pthread_mutex_unlock(&g_wolfssl_callback_mutex);
}

static void remove_wolfssl_ssl_callback(void *ssl)
{
    pthread_mutex_lock(&g_wolfssl_callback_mutex);

    for (size_t i = 0; i < g_wolfssl_ssl_count; i++)
    {
        if (g_wolfssl_ssl_callbacks[i].key == ssl)
        {
            if (i < g_wolfssl_ssl_count - 1)
            {
                g_wolfssl_ssl_callbacks[i] = g_wolfssl_ssl_callbacks[g_wolfssl_ssl_count - 1];
            }
            g_wolfssl_ssl_count--;
            break;
        }
    }

    pthread_mutex_unlock(&g_wolfssl_callback_mutex);
}

/**
 * Standalone Base64 encoder
 */
static int base64_encode(const uint8_t *src, size_t src_len, char *dst, size_t dst_len)
{
    size_t i, j;
    size_t encoded_len = ((src_len + 2) / 3) * 4;

    if (dst_len < encoded_len + 1)
    {
        return -1;
    }

    for (i = 0, j = 0; i < src_len;)
    {
        uint32_t octet_a = i < src_len ? src[i++] : 0;
        uint32_t octet_b = i < src_len ? src[i++] : 0;
        uint32_t octet_c = i < src_len ? src[i++] : 0;
        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;

        dst[j++] = base64_table[(triple >> 18) & 0x3F];
        dst[j++] = base64_table[(triple >> 12) & 0x3F];
        dst[j++] = base64_table[(triple >> 6) & 0x3F];
        dst[j++] = base64_table[triple & 0x3F];
    }

    size_t padding = src_len % 3;
    if (padding > 0)
    {
        for (i = 0; i < 3 - padding; i++)
        {
            dst[encoded_len - 1 - i] = '=';
        }
    }

    dst[encoded_len] = '\0';
    return encoded_len;
}

/**
 * Standalone Base64 decoder
 */
static int base64_decode(const char *src, size_t src_len, uint8_t *dst, size_t *dst_len)
{
    static int decode_table[256];
    static int table_initialized = 0;

    if (!table_initialized)
    {
        for (int i = 0; i < 256; i++)
        {
            decode_table[i] = -1;
        }
        for (int i = 0; i < 64; i++)
        {
            decode_table[(unsigned char)base64_table[i]] = i;
        }
        decode_table['='] = 0;
        table_initialized = 1;
    }

    size_t padding = 0;
    if (src_len >= 2 && src[src_len - 1] == '=')
        padding++;
    if (src_len >= 2 && src[src_len - 2] == '=')
        padding++;
    size_t output_len = (src_len / 4) * 3 - padding;

    if (dst == NULL)
    {
        *dst_len = output_len;
        return 0;
    }

    if (*dst_len < output_len)
    {
        return -1;
    }

    size_t i, j;
    for (i = 0, j = 0; i < src_len;)
    {
        while (i < src_len && (src[i] == ' ' || src[i] == '\n' || src[i] == '\r' || src[i] == '\t'))
        {
            i++;
        }
        if (i >= src_len)
            break;

        uint32_t sextet_a = i < src_len ? decode_table[(unsigned char)src[i++]] : 0;
        uint32_t sextet_b = i < src_len ? decode_table[(unsigned char)src[i++]] : 0;
        uint32_t sextet_c = i < src_len ? decode_table[(unsigned char)src[i++]] : 0;
        uint32_t sextet_d = i < src_len ? decode_table[(unsigned char)src[i++]] : 0;

        if (sextet_a == (uint32_t)-1 || sextet_b == (uint32_t)-1 ||
            sextet_c == (uint32_t)-1 || sextet_d == (uint32_t)-1)
        {
            return -1;
        }

        uint32_t triple = (sextet_a << 18) + (sextet_b << 12) + (sextet_c << 6) + sextet_d;

        if (j < output_len)
            dst[j++] = (triple >> 16) & 0xFF;
        if (j < output_len)
            dst[j++] = (triple >> 8) & 0xFF;
        if (j < output_len)
            dst[j++] = triple & 0xFF;
    }

    *dst_len = output_len;
    return 0;
}

/**
 * Convert DER format to PEM format
 */
static int der_to_pem(const char *header, const char *footer, uint8_t *der, size_t der_size,
                      uint8_t **pem, size_t *pem_size)
{
    size_t b64_len = ((der_size + 2) / 3) * 4;
    size_t lines = (b64_len + 63) / 64;
    size_t total_len = strlen(header) + b64_len + lines + strlen(footer) + 1;

    *pem = malloc(total_len);
    if (!*pem)
    {
        return -1;
    }

    char *b64 = malloc(b64_len + 1);
    if (!b64)
    {
        free(*pem);
        *pem = NULL;
        return -1;
    }

    if (base64_encode(der, der_size, b64, b64_len + 1) < 0)
    {
        free(b64);
        free(*pem);
        *pem = NULL;
        return -1;
    }

    char *p = (char *)*pem;
    strcpy(p, header);
    p += strlen(header);

    for (size_t i = 0; i < b64_len; i += 64)
    {
        size_t chunk = (b64_len - i < 64) ? (b64_len - i) : 64;
        memcpy(p, b64 + i, chunk);
        p += chunk;
        *p++ = '\n';
    }

    strcpy(p, footer);
    p += strlen(footer);

    *pem_size = p - (char *)*pem;

    free(b64);
    return 0;
}

/**
 * Write data to file with proper permissions
 */
static int write_file(const char *path, size_t size, const uint8_t *data, int is_private_key)
{
    FILE *file = fopen(path, "wb");
    if (!file)
    {
        fprintf(stderr, "[RA-TLS SO] Failed to open file for writing: %s\n", path);
        return -1;
    }

    if (fwrite(data, 1, size, file) != size)
    {
        fprintf(stderr, "[RA-TLS SO] Failed to write data to file: %s\n", path);
        fclose(file);
        return -1;
    }

    fclose(file);

    if (is_private_key)
    {
        if (chmod(path, 0600) != 0)
        {
            fprintf(stderr, "[RA-TLS SO] Warning: Failed to set permissions on private key: %s\n", path);
        }
    }

    return 0;
}

/**
 * Generate RA-TLS credentials and save to files
 */
static int generate_ratls_credentials(void)
{
    uint8_t *key_der = NULL;
    uint8_t *crt_der = NULL;
    uint8_t *key_pem = NULL;
    uint8_t *crt_pem = NULL;
    size_t key_der_size = 0;
    size_t crt_der_size = 0;
    size_t key_pem_size = 0;
    size_t crt_pem_size = 0;
    int ret = 0;

    printf("[RA-TLS SO] Generating RA-TLS credentials...\n");

    const char *key_path = getenv(ENV_RATLS_KEY_PATH);
    const char *cert_path = getenv(ENV_RATLS_CERT_PATH);

    if (!key_path)
    {
        key_path = DEFAULT_KEY_PATH;
        printf("[RA-TLS SO] %s not set, using default: %s\n", ENV_RATLS_KEY_PATH, key_path);
    }

    if (!cert_path)
    {
        cert_path = DEFAULT_CERT_PATH;
        printf("[RA-TLS SO] %s not set, using default: %s\n", ENV_RATLS_CERT_PATH, cert_path);
    }
    ret = ra_tls_create_key_and_crt_der(&key_der, &key_der_size, &crt_der, &crt_der_size);
    if (ret < 0)
    {
        fprintf(stderr, "[RA-TLS SO] ra_tls_create_key_and_crt_der failed: %d\n", ret);
        return ret;
    }

    printf("[RA-TLS SO] Generated DER format credentials (key: %zu bytes, cert: %zu bytes)\n",
           key_der_size, crt_der_size);

    ret = der_to_pem(PEM_KEY_HEADER, PEM_KEY_FOOTER, key_der, key_der_size, &key_pem, &key_pem_size);
    if (ret < 0)
    {
        fprintf(stderr, "[RA-TLS SO] Failed to convert key to PEM\n");
        goto err;
    }

    ret = der_to_pem(PEM_CERT_HEADER, PEM_CERT_FOOTER, crt_der, crt_der_size, &crt_pem, &crt_pem_size);
    if (ret < 0)
    {
        fprintf(stderr, "[RA-TLS SO] Failed to convert certificate to PEM\n");
        goto err;
    }

    ret = write_file(key_path, key_pem_size, key_pem, 1);
    if (ret < 0)
    {
        fprintf(stderr, "[RA-TLS SO] Failed to write key to PEM:%s\n", key_path);
        goto err;
    }

    printf("[RA-TLS SO] Saved private key: %s\n", key_path);

    ret = write_file(cert_path, crt_pem_size, crt_pem, 0);
    if (ret < 0)
    {
        fprintf(stderr, "[RA-TLS SO] Failed to write cert to PEM:%s\n", cert_path);
        goto err;
    }

    printf("[RA-TLS SO] Saved certificate: %s\n", cert_path);

    /* Verify the generated certificate using the in-memory DER buffer */
    printf("[RA-TLS SO] Verifying generated certificate...\n");
    
    struct ra_tls_verify_callback_results verify_callback_results = {0};
    ret = ra_tls_verify_callback_extended_der((uint8_t*)crt_der, crt_der_size, &verify_callback_results);
    if (ret < 0)
    {
        fprintf(stderr, "[RA-TLS SO] Generated certificate verification failed: %d\n", ret);
        fprintf(stderr, "[RA-TLS SO] VERIFY ERROR LOCTION: %d\n", verify_callback_results.err_loc);
        fprintf(stderr, "[RA-TLS SO] VERIFY SCHEMA: %d\n", verify_callback_results.attestation_scheme);
        fprintf(stderr, "[RA-TLS SO] VERIFY QUOTE RETURN: %d\n", verify_callback_results.dcap.func_verify_quote_result);
        fprintf(stderr, "[RA-TLS SO] VERIFY QUOTE RESULT: %d\n", verify_callback_results.dcap.quote_verification_result);
        goto err;
    }

    /* Free the in-memory certificate data */
    free(key_der);
    free(crt_der);
    free(key_pem);
    free(crt_pem);
    
    return 0;

err:
    free(key_der);
    free(crt_der);
    free(key_pem);
    free(crt_pem);
    return -1;
}

/* RA-TLS OID definitions for quote extraction */
#define NON_STANDARD_INTEL_SGX_QUOTE_OID \
    { 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x8A, 0x39, 0x06 }

#define TCG_DICE_TAGGED_EVIDENCE_OID_RAW \
    { 0x06, 0x06, 0x67, 0x81, 0x05, 0x05, 0x04, 0x09 }

/**
 * Minimal CBOR parser to extract quote from TCG DICE tagged evidence
 * DICE format: CBOR tag(60000) containing [quote_bytes, claims_bytes]
 * We only need to extract the quote_bytes (first element of the array)
 */
static int extract_quote_from_dice_cbor(const uint8_t* cbor_data, size_t cbor_size,
                                         const uint8_t** out_quote, size_t* out_quote_size)
{
    const uint8_t* ptr = cbor_data;
    const uint8_t* end = cbor_data + cbor_size;
    
    if (ptr >= end) {
        return -1;
    }
    
    /* Check for CBOR tag (major type 6) */
    uint8_t initial_byte = *ptr++;
    if ((initial_byte >> 5) != 6) {
        fprintf(stderr, "[RA-TLS SO] DICE CBOR: expected tag, got major type %d\n", initial_byte >> 5);
        return -1;
    }
    
    /* Read tag number (we expect 60000 = 0xEA60) */
    uint64_t tag_num = 0;
    uint8_t additional_info = initial_byte & 0x1F;
    
    if (additional_info < 24) {
        tag_num = additional_info;
    } else if (additional_info == 24) {
        if (ptr >= end) return -1;
        tag_num = *ptr++;
    } else if (additional_info == 25) {
        if (ptr + 2 > end) return -1;
        tag_num = ((uint64_t)ptr[0] << 8) | ptr[1];
        ptr += 2;
    } else if (additional_info == 26) {
        if (ptr + 4 > end) return -1;
        tag_num = ((uint64_t)ptr[0] << 24) | ((uint64_t)ptr[1] << 16) | 
                  ((uint64_t)ptr[2] << 8) | ptr[3];
        ptr += 4;
    } else {
        fprintf(stderr, "[RA-TLS SO] DICE CBOR: unsupported tag encoding\n");
        return -1;
    }
    
    printf("[RA-TLS SO] DICE CBOR: found tag %lu (expected 60000)\n", (unsigned long)tag_num);
    
    /* Now expect an array (major type 4) with 2 elements */
    if (ptr >= end) return -1;
    initial_byte = *ptr++;
    
    if ((initial_byte >> 5) != 4) {
        fprintf(stderr, "[RA-TLS SO] DICE CBOR: expected array, got major type %d\n", initial_byte >> 5);
        return -1;
    }
    
    additional_info = initial_byte & 0x1F;
    uint64_t array_len = 0;
    
    if (additional_info < 24) {
        array_len = additional_info;
    } else if (additional_info == 24) {
        if (ptr >= end) return -1;
        array_len = *ptr++;
    } else {
        fprintf(stderr, "[RA-TLS SO] DICE CBOR: unsupported array length encoding\n");
        return -1;
    }
    
    if (array_len != 2) {
        fprintf(stderr, "[RA-TLS SO] DICE CBOR: expected 2-element array, got %lu elements\n", 
                (unsigned long)array_len);
        return -1;
    }
    
    /* First element should be a byte string (major type 2) containing the quote */
    if (ptr >= end) return -1;
    initial_byte = *ptr++;
    
    if ((initial_byte >> 5) != 2) {
        fprintf(stderr, "[RA-TLS SO] DICE CBOR: expected byte string for quote, got major type %d\n", 
                initial_byte >> 5);
        return -1;
    }
    
    additional_info = initial_byte & 0x1F;
    uint64_t quote_len = 0;
    
    if (additional_info < 24) {
        quote_len = additional_info;
    } else if (additional_info == 24) {
        if (ptr >= end) return -1;
        quote_len = *ptr++;
    } else if (additional_info == 25) {
        if (ptr + 2 > end) return -1;
        quote_len = ((uint64_t)ptr[0] << 8) | ptr[1];
        ptr += 2;
    } else if (additional_info == 26) {
        if (ptr + 4 > end) return -1;
        quote_len = ((uint64_t)ptr[0] << 24) | ((uint64_t)ptr[1] << 16) | 
                    ((uint64_t)ptr[2] << 8) | ptr[3];
        ptr += 4;
    } else {
        fprintf(stderr, "[RA-TLS SO] DICE CBOR: unsupported byte string length encoding\n");
        return -1;
    }
    
    if (ptr + quote_len > end) {
        fprintf(stderr, "[RA-TLS SO] DICE CBOR: quote length %lu exceeds available data\n", 
                (unsigned long)quote_len);
        return -1;
    }
    
    *out_quote = ptr;
    *out_quote_size = quote_len;
    
    printf("[RA-TLS SO] DICE CBOR: successfully extracted quote (%lu bytes)\n", (unsigned long)quote_len);
    return 0;
}

/**
 * Helper function to find OID in certificate extensions
 * Simplified version based on gramine's find_oid_in_cert_extensions
 */
static int find_oid_in_extensions(const uint8_t* exts, size_t exts_size, 
                                   const uint8_t* oid, size_t oid_size,
                                   const uint8_t** out_data, size_t* out_size)
{
    const uint8_t* ptr = exts;
    const uint8_t* end = exts + exts_size;
    
    while (ptr < end) {
        /* Simple ASN.1 parsing - look for SEQUENCE tag */
        if (ptr + 2 > end || *ptr != 0x30) {
            ptr++;
            continue;
        }
        
        /* Check if OID matches */
        if (ptr + oid_size <= end && memcmp(ptr + 2, oid, oid_size) == 0) {
            /* Found the OID, now find the OCTET STRING with the data */
            const uint8_t* data_ptr = ptr + 2 + oid_size;
            
            /* Skip to OCTET STRING (tag 0x04) */
            while (data_ptr < end && *data_ptr != 0x04) {
                data_ptr++;
            }
            
            if (data_ptr + 2 > end) {
                return -1;
            }
            
            data_ptr++; /* Skip tag */
            
            /* Parse length */
            size_t len = *data_ptr++;
            if (len & 0x80) {
                /* Long form length */
                size_t num_bytes = len & 0x7F;
                if (data_ptr + num_bytes > end) {
                    return -1;
                }
                len = 0;
                for (size_t i = 0; i < num_bytes; i++) {
                    len = (len << 8) | *data_ptr++;
                }
            }
            
            if (data_ptr + len > end) {
                return -1;
            }
            
            *out_data = data_ptr;
            *out_size = len;
            return 0;
        }
        
        ptr++;
    }
    
    return -1;
}

/**
 * Helper function to extract quote from DER-encoded certificate
 * Tries both legacy OID and DICE OID
 */
static int extract_quote_from_cert_der(const uint8_t* cert_der, size_t cert_der_len,
                                        const uint8_t** out_quote, size_t* out_quote_size)
{
    /* Simple DER parser to find extensions */
    /* This is a simplified version - in production you'd use proper X.509 parsing */
    const uint8_t* ptr = cert_der;
    const uint8_t* end = cert_der + cert_der_len;
    
    /* Skip to extensions - this is a very simplified approach */
    /* In a real implementation, you'd properly parse the certificate structure */
    
    /* Try to find legacy OID */
    static const uint8_t legacy_oid[] = NON_STANDARD_INTEL_SGX_QUOTE_OID;
    const uint8_t* search_ptr = ptr;
    while (search_ptr + sizeof(legacy_oid) < end) {
        if (memcmp(search_ptr, legacy_oid, sizeof(legacy_oid)) == 0) {
            /* Found legacy OID, now find the OCTET STRING after it */
            const uint8_t* data_ptr = search_ptr + sizeof(legacy_oid);
            /* Skip to OCTET STRING (tag 0x04) */
            while (data_ptr < end && *data_ptr != 0x04) {
                data_ptr++;
                if (data_ptr - search_ptr > 100) break; /* Safety limit */
            }
            if (data_ptr < end && *data_ptr == 0x04) {
                data_ptr++; /* Skip tag */
                /* Parse length */
                size_t len = *data_ptr++;
                if (len & 0x80) {
                    size_t num_bytes = len & 0x7F;
                    if (data_ptr + num_bytes > end) return -1;
                    len = 0;
                    for (size_t i = 0; i < num_bytes; i++) {
                        len = (len << 8) | *data_ptr++;
                    }
                }
                if (data_ptr + len <= end) {
                    *out_quote = data_ptr;
                    *out_quote_size = len;
                    printf("[RA-TLS SO] Found quote in legacy OID (DER)\n");
                    return 0;
                }
            }
        }
        search_ptr++;
    }
    
    /* Try DICE OID */
    static const uint8_t dice_oid[] = TCG_DICE_TAGGED_EVIDENCE_OID_RAW;
    search_ptr = ptr;
    while (search_ptr + sizeof(dice_oid) < end) {
        if (memcmp(search_ptr, dice_oid, sizeof(dice_oid)) == 0) {
            /* Found DICE OID, now find the OCTET STRING after it */
            const uint8_t* data_ptr = search_ptr + sizeof(dice_oid);
            /* Skip to OCTET STRING (tag 0x04) */
            while (data_ptr < end && *data_ptr != 0x04) {
                data_ptr++;
                if (data_ptr - search_ptr > 100) break; /* Safety limit */
            }
            if (data_ptr < end && *data_ptr == 0x04) {
                data_ptr++; /* Skip tag */
                /* Parse length */
                size_t len = *data_ptr++;
                if (len & 0x80) {
                    size_t num_bytes = len & 0x7F;
                    if (data_ptr + num_bytes > end) return -1;
                    len = 0;
                    for (size_t i = 0; i < num_bytes; i++) {
                        len = (len << 8) | *data_ptr++;
                    }
                }
                if (data_ptr + len <= end) {
                    /* Extract quote from CBOR */
                    const uint8_t* quote_data = NULL;
                    size_t quote_size = 0;
                    if (extract_quote_from_dice_cbor(data_ptr, len, &quote_data, &quote_size) == 0) {
                        *out_quote = quote_data;
                        *out_quote_size = quote_size;
                        printf("[RA-TLS SO] Found quote in DICE OID (DER)\n");
                        return 0;
                    }
                }
            }
        }
        search_ptr++;
    }
    
    return -1;
}

/**
 * Helper function to extract platform instance ID from SGX quote
 * Extracts PPID (type 1) or computes PCK SPKI fingerprint (type 5)
 */
static void extract_platform_instance_id_from_quote(const uint8_t* quote_data, size_t quote_size)
{
    /* Reset platform instance ID */
    g_platform_instance_id_valid = 0;
    memset(g_platform_instance_id, 0, sizeof(g_platform_instance_id));
    
    if (!quote_data || quote_size < 48) {
        printf("[RA-TLS SO] Quote too small to parse: %zu bytes\n", quote_size);
        return;
    }
    
    /* Parse quote header to get signature size */
    /* Quote structure: version(2) + sign_type(2) + epid_group_id(4) + qe_svn(2) + pce_svn(2) + xeid(4) + basename(32) + report_body(384) + signature_size(4) + signature[] */
    const size_t quote_body_size = 48 + 384; /* header + report_body */
    
    if (quote_size < quote_body_size + 4) {
        printf("[RA-TLS SO] Quote too small for signature: %zu bytes\n", quote_size);
        return;
    }
    
    uint32_t signature_size;
    memcpy(&signature_size, quote_data + quote_body_size, 4);
    
    if (quote_size < quote_body_size + 4 + signature_size) {
        printf("[RA-TLS SO] Quote size mismatch: expected %zu, got %zu\n", 
               quote_body_size + 4 + signature_size, quote_size);
        return;
    }
    
    const uint8_t* sig_data = quote_data + quote_body_size + 4;
    
    /* Parse ECDSA signature data structure */
    /* Try P-256 layout: sig(64) + attest_pub_key(64) + qe_report(384) + qe_report_sig(64) + auth_data + cert_data */
    size_t offset = 0;
    uint16_t attestation_key_type;
    memcpy(&attestation_key_type, sig_data + offset, 2);
    offset += 2;
    
    size_t sig_len = (attestation_key_type == 2) ? 64 : 96;  /* P-256: 64, P-384: 96 */
    size_t pubkey_len = (attestation_key_type == 2) ? 64 : 96;
    
    offset += sig_len;           /* Skip signature */
    offset += pubkey_len;        /* Skip attestation public key */
    offset += 384;               /* Skip QE report body */
    offset += sig_len;           /* Skip QE report signature */
    
    if (offset + 2 > signature_size) {
        printf("[RA-TLS SO] Signature data too small for auth_data_len\n");
        return;
    }
    
    uint16_t auth_data_len;
    memcpy(&auth_data_len, sig_data + offset, 2);
    offset += 2;
    
    offset += auth_data_len;     /* Skip auth data */
    
    if (offset + 2 > signature_size) {
        printf("[RA-TLS SO] Signature data too small for cert_data_type\n");
        return;
    }
    
    uint16_t cert_data_type;
    memcpy(&cert_data_type, sig_data + offset, 2);
    offset += 2;
    
    if (offset + 4 > signature_size) {
        printf("[RA-TLS SO] Signature data too small for cert_data_size\n");
        return;
    }
    
    uint32_t cert_data_size;
    memcpy(&cert_data_size, sig_data + offset, 4);
    offset += 4;
    
    if (offset + cert_data_size > signature_size) {
        printf("[RA-TLS SO] Cert data size mismatch: offset=%zu, cert_data_size=%u, signature_size=%u\n",
               offset, cert_data_size, signature_size);
        return;
    }
    
    const uint8_t* cert_data = sig_data + offset;
    uint8_t data_type = cert_data_type & 0xFF;
    
    printf("[RA-TLS SO] Certification data type: %u\n", data_type);
    
    if (data_type == 1) {
        /* PPID-based certification data */
        if (cert_data_size < 16) {
            printf("[RA-TLS SO] PPID cert data too small: %u bytes\n", cert_data_size);
            return;
        }
        
        /* Extract PPID (first 16 bytes) and convert to hex */
        for (int i = 0; i < 16; i++) {
            sprintf(&g_platform_instance_id[i * 2], "%02x", cert_data[i]);
        }
        g_platform_instance_id[32] = '\0';
        g_platform_instance_id_valid = 1;
        
        printf("[RA-TLS SO] Extracted platform instance ID from PPID: %s\n", g_platform_instance_id);
        
    } else if (data_type == 5) {
        /* PCK certificate chain - extract SPKI fingerprint from leaf certificate */
        /* Look for PEM certificate in cert_data */
        const char* pem_start = memmem(cert_data, cert_data_size, "-----BEGIN CERTIFICATE-----", 27);
        
        if (!pem_start) {
            printf("[RA-TLS SO] No PEM certificate found in cert data type 5\n");
            return;
        }
        
        const char* pem_end = memmem(pem_start, cert_data_size - (pem_start - (const char*)cert_data), 
                                     "-----END CERTIFICATE-----", 25);
        if (!pem_end) {
            printf("[RA-TLS SO] Incomplete PEM certificate in cert data\n");
            return;
        }
        
        pem_end += 25; /* Include the end marker */
        size_t pem_len = pem_end - pem_start;
        
#ifdef HAVE_MBEDTLS_HEADERS
        /* Parse certificate using mbedTLS */
        mbedtls_x509_crt pck_cert;
        mbedtls_x509_crt_init(&pck_cert);
        
        int ret = mbedtls_x509_crt_parse(&pck_cert, (const unsigned char*)pem_start, pem_len + 1);
        if (ret != 0) {
            printf("[RA-TLS SO] Failed to parse PCK certificate: %d\n", ret);
            mbedtls_x509_crt_free(&pck_cert);
            return;
        }
        
        /* Extract SPKI (SubjectPublicKeyInfo) from certificate */
        /* The pk field contains the public key, we need to write it to DER format */
        unsigned char spki_der[512];
        int spki_len = mbedtls_pk_write_pubkey_der(&pck_cert.pk, spki_der, sizeof(spki_der));
        
        if (spki_len < 0) {
            printf("[RA-TLS SO] Failed to write SPKI DER: %d\n", spki_len);
            mbedtls_x509_crt_free(&pck_cert);
            return;
        }
        
        /* mbedtls_pk_write_pubkey_der writes from the end of the buffer */
        const unsigned char* spki_start = spki_der + sizeof(spki_der) - spki_len;
        
        /* Compute SHA-256 hash of SPKI */
        unsigned char sha256_hash[32];
        mbedtls_sha256(spki_start, spki_len, sha256_hash, 0); /* 0 = SHA-256, not SHA-224 */
        
        /* Convert to hex string */
        for (int i = 0; i < 32; i++) {
            sprintf(&g_platform_instance_id[i * 2], "%02x", sha256_hash[i]);
        }
        g_platform_instance_id[64] = '\0';
        g_platform_instance_id_valid = 1;
        
        printf("[RA-TLS SO] Extracted platform instance ID from PCK SPKI: %s\n", g_platform_instance_id);
        
        mbedtls_x509_crt_free(&pck_cert);
#else
        printf("[RA-TLS SO] mbedTLS headers not available, cannot extract PCK SPKI fingerprint\n");
#endif
    } else {
        printf("[RA-TLS SO] Unsupported certification data type: %u\n", data_type);
    }
}

/* Whitelist verification functions */
static int parse_csv_line(const char *line, char **tokens, int max_tokens)
{
    int count = 0;
    const char *start = line;
    const char *end;

    while (count < max_tokens && *start)
    {
        while (*start == ' ' || *start == '\t')
            start++;

        if (*start == '\0')
            break;

        end = start;
        while (*end && *end != ',' && *end != '\n' && *end != '\r')
            end++;

        size_t len = end - start;
        tokens[count] = malloc(len + 1);
        if (!tokens[count])
        {
            for (int i = 0; i < count; i++)
                free(tokens[i]);
            return -1;
        }

        memcpy(tokens[count], start, len);
        tokens[count][len] = '\0';

        while (len > 0 && (tokens[count][len - 1] == ' ' || tokens[count][len - 1] == '\t'))
        {
            tokens[count][--len] = '\0';
        }

        count++;

        if (*end == ',')
            start = end + 1;
        else
            break;
    }

    return count;
}

static void free_tokens(char **tokens, int count)
{
    for (int i = 0; i < count; i++)
    {
        free(tokens[i]);
    }
}

static int is_wildcard(const char *str)
{
    /* Empty string or "0" means wildcard (ignore this field) */
    return !str || *str == '\0' || strcmp(str, "0") == 0;
}

static int hex_string_match(const char *a, const char *b)
{
    return strcasecmp(a, b) == 0;
}

/**
 * Helper function to print binary data as hex string
 */
static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("[RA-TLS SO]   %s: ", label);
    for (size_t i = 0; i < len; i++)
    {
        printf("%02x", data[i]);
    }
    printf("\n");
}

/**
 * Measurement verification callback
 */
static int verify_measurements_callback(const char *mrenclave, const char *mrsigner,
                                        const char *isv_prod_id, const char *isv_svn)
{
    printf("[RA-TLS SO] Verifying measurements:\n");
    
    /* Print measurements as hex (they are binary data, not strings) */
    print_hex("MRENCLAVE  ", (const uint8_t*)mrenclave, 32);  /* sgx_measurement_t is 32 bytes */
    print_hex("MRSIGNER   ", (const uint8_t*)mrsigner, 32);   /* sgx_measurement_t is 32 bytes */
    
    /* ISV_PROD_ID and ISV_SVN are uint16_t (2 bytes each) */
    uint16_t prod_id = *(const uint16_t*)isv_prod_id;
    uint16_t svn = *(const uint16_t*)isv_svn;
    printf("[RA-TLS SO]   ISV_PROD_ID: %u (0x%04x)\n", prod_id, prod_id);
    printf("[RA-TLS SO]   ISV_SVN:     %u (0x%04x)\n", svn, svn);

    /* First, call user's callback if set */
    pthread_mutex_lock(&g_user_measurements_cb_mutex);
    verify_measurements_cb_t user_cb = g_user_measurements_cb;
    pthread_mutex_unlock(&g_user_measurements_cb_mutex);
    
    if (user_cb)
    {
        printf("[RA-TLS SO] Calling user measurement callback\n");
        int user_result = user_cb(mrenclave, mrsigner, isv_prod_id, isv_svn);
        if (user_result != 0)
        {
            fprintf(stderr, "[RA-TLS SO] User measurement callback rejected by user callback: %d\n", user_result);
            return user_result;
        }
        printf("[RA-TLS SO] User measurement callback accepted by user callback, proceeding with whitelist check\n");
    }

    /* If user callback passed or not set, check whitelist */
    const char *whitelist_b64 = getenv(ENV_RATLS_WHITELIST_CONFIG);
    if (!whitelist_b64 || !*whitelist_b64)
    {
        printf("[RA-TLS SO] %s not set or empty, accepting connection\n",
                ENV_RATLS_WHITELIST_CONFIG);
        return 0;
    }

    size_t whitelist_len = strlen(whitelist_b64);
    size_t decoded_len = 0;

    if (base64_decode(whitelist_b64, whitelist_len, NULL, &decoded_len) < 0)
    {
        fprintf(stderr, "[RA-TLS SO] Failed to calculate decoded whitelist size\n");
        return 0;
    }

    uint8_t *whitelist_data = malloc(decoded_len + 1);
    if (!whitelist_data)
    {
        fprintf(stderr, "[RA-TLS SO] Failed to allocate memory for whitelist\n");
        return 0;
    }

    if (base64_decode(whitelist_b64, whitelist_len, whitelist_data, &decoded_len) < 0)
    {
        fprintf(stderr, "[RA-TLS SO] Failed to decode whitelist\n");
        free(whitelist_data);
        return 0;
    }

    whitelist_data[decoded_len] = '\0';

    char *lines[5] = {NULL};
    int line_count = 0;
    char *p = (char *)whitelist_data;
    char *line_start = p;

    while (*p && line_count < 5)
    {
        if (*p == '\n' || *p == '\r')
        {
            *p = '\0';
            if (p > line_start)
            {
                lines[line_count++] = line_start;
            }
            p++;
            while (*p == '\n' || *p == '\r')
                p++;
            line_start = p;
        }
        else
        {
            p++;
        }
    }

    if (p > line_start && line_count < 5)
    {
        lines[line_count++] = line_start;
    }

    /* Require exactly 5 lines */
    if (line_count < 5)
    {
        fprintf(stderr, "[RA-TLS SO] Invalid whitelist format: expected at least 5 lines, got %d\n", line_count);
        free(whitelist_data);
        return 0;
    }

    char *mrenclave_tokens[MAX_WHITELIST_ENTRIES];
    char *mrsigner_tokens[MAX_WHITELIST_ENTRIES];
    char *isv_prod_id_tokens[MAX_WHITELIST_ENTRIES];
    char *isv_svn_tokens[MAX_WHITELIST_ENTRIES];
    char *platform_instance_id_tokens[MAX_WHITELIST_ENTRIES];

    int mrenclave_count = parse_csv_line(lines[0], mrenclave_tokens, MAX_WHITELIST_ENTRIES);
    int mrsigner_count = parse_csv_line(lines[1], mrsigner_tokens, MAX_WHITELIST_ENTRIES);
    int isv_prod_id_count = parse_csv_line(lines[2], isv_prod_id_tokens, MAX_WHITELIST_ENTRIES);
    int isv_svn_count = parse_csv_line(lines[3], isv_svn_tokens, MAX_WHITELIST_ENTRIES);
    int platform_instance_id_count = parse_csv_line(lines[4], platform_instance_id_tokens, MAX_WHITELIST_ENTRIES);

    if (mrenclave_count < 0 || mrsigner_count < 0 || isv_prod_id_count < 0 || isv_svn_count < 0 || platform_instance_id_count < 0)
    {
        fprintf(stderr, "[RA-TLS SO] Failed to parse whitelist lines\n");
        free(whitelist_data);
        return 0;
    }

    /* Validate that all non-empty lines have the same number of fields */
    /* Empty lines (count=0) are treated as wildcards and are allowed */
    int expected_count = -1;
    int counts[5] = {mrenclave_count, mrsigner_count, isv_prod_id_count, isv_svn_count, platform_instance_id_count};
    const char* field_names[5] = {"MRENCLAVE", "MRSIGNER", "ISV_PROD_ID", "ISV_SVN", "PLATFORM_INSTANCE_ID"};
    
    for (int i = 0; i < 5; i++)
    {
        if (counts[i] > 0)
        {
            if (expected_count == -1)
            {
                expected_count = counts[i];
            }
            else if (counts[i] != expected_count)
            {
                fprintf(stderr, "[RA-TLS SO] Whitelist data corrupted: %s has %d fields, expected %d\n",
                        field_names[i], counts[i], expected_count);
                free_tokens(mrenclave_tokens, mrenclave_count);
                free_tokens(mrsigner_tokens, mrsigner_count);
                free_tokens(isv_prod_id_tokens, isv_prod_id_count);
                free_tokens(isv_svn_tokens, isv_svn_count);
                free_tokens(platform_instance_id_tokens, platform_instance_id_count);
                free(whitelist_data);
                /* Return 0 to use user callback result (which was already called) */
                return 0;
            }
        }
    }
    
    /* If all lines are empty, accept (all wildcards) */
    if (expected_count == -1)
    {
        expected_count = 0;
    }

    int max_entries = expected_count;

    /* Convert binary measurements to hex strings for comparison with whitelist */
    char mrenclave_hex[65];  /* 32 bytes = 64 hex chars + null terminator */
    char mrsigner_hex[65];   /* 32 bytes = 64 hex chars + null terminator */
    char isv_prod_id_hex[5]; /* 2 bytes = 4 hex chars + null terminator */
    char isv_svn_hex[5];     /* 2 bytes = 4 hex chars + null terminator */
    
    /* Convert MRENCLAVE to hex string */
    for (int i = 0; i < 32; i++)
    {
        sprintf(&mrenclave_hex[i * 2], "%02x", ((const uint8_t*)mrenclave)[i]);
    }
    mrenclave_hex[64] = '\0';
    
    /* Convert MRSIGNER to hex string */
    for (int i = 0; i < 32; i++)
    {
        sprintf(&mrsigner_hex[i * 2], "%02x", ((const uint8_t*)mrsigner)[i]);
    }
    mrsigner_hex[64] = '\0';
    
    /* Convert ISV_PROD_ID to hex string */
    prod_id = *(const uint16_t*)isv_prod_id;
    sprintf(isv_prod_id_hex, "%04x", prod_id);
    
    /* Convert ISV_SVN to hex string */
    svn = *(const uint16_t*)isv_svn;
    sprintf(isv_svn_hex, "%04x", svn);
    
    /* Print platform instance ID if available */
    if (g_platform_instance_id_valid)
    {
        printf("[RA-TLS SO]   PLATFORM_INSTANCE_ID: %s\n", g_platform_instance_id);
    }
    else
    {
        printf("[RA-TLS SO]   PLATFORM_INSTANCE_ID: not available\n");
    }

    int match_found = 0;

    for (int i = 0; i < max_entries; i++)
    {
        int mrenclave_match = (i >= mrenclave_count) || is_wildcard(mrenclave_tokens[i]) ||
                              hex_string_match(mrenclave_hex, mrenclave_tokens[i]);
        int mrsigner_match = (i >= mrsigner_count) || is_wildcard(mrsigner_tokens[i]) ||
                             hex_string_match(mrsigner_hex, mrsigner_tokens[i]);
        int isv_prod_id_match = (i >= isv_prod_id_count) || is_wildcard(isv_prod_id_tokens[i]) ||
                                hex_string_match(isv_prod_id_hex, isv_prod_id_tokens[i]);
        int isv_svn_match = (i >= isv_svn_count) || is_wildcard(isv_svn_tokens[i]) ||
                            hex_string_match(isv_svn_hex, isv_svn_tokens[i]);
        
        /* Check platform instance ID if whitelist has it */
        int platform_instance_id_match = 1; /* Default to match if not in whitelist */
        if (platform_instance_id_count > 0 && i < platform_instance_id_count)
        {
            if (is_wildcard(platform_instance_id_tokens[i]))
            {
                platform_instance_id_match = 1; /* Wildcard always matches */
            }
            else if (g_platform_instance_id_valid)
            {
                platform_instance_id_match = hex_string_match(g_platform_instance_id, platform_instance_id_tokens[i]);
            }
            else
            {
                /* Platform instance ID required but not available */
                platform_instance_id_match = 0;
            }
        }

        if (mrenclave_match && mrsigner_match && isv_prod_id_match && isv_svn_match && platform_instance_id_match)
        {
            printf("[RA-TLS SO] Measurements matched whitelist entry %d\n", i);
            match_found = 1;
            break;
        }
    }

    free_tokens(mrenclave_tokens, mrenclave_count);
    free_tokens(mrsigner_tokens, mrsigner_count);
    free_tokens(isv_prod_id_tokens, isv_prod_id_count);
    free_tokens(isv_svn_tokens, isv_svn_count);
    if (platform_instance_id_count > 0)
    {
        free_tokens(platform_instance_id_tokens, platform_instance_id_count);
    }
    free(whitelist_data);

    if (!match_found)
    {
        fprintf(stderr, "[RA-TLS SO] Measurements do not match any whitelist entry, rejecting connection\n");
        return -1;
    }

    printf("[RA-TLS SO] Measurements verified successfully\n");
    return 0;
}

/**
 * mbedTLS certificate verification callback
 * Calls user's callback first (discards result), then runs RA-TLS (uses our result)
 */
static int my_verify_callback(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
{
    /* Check if RA-TLS verification is enabled */
    int enabled = is_ratls_enabled();

    fprintf(stdout, "my_verify_callback\n");

    /* Find user callback using the config pointer passed as data */
    mbedtls_ssl_config *conf = (mbedtls_ssl_config *)data;
    pthread_mutex_lock(&g_mbedtls_callback_mutex);
    mbedtls_callback_entry_t *entry = NULL;
    if (conf)
    {
        entry = find_mbedtls_callback(conf);
    }
    pthread_mutex_unlock(&g_mbedtls_callback_mutex);

    /* If OFF: call user callback and return user's result */
    if (!enabled || depth != 0)
    {
        if (entry && entry->verify_callback)
        {
            return entry->verify_callback(entry->verify_p, crt, depth, flags);
        }
        /* No user callback, return 0 (default library behavior, rely on flags) */
        return 0;
    }

    /* If ON: call user callback (ignore result), then do RA-TLS verification */
    if (entry && entry->verify_callback)
    {
        uint32_t user_flags = *flags;
        (void)entry->verify_callback(entry->verify_p, crt, depth, &user_flags);
    }

#ifdef HAVE_MBEDTLS_HEADERS
    /* Extract platform instance ID from quote before running RA-TLS verification */
    /* Try to find the quote in certificate extensions */
    const uint8_t* quote_data = NULL;
    size_t quote_size = 0;
    
    /* Try legacy OID first */
    static const uint8_t legacy_oid[] = NON_STANDARD_INTEL_SGX_QUOTE_OID;
    if (find_oid_in_extensions(crt->v3_ext.p, crt->v3_ext.len, legacy_oid, sizeof(legacy_oid), 
                                &quote_data, &quote_size) == 0) {
        printf("[RA-TLS SO] Found quote in legacy OID extension\n");
        extract_platform_instance_id_from_quote(quote_data, quote_size);
    } else {
        /* Try TCG DICE OID */
        static const uint8_t dice_oid[] = TCG_DICE_TAGGED_EVIDENCE_OID_RAW;
        const uint8_t* dice_data = NULL;
        size_t dice_size = 0;
        
        if (find_oid_in_extensions(crt->v3_ext.p, crt->v3_ext.len, dice_oid, sizeof(dice_oid), 
                                    &dice_data, &dice_size) == 0) {
            printf("[RA-TLS SO] Found TCG DICE tagged evidence extension\n");
            
            /* Extract quote from CBOR structure */
            if (extract_quote_from_dice_cbor(dice_data, dice_size, &quote_data, &quote_size) == 0) {
                extract_platform_instance_id_from_quote(quote_data, quote_size);
            } else {
                printf("[RA-TLS SO] Failed to extract quote from DICE CBOR\n");
            }
        } else {
            printf("[RA-TLS SO] Neither legacy nor DICE OID found, platform instance ID extraction skipped\n");
        }
    }
    
    /* Run our RA-TLS verification (requires headers to access crt->raw) */
    *flags = 0;
    struct ra_tls_verify_callback_results verify_callback_results={0};
    int ret = ra_tls_verify_callback_extended_der(crt->raw.p, crt->raw.len, &verify_callback_results);
    if (ret < 0)
    {
        fprintf(stderr, "[RA-TLS SO] RA-TLS verification failed: %d\n", ret);
        return -1;
    }

    printf("[RA-TLS SO] RA-TLS verification succeeded (mbedTLS)\n");
    return 0;
#else
    /* Headers not available - cannot access crt->raw for RA-TLS verification */
    fprintf(stderr, "[RA-TLS SO] mbedTLS headers not available, cannot run RA-TLS verification\n");
    fprintf(stderr, "[RA-TLS SO] Compile with -DHAVE_MBEDTLS_HEADERS to enable RA-TLS for mbedTLS\n");
    return -1;
#endif
}

/**
 * OpenSSL certificate verification callback
 * Calls user's callback first (discards result), then runs RA-TLS (uses our result)
 * Helper functions are resolved lazily at call time
 */
static int ratls_openssl_verify_cb(int preverify_ok, X509_STORE_CTX *ctx)
{
    /* Check if RA-TLS verification is enabled */
    int enabled = is_ratls_enabled();

    /* Resolve helper function for getting certificate chain depth */
    if (!openssl_X509_STORE_CTX_get_error_depth)
    {
        openssl_X509_STORE_CTX_get_error_depth = dlsym(RTLD_DEFAULT, "X509_STORE_CTX_get_error_depth");
    }

    /* Get certificate chain depth (0 = peer cert, 1+ = CA certs) */
    int depth = 0;
    if (openssl_X509_STORE_CTX_get_error_depth)
    {
        depth = openssl_X509_STORE_CTX_get_error_depth(ctx);
    }

    /* Resolve helper functions for context lookup if not already resolved */
    if (!openssl_SSL_get_ex_data_X509_STORE_CTX_idx)
    {
        openssl_SSL_get_ex_data_X509_STORE_CTX_idx = dlsym(RTLD_DEFAULT, "SSL_get_ex_data_X509_STORE_CTX_idx");
    }
    if (!openssl_X509_STORE_CTX_get_ex_data)
    {
        openssl_X509_STORE_CTX_get_ex_data = dlsym(RTLD_DEFAULT, "X509_STORE_CTX_get_ex_data");
    }
    if (!openssl_SSL_get_SSL_CTX)
    {
        openssl_SSL_get_SSL_CTX = dlsym(RTLD_DEFAULT, "SSL_get_SSL_CTX");
    }

    /* Get SSL* from X509_STORE_CTX using ex_data */
    void *ssl = NULL;
    void *ssl_ctx = NULL;
    if (openssl_SSL_get_ex_data_X509_STORE_CTX_idx && openssl_X509_STORE_CTX_get_ex_data)
    {
        int idx = openssl_SSL_get_ex_data_X509_STORE_CTX_idx();
        ssl = openssl_X509_STORE_CTX_get_ex_data(ctx, idx);
        if (ssl && openssl_SSL_get_SSL_CTX)
        {
            ssl_ctx = openssl_SSL_get_SSL_CTX(ssl);
        }
    }

    /* Find user callback - try SSL level first, then CTX level */
    pthread_mutex_lock(&g_openssl_callback_mutex);
    openssl_callback_entry_t *entry = NULL;

    /* Try SSL-level lookup first (most specific) */
    if (ssl)
    {
        entry = find_openssl_ssl_callback(ssl);
    }

    /* Fall back to CTX-level lookup if no SSL-level callback found */
    if (!entry && ssl_ctx)
    {
        entry = find_openssl_ctx_callback(ssl_ctx);
    }
    pthread_mutex_unlock(&g_openssl_callback_mutex);

    /* If OFF or non-first certificate: call user callback and return user's result */
    if (!enabled || depth != 0)
    {
        if (entry && entry->verify_callback)
        {
            return entry->verify_callback(preverify_ok, ctx);
        }
        /* No user callback, return preverify_ok (default library behavior) */
        return preverify_ok;
    }

    /* If ON: call user callback (ignore result), then do RA-TLS verification */
    if (entry && entry->verify_callback)
    {
        (void)entry->verify_callback(preverify_ok, ctx);
    }

    /* Resolve helper functions lazily if not already resolved */
    if (!openssl_X509_STORE_CTX_get0_cert)
    {
        openssl_X509_STORE_CTX_get0_cert = dlsym(RTLD_DEFAULT, "X509_STORE_CTX_get0_cert");
        if (!openssl_X509_STORE_CTX_get0_cert)
        {
            openssl_X509_STORE_CTX_get0_cert = dlsym(RTLD_DEFAULT, "X509_STORE_CTX_get_current_cert");
        }
    }

    if (!openssl_i2d_X509)
    {
        openssl_i2d_X509 = dlsym(RTLD_DEFAULT, "i2d_X509");
    }

    if (!openssl_X509_STORE_CTX_set_error)
    {
        openssl_X509_STORE_CTX_set_error = dlsym(RTLD_DEFAULT, "X509_STORE_CTX_set_error");
    }

    if (!openssl_X509_STORE_CTX_get0_cert || !openssl_i2d_X509 || !openssl_X509_STORE_CTX_set_error)
    {
        fprintf(stderr, "[RA-TLS SO] Failed to resolve OpenSSL helper functions\n");
        return 0;
    }

    X509 *cert = openssl_X509_STORE_CTX_get0_cert(ctx);
    if (!cert)
    {
        fprintf(stderr, "[RA-TLS SO] Failed to get certificate from context\n");
        return 0;
    }

    unsigned char *der = NULL;
    int der_len = openssl_i2d_X509(cert, &der);
    if (der_len <= 0)
    {
        fprintf(stderr, "[RA-TLS SO] Failed to convert certificate to DER\n");
        return 0;
    }

    /* Extract platform instance ID from quote before running RA-TLS verification */
    const uint8_t* quote_data = NULL;
    size_t quote_size = 0;
    if (extract_quote_from_cert_der(der, der_len, &quote_data, &quote_size) == 0) {
        extract_platform_instance_id_from_quote(quote_data, quote_size);
    } else {
        printf("[RA-TLS SO] Could not extract quote from certificate (OpenSSL)\n");
    }

    struct ra_tls_verify_callback_results verify_callback_results={0};
    int ret = ra_tls_verify_callback_extended_der(der, der_len, &verify_callback_results);
    free(der);

    if (ret < 0)
    {
        fprintf(stderr, "[RA-TLS SO] RA-TLS verification failed: %d\n", ret);
        return 0;
    }

    openssl_X509_STORE_CTX_set_error(ctx, 0);
    printf("[RA-TLS SO] RA-TLS verification succeeded (OpenSSL)\n");
    return 1;
}

static int ratls_openssl_cert_verify_cb(X509_STORE_CTX *ctx, void *arg)
{
    (void)arg;
    return ratls_openssl_verify_cb(1, ctx);
}

/**
 * wolfSSL certificate verification callback
 * Calls user's callback first (discards result), then runs RA-TLS (uses our result)
 * Helper functions are resolved lazily at call time
 */
static int ratls_wolfssl_verify_cb(int preverify_ok, void *ctx)
{
    /* Check if RA-TLS verification is enabled */
    int enabled = is_ratls_enabled();

    /* Resolve helper function for getting certificate chain depth */
    if (!wolfssl_X509_STORE_CTX_get_error_depth)
    {
        wolfssl_X509_STORE_CTX_get_error_depth = dlsym(RTLD_DEFAULT, "wolfSSL_X509_STORE_CTX_get_error_depth");
    }

    /* Get certificate chain depth (0 = peer cert, 1+ = CA certs) */
    int depth = 0;
    if (wolfssl_X509_STORE_CTX_get_error_depth)
    {
        depth = wolfssl_X509_STORE_CTX_get_error_depth(ctx);
    }

    /* Resolve helper functions for context lookup if not already resolved */
    if (!wolfssl_SSL_get_ex_data_X509_STORE_CTX_idx)
    {
        wolfssl_SSL_get_ex_data_X509_STORE_CTX_idx = dlsym(RTLD_DEFAULT, "wolfSSL_get_ex_data_X509_STORE_CTX_idx");
    }
    if (!wolfssl_X509_STORE_CTX_get_ex_data)
    {
        wolfssl_X509_STORE_CTX_get_ex_data = dlsym(RTLD_DEFAULT, "wolfSSL_X509_STORE_CTX_get_ex_data");
    }
    if (!wolfssl_SSL_get_SSL_CTX)
    {
        wolfssl_SSL_get_SSL_CTX = dlsym(RTLD_DEFAULT, "wolfSSL_get_SSL_CTX");
    }

    /* Try to get WOLFSSL* from X509_STORE_CTX using ex_data (if available) */
    void *ssl = NULL;
    void *ssl_ctx = NULL;
    if (wolfssl_SSL_get_ex_data_X509_STORE_CTX_idx && wolfssl_X509_STORE_CTX_get_ex_data)
    {
        int idx = wolfssl_SSL_get_ex_data_X509_STORE_CTX_idx();
        ssl = wolfssl_X509_STORE_CTX_get_ex_data(ctx, idx);
        if (ssl && wolfssl_SSL_get_SSL_CTX)
        {
            ssl_ctx = wolfssl_SSL_get_SSL_CTX(ssl);
        }
    }

    /* Find user callback - try SSL level first, then CTX level */
    pthread_mutex_lock(&g_wolfssl_callback_mutex);
    wolfssl_callback_entry_t *entry = NULL;

    /* Try SSL-level lookup first (most specific) if we have SSL* */
    if (ssl)
    {
        entry = find_wolfssl_ssl_callback(ssl);
    }

    /* Fall back to CTX-level lookup if no SSL-level callback found */
    if (!entry && ssl_ctx)
    {
        entry = find_wolfssl_ctx_callback(ssl_ctx);
    }

    /* If ex_data APIs not available, fall back to CTX-level only */
    if (!entry && !ssl)
    {
        /* Without SSL*, we can only check CTX-level callbacks */
        /* This is a limitation when wolfSSL doesn't expose ex_data APIs */
        for (size_t i = 0; i < g_wolfssl_ctx_count; i++)
        {
            if (g_wolfssl_ctx_callbacks[i].verify_callback)
            {
                entry = &g_wolfssl_ctx_callbacks[i];
                break;
            }
        }
    }
    pthread_mutex_unlock(&g_wolfssl_callback_mutex);

    /* If OFF or non-first certificate: call user callback and return user's result */
    if (!enabled || depth != 0)
    {
        if (entry && entry->verify_callback)
        {
            typedef int (*wolfssl_verify_cb_t)(int, void *);
            wolfssl_verify_cb_t user_cb = (wolfssl_verify_cb_t)entry->verify_callback;
            return user_cb(preverify_ok, ctx);
        }
        /* No user callback, return preverify_ok (default library behavior) */
        return preverify_ok;
    }

    /* If ON: call user callback (ignore result), then do RA-TLS verification */
    if (entry && entry->verify_callback)
    {
        typedef int (*wolfssl_verify_cb_t)(int, void *);
        wolfssl_verify_cb_t user_cb = (wolfssl_verify_cb_t)entry->verify_callback;
        (void)user_cb(preverify_ok, ctx);
    }

    /* Resolve helper functions lazily if not already resolved */
    if (!wolfssl_X509_STORE_CTX_get_current_cert)
    {
        wolfssl_X509_STORE_CTX_get_current_cert = dlsym(RTLD_DEFAULT, "wolfSSL_X509_STORE_CTX_get_current_cert");
        if (!wolfssl_X509_STORE_CTX_get_current_cert)
        {
            wolfssl_X509_STORE_CTX_get_current_cert = dlsym(RTLD_DEFAULT, "wolfSSL_X509_STORE_CTX_get0_cert");
        }
    }

    if (!wolfssl_i2d_X509)
    {
        wolfssl_i2d_X509 = dlsym(RTLD_DEFAULT, "wolfSSL_i2d_X509");
    }

    if (!wolfssl_X509_STORE_CTX_set_error)
    {
        wolfssl_X509_STORE_CTX_set_error = dlsym(RTLD_DEFAULT, "wolfSSL_X509_STORE_CTX_set_error");
    }

    if (!wolfssl_X509_STORE_CTX_get_current_cert || !wolfssl_i2d_X509 || !wolfssl_X509_STORE_CTX_set_error)
    {
        fprintf(stderr, "[RA-TLS SO] Failed to resolve wolfSSL helper functions\n");
        return 0;
    }

    void *cert = wolfssl_X509_STORE_CTX_get_current_cert(ctx);
    if (!cert)
    {
        fprintf(stderr, "[RA-TLS SO] Failed to get certificate from context\n");
        return 0;
    }

    unsigned char *der = NULL;
    int der_len = wolfssl_i2d_X509(cert, &der);
    if (der_len <= 0)
    {
        fprintf(stderr, "[RA-TLS SO] Failed to convert certificate to DER\n");
        return 0;
    }

    /* Extract platform instance ID from quote before running RA-TLS verification */
    const uint8_t* quote_data = NULL;
    size_t quote_size = 0;
    if (extract_quote_from_cert_der(der, der_len, &quote_data, &quote_size) == 0) {
        extract_platform_instance_id_from_quote(quote_data, quote_size);
    } else {
        printf("[RA-TLS SO] Could not extract quote from certificate (wolfSSL)\n");
    }

    struct ra_tls_verify_callback_results verify_callback_results={0};
    int ret = ra_tls_verify_callback_extended_der(der, der_len, &verify_callback_results);
    free(der);

    if (ret < 0)
    {
        fprintf(stderr, "[RA-TLS SO] RA-TLS verification failed: %d\n", ret);
        return 0;
    }

    wolfssl_X509_STORE_CTX_set_error(ctx, 0);
    printf("[RA-TLS SO] RA-TLS verification succeeded (wolfSSL)\n");
    return 1;
}

/**
 * Hook ra_tls_set_measurement_callback to intercept user callbacks
 * This is an LD_PRELOAD hook that saves user callbacks and installs our wrapper
 */
void ra_tls_set_measurement_callback(verify_measurements_cb_t f_cb)
{
    static void (*real_ra_tls_set_measurement_callback)(verify_measurements_cb_t) = NULL;
    
    /* Get the real function pointer on first call */
    if (!real_ra_tls_set_measurement_callback)
    {
        real_ra_tls_set_measurement_callback = dlsym(RTLD_NEXT, "ra_tls_set_measurement_callback");
        if (!real_ra_tls_set_measurement_callback)
        {
            fprintf(stderr, "[RA-TLS SO] Failed to find real ra_tls_set_measurement_callback: %s\n", dlerror());
            return;
        }
    }
    
    /* If the callback is our own verify_measurements_callback, just pass it through
     * without storing it as a user callback (avoid recursion) */
    if (f_cb == verify_measurements_callback)
    {
        printf("[RA-TLS SO] Installing our own measurement callback\n");
        real_ra_tls_set_measurement_callback(verify_measurements_callback);
        return;
    }
    
    /* Otherwise, this is a user-provided callback - save it and install our wrapper */
    printf("[RA-TLS SO] Saving user measurement callback\n");
    pthread_mutex_lock(&g_user_measurements_cb_mutex);
    g_user_measurements_cb = f_cb;
    pthread_mutex_unlock(&g_user_measurements_cb_mutex);
}

/**
 * Initialize RA-TLS verification library
 */
static void init_ratls_verify(void)
{
    if (g_ratls_verify_initialized)
    {
        return;
    }

    ra_tls_set_measurement_callback(verify_measurements_callback);

    g_ratls_verify_initialized = 1;
    printf("[RA-TLS SO] RA-TLS verification library initialized successfully\n");
}

/**
 * Check if a TLS stack is enabled via environment variable
 */
/* ========== LD_PRELOAD Interposed Functions ========== */

/**
 * mbedTLS: Intercept mbedtls_ssl_conf_verify
 * Stores user callback, then installs our wrapper callback
 */
/**
 * mbedTLS: Intercept mbedtls_ssl_conf_verify
 * When RATLS_ENABLE_VERIFY=1: stores user callback and installs our wrapper
 * When RATLS_ENABLE_VERIFY=0: passthrough
 */
void mbedtls_ssl_conf_verify(mbedtls_ssl_config *conf,
                             int (*f_vrfy)(void *, mbedtls_x509_crt *, int, uint32_t *),
                             void *p_vrfy)
{
    /* Store-only wrapper: just save user callback, don't call real function */
    /* Installation is handled by early-install wrappers (mbedtls_ssl_setup, mbedtls_ssl_handshake) */

    /* Check if callback is our own wrapper - ignore if so */
    if (f_vrfy == my_verify_callback)
    {
        /* Don't store our own callback as user callback */
        return;
    }

    /* Store user's callback in our tracking map */
    store_mbedtls_callback(conf, f_vrfy, p_vrfy);
}

/**
 * mbedTLS: Intercept mbedtls_ssl_config_defaults
 * Resolves real function per-call using RTLD_NEXT for correct dispatch
 */
int mbedtls_ssl_config_defaults(mbedtls_ssl_config *conf, int endpoint, int transport, int preset)
{
    /* Resolve real function per-call using RTLD_NEXT */
    int (*real_func)(mbedtls_ssl_config *, int, int, int);
    real_func = dlsym(RTLD_NEXT, "mbedtls_ssl_config_defaults");

    int ret = 0;
    if (real_func)
    {
        ret = real_func(conf, endpoint, transport, preset);
        if (ret == 0)
        {
            printf("[RA-TLS SO] Intercepted mbedtls_ssl_config_defaults, installing RA-TLS callback\n");
            mbedtls_ssl_conf_verify(conf, my_verify_callback, NULL);
        }
    }
    return ret;
}

/**
 * OpenSSL: Intercept SSL_CTX_set_verify
 * When RATLS_ENABLE_VERIFY=1: stores user callback and installs our wrapper
 * When RATLS_ENABLE_VERIFY=0: passthrough
 */
void SSL_CTX_set_verify(SSL_CTX *ctx, int mode, int (*callback)(int, X509_STORE_CTX *))
{
    /* Store-only wrapper: just save user callback, don't call real function */
    /* Installation is handled by early-install wrappers (SSL_connect, SSL_accept, etc.) */

    /* Check if callback is our own wrapper - ignore if so */
    if (callback == ratls_openssl_verify_cb)
    {
        /* Don't store our own callback as user callback */
        return;
    }

    /* Store user's callback and mode in our tracking map */
    store_openssl_ctx_callback(ctx, callback, mode, NULL, NULL);
}

/**
 * OpenSSL: Intercept SSL_set_verify
 * When RATLS_ENABLE_VERIFY=1: stores user callback and installs our wrapper
 * When RATLS_ENABLE_VERIFY=0: passthrough
 */
void SSL_set_verify(SSL *ssl, int mode, int (*callback)(int, X509_STORE_CTX *))
{
    /* Store-only wrapper: just save user callback, don't call real function */
    /* Installation is handled by early-install wrappers (SSL_connect, SSL_accept, etc.) */

    /* Check if callback is our own wrapper - ignore if so */
    if (callback == ratls_openssl_verify_cb)
    {
        /* Don't store our own callback as user callback */
        return;
    }

    /* Store user's callback and mode in our tracking map */
    store_openssl_ssl_callback(ssl, callback, mode, NULL, NULL);
}

/**
 * OpenSSL: Intercept SSL_CTX_set_cert_verify_callback
 * When RATLS_ENABLE_VERIFY=1: stores user callback and installs our wrapper
 * When RATLS_ENABLE_VERIFY=0: passthrough
 */
void SSL_CTX_set_cert_verify_callback(SSL_CTX *ctx, int (*cb)(X509_STORE_CTX *, void *), void *arg)
{
    /* Store-only wrapper: just save user callback, don't call real function */
    /* Installation is handled by early-install wrappers (SSL_connect, SSL_accept, etc.) */

    /* Check if callback is our own wrapper - ignore if so */
    if (cb == ratls_openssl_cert_verify_cb)
    {
        /* Don't store our own callback as user callback */
        return;
    }

    /* Store user's callback and arg in our tracking map */
    store_openssl_ctx_callback(ctx, NULL, 0, cb, arg);
}

/**
 * wolfSSL: Intercept wolfSSL_CTX_set_verify
 * When RATLS_ENABLE_VERIFY=1: stores user callback and installs our wrapper
 * When RATLS_ENABLE_VERIFY=0: passthrough
 */
void wolfSSL_CTX_set_verify(void *ctx, int mode, void *callback)
{
    /* Store-only wrapper: just save user callback, don't call real function */
    /* Installation is handled by early-install wrappers (wolfSSL_connect, wolfSSL_accept) */

    /* Check if callback is our own wrapper - ignore if so */
    if (callback == (void *)ratls_wolfssl_verify_cb)
    {
        /* Don't store our own callback as user callback */
        return;
    }

    /* Store user's callback and mode in our tracking map */
    store_wolfssl_ctx_callback(ctx, callback, mode);
}

/**
 * wolfSSL: Intercept wolfSSL_set_verify
 * When RATLS_ENABLE_VERIFY=1: stores user callback and installs our wrapper
 * When RATLS_ENABLE_VERIFY=0: passthrough
 */
void wolfSSL_set_verify(void *ssl, int mode, void *callback)
{
    /* Store-only wrapper: just save user callback, don't call real function */
    /* Installation is handled by early-install wrappers (wolfSSL_connect, wolfSSL_accept) */

    /* Check if callback is our own wrapper - ignore if so */
    if (callback == (void *)ratls_wolfssl_verify_cb)
    {
        /* Don't store our own callback as user callback */
        return;
    }

    /* Store user's callback and mode in our tracking map */
    store_wolfssl_ssl_callback(ssl, callback, mode);
}

/* ========== Early Install Wrappers (Proactive Callback Installation) ========== */

/**
 * OpenSSL: Intercept SSL_CTX_new - Install callback proactively
 * Always installs our RA-TLS callback (env var gating happens inside callback)
 */
SSL_CTX *SSL_CTX_new(const void *method)
{
    /* Resolve real function per-call using RTLD_NEXT */
    SSL_CTX *(*real_func)(const void *);
    real_func = dlsym(RTLD_NEXT, "SSL_CTX_new");

    /* Fallback to RTLD_DEFAULT for statically-linked but exported symbols (e.g., Node.js) */
    if (!real_func)
    {
        real_func = dlsym(RTLD_DEFAULT, "SSL_CTX_new");
        /* Ensure we didn't resolve to our own wrapper (avoid infinite recursion) */
        if (real_func == SSL_CTX_new)
        {
            real_func = NULL;
        }
    }

    if (!real_func)
    {
        return NULL;
    }

    SSL_CTX *ctx = real_func(method);
    if (ctx)
    {
        printf("[RA-TLS SO] Intercepted SSL_CTX_new, proactively installing RA-TLS callback\n");

        /* Check if user has already set verification mode */
        pthread_mutex_lock(&g_openssl_callback_mutex);
        openssl_callback_entry_t *entry = find_openssl_ctx_callback(ctx);
        int user_requires_peer_cert = (entry && (entry->verify_mode & 0x02));
        pthread_mutex_unlock(&g_openssl_callback_mutex);

        /* Priority: user setting > environment variable */
        int mode = 0x01; /* SSL_VERIFY_PEER */
        if (user_requires_peer_cert || is_require_peer_cert_enabled())
        {
            mode |= 0x02; /* SSL_VERIFY_FAIL_IF_NO_PEER_CERT */
        }

        /* Set reentrancy guard to prevent storing our own callback */
        g_installing_ours = 1;
        SSL_CTX_set_verify(ctx, mode, ratls_openssl_verify_cb);
        g_installing_ours = 0;
    }
    return ctx;
}

/**
 * OpenSSL: Intercept SSL_new - Install callback proactively
 * Always installs our RA-TLS callback (env var gating happens inside callback)
 */
SSL *SSL_new(SSL_CTX *ctx)
{
    /* Resolve real function per-call using RTLD_NEXT */
    SSL *(*real_func)(SSL_CTX *);
    real_func = dlsym(RTLD_NEXT, "SSL_new");

    /* Fallback to RTLD_DEFAULT for statically-linked but exported symbols (e.g., Node.js) */
    if (!real_func)
    {
        real_func = dlsym(RTLD_DEFAULT, "SSL_new");
        /* Ensure we didn't resolve to our own wrapper (avoid infinite recursion) */
        if (real_func == SSL_new)
        {
            real_func = NULL;
        }
    }

    if (!real_func)
    {
        return NULL;
    }

    SSL *ssl = real_func(ctx);
    if (ssl)
    {
        printf("[RA-TLS SO] Intercepted SSL_new, proactively installing RA-TLS callback\n");

        /* Check if user has already set verification mode on SSL or CTX */
        pthread_mutex_lock(&g_openssl_callback_mutex);
        openssl_callback_entry_t *ssl_entry = find_openssl_ssl_callback(ssl);
        openssl_callback_entry_t *ctx_entry = find_openssl_ctx_callback(ctx);
        int user_requires_peer_cert = (ssl_entry && (ssl_entry->verify_mode & 0x02)) ||
                                      (ctx_entry && (ctx_entry->verify_mode & 0x02));
        pthread_mutex_unlock(&g_openssl_callback_mutex);

        /* Priority: user setting > environment variable */
        int mode = 0x01; /* SSL_VERIFY_PEER */
        if (user_requires_peer_cert || is_require_peer_cert_enabled())
        {
            mode |= 0x02; /* SSL_VERIFY_FAIL_IF_NO_PEER_CERT */
        }

        /* Set reentrancy guard to prevent storing our own callback */
        g_installing_ours = 1;
        SSL_set_verify(ssl, mode, ratls_openssl_verify_cb);
        g_installing_ours = 0;
    }
    return ssl;
}

/**
 * OpenSSL: Intercept SSL_connect - Ensure callback is installed before handshake
 * Always ensures our RA-TLS callback is installed (env var gating happens inside callback)
 */
int SSL_connect(SSL *ssl)
{
    /* Resolve real function per-call using RTLD_NEXT */
    int (*real_func)(SSL *);
    real_func = dlsym(RTLD_NEXT, "SSL_connect");

    /* Fallback to RTLD_DEFAULT for statically-linked but exported symbols (e.g., Node.js) */
    if (!real_func)
    {
        real_func = dlsym(RTLD_DEFAULT, "SSL_connect");
        /* Ensure we didn't resolve to our own wrapper (avoid infinite recursion) */
        if (real_func == SSL_connect)
        {
            real_func = NULL;
        }
    }

    if (!real_func)
    {
        return -1;
    }

    /* Ensure RA-TLS callback is installed */
    printf("[RA-TLS SO] Intercepted SSL_connect, ensuring RA-TLS callback is installed\n");

    /* Check if our callback is already installed */
    pthread_mutex_lock(&g_openssl_callback_mutex);
    openssl_callback_entry_t *entry = find_openssl_ssl_callback(ssl);
    int already_installed = (entry && entry->installed_ours_verify);
    int user_requires_peer_cert = (entry && (entry->verify_mode & 0x02));
    pthread_mutex_unlock(&g_openssl_callback_mutex);

    if (!already_installed)
    {
        /* Install our callback now */
        printf("[RA-TLS SO] Installing RA-TLS callback before handshake\n");
        /* Priority: user setting > environment variable */
        /* Minimum: SSL_VERIFY_PEER to ensure callback runs */
        int mode = 0x01; /* SSL_VERIFY_PEER */
        if (user_requires_peer_cert || is_require_peer_cert_enabled())
        {
            mode |= 0x02; /* SSL_VERIFY_FAIL_IF_NO_PEER_CERT */
        }

        /* Resolve real SSL_set_verify function and call it directly (not our wrapper) */
        void (*real_set_verify)(SSL *, int, int (*)(int, X509_STORE_CTX *));
        real_set_verify = dlsym(RTLD_NEXT, "SSL_set_verify");
        if (!real_set_verify)
        {
            real_set_verify = dlsym(RTLD_DEFAULT, "SSL_set_verify");
        }
        if (real_set_verify)
        {
            real_set_verify(ssl, mode, ratls_openssl_verify_cb);
            /* Mark as installed */
            pthread_mutex_lock(&g_openssl_callback_mutex);
            entry = find_openssl_ssl_callback(ssl);
            if (entry)
            {
                entry->installed_ours_verify = 1;
            }
            pthread_mutex_unlock(&g_openssl_callback_mutex);
        }
    }

    return real_func(ssl);
}

/**
 * OpenSSL: Intercept SSL_accept - Ensure callback is installed before handshake
 * Always ensures our RA-TLS callback is installed (env var gating happens inside callback)
 */
int SSL_accept(SSL *ssl)
{
    /* Resolve real function per-call using RTLD_NEXT */
    int (*real_func)(SSL *);
    real_func = dlsym(RTLD_NEXT, "SSL_accept");

    /* Fallback to RTLD_DEFAULT for statically-linked but exported symbols (e.g., Node.js) */
    if (!real_func)
    {
        real_func = dlsym(RTLD_DEFAULT, "SSL_accept");
        /* Ensure we didn't resolve to our own wrapper (avoid infinite recursion) */
        if (real_func == SSL_accept)
        {
            real_func = NULL;
        }
    }

    if (!real_func)
    {
        return -1;
    }

    /* Ensure RA-TLS callback is installed */
    printf("[RA-TLS SO] Intercepted SSL_accept, ensuring RA-TLS callback is installed\n");

    /* Check if our callback is already installed */
    pthread_mutex_lock(&g_openssl_callback_mutex);
    openssl_callback_entry_t *entry = find_openssl_ssl_callback(ssl);
    int already_installed = (entry && entry->installed_ours_verify);
    int user_requires_peer_cert = (entry && (entry->verify_mode & 0x02));
    pthread_mutex_unlock(&g_openssl_callback_mutex);

    if (!already_installed)
    {
        /* Install our callback now */
        printf("[RA-TLS SO] Installing RA-TLS callback before handshake\n");
        /* Priority: user setting > environment variable */
        /* Minimum: SSL_VERIFY_PEER to ensure callback runs */
        int mode = 0x01; /* SSL_VERIFY_PEER */
        if (user_requires_peer_cert || is_require_peer_cert_enabled())
        {
            mode |= 0x02; /* SSL_VERIFY_FAIL_IF_NO_PEER_CERT */
        }

        /* Resolve real SSL_set_verify function and call it directly (not our wrapper) */
        void (*real_set_verify)(SSL *, int, int (*)(int, X509_STORE_CTX *));
        real_set_verify = dlsym(RTLD_NEXT, "SSL_set_verify");
        if (!real_set_verify)
        {
            real_set_verify = dlsym(RTLD_DEFAULT, "SSL_set_verify");
        }
        if (real_set_verify)
        {
            real_set_verify(ssl, mode, ratls_openssl_verify_cb);
            /* Mark as installed */
            pthread_mutex_lock(&g_openssl_callback_mutex);
            entry = find_openssl_ssl_callback(ssl);
            if (entry)
            {
                entry->installed_ours_verify = 1;
            }
            pthread_mutex_unlock(&g_openssl_callback_mutex);
        }
    }

    return real_func(ssl);
}

/**
 * OpenSSL: Intercept SSL_do_handshake - Ensure callback is installed before handshake
 * Always ensures our RA-TLS callback is installed (env var gating happens inside callback)
 */
int SSL_do_handshake(SSL *ssl)
{
    /* Resolve real function per-call using RTLD_NEXT */
    int (*real_func)(SSL *);
    real_func = dlsym(RTLD_NEXT, "SSL_do_handshake");

    /* Fallback to RTLD_DEFAULT for statically-linked but exported symbols (e.g., Node.js) */
    if (!real_func)
    {
        real_func = dlsym(RTLD_DEFAULT, "SSL_do_handshake");
        /* Ensure we didn't resolve to our own wrapper (avoid infinite recursion) */
        if (real_func == SSL_do_handshake)
        {
            real_func = NULL;
        }
    }

    if (!real_func)
    {
        return -1;
    }

    /* Ensure RA-TLS callback is installed */
    printf("[RA-TLS SO] Intercepted SSL_do_handshake, ensuring RA-TLS callback is installed\n");

    /* Check if our callback is already installed */
    pthread_mutex_lock(&g_openssl_callback_mutex);
    openssl_callback_entry_t *entry = find_openssl_ssl_callback(ssl);
    int already_installed = (entry && entry->installed_ours_verify);
    int user_requires_peer_cert = (entry && (entry->verify_mode & 0x02));
    pthread_mutex_unlock(&g_openssl_callback_mutex);

    if (!already_installed)
    {
        /* Install our callback now */
        printf("[RA-TLS SO] Installing RA-TLS callback before handshake\n");
        /* Priority: user setting > environment variable */
        /* Minimum: SSL_VERIFY_PEER to ensure callback runs */
        int mode = 0x01; /* SSL_VERIFY_PEER */
        if (user_requires_peer_cert || is_require_peer_cert_enabled())
        {
            mode |= 0x02; /* SSL_VERIFY_FAIL_IF_NO_PEER_CERT */
        }

        /* Resolve real SSL_set_verify function and call it directly (not our wrapper) */
        void (*real_set_verify)(SSL *, int, int (*)(int, X509_STORE_CTX *));
        real_set_verify = dlsym(RTLD_NEXT, "SSL_set_verify");
        if (!real_set_verify)
        {
            real_set_verify = dlsym(RTLD_DEFAULT, "SSL_set_verify");
        }
        if (real_set_verify)
        {
            real_set_verify(ssl, mode, ratls_openssl_verify_cb);
            /* Mark as installed */
            pthread_mutex_lock(&g_openssl_callback_mutex);
            entry = find_openssl_ssl_callback(ssl);
            if (entry)
            {
                entry->installed_ours_verify = 1;
            }
            pthread_mutex_unlock(&g_openssl_callback_mutex);
        }
    }

    return real_func(ssl);
}

/**
 * mbedTLS: Intercept mbedtls_ssl_setup - Install callback proactively
 * Always installs our RA-TLS callback (env var gating happens inside callback)
 */
int mbedtls_ssl_setup(mbedtls_ssl_context *ssl, const mbedtls_ssl_config *conf)
{

    /* Resolve real function per-call using RTLD_NEXT */
    int (*real_func)(mbedtls_ssl_context *, const mbedtls_ssl_config *);
    real_func = dlsym(RTLD_NEXT, "mbedtls_ssl_setup");

    /* Fallback to RTLD_DEFAULT for statically-linked but exported symbols (e.g., Node.js) */
    if (!real_func)
    {
        real_func = dlsym(RTLD_DEFAULT, "mbedtls_ssl_setup");
        /* Ensure we didn't resolve to our own wrapper (avoid infinite recursion) */
        if (real_func == mbedtls_ssl_setup)
        {
            real_func = NULL;
        }
    }

    if (!real_func)
    {
        return -1;
    }

    int ret = real_func(ssl, conf);

    /* Always install callback if setup succeeded */
    if (ret == 0 && conf)
    {
        /* Check if our callback is already installed */
        pthread_mutex_lock(&g_mbedtls_callback_mutex);
        mbedtls_callback_entry_t *entry = find_mbedtls_callback(conf);
        int already_installed = (entry && entry->installed_ours);
        pthread_mutex_unlock(&g_mbedtls_callback_mutex);

        if (!already_installed)
        {
            /* Install RA-TLS callback */
            printf("[RA-TLS SO] Intercepted mbedtls_ssl_setup, proactively installing RA-TLS callback\n");

            /* Resolve real mbedtls_ssl_conf_verify function and call it directly (not our wrapper) */
            void (*real_conf_verify)(mbedtls_ssl_config *, int (*)(void *, mbedtls_x509_crt *, int, uint32_t *), void *);
            real_conf_verify = dlsym(RTLD_NEXT, "mbedtls_ssl_conf_verify");
            if (!real_conf_verify)
            {
                real_conf_verify = dlsym(RTLD_DEFAULT, "mbedtls_ssl_conf_verify");
            }
            if (real_conf_verify)
            {
                /* Cast away const - mbedtls_ssl_setup receives const config but mbedtls_ssl_conf_verify expects non-const.
                 * This is safe because the config is built before handshake and mbedtls_ssl_conf_verify only modifies it. */
                real_conf_verify((mbedtls_ssl_config *)conf, my_verify_callback, (void *)conf);
                /* Mark as installed */
                pthread_mutex_lock(&g_mbedtls_callback_mutex);
                entry = find_mbedtls_callback(conf);
                if (entry)
                {
                    entry->installed_ours = 1;
                }
                pthread_mutex_unlock(&g_mbedtls_callback_mutex);
            }
        }
    }
    return ret;
}

/**
 * mbedTLS: Intercept mbedtls_ssl_handshake - Ensure callback is installed before handshake
 * Always ensures our RA-TLS callback is installed (env var gating happens inside callback)
 * Note: We can't easily get the config from ssl without headers, so this is best-effort
 */
int mbedtls_ssl_handshake(mbedtls_ssl_context *ssl)
{

    /* Resolve real function per-call using RTLD_NEXT */
    int (*real_func)(mbedtls_ssl_context *);
    real_func = dlsym(RTLD_NEXT, "mbedtls_ssl_handshake");

    /* Fallback to RTLD_DEFAULT for statically-linked but exported symbols (e.g., Node.js) */
    if (!real_func)
    {
        real_func = dlsym(RTLD_DEFAULT, "mbedtls_ssl_handshake");
        /* Ensure we didn't resolve to our own wrapper (avoid infinite recursion) */
        if (real_func == mbedtls_ssl_handshake)
        {
            real_func = NULL;
        }
    }

    if (!real_func)
    {
        return -1;
    }

    /* Best-effort callback installation */
    printf("[RA-TLS SO] Intercepted mbedtls_ssl_handshake (best-effort, cannot access config)\n");

    return real_func(ssl);
}

/**
 * wolfSSL: Intercept wolfSSL_CTX_new - Install callback proactively
 * Always installs our RA-TLS callback (env var gating happens inside callback)
 */
void *wolfSSL_CTX_new(void *method)
{

    /* Resolve real function per-call using RTLD_NEXT */
    void *(*real_func)(void *);
    real_func = dlsym(RTLD_NEXT, "wolfSSL_CTX_new");

    /* Fallback to RTLD_DEFAULT for statically-linked but exported symbols (e.g., Node.js) */
    if (!real_func)
    {
        real_func = dlsym(RTLD_DEFAULT, "wolfSSL_CTX_new");
        /* Ensure we didn't resolve to our own wrapper (avoid infinite recursion) */
        if (real_func == wolfSSL_CTX_new)
        {
            real_func = NULL;
        }
    }

    if (!real_func)
    {
        return NULL;
    }

    void *ctx = real_func(method);
    if (ctx)
    {
        printf("[RA-TLS SO] Intercepted wolfSSL_CTX_new, proactively installing RA-TLS callback\n");

        /* Check if user has already set verification mode */
        pthread_mutex_lock(&g_wolfssl_callback_mutex);
        wolfssl_callback_entry_t *entry = NULL;
        for (size_t i = 0; i < g_wolfssl_ctx_count; i++)
        {
            if (g_wolfssl_ctx_callbacks[i].key == ctx)
            {
                entry = &g_wolfssl_ctx_callbacks[i];
                break;
            }
        }
        int user_requires_peer_cert = (entry && (entry->verify_mode & 0x02));
        pthread_mutex_unlock(&g_wolfssl_callback_mutex);

        /* Priority: user setting > environment variable */
        int mode = 0x01; /* SSL_VERIFY_PEER equivalent */
        if (user_requires_peer_cert || is_require_peer_cert_enabled())
        {
            mode |= 0x02; /* SSL_VERIFY_FAIL_IF_NO_PEER_CERT equivalent */
        }

        /* Set reentrancy guard to prevent storing our own callback */
        g_installing_ours = 1;
        wolfSSL_CTX_set_verify(ctx, mode, ratls_wolfssl_verify_cb);
        g_installing_ours = 0;
    }
    return ctx;
}

/**
 * wolfSSL: Intercept wolfSSL_new - Install callback proactively
 * Always installs our RA-TLS callback (env var gating happens inside callback)
 */
void *wolfSSL_new(void *ctx)
{
    /* Resolve real function per-call using RTLD_NEXT */
    void *(*real_func)(void *);
    real_func = dlsym(RTLD_NEXT, "wolfSSL_new");

    /* Fallback to RTLD_DEFAULT for statically-linked but exported symbols (e.g., Node.js) */
    if (!real_func)
    {
        real_func = dlsym(RTLD_DEFAULT, "wolfSSL_new");
        /* Ensure we didn't resolve to our own wrapper (avoid infinite recursion) */
        if (real_func == wolfSSL_new)
        {
            real_func = NULL;
        }
    }

    if (!real_func)
    {
        return NULL;
    }

    void *ssl = real_func(ctx);
    if (ssl)
    {
        printf("[RA-TLS SO] Intercepted wolfSSL_new, proactively installing RA-TLS callback\n");

        /* Check if user has already set verification mode on SSL or CTX */
        pthread_mutex_lock(&g_wolfssl_callback_mutex);
        wolfssl_callback_entry_t *ssl_entry = NULL;
        wolfssl_callback_entry_t *ctx_entry = NULL;
        for (size_t i = 0; i < g_wolfssl_ssl_count; i++)
        {
            if (g_wolfssl_ssl_callbacks[i].key == ssl)
            {
                ssl_entry = &g_wolfssl_ssl_callbacks[i];
                break;
            }
        }
        for (size_t i = 0; i < g_wolfssl_ctx_count; i++)
        {
            if (g_wolfssl_ctx_callbacks[i].key == ctx)
            {
                ctx_entry = &g_wolfssl_ctx_callbacks[i];
                break;
            }
        }
        int user_requires_peer_cert = (ssl_entry && (ssl_entry->verify_mode & 0x02)) ||
                                      (ctx_entry && (ctx_entry->verify_mode & 0x02));
        pthread_mutex_unlock(&g_wolfssl_callback_mutex);

        /* Priority: user setting > environment variable */
        int mode = 0x01; /* SSL_VERIFY_PEER equivalent */
        if (user_requires_peer_cert || is_require_peer_cert_enabled())
        {
            mode |= 0x02; /* SSL_VERIFY_FAIL_IF_NO_PEER_CERT equivalent */
        }

        /* Set reentrancy guard to prevent storing our own callback */
        g_installing_ours = 1;
        wolfSSL_set_verify(ssl, mode, ratls_wolfssl_verify_cb);
        g_installing_ours = 0;
    }
    return ssl;
}

/**
 * wolfSSL: Intercept wolfSSL_connect - Ensure callback is installed before handshake
 */
/**
 * wolfSSL: Intercept wolfSSL_connect - Ensure callback is installed before handshake
 * Always ensures our RA-TLS callback is installed (env var gating happens inside callback)
 */
int wolfSSL_connect(void *ssl)
{

    /* Resolve real function per-call using RTLD_NEXT */
    int (*real_func)(void *);
    real_func = dlsym(RTLD_NEXT, "wolfSSL_connect");

    /* Fallback to RTLD_DEFAULT for statically-linked but exported symbols (e.g., Node.js) */
    if (!real_func)
    {
        real_func = dlsym(RTLD_DEFAULT, "wolfSSL_connect");
        /* Ensure we didn't resolve to our own wrapper (avoid infinite recursion) */
        if (real_func == wolfSSL_connect)
        {
            real_func = NULL;
        }
    }

    if (!real_func)
    {
        return -1;
    }

    /* Ensure RA-TLS callback is installed */
    printf("[RA-TLS SO] Intercepted wolfSSL_connect, ensuring RA-TLS callback is installed\n");

    /* Check if our callback is already installed */
    pthread_mutex_lock(&g_wolfssl_callback_mutex);
    wolfssl_callback_entry_t *entry = find_wolfssl_ssl_callback(ssl);
    int already_installed = (entry && entry->installed_ours);
    int user_requires_peer_cert = (entry && (entry->verify_mode & 0x02));
    pthread_mutex_unlock(&g_wolfssl_callback_mutex);

    if (!already_installed)
    {
        /* Install our callback now */
        printf("[RA-TLS SO] Installing RA-TLS callback before handshake\n");
        /* Priority: user setting > environment variable */
        /* Minimum: SSL_VERIFY_PEER to ensure callback runs */
        int mode = 0x01; /* SSL_VERIFY_PEER equivalent */
        if (user_requires_peer_cert || is_require_peer_cert_enabled())
        {
            mode |= 0x02; /* SSL_VERIFY_FAIL_IF_NO_PEER_CERT equivalent */
        }

        /* Resolve real wolfSSL_set_verify function and call it directly (not our wrapper) */
        void (*real_set_verify)(void *, int, void *);
        real_set_verify = dlsym(RTLD_NEXT, "wolfSSL_set_verify");
        if (!real_set_verify)
        {
            real_set_verify = dlsym(RTLD_DEFAULT, "wolfSSL_set_verify");
        }
        if (real_set_verify)
        {
            real_set_verify(ssl, mode, (void *)ratls_wolfssl_verify_cb);
            /* Mark as installed */
            pthread_mutex_lock(&g_wolfssl_callback_mutex);
            entry = find_wolfssl_ssl_callback(ssl);
            if (entry)
            {
                entry->installed_ours = 1;
            }
            pthread_mutex_unlock(&g_wolfssl_callback_mutex);
        }
    }

    return real_func(ssl);
}

/**
 * wolfSSL: Intercept wolfSSL_accept - Ensure callback is installed before handshake
 * Always ensures our RA-TLS callback is installed (env var gating happens inside callback)
 */
int wolfSSL_accept(void *ssl)
{

    /* Resolve real function per-call using RTLD_NEXT */
    int (*real_func)(void *);
    real_func = dlsym(RTLD_NEXT, "wolfSSL_accept");

    /* Fallback to RTLD_DEFAULT for statically-linked but exported symbols (e.g., Node.js) */
    if (!real_func)
    {
        real_func = dlsym(RTLD_DEFAULT, "wolfSSL_accept");
        /* Ensure we didn't resolve to our own wrapper (avoid infinite recursion) */
        if (real_func == wolfSSL_accept)
        {
            real_func = NULL;
        }
    }

    if (!real_func)
    {
        return -1;
    }

    /* Ensure RA-TLS callback is installed */
    printf("[RA-TLS SO] Intercepted wolfSSL_accept, ensuring RA-TLS callback is installed\n");

    /* Check if our callback is already installed */
    pthread_mutex_lock(&g_wolfssl_callback_mutex);
    wolfssl_callback_entry_t *entry = find_wolfssl_ssl_callback(ssl);
    int already_installed = (entry && entry->installed_ours);
    int user_requires_peer_cert = (entry && (entry->verify_mode & 0x02));
    pthread_mutex_unlock(&g_wolfssl_callback_mutex);

    if (!already_installed)
    {
        /* Install our callback now */
        printf("[RA-TLS SO] Installing RA-TLS callback before handshake\n");
        /* Priority: user setting > environment variable */
        /* Minimum: SSL_VERIFY_PEER to ensure callback runs */
        int mode = 0x01; /* SSL_VERIFY_PEER equivalent */
        if (user_requires_peer_cert || is_require_peer_cert_enabled())
        {
            mode |= 0x02; /* SSL_VERIFY_FAIL_IF_NO_PEER_CERT equivalent */
        }

        /* Resolve real wolfSSL_set_verify function and call it directly (not our wrapper) */
        void (*real_set_verify)(void *, int, void *);
        real_set_verify = dlsym(RTLD_NEXT, "wolfSSL_set_verify");
        if (!real_set_verify)
        {
            real_set_verify = dlsym(RTLD_DEFAULT, "wolfSSL_set_verify");
        }
        if (real_set_verify)
        {
            real_set_verify(ssl, mode, (void *)ratls_wolfssl_verify_cb);
            /* Mark as installed */
            pthread_mutex_lock(&g_wolfssl_callback_mutex);
            entry = find_wolfssl_ssl_callback(ssl);
            if (entry)
            {
                entry->installed_ours = 1;
            }
            pthread_mutex_unlock(&g_wolfssl_callback_mutex);
        }
    }

    return real_func(ssl);
}

/* ========== Cleanup Wrappers (Memory Management) ========== */

/**
 * OpenSSL: Intercept SSL_CTX_free - Clean up callback tracking
 */
void SSL_CTX_free(SSL_CTX *ctx)
{
    if (ctx)
    {
        printf("[RA-TLS SO] Intercepted SSL_CTX_free, cleaning up callback tracking\n");
        remove_openssl_ctx_callback(ctx);
    }

    /* Resolve real function per-call using RTLD_NEXT */
    void (*real_func)(SSL_CTX *);
    real_func = dlsym(RTLD_NEXT, "SSL_CTX_free");

    if (real_func)
    {
        real_func(ctx);
    }
}

/**
 * OpenSSL: Intercept SSL_free - Clean up callback tracking
 */
void SSL_free(SSL *ssl)
{
    if (ssl)
    {
        printf("[RA-TLS SO] Intercepted SSL_free, cleaning up callback tracking\n");
        remove_openssl_ssl_callback(ssl);
    }

    /* Resolve real function per-call using RTLD_NEXT */
    void (*real_func)(SSL *);
    real_func = dlsym(RTLD_NEXT, "SSL_free");

    if (real_func)
    {
        real_func(ssl);
    }
}

/**
 * mbedTLS: Intercept mbedtls_ssl_config_free - Clean up callback tracking
 */
void mbedtls_ssl_config_free(mbedtls_ssl_config *conf)
{
    if (conf)
    {
        printf("[RA-TLS SO] Intercepted mbedtls_ssl_config_free, cleaning up callback tracking\n");
        remove_mbedtls_callback(conf);
    }

    /* Resolve real function per-call using RTLD_NEXT */
    void (*real_func)(mbedtls_ssl_config *);
    real_func = dlsym(RTLD_NEXT, "mbedtls_ssl_config_free");

    if (real_func)
    {
        real_func(conf);
    }
}

/**
 * mbedTLS: Intercept mbedtls_ssl_free - Clean up callback tracking
 */
void mbedtls_ssl_free(mbedtls_ssl_context *ssl)
{
    if (ssl)
    {
        printf("[RA-TLS SO] Intercepted mbedtls_ssl_free\n");
        /* Note: mbedtls_ssl doesn't have separate callback tracking */
    }

    /* Resolve real function per-call using RTLD_NEXT */
    void (*real_func)(mbedtls_ssl_context *);
    real_func = dlsym(RTLD_NEXT, "mbedtls_ssl_free");

    if (real_func)
    {
        real_func(ssl);
    }
}

/**
 * wolfSSL: Intercept wolfSSL_CTX_free - Clean up callback tracking
 */
void wolfSSL_CTX_free(void *ctx)
{
    if (ctx)
    {
        printf("[RA-TLS SO] Intercepted wolfSSL_CTX_free, cleaning up callback tracking\n");
        remove_wolfssl_ctx_callback(ctx);
    }

    /* Resolve real function per-call using RTLD_NEXT */
    void (*real_func)(void *);
    real_func = dlsym(RTLD_NEXT, "wolfSSL_CTX_free");

    if (real_func)
    {
        real_func(ctx);
    }
}

/**
 * wolfSSL: Intercept wolfSSL_free - Clean up callback tracking
 */
void wolfSSL_free(void *ssl)
{
    if (ssl)
    {
        printf("[RA-TLS SO] Intercepted wolfSSL_free, cleaning up callback tracking\n");
        remove_wolfssl_ssl_callback(ssl);
    }

    /* Resolve real function per-call using RTLD_NEXT */
    void (*real_func)(void *);
    real_func = dlsym(RTLD_NEXT, "wolfSSL_free");

    if (real_func)
    {
        real_func(ssl);
    }
}

/**
 * Intercept dlopen to detect when new TLS libraries are loaded
 * Note: Wrappers resolve per-call using RTLD_NEXT, so no action needed beyond logging
 */
void *dlopen(const char *filename, int flags)
{
    if (!real_dlopen)
    {
        real_dlopen = dlsym(RTLD_NEXT, "dlopen");
        if (!real_dlopen)
        {
            fprintf(stderr, "[RA-TLS SO] Failed to resolve real dlopen\n");
            return NULL;
        }
    }

    void *handle = real_dlopen(filename, flags);

    if (handle)
    {
        /* Register handle in our registry for reference counting */
        register_handle(handle, filename);

        if (filename)
        {
            /* Log TLS library loads for observability */
            if (strstr(filename, "libssl") || strstr(filename, "libcrypto"))
            {
                printf("[RA-TLS SO] Detected OpenSSL library load: %s\n", filename);
            }
            else if (strstr(filename, "libwolfssl"))
            {
                printf("[RA-TLS SO] Detected wolfSSL library load: %s\n", filename);
            }
            else if (strstr(filename, "libmbedtls") || strstr(filename, "libmbedx509"))
            {
                printf("[RA-TLS SO] Detected mbedTLS library load: %s\n", filename);
            }
        }
    }

    return handle;
}

/**
 * Intercept dlmopen to detect when new TLS libraries are loaded
 * Note: Wrappers resolve per-call using RTLD_NEXT, so no action needed beyond logging
 */
void *dlmopen(long lmid, const char *filename, int flags)
{
    if (!real_dlmopen)
    {
        real_dlmopen = dlsym(RTLD_NEXT, "dlmopen");
        if (!real_dlmopen)
        {
            fprintf(stderr, "[RA-TLS SO] Failed to resolve real dlmopen\n");
            return NULL;
        }
    }

    void *handle = real_dlmopen(lmid, filename, flags);

    if (handle)
    {
        /* Register handle in our registry for reference counting */
        register_handle(handle, filename);

        if (filename)
        {
            /* Log TLS library loads for observability */
            if (strstr(filename, "libssl") || strstr(filename, "libcrypto"))
            {
                printf("[RA-TLS SO] Detected OpenSSL library load via dlmopen: %s\n", filename);
            }
            else if (strstr(filename, "libwolfssl"))
            {
                printf("[RA-TLS SO] Detected wolfSSL library load via dlmopen: %s\n", filename);
            }
            else if (strstr(filename, "libmbedtls") || strstr(filename, "libmbedx509"))
            {
                printf("[RA-TLS SO] Detected mbedTLS library load via dlmopen: %s\n", filename);
            }
        }
    }

    return handle;
}

/**
 * Register a handle in the handle registry
 * Returns 1 on success, 0 on failure
 */
static int register_handle(void *handle, const char *path)
{
    if (!handle)
        return 0;

    pthread_mutex_lock(&g_handle_registry_mutex);

    /* Check if handle already exists - increment refcount */
    for (size_t i = 0; i < g_handle_count; i++)
    {
        if (g_handle_registry[i].handle == handle)
        {
            g_handle_registry[i].refcount++;
            pthread_mutex_unlock(&g_handle_registry_mutex);
            return 1;
        }
    }

    /* Add new entry */
    if (g_handle_count >= MAX_HANDLE_ENTRIES)
    {
        fprintf(stderr, "[RA-TLS SO] Handle registry full, cannot register handle\n");
        pthread_mutex_unlock(&g_handle_registry_mutex);
        return 0;
    }

    handle_registry_entry_t *entry = &g_handle_registry[g_handle_count];
    entry->handle = handle;
    entry->refcount = 1;

    /* Store path (canonicalize if possible) */
    if (path)
    {
        char *resolved = realpath(path, NULL);
        if (resolved)
        {
            strncpy(entry->path, resolved, sizeof(entry->path) - 1);
            entry->path[sizeof(entry->path) - 1] = '\0';
            free(resolved);
        }
        else
        {
            strncpy(entry->path, path, sizeof(entry->path) - 1);
            entry->path[sizeof(entry->path) - 1] = '\0';
        }
    }
    else
    {
        entry->path[0] = '\0';
    }

    /* Detect TLS provider by probing symbols */
    entry->is_openssl = (dlsym(handle, "SSL_CTX_set_verify") != NULL);
    entry->is_mbedtls = (dlsym(handle, "mbedtls_ssl_conf_verify") != NULL);
    entry->is_wolfssl = (dlsym(handle, "wolfSSL_CTX_set_verify") != NULL);

    g_handle_count++;

    pthread_mutex_unlock(&g_handle_registry_mutex);
    return 1;
}

/**
 * Decrement refcount for a handle and return the entry if refcount reaches 0
 * Returns pointer to entry if this is the last reference, NULL otherwise
 * Caller must hold g_handle_registry_mutex
 */
static handle_registry_entry_t *decrement_handle_refcount_locked(void *handle)
{
    for (size_t i = 0; i < g_handle_count; i++)
    {
        if (g_handle_registry[i].handle == handle)
        {
            g_handle_registry[i].refcount--;
            if (g_handle_registry[i].refcount <= 0)
            {
                /* Return pointer to entry - caller will use it then remove it */
                return &g_handle_registry[i];
            }
            return NULL; /* Still has references */
        }
    }
    return NULL; /* Handle not found */
}

/**
 * Remove a handle from the registry
 * Caller must hold g_handle_registry_mutex
 */
static void remove_handle_locked(void *handle)
{
    for (size_t i = 0; i < g_handle_count; i++)
    {
        if (g_handle_registry[i].handle == handle)
        {
            /* Remove by shifting remaining entries */
            memmove(&g_handle_registry[i], &g_handle_registry[i + 1],
                    (g_handle_count - i - 1) * sizeof(handle_registry_entry_t));
            g_handle_count--;
            return;
        }
    }
}

/**
 * Cleanup callback maps when a TLS provider SO is being unloaded
 */
static void cleanup_callbacks_for_unloaded_so(const char *so_path)
{
    if (!so_path)
        return;

    int cleaned_openssl_ctx = 0, cleaned_openssl_ssl = 0;
    int cleaned_mbedtls = 0;
    int cleaned_wolfssl_ctx = 0, cleaned_wolfssl_ssl = 0;

    /* Check if this is an OpenSSL library */
    if (strstr(so_path, "libssl") || strstr(so_path, "libcrypto"))
    {
        pthread_mutex_lock(&g_openssl_callback_mutex);
        /* Clear all OpenSSL callback entries - contexts will be invalid after unload */
        cleaned_openssl_ctx = g_openssl_ctx_count;
        cleaned_openssl_ssl = g_openssl_ssl_count;
        g_openssl_ctx_count = 0;
        g_openssl_ssl_count = 0;
        memset(g_openssl_ctx_callbacks, 0, sizeof(g_openssl_ctx_callbacks));
        memset(g_openssl_ssl_callbacks, 0, sizeof(g_openssl_ssl_callbacks));
        pthread_mutex_unlock(&g_openssl_callback_mutex);
    }

    /* Check if this is a wolfSSL library */
    if (strstr(so_path, "libwolfssl"))
    {
        pthread_mutex_lock(&g_wolfssl_callback_mutex);
        /* Clear all wolfSSL callback entries */
        cleaned_wolfssl_ctx = g_wolfssl_ctx_count;
        cleaned_wolfssl_ssl = g_wolfssl_ssl_count;
        g_wolfssl_ctx_count = 0;
        g_wolfssl_ssl_count = 0;
        memset(g_wolfssl_ctx_callbacks, 0, sizeof(g_wolfssl_ctx_callbacks));
        memset(g_wolfssl_ssl_callbacks, 0, sizeof(g_wolfssl_ssl_callbacks));
        pthread_mutex_unlock(&g_wolfssl_callback_mutex);
    }

    /* Check if this is a mbedTLS library */
    if (strstr(so_path, "libmbedtls") || strstr(so_path, "libmbedx509"))
    {
        pthread_mutex_lock(&g_mbedtls_callback_mutex);
        /* Clear all mbedTLS callback entries */
        cleaned_mbedtls = g_mbedtls_count;
        g_mbedtls_count = 0;
        memset(g_mbedtls_callbacks, 0, sizeof(g_mbedtls_callbacks));
        pthread_mutex_unlock(&g_mbedtls_callback_mutex);
    }

    /* Log cleanup results */
    if (cleaned_openssl_ctx || cleaned_openssl_ssl)
    {
        printf("[RA-TLS SO] Cleaned up %d OpenSSL CTX and %d SSL callback entries for unloading: %s\n",
               cleaned_openssl_ctx, cleaned_openssl_ssl, so_path);
    }
    if (cleaned_wolfssl_ctx || cleaned_wolfssl_ssl)
    {
        printf("[RA-TLS SO] Cleaned up %d wolfSSL CTX and %d SSL callback entries for unloading: %s\n",
               cleaned_wolfssl_ctx, cleaned_wolfssl_ssl, so_path);
    }
    if (cleaned_mbedtls)
    {
        printf("[RA-TLS SO] Cleaned up %d mbedTLS callback entries for unloading: %s\n",
               cleaned_mbedtls, so_path);
    }
}

/**
 * Cleanup callback entries whose user callback function pointers belong to the SO being unloaded
 */
static void cleanup_callbacks_by_provenance(const char *so_path)
{
    if (!so_path)
        return;

    int removed_count = 0;
    Dl_info info;

    /* Check OpenSSL CTX callbacks */
    pthread_mutex_lock(&g_openssl_callback_mutex);
    for (size_t i = 0; i < g_openssl_ctx_count;)
    {
        if (g_openssl_ctx_callbacks[i].verify_callback)
        {
            if (dladdr((void *)g_openssl_ctx_callbacks[i].verify_callback, &info) != 0)
            {
                if (info.dli_fname && strcmp(info.dli_fname, so_path) == 0)
                {
                    /* This callback belongs to the SO being unloaded - remove it */
                    memmove(&g_openssl_ctx_callbacks[i], &g_openssl_ctx_callbacks[i + 1],
                            (g_openssl_ctx_count - i - 1) * sizeof(openssl_callback_entry_t));
                    g_openssl_ctx_count--;
                    removed_count++;
                    continue; /* Don't increment i */
                }
            }
        }
        i++;
    }
    pthread_mutex_unlock(&g_openssl_callback_mutex);

    /* Check OpenSSL SSL callbacks */
    pthread_mutex_lock(&g_openssl_callback_mutex);
    for (size_t i = 0; i < g_openssl_ssl_count;)
    {
        if (g_openssl_ssl_callbacks[i].verify_callback)
        {
            if (dladdr((void *)g_openssl_ssl_callbacks[i].verify_callback, &info) != 0)
            {
                if (info.dli_fname && strcmp(info.dli_fname, so_path) == 0)
                {
                    memmove(&g_openssl_ssl_callbacks[i], &g_openssl_ssl_callbacks[i + 1],
                            (g_openssl_ssl_count - i - 1) * sizeof(openssl_callback_entry_t));
                    g_openssl_ssl_count--;
                    removed_count++;
                    continue;
                }
            }
        }
        i++;
    }
    pthread_mutex_unlock(&g_openssl_callback_mutex);

    /* Check mbedTLS callbacks */
    pthread_mutex_lock(&g_mbedtls_callback_mutex);
    for (size_t i = 0; i < g_mbedtls_count;)
    {
        if (g_mbedtls_callbacks[i].verify_callback)
        {
            if (dladdr((void *)g_mbedtls_callbacks[i].verify_callback, &info) != 0)
            {
                if (info.dli_fname && strcmp(info.dli_fname, so_path) == 0)
                {
                    memmove(&g_mbedtls_callbacks[i], &g_mbedtls_callbacks[i + 1],
                            (g_mbedtls_count - i - 1) * sizeof(mbedtls_callback_entry_t));
                    g_mbedtls_count--;
                    removed_count++;
                    continue;
                }
            }
        }
        i++;
    }
    pthread_mutex_unlock(&g_mbedtls_callback_mutex);

    /* Check wolfSSL CTX callbacks */
    pthread_mutex_lock(&g_wolfssl_callback_mutex);
    for (size_t i = 0; i < g_wolfssl_ctx_count;)
    {
        if (g_wolfssl_ctx_callbacks[i].verify_callback)
        {
            if (dladdr((void *)g_wolfssl_ctx_callbacks[i].verify_callback, &info) != 0)
            {
                if (info.dli_fname && strcmp(info.dli_fname, so_path) == 0)
                {
                    memmove(&g_wolfssl_ctx_callbacks[i], &g_wolfssl_ctx_callbacks[i + 1],
                            (g_wolfssl_ctx_count - i - 1) * sizeof(wolfssl_callback_entry_t));
                    g_wolfssl_ctx_count--;
                    removed_count++;
                    continue;
                }
            }
        }
        i++;
    }
    pthread_mutex_unlock(&g_wolfssl_callback_mutex);

    /* Check wolfSSL SSL callbacks */
    pthread_mutex_lock(&g_wolfssl_callback_mutex);
    for (size_t i = 0; i < g_wolfssl_ssl_count;)
    {
        if (g_wolfssl_ssl_callbacks[i].verify_callback)
        {
            if (dladdr((void *)g_wolfssl_ssl_callbacks[i].verify_callback, &info) != 0)
            {
                if (info.dli_fname && strcmp(info.dli_fname, so_path) == 0)
                {
                    memmove(&g_wolfssl_ssl_callbacks[i], &g_wolfssl_ssl_callbacks[i + 1],
                            (g_wolfssl_ssl_count - i - 1) * sizeof(wolfssl_callback_entry_t));
                    g_wolfssl_ssl_count--;
                    removed_count++;
                    continue;
                }
            }
        }
        i++;
    }
    pthread_mutex_unlock(&g_wolfssl_callback_mutex);

    if (removed_count > 0)
    {
        printf("[RA-TLS SO] Removed %d callback entries with user callbacks from unloading SO: %s\n",
               removed_count, so_path);
    }
}

/**
 * Intercept dlclose to cleanup callback maps when SOs are unloaded
 * Only performs cleanup when the reference count reaches 0 (actual unload)
 */
int dlclose(void *handle)
{
    if (!real_dlclose)
    {
        real_dlclose = dlsym(RTLD_NEXT, "dlclose");
        if (!real_dlclose)
        {
            fprintf(stderr, "[RA-TLS SO] Failed to resolve real dlclose\n");
            return -1;
        }
    }

    if (!handle)
    {
        return real_dlclose(handle);
    }

    /* Decrement refcount and check if this is the last reference */
    pthread_mutex_lock(&g_handle_registry_mutex);

    handle_registry_entry_t *entry = decrement_handle_refcount_locked(handle);

    if (entry)
    {
        /* This is the last reference - SO will actually be unloaded */
        /* Save path and provider flags before we remove the entry */
        char so_path[PATH_MAX];
        strncpy(so_path, entry->path, sizeof(so_path) - 1);
        so_path[sizeof(so_path) - 1] = '\0';

        int is_openssl = entry->is_openssl;
        int is_mbedtls = entry->is_mbedtls;
        int is_wolfssl = entry->is_wolfssl;

        /* If we don't have a path from registry, try dlinfo as fallback */
        if (so_path[0] == '\0')
        {
#ifdef RTLD_DI_LINKMAP
            struct link_map *map = NULL;
            if (dlinfo(handle, RTLD_DI_LINKMAP, &map) == 0 && map && map->l_name)
            {
                strncpy(so_path, map->l_name, sizeof(so_path) - 1);
                so_path[sizeof(so_path) - 1] = '\0';
            }
#endif
        }

        /* Remove from registry before cleanup (we've saved the data we need) */
        remove_handle_locked(handle);

        pthread_mutex_unlock(&g_handle_registry_mutex);

        /* Perform cleanup BEFORE calling real dlclose */
        if (so_path[0] != '\0')
        {
            /* Cleanup callback maps for TLS provider SOs */
            cleanup_callbacks_for_unloaded_so(so_path);

            /* Cleanup callback entries whose user callbacks belong to this SO */
            cleanup_callbacks_by_provenance(so_path);
        }
        else if (is_openssl || is_mbedtls || is_wolfssl)
        {
            /* We detected it's a TLS provider but don't have path - clear all maps for that provider */
            printf("[RA-TLS SO] Cleaning up TLS provider (path unknown) - OpenSSL:%d mbedTLS:%d wolfSSL:%d\n",
                   is_openssl, is_mbedtls, is_wolfssl);

            if (is_openssl)
            {
                pthread_mutex_lock(&g_openssl_callback_mutex);
                g_openssl_ctx_count = 0;
                g_openssl_ssl_count = 0;
                memset(g_openssl_ctx_callbacks, 0, sizeof(g_openssl_ctx_callbacks));
                memset(g_openssl_ssl_callbacks, 0, sizeof(g_openssl_ssl_callbacks));
                pthread_mutex_unlock(&g_openssl_callback_mutex);
            }

            if (is_mbedtls)
            {
                pthread_mutex_lock(&g_mbedtls_callback_mutex);
                g_mbedtls_count = 0;
                memset(g_mbedtls_callbacks, 0, sizeof(g_mbedtls_callbacks));
                pthread_mutex_unlock(&g_mbedtls_callback_mutex);
            }

            if (is_wolfssl)
            {
                pthread_mutex_lock(&g_wolfssl_callback_mutex);
                g_wolfssl_ctx_count = 0;
                g_wolfssl_ssl_count = 0;
                memset(g_wolfssl_ctx_callbacks, 0, sizeof(g_wolfssl_ctx_callbacks));
                memset(g_wolfssl_ssl_callbacks, 0, sizeof(g_wolfssl_ssl_callbacks));
                pthread_mutex_unlock(&g_wolfssl_callback_mutex);
            }
        }
    }
    else
    {
        /* Still has references or handle not in registry - no cleanup needed */
        pthread_mutex_unlock(&g_handle_registry_mutex);
    }

    /* Now call the real dlclose */
    return real_dlclose(handle);
}

/**
 * Constructor: Initialize the SO library
 */
__attribute__((constructor)) static void ratls_quota_init(void)
{
    printf("[RA-TLS SO] Initializing RA-TLS Quota Verification Library (v6)\n");

    /* Note: RATLS_ENABLE_VERIFY and RATLS_REQUIRE_PEER_CERT are read in real-time */
    /* This allows dynamic configuration changes at runtime */

    /* Initialize RA-TLS verification library */
    pthread_once(&g_init_once, init_ratls_verify);

    if (!g_ratls_verify_initialized)
    {
        fprintf(stderr, "[RA-TLS SO] Failed to initialize RA-TLS verification, exiting\n");
        exit(1);
    }

    /* Generate RA-TLS credentials */
    int ret = generate_ratls_credentials();
    if (ret < 0)
    {
        fprintf(stderr, "[RA-TLS SO] Failed to generate RA-TLS credentials,%d\n", ret);
        exit(ret);
    }


    printf("[RA-TLS SO] Initialization complete\n");
}
