//
// Created by HISONA on 2016. 2. 29..
//

#ifndef HTTPS_CLIENT_HTTPS_H
#define HTTPS_CLIENT_HTTPS_H

/*---------------------------------------------------------------------*/

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <errno.h>
#include <limits.h>

#define USE_STDLIB
#include "api.h"
#include "pal_error.h"
#include "pal.h"

// #include <netinet/in.h>

// #include "linux_socket.h"

#include "mbedtls/config-pal.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include "mbedtls/pkcs12.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crl.h"
#include "mbedtls/base64.h"
#include "mbedtls/sha256.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include <mbedtls/platform.h>

/*---------------------------------------------------------------------*/
#define URI_MAX         4096

#define H_FIELD_SIZE    1024
#define H_READ_SIZE     2048

#undef TRUE
#undef FALSE

#define TRUE    1
#define FALSE   0

typedef unsigned char BOOL;

typedef struct
{
    char method[8];
    int  status;
    char content_type[H_FIELD_SIZE];
    long content_length;
    BOOL chunked;
    BOOL close;
    char location[H_FIELD_SIZE];
    char referrer[H_FIELD_SIZE];
    char cookie[H_FIELD_SIZE];
    char boundary[H_FIELD_SIZE];
    char ext_headers[H_FIELD_SIZE];

} HTTP_HEADER;

typedef struct
{
    BOOL    verify;

    PAL_HANDLE                  handle_ssl_fd;
    mbedtls_entropy_context     entropy;
    mbedtls_ctr_drbg_context    ctr_drbg;
    mbedtls_ssl_context         ssl;
    mbedtls_ssl_config          conf;
    mbedtls_x509_crt            cacert;

} HTTP_SSL;

typedef struct {

    BOOL    https;
    BOOL    resolved;
    char    host[256];
    char    ipaddr[256];
    char    port[8];
    char    path[H_FIELD_SIZE];

} HTTP_URL;

typedef struct
{
    BOOL        initialized;
    HTTP_URL    url;

    HTTP_HEADER request;
    HTTP_HEADER response;
    HTTP_SSL    tls;

    long        length;
    char        r_buf[H_READ_SIZE];
    long        r_len;
    BOOL        header_end;
    char        *body;
    long        body_size;
    long        body_len;


} HTTP_INFO;


/*---------------------------------------------------------------------*/

char *strtoken(char *src, char *dst, int size);
int strncasecmp(const char* s1, const char* s2, size_t n);

int  http_init(HTTP_INFO *hi, BOOL verify);
int  http_close(HTTP_INFO *hi);
int  http_get(HTTP_INFO *hi, const char *ipaddr, const char *url, char *response, int size, const char *cacerts_buf, size_t cacerts_bufsz);
int  http_post(HTTP_INFO *hi, const char *ipaddr, char *url, char *data, char *response, int size, const char *cacerts_buf, size_t cacerts_bufsz);

void http_strerror(char *buf, int len);
int  http_open(HTTP_INFO *hi, const char *ipaddr, char *url, const char *cacerts_buf, size_t cacerts_bufsz);
int  http_write_header(HTTP_INFO *hi);
int  http_write(HTTP_INFO *hi, char *data, int len);
int  http_write_end(HTTP_INFO *hi);
int  http_read_chunked(HTTP_INFO *hi, char *response, int size);
int  parse_url(const char *ipaddr, char *src_url, HTTP_URL *urlinfo);

int inet_pton4(const char* src, size_t len, void* dst);

#endif //HTTPS_CLIENT_HTTPS_H

