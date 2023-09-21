//
// Created by HISONA on 2016. 2. 29..
//

/*
 * The code has been modified to
 * make it workable with Gramine LibOS
 * 
 */

#include "https.h"
#include "log.h"
#include "mbedtls/ssl.h"
#include "pal_error.h"
#include "socket_utils.h"

/*---------------------------------------------------------------------*/
static int _error;

/*---------------------------------------------------------------------*/
// static void my_debug( void *ctx, int level,
//                       const char *file, int line,
//                       const char *str );

char* strstr_alt(const char* string, const char* substring);
int strncasecmp(const char* s1, const char* s2, size_t n);
// char* strncpy (char *s1, const char *s2, size_t n);
char* strncpy(char* __restrict dst, const char* __restrict src, size_t maxlen);
char* strtoken(char *src, char *dst, int size);

static int send_cb(void* hdl, uint8_t const* buf, size_t buf_size);
static int recv_cb(void* hdl, uint8_t* buf, size_t buf_size);
static void mbedtls_pal_disconnect(HTTP_INFO *hi);
static int http_header(HTTP_INFO *hi, char *param);
static int http_parse(HTTP_INFO *hi);

static int https_init(HTTP_INFO *hi, BOOL https, BOOL verify);
static int https_close(HTTP_INFO *hi);
static int https_connect(HTTP_INFO *hi, HTTP_URL const *urlinfo, const char *cacerts_buf, size_t cacerts_bufsz);
static int https_write(HTTP_INFO *hi, const char *buffer, int len);
static int https_read(HTTP_INFO *hi, char *buffer, int len);

/*---------------------------------------------------------------------------*/



static int recv_cb(void* hdl, unsigned char* buf, size_t buf_size) {
    log_debug("******* recv_cb: %ld", buf_size);
    PAL_HANDLE hdl_ssl_fd = *(PAL_HANDLE*)hdl;
    if (!hdl_ssl_fd)
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;

    size_t sz = 0;
    if (sz > INT_MAX) {
        /* pal_recv_cb cannot receive more than 32-bit limit, trim buf_size to fit in 32-bit */
        sz = INT_MAX;
    }
    log_debug("recv_cb: %ld", sz);

    struct iovec iov = {
                    .iov_base = (void*)buf,
                    .iov_len = buf_size,
                };
    int ret = PalSocketRecv(hdl_ssl_fd, &iov, 1, &sz,
                           /*addr=*/NULL, /*force_nonblocking=*/false);

    // int ret = PalStreamRead(hdl_ssl_fd, 0, &sz, (void*)buf);
    if (ret < 0) {
        if (ret == -EINTR || ret == -EAGAIN || ret == -EWOULDBLOCK)
            return MBEDTLS_ERR_SSL_WANT_READ;
        if (ret == -EPIPE)
            return MBEDTLS_ERR_NET_CONN_RESET;
        log_debug("FAIL recv_cb: %d", ret);
        return MBEDTLS_ERR_NET_RECV_FAILED;
    }
    log_debug("recv_cb read count: %ld", sz);
    return sz;
}

static int send_cb(void* hdl, const unsigned char* buf, size_t buf_size) {
    log_debug("*****  send_cb: %ld", buf_size);
    PAL_HANDLE hdl_ssl_fd = *(PAL_HANDLE*)hdl;
    if (!hdl_ssl_fd)
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;

    size_t sz = 0;
    if (sz > INT_MAX) {
        /* pal_send_cb cannot send more than 32-bit limit, trim buf_size to fit in 32-bit */
        sz = INT_MAX;
    }
    log_debug("send_cb: %ld", buf_size);
    struct iovec iov = {
        .iov_base = (void*)buf,
        .iov_len = buf_size,
    };
    int ret = PalSocketSend(hdl_ssl_fd, &iov, 1, &sz,
                            /*addr=*/NULL, /*force_nonblocking=*/false);
    // int ret = PalStreamWrite(hdl_ssl_fd, 0, &sz, (void*)buf);
    if (ret < 0) {
        if (ret == -EINTR || ret == -EAGAIN || ret == -EWOULDBLOCK)
            return MBEDTLS_ERR_SSL_WANT_WRITE;
        if (ret == -EPIPE)
            return MBEDTLS_ERR_NET_CONN_RESET;
        log_debug("FAIL send_cb: %d", ret);
        return MBEDTLS_ERR_NET_SEND_FAILED;
    }
    log_debug("send_cb count: %ld", sz);
    return sz;
}

char* strstr_alt(const char* string, const char* substring)
{
	const char *a, *b;

	/* First scan quickly through the two strings looking for a
	 * single-character match.  When it's found, then compare the
	 * rest of the substring.
	 */

	b = substring;

	if(*b == 0)
	{
		return (char*)string;
	}
    log_debug("strstr_alt: %s, %s", string, substring);
	for(; *string != 0; string += 1)
	{
		if(*string != *b)
		{
			continue;
		}

		a = string;
        log_debug("strstr_alt(2): %s, %s", string, substring);
		while(1)
		{
			if(*b == 0)
			{
                log_debug("strstr_alt(3.0): %s, %s", string, substring);
				return (char*)string;
			}
            log_debug("strstr_alt(3): %s, %s", string, substring);
			if(*a++ != *b++)
			{
				break;
			}
		}

		b = substring;
	}
    log_debug("strstr_alt(4): %s, %s", string, substring);
	return NULL;
}

int strncasecmp(const char* s1, const char* s2, size_t n)
{
    if (n == 0)
        return 0;

    while (n-- != 0 && tolower(*s1) == tolower(*s2)) {
        if (n == 0 || *s1 == '\0' || *s2 == '\0')
            break;
        s1++;
        s2++;
    }

    return tolower(*(unsigned char*)s1) - tolower(*(unsigned char*)s2);
}

// char* strncpy (char *s1, const char *s2, size_t n)
// {
//   size_t size = strlen (s2);
//   if (size != n)
//     memset (s1 + size, '\0', n - size);
//   return memcpy (s1, s2, size);
// }

char* strncpy(char* __restrict dst, const char* __restrict src, size_t maxlen)
{
	const size_t srclen = strnlen(src, maxlen);
	if(srclen < maxlen)
	{
		//  The stpncpy() and strncpy() functions copy at most maxlen
		//  characters from src into dst.
		memcpy(dst, src, srclen);
		//  If src is less than maxlen characters long, the remainder
		//  of dst is filled with '\0' characters.
		memset(dst + srclen, 0, maxlen - srclen);
	}
	else
	{
		//  Otherwise, dst is not terminated.
		memcpy(dst, src, maxlen);
	}
	//  The strcpy() and strncpy() functions return dst.
	return dst;
}

char* strtoken(char *src, char *dst, int size)
{
    char *p, *st, *ed;
    int  len = 0;

    // l-trim
    p = src;

    while(TRUE)
    {
        if((*p == '\n') || (*p == 0)) return NULL; /* value is not exists */
        if((*p != ' ') && (*p != '\t')) break;
        p++;
    }

    st = p;
    while(TRUE)
    {
        ed = p;
        if(*p == ' ') {
            p++;
            break;
        }
        if((*p == '\n') || (*p == 0)) break;
        p++;
    }

    // r-trim
    while(TRUE)
    {
        ed--;
        if(st == ed) break;
        if((*ed != ' ') && (*ed != '\t')) break;
    }

    len = (int)(ed - st + 1);
    if((size > 0) && (len >= size)) len = size - 1;

    strncpy(dst, st, len);
    dst[len]=0;

    return p;
}

/*---------------------------------------------------------------------*/
int parse_url(const char *ipaddr, char *src_url, HTTP_URL *urlinfo)
{
    char *p1, *p2;
    size_t str_sz = 1024;
    char str[str_sz];
    urlinfo->resolved = 0;

    if (ipaddr && strncpy(urlinfo->ipaddr, ipaddr, sizeof(urlinfo->ipaddr))) {
        urlinfo->resolved = 1;
    }

    memset(str, 0, str_sz);
    log_debug("parse_url: src_url: %s", src_url);
    if(strncmp(src_url, "http://", 7)==0) {
        p1=&src_url[7];
        urlinfo->https = 0;
        snprintf(urlinfo->port, 5, "80");
    } else if(strncmp(src_url, "https://", 8)==0) {
        p1=&src_url[8];
        urlinfo->https = 1;
        snprintf(urlinfo->port, 5, "443");
    } else {
        p1 = &src_url[0];
        urlinfo->https = 0;
        snprintf(urlinfo->port, 5, "80");
    }
    log_debug("parse_url <%d, %s>:2", urlinfo->https, p1);
    if((p2=strstr_alt(p1, "/")) == NULL) {
        snprintf(str, str_sz, "%s", p1);
        snprintf(urlinfo->path, sizeof(urlinfo->path), "/");
    } else {
        log_debug("parse_url <%s, %s>:3", p2, p1);
        strncpy(str, p1, p2-p1);
        log_debug("parse_url <%s, %s>:4", str, p1);
        snprintf(urlinfo->path, sizeof(urlinfo->path), "%s", p2);
    }
    if((p1=strstr_alt(str, ":")) != NULL) {
        *p1=0;
        snprintf(urlinfo->host, sizeof(urlinfo->host), "%s", str);
        snprintf(urlinfo->port, sizeof(urlinfo->port), "%s", p1+1);
    } else {
        snprintf(urlinfo->host, sizeof(urlinfo->host), "%s", str);
    }
    log_debug("PARSE URL: host:%s, port:%s, path:%s", urlinfo->host, urlinfo->port, urlinfo->path);
    return 0;
}

/*---------------------------------------------------------------------*/
static int http_header(HTTP_INFO *hi, char *param)
{
    char *token;
    char t1[256], t2[256];
    int  len;

    token = param;

    if((token=strtoken(token, t1, 256)) == 0) return -1;
    if((token=strtoken(token, t2, 256)) == 0) return -1;

    if(strncasecmp(t1, "HTTP", 4) == 0)
    {
        hi->response.status = atoi(t2);
    }
    else if(strncasecmp(t1, "set-cookie:", 11) == 0)
    {
        snprintf(hi->response.cookie, 512, "%s", t2);
    }
    else if(strncasecmp(t1, "location:", 9) == 0)
    {
        len = (int)strlen(t2);
        strncpy(hi->response.location, t2, len);
        hi->response.location[len] = 0;
    }
    else if(strncasecmp(t1, "content-length:", 15) == 0)
    {
        hi->response.content_length = atoi(t2);
    }
    else if(strncasecmp(t1, "transfer-encoding:", 18) == 0)
    {
        if(strncasecmp(t2, "chunked", 7) == 0)
        {
            hi->response.chunked = TRUE;
        }
    }
    else if(strncasecmp(t1, "connection:", 11) == 0)
    {
        if(strncasecmp(t2, "close", 5) == 0)
        {
            hi->response.close = TRUE;
        }
    }

    return 1;
}

/*---------------------------------------------------------------------*/
static int http_parse(HTTP_INFO *hi)
{
    char    *p1, *p2;
    long    len;


    if(hi->r_len <= 0) return -1;

    p1 = hi->r_buf;

    while(1)
    {
        if(hi->header_end == FALSE)     // header parser
        {
            if((p2 = strstr_alt(p1, "\r\n")) != NULL)
            {
                len = (long)(p2 - p1);
                *p2 = 0;

                if(len > 0)
                {
                    // printf("header: %s(%ld)\n", p1, len);

                    http_header(hi, p1);
                    p1 = p2 + 2;    // skip CR+LF
                }
                else
                {
                    hi->header_end = TRUE; // reach the header-end.

                    // printf("header_end .... \n");

                    p1 = p2 + 2;    // skip CR+LF

                    if(hi->response.chunked == TRUE)
                    {
                        len = hi->r_len - (p1 - hi->r_buf);
                        if(len > 0)
                        {
                            if((p2 = strstr_alt(p1, "\r\n")) != NULL)
                            {
                                *p2 = 0;

                                if((hi->length = strtol(p1, NULL, 16)) == 0)
                                {
                                    hi->response.chunked = FALSE;
                                }
                                else
                                {
                                    hi->response.content_length += hi->length;
                                }
                                p1 = p2 + 2;    // skip CR+LF
                            }
                            else
                            {
                                // copy the data as chunked size ...
                                strncpy(hi->r_buf, p1, len);
                                hi->r_buf[len] = 0;
                                hi->r_len = len;
                                hi->length = -1;

                                break;
                            }
                        }
                        else
                        {
                            hi->r_len = 0;
                            hi->length = -1;

                            break;
                        }
                    }
                    else
                    {
                        hi->length = hi->response.content_length;
                    }
                }

            }
            else
            {
                len = hi->r_len - (p1 - hi->r_buf);
                if(len  > 0)
                {
                    // keep the partial header data ...
                    strncpy(hi->r_buf, p1, len);
                    hi->r_buf[len] = 0;
                    hi->r_len = len;
                }
                else
                {
                    hi->r_len = 0;
                }

                break;
            }
        }
        else    // body parser ...
        {
            if(hi->response.chunked == TRUE && hi->length == -1)
            {
                len = hi->r_len - (p1 - hi->r_buf);
                if(len > 0)
                {
                    if ((p2 = strstr_alt(p1, "\r\n")) != NULL)
                    {
                        *p2 = 0;

                        if((hi->length = strtol(p1, NULL, 16)) == 0)
                        {
                            hi->response.chunked = FALSE;
                        }
                        else
                        {
                            hi->response.content_length += hi->length;
                        }

                        p1 = p2 + 2;    // skip CR+LF
                    }
                    else
                    {
                        // copy the remain data as chunked size ...
                        strncpy(hi->r_buf, p1, len);
                        hi->r_buf[len] = 0;
                        hi->r_len = len;
                        hi->length = -1;

                        break;
                    }
                }
                else
                {
                    hi->r_len = 0;

                    break;
                }
            }
            else
            {
                if(hi->length > 0)
                {
                    len = hi->r_len - (p1 - hi->r_buf);

                    if(len > hi->length)
                    {
                        // copy the data for response ..
                        if(hi->body_len < hi->body_size-1)
                        {
                            if (hi->body_size > (hi->body_len + hi->length))
                            {
                                strncpy(&(hi->body[hi->body_len]), p1, hi->length);
                                hi->body_len += hi->length;
                                hi->body[hi->body_len] = 0;
                            }
                            else
                            {
                                strncpy(&(hi->body[hi->body_len]), p1, hi->body_size - hi->body_len - 1);
                                hi->body_len = hi->body_size - 1;
                                hi->body[hi->body_len] = 0;
                            }
                        }

                        p1 += hi->length;
                        len -= hi->length;

                        if(hi->response.chunked == TRUE && len >= 2)
                        {
                            p1 += 2;    // skip CR+LF
                            hi->length = -1;
                        }
                        else
                        {
                            return -1;
                        }
                    }
                    else
                    {
                        // copy the data for response ..
                        if(hi->body_len < hi->body_size-1)
                        {
                            if (hi->body_size > (hi->body_len + len))
                            {
                                strncpy(&(hi->body[hi->body_len]), p1, len);
                                hi->body_len += len;
                                hi->body[hi->body_len] = 0;
                            }
                            else
                            {
                                strncpy(&(hi->body[hi->body_len]), p1, hi->body_size - hi->body_len - 1);
                                hi->body_len = hi->body_size - 1;
                                hi->body[hi->body_len] = 0;
                            }
                        }

                        hi->length -= len;
                        hi->r_len = 0;

                        if(hi->response.chunked == FALSE && hi->length <= 0) return 1;

                        break;
                    }
                }
                else
                {
                    if(hi->response.chunked == FALSE) return 1;

                    // chunked size check ..
                    if((hi->r_len > 2) && (memcmp(p1, "\r\n", 2) == 0))
                    {
                        p1 += 2;
                        hi->length = -1;
                    }
                    else
                    {
                        hi->length = -1;
                        hi->r_len = 0;
                    }
                }
            }
        }
    }

    return 0;
}

/*---------------------------------------------------------------------*/
static int https_init(HTTP_INFO *hi, BOOL https, BOOL verify)
{
    memset(hi, 0, sizeof(HTTP_INFO));

    if(https == TRUE)
    {
        mbedtls_ssl_init( &hi->tls.ssl );
        mbedtls_ssl_config_init( &hi->tls.conf );
        mbedtls_x509_crt_init( &hi->tls.cacert );
        mbedtls_ctr_drbg_init( &hi->tls.ctr_drbg );
        hi->initialized = TRUE;
        log_debug("https_init");
    }

    hi->tls.verify = verify;
    hi->url.https = https;

//  printf("https_init ... \n");

    return 0;
}

/*---------------------------------------------------------------------*/
static int https_close(HTTP_INFO *hi)
{
    if (hi->initialized) {
        mbedtls_ssl_close_notify(&hi->tls.ssl);
        mbedtls_pal_disconnect(hi);

        mbedtls_x509_crt_free(&hi->tls.cacert);
        mbedtls_ssl_free(&hi->tls.ssl);
        mbedtls_ssl_config_free(&hi->tls.conf);
        mbedtls_ctr_drbg_free(&hi->tls.ctr_drbg);
        mbedtls_entropy_free(&hi->tls.entropy);

        //  printf("https_close ... \n");
        log_debug("https_close");
    }
    hi->initialized = FALSE;
    return 0;
}

static void mbedtls_pal_disconnect(HTTP_INFO *hi)
{
    if (hi->tls.handle_ssl_fd) {
        PalObjectClose(hi->tls.handle_ssl_fd);
        hi->tls.handle_ssl_fd = NULL;
    }
}

// int __inet_aton(const char *s0, struct in_addr *dest);
// in_addr_t inet_addr(const char *p);

// int __inet_aton(const char *s0, struct in_addr *dest)
// {
//     const char *s = s0;
//     unsigned char *d = (void *)dest;
//     unsigned long a[4] = { 0 };
//     char *z;
//     int i;
 
//     for (i=0; i<4; i++) {
//         a[i] = strtoul(s, &z, 0);
//         if (z==s || (*z && *z != '.') || !isdigit(*s))
//             return 0;
//         if (!*z) break;
//         s=z+1;
//     }
//     if (i==4) return 0;
//     switch (i) {
//     case 0:
//         a[1] = a[0] & 0xffffff;
//         a[0] >>= 24;
//     case 1:
//         a[2] = a[1] & 0xffff;
//         a[1] >>= 16;
//     case 2:
//         a[3] = a[2] & 0xff;
//         a[2] >>= 8;
//     }
//     for (i=0; i<4; i++) {
//         if (a[i] > 255) return 0;
//         d[i] = a[i];
//     }
//     return 1;
// }

// in_addr_t inet_addr(const char *p)
// {
//     struct in_addr a;
//     if (!__inet_aton(p, &a)) return -1;
//     return a.s_addr;
// }

/*
 * Initiate a TCP connection with host:port and the given protocol
 * waiting for timeout (ms)
 */
static int mbedtls_pal_connect(HTTP_INFO *hi, const char *host, const char *port)
{
    __UNUSED(host);

    int ret = -1;
    char uri[URI_MAX];
    snprintf(uri, URI_MAX, "tcp:%s:%s", host, port);
    log_debug("mbedtls_pal_connect: %s", uri);

    mbedtls_pal_disconnect(hi);

    uint32_t haddr = 0xEAEAEAEA;
    if (inet_pton4(host, strlen(host), &haddr) != 1) {
        log_debug("len: %ld, dst: %0x", sizeof(haddr), haddr);
        log_error("%s cannot be parsed correctly", host);
        return -2;
    }

    struct pal_socket_addr addr = {
        .domain = PAL_IPV4,
        .ipv4 = {
            .addr = haddr,
            .port = htons(atoi(port)),
        },
    };

    ret = PalSocketCreate(PAL_IPV4, PAL_SOCKET_TCP, /*options=*/0,
                          &hi->tls.handle_ssl_fd);

    //ret = PalStreamOpen(uri, PAL_ACCESS_RDWR, 0, PAL_CREATE_IGNORED, 0,
                        // &hi->tls.handle_ssl_fd);
    if (ret >= 0 && hi->tls.handle_ssl_fd) {
        ret = 0;
    } else {
        mbedtls_pal_disconnect(hi);
        log_error("PalSocketCreate(...) failed : %d", ret);
        return -3;
    }

    ret = PalSocketConnect(hi->tls.handle_ssl_fd, &addr, /*local_addr=*/NULL);
    if (ret >= 0 && hi->tls.handle_ssl_fd) {
        ret = 0;
    } else {
        mbedtls_pal_disconnect(hi);
        log_error("PalSocketConnect(...) failed : %d", ret);
        return -4;
    }

    return ret;
}

/*---------------------------------------------------------------------*/
/* the TCP connection is established through PAL api */
static int https_connect(HTTP_INFO *hi, HTTP_URL const *urlinfo, const char *cacerts_buf, size_t cacerts_bufsz)
{
    int ret = PAL_ERROR_INVAL, https, actcerts = FALSE;
    char errbuf[256];

    https = hi->url.https;

    if(https == 1)
    {
        if (hi->tls.verify) {
            actcerts = cacerts_buf != NULL && cacerts_bufsz > 0;
            if (!actcerts) {
                log_error("The TLS certificates are not configured correctly");
                return PAL_ERROR_INVAL;
            }
            /*
             * contain either PEM or DER encoded data.
             * A terminating null byte is always appended. It is included in the announced
             * length only if the data looks like it is PEM encoded.
             */
            if (actcerts && strstr(cacerts_buf, "-----BEGIN ") != NULL) {
                // It assumes that a trailing NULL has been accounted by update_buffer(...)
                ++cacerts_bufsz;
            }
            // log_always("----> %ld, %ld", cacerts_bufsz, strlen(cacerts_buf));
        }
        mbedtls_entropy_init( &hi->tls.entropy );

        ret = mbedtls_ctr_drbg_seed( &hi->tls.ctr_drbg, mbedtls_entropy_func, &hi->tls.entropy, NULL, 0);
        if( ret != 0 )
        {
            log_error("mbedtls_ctr_drbg_seed failed: %d", ret);
            return ret;
        }

        // ca_crt_rsa[ca_crt_rsa_size - 1] = 0;
        // ret = mbedtls_x509_crt_parse(&hi->tls.cacert, (uint8_t *)ca_crt_rsa, ca_crt_rsa_size);
        // if( ret != 0 )
        // {
        //     return ret;
        // }

        ret = mbedtls_ssl_config_defaults( &hi->tls.conf,
                                           MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT );
        if( ret != 0 )
        {
            log_error("mbedtls_ssl_config_defaults failed: %d", ret);
            return ret;
        }

        mbedtls_ssl_conf_authmode( &hi->tls.conf, actcerts ? MBEDTLS_SSL_VERIFY_REQUIRED : MBEDTLS_SSL_VERIFY_OPTIONAL);
        if (actcerts) {
            ret = mbedtls_x509_crt_parse(&hi->tls.cacert, (const unsigned char *)cacerts_buf, cacerts_bufsz);
            if (ret == 0)
                log_debug("All certificates were parsed successfully");
            if (ret > 0)
                log_warning("%d certificates that couldn't be parsed", ret);
            if (ret < 0) {
                mbedtls_strerror(ret, errbuf, 256);
                log_error("Parse certs failed with error code %d: %s", ret, errbuf);
                return ret;
            }
            mbedtls_ssl_conf_ca_chain( &hi->tls.conf, &hi->tls.cacert, NULL);
        }
        mbedtls_ssl_conf_rng( &hi->tls.conf, mbedtls_ctr_drbg_random, &hi->tls.ctr_drbg );
        mbedtls_ssl_conf_read_timeout( &hi->tls.conf, 5000 );
 
        ret = mbedtls_ssl_setup( &hi->tls.ssl, &hi->tls.conf );
        if( ret != 0 )
        {
            log_error("mbedtls_ssl_setup failed: %d", ret);
            return ret;
        }

        ret = mbedtls_ssl_set_hostname( &hi->tls.ssl, urlinfo->host );
        if( ret != 0 )
        {
            log_error("mbedtls_ssl_set_hostname failed: %d", ret);
            return ret;
        }
        // log_always("TLS hostname set: %s", urlinfo->host);
        // mbedtls_debug_set_threshold( 5 );
        // mbedtls_ssl_conf_dbg(&hi->tls.conf, my_debug, NULL );
    }

    ret = mbedtls_pal_connect(hi,
                urlinfo->resolved ? urlinfo->ipaddr : urlinfo->host,
                urlinfo->port);
    if( ret != 0 )
    {
        log_error("mbedtls_pal_connect failed: %d", ret);
        return ret;
    }

    mbedtls_ssl_set_bio(&hi->tls.ssl, &hi->tls.handle_ssl_fd, send_cb, recv_cb, NULL);

    while ((ret = mbedtls_ssl_handshake(&hi->tls.ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_strerror(ret, errbuf, 256);
            log_error("mbedtls_ssl_handshake failed with error %d: %s", ret, errbuf);
            if (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
                if (actcerts) {
                    int ret2 = mbedtls_ssl_get_verify_result(&hi->tls.ssl);
                    if (ret2 != 0) {
                        if (ret2 == -1) {
                            log_error("mbedtls_ssl_get_verify_result failed with unknown reasons");
                        } else {
                            log_error("mbedtls_ssl_get_verify_result failed with error code %d", ret2);
                            if (mbedtls_x509_crt_verify_info(errbuf, 256, ">> ", ret2) >= 0)
                                log_error("%s", errbuf);
                            else {
                                log_error("Failed to retrieve verification info");
                            }
                        }
                    }
                }
            }
            return ret;
        }
    }

    return 0;
}

/*---------------------------------------------------------------------*/
static int https_write(HTTP_INFO *hi, const char *buffer, int len)
{
    int ret, slen = 0;

    while(1)
    {
        ret = mbedtls_ssl_write(&hi->tls.ssl, (unsigned char *)&buffer[slen], (size_t)(len-slen));

        if(ret == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
        else if(ret <= 0) return ret;

        slen += ret;

        if(slen >= len) break;
    }

    return slen;
}

/*---------------------------------------------------------------------*/
static int https_read(HTTP_INFO *hi, char *buffer, int len)
{
   return mbedtls_ssl_read(&hi->tls.ssl, (unsigned char *)buffer, (size_t)len);
}

/*---------------------------------------------------------------------*/
int http_init(HTTP_INFO *hi, BOOL verify)
{
    return https_init(hi, TRUE, verify);
}

/*---------------------------------------------------------------------*/
int http_close(HTTP_INFO *hi)
{
    return https_close(hi);
}

/*---------------------------------------------------------------------*/
int http_get(HTTP_INFO *hi, const char *ipaddr, const char *url, char *response, int size, const char *cacerts_buf, size_t cacerts_bufsz)
{
    char        request[1024], err[100];
    HTTP_URL    url_info;
    // int         verify;
    int         ret, len;


    if(NULL == hi) return -1;

    // verify = hi->tls.verify;
    log_debug("http_get: %s", url);
    parse_url(ipaddr, (char*)url, &url_info);
    log_debug("http_get: %d, %s %s %s", url_info.https, url_info.host, url_info.port, url_info.path);
        // https_close(hi);

        // https_init(hi, url_info.https, verify);

        if((ret=https_connect(hi, &url_info, cacerts_buf, cacerts_bufsz)) < 0)
        {
            https_close(hi);

            mbedtls_strerror(ret, err, 100);
            snprintf(response, 256, "socket error: %s(%d)", err, ret);
            log_error("https_connect failed: %d", ret);
            return -1;
        }

    /* Send HTTP request. */
    len = snprintf(request, 1024,
            "GET %s HTTP/1.1\r\n"
            "User-Agent: Ambergra/0.2\r\n"
            "Host: %s\r\n"
            "%s"
            "%s\r\n",
            url_info.path, url_info.host,
            hi->request.ext_headers, hi->request.cookie);

    log_debug("%s", request);

    if((ret = https_write(hi, request, len)) != len)
    {
        https_close(hi);

        mbedtls_strerror(ret, err, 100);

        snprintf(response, 256, "socket error: %s(%d)", err, ret);

        return -1;
    }

//  printf("request: %s \r\n\r\n", request);

    hi->response.status = 0;
    hi->response.content_length = 0;
    hi->response.close = 0;

    hi->r_len = 0;
    hi->header_end = 0;

    hi->body = response;
    hi->body_size = size;
    hi->body_len = 0;

    while(1)
    {
        ret = https_read(hi, &hi->r_buf[hi->r_len], (int)(H_READ_SIZE - hi->r_len));
        if(ret == MBEDTLS_ERR_SSL_WANT_READ) continue;
        else if(ret < 0)
        {
            https_close(hi);

            mbedtls_strerror(ret, err, 100);

            snprintf(response, 256, "socket error: %s(%d)", err, ret);

            return -1;
        }
        else if(ret == 0)
        {
            https_close(hi);
            break;
        }

        hi->r_len += ret;
        hi->r_buf[hi->r_len] = 0;

        // printf("read(%ld): |%s| \n", hi->r_len, hi->r_buf);
        // printf("read(%ld) ... \n", hi->r_len);

        if(http_parse(hi) != 0) break;
    }

    if(hi->response.close == 1)
    {
        https_close(hi);
    }
    else
    {
        strncpy(hi->url.host, url_info.host, strlen(url_info.host));
        strncpy(hi->url.port, url_info.port, strlen(url_info.port));
        strncpy(hi->url.path, url_info.path, strlen(url_info.path));
    }

    /*
    printf("status: %d \n", hi->response.status);
    printf("cookie: %s \n", hi->response.cookie);
    printf("location: %s \n", hi->response.location);
    printf("referrer: %s \n", hi->response.referrer);
    printf("length: %ld \n", hi->response.content_length);
    printf("body: %ld \n", hi->body_len);
    */

    return hi->response.status;

}

/*---------------------------------------------------------------------*/
int http_post(HTTP_INFO *hi, const char *ipaddr, char *url, char *data, char *response, int size, const char *cacerts_buf, size_t cacerts_bufsz)
{
    char*       req_buf = NULL;
    size_t      req_bufsz = 0;
    char        err[100];
    HTTP_URL    url_info;
    // int         verify;
    int         ret, len;

    if(NULL == hi) return -1;

    // verify = hi->tls.verify;

    parse_url(ipaddr, url, &url_info);

        // https_close(hi);

        // https_init(hi, url_info.https, verify);

        if((ret=https_connect(hi, &url_info, cacerts_buf, cacerts_bufsz)) < 0)
        {
            https_close(hi);

            mbedtls_strerror(ret, err, 100);
            snprintf(response, 256, "socket error: %s(%d)", err, ret);

            return -1;
        }

    req_bufsz = strlen(data) + 1024;
    req_buf = calloc(1, req_bufsz);
    if (!req_buf)
        return -ENOMEM;

    /* Send HTTP request. */
    len = snprintf(req_buf, req_bufsz,
            "POST %s HTTP/1.1\r\n"
            "User-Agent: Ambergra/0.2\r\n"
            "Host: %s\r\n"
            "Content-Length: %d\r\n"
            "%s"
            "%s\r\n"
            "%s",
            url_info.path, url_info.host,
            (int)strlen(data),
            hi->request.ext_headers,
            hi->request.cookie,
            data);

    log_debug("%s", req_buf);

    ret = https_write(hi, req_buf, len);
    free(req_buf);
    req_buf = NULL;
    if (ret != len)
    {
        https_close(hi);

        mbedtls_strerror(ret, err, 100);

        snprintf(response, 256, "socket error: %s(%d)", err, ret);

        return -1;
    }

//  printf("request: %s \r\n\r\n", request);

    hi->response.status = 0;
    hi->response.content_length = 0;
    hi->response.close = 0;

    hi->r_len = 0;
    hi->header_end = 0;

    hi->body = response;
    hi->body_size = size;
    hi->body_len = 0;

    hi->body[0] = 0;

    while(1)
    {
        ret = https_read(hi, &hi->r_buf[hi->r_len], (int)(H_READ_SIZE - hi->r_len));
        if(ret == MBEDTLS_ERR_SSL_WANT_READ) continue;
        else if(ret < 0)
        {
            https_close(hi);

            mbedtls_strerror(ret, err, 100);

            snprintf(response, 256, "socket error: %s(%d)", err, ret);

            return -1;
        }
        else if(ret == 0)
        {
            https_close(hi);
            break;
        }

        hi->r_len += ret;
        hi->r_buf[hi->r_len] = 0;

//        printf("read(%ld): %s \n", hi->r_len, hi->r_buf);
//        printf("read(%ld) \n", hi->r_len);

        if(http_parse(hi) != 0) break;
    }

    if(hi->response.close == 1)
    {
        https_close(hi);
    }
    else
    {
        strncpy(hi->url.host, url_info.host, strlen(url_info.host));
        strncpy(hi->url.port, url_info.port, strlen(url_info.port));
        strncpy(hi->url.path, url_info.path, strlen(url_info.path));
    }

/*
    printf("status: %d \n", hi->response.status);
    printf("cookie: %s \n", hi->response.cookie);
    printf("location: %s \n", hi->response.location);
    printf("referrer: %s \n", hi->response.referrer);
    printf("length: %d \n", hi->response.content_length);
    printf("body: %d \n", hi->body_len);
*/

    return hi->response.status;

}

/*---------------------------------------------------------------------*/
void http_strerror(char *buf, int len)
{
    mbedtls_strerror(_error, buf, len);
}

/*---------------------------------------------------------------------*/
int http_open(HTTP_INFO *hi, const char *ipaddr, char *url, const char *cacerts_buf, size_t cacerts_bufsz )
{
    HTTP_URL    urlinfo;
    int         verify;
    int         ret;

    if (NULL == hi) return -1;

    verify = hi->tls.verify;

    parse_url(ipaddr, url, &urlinfo);

        https_close(hi);

        https_init(hi, urlinfo.https, verify);

        if ((ret = https_connect(hi, &urlinfo, cacerts_buf, cacerts_bufsz)) < 0)
        {
            https_close(hi);

            _error = ret;

            return -1;
        }

    strncpy(hi->url.host, urlinfo.host, strlen(urlinfo.host));
    strncpy(hi->url.port, urlinfo.port, strlen(urlinfo.port));
    strncpy(hi->url.path, urlinfo.path, strlen(urlinfo.path));

    return 0;
}

/*---------------------------------------------------------------------*/
int http_write_header(HTTP_INFO *hi)
{
    char        request[4096]/* , buf[H_FIELD_SIZE] */;
    int         ret, len;


    if (NULL == hi) return -1;

    /* Send HTTP request. */
    len = snprintf(request, 1024,
                   "%s %s HTTP/1.1\r\n"
                   "User-Agent: Mozilla/4.0\r\n"
                   "Host: %s:%s\r\n"
                   "Content-Type: %s\r\n",
                   hi->request.method, hi->url.path,
                   hi->url.host, hi->url.port,
                   hi->request.content_type);


    if(hi->request.referrer[0] != 0)
    {
        len += snprintf(&request[len], H_FIELD_SIZE,
                        "Referer: %s\r\n", hi->request.referrer);
    }

    if(hi->request.chunked == TRUE)
    {
        len += snprintf(&request[len], H_FIELD_SIZE,
                        "Transfer-Encoding: chunked\r\n");
    }
    else
    {
        len += snprintf(&request[len], H_FIELD_SIZE,
                        "Content-Length: %ld\r\n", hi->request.content_length);
    }

    if(hi->request.close == TRUE)
    {
        len += snprintf(&request[len], H_FIELD_SIZE,
                        "Connection: close\r\n");
    }
    else
    {
        len += snprintf(&request[len], H_FIELD_SIZE,
                        "Connection: Keep-Alive\r\n");
    }

    if(hi->request.cookie[0] != 0)
    {
        len += snprintf(&request[len], H_FIELD_SIZE,
                        "Cookie: %s\r\n", hi->request.cookie);
    }

    len += snprintf(&request[len], H_FIELD_SIZE, "\r\n");


    // printf("%s", request);

    if ((ret = https_write(hi, request, len)) != len)
    {
        https_close(hi);

        _error = ret;

        return -1;
    }

    return 0;
}

/*---------------------------------------------------------------------*/
int http_write(HTTP_INFO *hi, char *data, int len)
{
    char        str[10];
    int         ret, l;


    if(NULL == hi || len <= 0) return -1;

    if(hi->request.chunked == TRUE)
    {
        l = snprintf(str, 10, "%x\r\n", len);

        if ((ret = https_write(hi, str, l)) != l)
        {
            https_close(hi);
            _error = ret;

            return -1;
        }
    }

    if((ret = https_write(hi, data, len)) != len)
    {
        https_close(hi);
        _error = ret;

        return -1;
    }

    if(hi->request.chunked == TRUE)
    {
        if ((ret = https_write(hi, "\r\n", 2)) != 2)
        {
            https_close(hi);
            _error = ret;

            return -1;
        }
    }

    return len;
}

/*---------------------------------------------------------------------*/
int http_write_end(HTTP_INFO *hi)
{
    char        str[10];
    int         ret, len;

    if (NULL == hi) return -1;

    if(hi->request.chunked == TRUE)
    {
        len = snprintf(str, 10, "0\r\n\r\n");
    }
    else
    {
        len = snprintf(str, 10, "\r\n\r\n");
    }

    if ((ret = https_write(hi, str, len)) != len)
    {
        https_close(hi);
        _error = ret;

        return -1;
    }

    return len;
}

/*---------------------------------------------------------------------*/
int http_read_chunked(HTTP_INFO *hi, char *response, int size)
{
    int ret;


    if (NULL == hi) return -1;

//  printf("request: %s \r\n\r\n", request);

    hi->response.status = 0;
    hi->response.content_length = 0;
    hi->response.close = 0;

    hi->r_len = 0;
    hi->header_end = 0;

    hi->body = response;
    hi->body_size = size;
    hi->body_len = 0;

    hi->body[0] = 0;

    while(1)
    {
        ret = https_read(hi, &hi->r_buf[hi->r_len], (int)(H_READ_SIZE - hi->r_len));
        if(ret == MBEDTLS_ERR_SSL_WANT_READ) continue;
        else if(ret < 0)
        {
            https_close(hi);
            _error = ret;

            return -1;
        }
        else if(ret == 0)
        {
            https_close(hi);
            break;
        }

        hi->r_len += ret;
        hi->r_buf[hi->r_len] = 0;

//        printf("read(%ld): %s \n", hi->r_len, hi->r_buf);
//        printf("read(%ld) \n", hi->r_len);

        if(http_parse(hi) != 0) break;
    }

    if(hi->response.close == 1)
    {
        https_close(hi);
    }

/*
    printf("status: %d \n", hi->status);
    printf("cookie: %s \n", hi->cookie);
    printf("location: %s \n", hi->location);
    printf("referrer: %s \n", hi->referrer);
    printf("length: %d \n", hi->content_length);
    printf("body: %d \n", hi->body_len);
*/

    return hi->response.status;
}

#ifndef NS_INADDRSZ
#define NS_INADDRSZ 4
#endif

/* int inet_pton4(src, dst)
 *    like inet_aton() but without all the hexadecimal, octal (with the
 *    exception of 0) and shorthand.
 * return:
 *    1 if `src' is a valid dotted quad, else 0.
 * notice:
 *    does not touch `dst' unless it's returning 1.
 * author:
 *    Paul Vixie, 1996.
 */
int inet_pton4(const char* src, size_t len, void* dstp) {
    unsigned char* dst = (unsigned char*)dstp;
    const char* end    = src + len;
    int saw_digit, octets, ch;
    unsigned char tmp[NS_INADDRSZ], *tp;

    saw_digit   = 0;
    octets      = 0;
    *(tp = tmp) = 0;
    while (src < end && (ch = *src++) != '\0') {
        if (ch >= '0' && ch <= '9') {
            uint32_t new = *tp * 10 + (ch - '0');

            if (saw_digit && *tp == 0)
                return 0;
            if (new > 255)
                return 0;
            *tp = new;
            if (!saw_digit) {
                if (++octets > 4)
                    return 0;
                saw_digit = 1;
            }
        } else if (ch == '.' && saw_digit) {
            if (octets == 4)
                return 0;
            *++tp     = 0;
            saw_digit = 0;
        } else {
            return 0;
        }
    }
    if (octets < 4)
        return 0;
    memcpy(dst, tmp, NS_INADDRSZ);
    return 1;
}
