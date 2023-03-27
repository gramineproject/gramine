/* Attestation API test. Only works for SGX PAL. */

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mbedtls/cipher.h"
#include "mbedtls/cmac.h"

#include "enclave_api.h"
#include "rw_file.h"
#include "sgx_arch.h"
#include "sgx_attest.h"

uint8_t g_quote[SGX_QUOTE_MAX_SIZE];

char user_report_data_str[] = "This is user-provided report data";

enum { SUCCESS = 0, FAILURE = -1 };

ssize_t (*file_read_f)(const char* path, char* buf, size_t bytes);
ssize_t (*file_write_f)(const char* path, const char* buf, size_t bytes);

/*!
 * \brief Verify the signature on `report`.
 *
 * If verification succeeds, it means the enclave which produced `report` runs on same platform
 * as the enclave executing this function.
 *
 * \returns 0 if signature verification succeeded, -1 otherwise.
 */
static int verify_report_mac(sgx_report_t* report) {
    int ret;

    /* setup key request structure */
    __sgx_mem_aligned sgx_key_request_t key_request;
    memset(&key_request, 0, sizeof(key_request));
    key_request.key_name = SGX_REPORT_KEY;
    memcpy(&key_request.key_id, &report->key_id, sizeof(key_request.key_id));

    /* retrieve key via EGETKEY instruction leaf */
    __sgx_mem_aligned uint8_t key[128 / 8];
    memset(key, 0, sizeof(key));
    sgx_getkey(&key_request, (sgx_key_128bit_t*)key);

    /* calculate message authentication code (MAC) over report body;
     * signature is calculated over part of report BEFORE the key_id field */
    sgx_mac_t mac = {0};
    const int bits_per_byte = 8;
    const mbedtls_cipher_info_t* cipher_info =
        mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
    ret = mbedtls_cipher_cmac(cipher_info, key, sizeof(key) * bits_per_byte,
                              (const unsigned char*)report, offsetof(sgx_report_t, key_id),
                              (uint8_t*)&mac);
    if (ret) {
        fprintf(stderr, "MAC calculation over report body failed: %d (mbedtls error code)\n", ret);
        return FAILURE;
    }

    /* compare calculated MAC against MAC sent with report */
    ret = memcmp(&mac, report->mac, sizeof(mac));
    if (ret) {
        fprintf(stderr, "MAC comparison failed\n");
        return FAILURE;
    }

    return SUCCESS;
}

/*!
 * \brief Test local attestation interface.
 *
 * Perform the following steps in order:
 *   1. read `my_target_info` file
 *   2. write data from `my_target_info` to `target_info` file
 *   3. write some custom data to `user_report_data` file
 *   4. read `report` file
 *   5. verify data read from `report`
 *
 * \returns 0 if the test succeeded, -1 otherwise.
 */
static int test_local_attestation(void) {
    ssize_t bytes;

    /* 1. read `my_target_info` file */
    sgx_target_info_t target_info;
    bytes = file_read_f("/dev/attestation/my_target_info", (char*)&target_info,
                        sizeof(target_info));
    if (bytes != sizeof(target_info)) {
        /* error is already printed by file_read_f() */
        return FAILURE;
    }

    /* 2. write data from `my_target_info` to `target_info` file */
    bytes = file_write_f("/dev/attestation/target_info", (char*)&target_info, sizeof(target_info));
    if (bytes != sizeof(target_info)) {
        /* error is already printed by file_write_f() */
        return FAILURE;
    }

    /* 3. write some custom data to `user_report_data` file */
    sgx_report_data_t user_report_data = {0};
    static_assert(sizeof(user_report_data) >= sizeof(user_report_data_str),
                  "insufficient size of user_report_data");

    memcpy((void*)&user_report_data, (void*)user_report_data_str, sizeof(user_report_data_str));

    bytes = file_write_f("/dev/attestation/user_report_data", (char*)&user_report_data,
                         sizeof(user_report_data));
    if (bytes != sizeof(user_report_data)) {
        /* error is already printed by file_write_f() */
        return FAILURE;
    }

    /* 4. read `report` file */
    sgx_report_t report;
    bytes = file_read_f("/dev/attestation/report", (char*)&report, sizeof(report));
    if (bytes != sizeof(report)) {
        /* error is already printed by file_read_f() */
        return FAILURE;
    }

    /* 5. verify data read from `report` */
    return verify_report_mac(&report);
}

/* This currently does not include 'quote'. Since the quote interface does not implement caching,
 * we do not want to have 10^5 interactions with the quoting service (would take too long). */
static const char* paths[] = {
    "/dev/attestation/user_report_data",
    "/dev/attestation/target_info",
    "/dev/attestation/my_target_info",
    "/dev/attestation/report",
};

/*!
 * \brief Test resource leaks in the attestation pseudo filesystem.
 *
 * Perform the following steps 100,000 times:
 *   1. open one of the /dev/attestation files
 *   2. close this file
 *
 * \returns 0 if the test succeeded, -1 otherwise.
 */
static int test_resource_leak(void) {
    /* repeatedly open()/close() pseudo-files to hopefully uncover resource leaks */
    for (unsigned int j = 0; j < sizeof(paths) / sizeof(&paths[0]); j++) {
        for (unsigned int i = 0; i < 100000; i++) {
            int fd = open(paths[j], O_RDONLY);
            if (fd < 0) {
                fprintf(stderr, "opening %s failed: %s\n", paths[j], strerror(errno));
                return FAILURE;
            }

            int ret = close(fd);
            if (ret < 0) {
                fprintf(stderr, "closing %s failed: %s\n", paths[j], strerror(errno));
                return FAILURE;
            }
        }
    }
    return SUCCESS;
}

/*!
 * \brief Test quote interface (currently SGX quote obtained from the Quoting Enclave).
 *
 * Perform the following steps in order:
 *   1. write some custom data to `user_report_data` file
 *   2. read `quote` file
 *   3. verify report data read from `quote`
 *
 * \returns 0 if the test succeeds, -1 otherwise.
 */
static int test_quote_interface(void) {
    ssize_t bytes;

    /* 1. write some custom data to `user_report_data` file */
    sgx_report_data_t user_report_data = {0};
    static_assert(sizeof(user_report_data) >= sizeof(user_report_data_str),
                  "insufficient size of user_report_data");

    memcpy((void*)&user_report_data, (void*)user_report_data_str, sizeof(user_report_data_str));

    bytes = file_write_f("/dev/attestation/user_report_data", (char*)&user_report_data,
                         sizeof(user_report_data));
    if (bytes != sizeof(user_report_data)) {
        /* error is already printed by file_write_f() */
        return FAILURE;
    }

    /* 2. read `quote` file */
    bytes = file_read_f("/dev/attestation/quote", (char*)&g_quote, sizeof(g_quote));
    if (bytes < 0) {
        /* error is already printed by file_read_f() */
        return FAILURE;
    }

    /* 3. verify report data read from `quote` */
    if ((size_t)bytes < sizeof(sgx_quote_body_t)) {
        fprintf(stderr, "obtained SGX quote is too small: %ldB (must be at least %ldB)\n", bytes,
                sizeof(sgx_quote_body_t));
        return FAILURE;
    }

    sgx_quote_body_t* quote_body = (sgx_quote_body_t*)g_quote;

    if (quote_body->version != /*EPID*/2 && quote_body->version != /*DCAP*/3) {
        fprintf(stderr, "version of SGX quote is not EPID (2) and not ECDSA/DCAP (3)\n");
        return FAILURE;
    }

    int ret = memcmp(quote_body->report_body.report_data.d, user_report_data.d,
                     sizeof(user_report_data));
    if (ret) {
        fprintf(stderr, "comparison of report data in SGX quote failed\n");
        return FAILURE;
    }

    return SUCCESS;
}

int main(int argc, char** argv) {
    file_read_f  = posix_file_read;
    file_write_f = posix_file_write;

    if (argc > 1) {
        /* simple trick to test stdio-style interface to pseudo-files in our tests */
        file_read_f  = stdio_file_read;
        file_write_f = stdio_file_write;
    }

    printf("Test local attestation... %s\n",
           test_local_attestation() == SUCCESS ? "SUCCESS" : "FAIL");
    printf("Test quote interface... %s\n",
           test_quote_interface() == SUCCESS ? "SUCCESS" : "FAIL");
    printf("Test resource leaks in attestation filesystem... %s\n",
           test_resource_leak() == SUCCESS ? "SUCCESS" : "FAIL");
    return 0;
}
