/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Fortanix
 *                    Bobby Marinov <Bobby.Marinov@fortanix.com>
 */

#define _GNU_SOURCE
//#include <err.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "dump.h"


#define MAX_FILE_VALUES     1024
#define MAX_LINE_LENGTH     1024
#define MAX_ERR_TEXT_LEN    1024

#define SPRINTF(__fmt__, ...)   snprintf(err_txt, sizeof err_txt, \
                                         __fmt__, __VA_ARGS__)


// outputs
static char err_txt[MAX_ERR_TEXT_LEN] = {0};


static char* get_parent(const char *file_pathp)
{
    char *parentp = strdup(file_pathp);
    for (ssize_t i = strlen(parentp) - 1; i >= 0; i--) {
        if (*(parentp + i) == '/') {
            *(parentp + i) = '\0';
            return parentp;
        }
    }

    return NULL;
} // get_parent()

static char* read_file_values(const char *file_pathp,
                              size_t *n_valuesp, long **valuespp)
{
    // outputs
    long   *valsp = NULL;
    size_t  index = 0;
    // locals
    char *parentp = NULL;
    FILE *fp = NULL;
    char  line[MAX_LINE_LENGTH];

    // get parent
    parentp = get_parent(file_pathp);
    if (NULL == parentp) {
        SPRINTF("File '%s': can't get the parent directory.", parentp);
        goto cleanup;
    }
    if (access(parentp, F_OK) != 0) {
        SPRINTF("File '%s': The parent directory does not exist.", parentp);
        goto cleanup;
    }

    if (access(parentp, X_OK) != 0) {
        SPRINTF("File '%s': The parent directory is not a directory.", parentp);
        goto cleanup;
    }

    if (access(file_pathp, F_OK) != 0) {
        SPRINTF("File '%s': does not exists.", parentp);
        goto cleanup;
    }

    valsp = malloc(MAX_FILE_VALUES * sizeof(*valsp));
    if (!valsp) {
        SPRINTF("File '%s': Failed to allocate memory.", parentp);
        goto cleanup;
    }

    fp = fopen(file_pathp, "r");
    if (!fp) {
        SPRINTF("File '%s': Failed to open.", parentp);
        goto cleanup;
    }

    while (fgets(line, sizeof(line), fp)) {
        char *tokp;
        line[sizeof(line) - 1] = '\x00';
        for (tokp = strtok(line, " ,.:\t\r\n");
             tokp != NULL;
             tokp = strtok(NULL, " ,.:\t\r\n")) {
            errno = 0;
            valsp[index] = strtol(tokp, NULL, 10);
            if (errno != 0) {
                SPRINTF("File '%s': Err: %s(%d)", parentp, strerror(errno), errno);
                goto cleanup;
            }
            ++index;
            if (index >= MAX_FILE_VALUES) {
                goto cleanup;
            }
        } // for (tok)
    } // get line

cleanup:
    if (NULL != fp) {
        fclose(fp);
    }
    if (NULL != parentp) {
        free(parentp);
    }

    if ('\x00' != err_txt[0]) {
        if (NULL != valsp) {
            free(valsp);
        }
        return err_txt;
    }

    // pass-back the requested values
    *n_valuesp = index;
    *valuespp  = valsp;

    return NULL;
} // read_file_values()

// each call overwrtes the previous call output
// returns NULL on success or an error string
static char* test_parent_stats(const char *file_pathp)
{
    char *parentp = NULL;
    struct stat stats;
    int mode;

    // get parent
    parentp = get_parent(file_pathp);
    if (NULL == parentp) {
        SPRINTF("File '%s': The parent directory does not exist.", file_pathp);
        goto cleanup;
    }

    if (access(parentp, F_OK) != 0) {
        SPRINTF("'%s' must exist.", parentp);
        goto cleanup;
    }

    if (stat(parentp, &stats) != 0) {
        SPRINTF("Failed to get stats for '%s'. err_txt: %s(%d)", 
                parentp, strerror(errno), errno);
        goto cleanup;
    }
    if (!S_ISDIR(stats.st_mode)) {
        SPRINTF("'%s' must be a directory.", parentp);
        goto cleanup;
    }

    if (stats.st_uid != 0) {
        SPRINTF("'%s' must be owned by 'root'.", parentp);
        goto cleanup;
    }

    if (stats.st_gid != 0) {
        SPRINTF("'%s' must be owned by 'root' group.", parentp);
        goto cleanup;
    }

    // Check parent directory permissions
    mode = stats.st_mode & 0777;
    if ((mode & 0444) != 0444) {
        SPRINTF("'%s' is not readable by everyone.", parentp);
        goto cleanup;
    }

    if ((mode & 0222) != 0) {
        SPRINTF("'%s' should be non-writeable.", parentp);
        goto cleanup;
    }

    if ((mode & 0111) != 0111) {
        SPRINTF("'%s' must be browsable by everyone.", parentp);
        goto cleanup;
    }

    printf("'%s': Parent stats test SUCCESS\n", file_pathp);
    err_txt[0] = '\x00';

cleanup:
    if (NULL != parentp) {
        free(parentp);
    }

    if ('\x00' != err_txt[0]) {
        return err_txt;
    }

    return NULL;
} // test_parent_stats()

static char* test_file_stats(const char *file_pathp)
{
    struct stat stats;
    mode_t mode;

    if (stat(file_pathp, &stats) != 0) {
        SPRINTF("Failed to get stats for '%s'. err_txt: %s(%d)", 
                file_pathp, strerror(errno), errno);
        goto cleanup;
    }
    if (S_ISDIR(stats.st_mode)) {
        SPRINTF("'%s' cannot be a directory.", file_pathp);
        goto cleanup;
    }
    if (!S_ISREG(stats.st_mode)) {
        SPRINTF("'%s' is not a regular file.", file_pathp);
        goto cleanup;
    }

    if (stats.st_uid != 0) {
        SPRINTF("'%s' must be owned by 'root'.", file_pathp);
        goto cleanup;
    }

    if (stats.st_gid != 0) {
        SPRINTF("'%s' must be owned by 'root' group.", file_pathp);
        goto cleanup;
    }

    // Check file permissions
    mode = stats.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO);
    if ((mode & (S_IRUSR| S_IRGRP| S_IROTH)) != (S_IRUSR| S_IRGRP| S_IROTH)) {
        SPRINTF("'%s' is not readable by everyone.", file_pathp);
        goto cleanup;
    }

    if ((mode & S_IWUSR) == S_IWUSR) {
        SPRINTF("'%s' must be writeable by its owner.", file_pathp);
        goto cleanup;
    }

    if ((mode & (S_IWGRP | S_IWOTH)) != 0) {
        SPRINTF("'%s' must not be writeable by groups or others.", file_pathp);
        goto cleanup;
    }

    if ((mode & (S_IXUSR| S_IXGRP| S_IXOTH)) != 0) {
        SPRINTF("'%s' can not be executable.", file_pathp);
        goto cleanup;
    }

    printf("'%s': File stats test SUCCESS\n", file_pathp);
    err_txt[0] = '\x00';

cleanup:
    if ('\x00' != err_txt[0]) {
        return err_txt;
    }

    return NULL;
} // test_file_stats()

static char* test_file_content(const char *file_pathp, long minv, long maxv)
{
    size_t n_values;
    long *valuesp = NULL;
    char *errp;

    errp = read_file_values(file_pathp, &n_values, &valuesp);
    if (NULL != errp) {
        return errp;
    }
    if (0 == n_values) {
        SPRINTF("'%s' did not contain any values.", file_pathp);
        goto cleanup;
    }
    if (1 != n_values) {
        SPRINTF("Expected a single value inside '%s' file. "
                "Received %lu values instead.", file_pathp, n_values);
        goto cleanup;
    }
    if (NULL == valuesp) {
        SPRINTF("Internal error while processing '%s'.", file_pathp);
        goto cleanup;
    }

    if (minv == maxv) {
        if (minv != *valuesp) {
            SPRINTF("File '%s' value is not the expected. "
                    "Received %lu, expected %lu.", file_pathp, *valuesp, minv);
            goto cleanup;
        }
    } else {
        if (minv > *valuesp) {
            SPRINTF("File '%s' value is smaller than expected. "
                    "Received %lu, expected %lu to %lu.",
                    file_pathp, *valuesp, minv, maxv);
            goto cleanup;
        } else if (maxv < *valuesp) {
            SPRINTF("File '%s' value is larger than expected. "
                    "Received %lu, expected %lu to %lu.",
                    file_pathp, *valuesp, minv, maxv);
            goto cleanup;
        }
    }

    printf("'%s': File content test SUCCESS\n", file_pathp);
    err_txt[0] = '\x00';

cleanup:
    if (NULL != valuesp) {
        free(valuesp);
    }
    if ('\x00' != err_txt[0]) {
        return err_txt;
    }

    return NULL;
} // test_file_content()

int main(int argc, char* argv[]) {
    long minv, maxv;
    char *errp;

    if ((3 != argc) && (4 != argc)) {
        fprintf(stderr, "Usage: %s <proc_file> <exp_val>\n", argv[0]);
        fprintf(stderr, "       %s <proc_file> <exp_val_min> <exp_val_max>\n", argv[0]);
        return -1;
    }

    errno = 0;
    minv = strtol(argv[2], NULL, 10);
    if (0 != errno) {
        fprintf(stderr, "Bad argv[2]. ERROR: %s(%d)\n", strerror(errno), errno);
        return 2;
    }
    if (4 == argc) {
        errno = 0;
        maxv = strtol(argv[3], NULL, 10);
        if (0 != errno) {
            fprintf(stderr, "Bad argv[3]. ERROR: %s(%d)\n", strerror(errno), errno);
            return 3;
        }
    } else {
        maxv  = minv;
    }

    errp = test_parent_stats(argv[1]);
    if (NULL != errp) {
        fprintf(stderr, "ERROR: %s\n", errp);
        return 4;
    }

    errp = test_file_stats(argv[1]);
    if (NULL != errp) {
        fprintf(stderr, "ERROR: %s\n", errp);
        return 5;
    }

    errp = test_file_content(argv[1], minv, maxv);
    if (NULL != errp) {
        fprintf(stderr, "ERROR: %s\n", errp);
        return 6;
    }

    printf("'%s': TEST OK\n", argv[1]);

    return 0;
} // main()
