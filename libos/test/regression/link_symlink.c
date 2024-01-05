/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/*
 * Tests for renaming and deleting files. Mostly focus on cases where a file is still open.
 */

#define _DEFAULT_SOURCE /* fchmod */

#include <assert.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "common.h"
#include "rw_file.h"

static const char message1[] = "first message\n";
static const size_t message1_len = sizeof(message1) - 1;

static const char message2[] = "second message\n";
//static const size_t message2_len = sizeof(message2) - 1;

static const char message3[] = "third file content\n";
static const size_t message3_len = sizeof(message3) - 1;

static_assert(sizeof(message1) != sizeof(message2) &&
              sizeof(message1) != sizeof(message3) &&
              sizeof(message2) != sizeof(message3), 
              "the messages should have different lengths");

#define FILENAME_PREFIX     "link_symlink_test_file"
#define FILENAME_PREFIX_LEN (ARRAY_LEN(FILENAME_PREFIX) - 1)
#define DIRNAME_PREFIX      "link_symlink_test_dir"
#define DIRNAME_PREFIX_LEN  (ARRAY_LEN(DIRNAME_PREFIX) - 1)

static void remove_test_files_and_dirs_recursively(char* path) {
    char* entry_path = NULL;
    DIR *dir = opendir(path);
    if (dir == NULL) {
        err(1, "Error opening directory: '%s'", path);
    }
    size_t len = strlen(path);
    bool separator_present = (len && (*(path + len -1) == '/')) ? true: false;

    struct dirent* entry;
    for(entry = readdir(dir); entry != NULL; entry = readdir(dir)) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        bool is_dir = true;
        if (strncmp(entry->d_name, FILENAME_PREFIX, FILENAME_PREFIX_LEN) == 0)
            is_dir = false;
        else if (strncmp(entry->d_name, DIRNAME_PREFIX, DIRNAME_PREFIX_LEN) != 0)
            continue;

        /* Construct the full path of the entry */
        if (entry_path == NULL) {
            entry_path = malloc(PATH_MAX + 1);
            if (entry_path == NULL)
                err(1, "Failed to allocate path buffer for '%s/%s'", path, entry->d_name);
        }
        if (separator_present)
            snprintf(entry_path, PATH_MAX, "%s%s", path, entry->d_name);
        else
            snprintf(entry_path, PATH_MAX, "%s/%s", path, entry->d_name);
        *(entry_path + PATH_MAX) = '\x00';

        if (is_dir)
            remove_test_files_and_dirs_recursively(entry_path);
        else
            remove(entry_path);
    }

    free(entry_path);
    closedir(dir);

    if (len) {
        char* file = path + len - 1;
        if (separator_present)
            --file;
        while (file > path) {
            if (*file == '/')
                break;
            --file;
        }
        if (*file == '/')
            ++file;
        if (strncmp(file, DIRNAME_PREFIX, DIRNAME_PREFIX_LEN) == 0)
            rmdir(path);
    }
}

#define DIR_SEPARATOR_STR   "/"
#define DIR_SEPARATOR_CHAR  (DIR_SEPARATOR_STR[0])
static char* os_path_join(char* base_path, ...) {
    if (base_path == NULL)
        return NULL;

    size_t total_sz = 0;
    size_t len = strlen(base_path);
    bool remove_last = true;
    if (len && *(base_path + len - 1) == DIR_SEPARATOR_CHAR) {
        --len;
        remove_last = false;
    }

    /* calculate total size */
    const char* sub;
    total_sz += len + 1; /* '+1' - path separator */
    va_list args;
    va_start(args, base_path);
    while ((sub = va_arg(args, const char *)) != NULL) {
        len = strlen(sub);
        if (len && (*sub == DIR_SEPARATOR_CHAR)) {
            --len;
            ++sub;
        }
        if (len && (*(sub + len - 1) == DIR_SEPARATOR_CHAR)) {
            --len;
            remove_last = false;
        } else
            remove_last = true;
        total_sz += len + 1; /* '+1' - path separator */
    }
    va_end(args);

    ++total_sz; /* '+1' - zero-terminator */

    char* out = (char*)malloc(total_sz);
    if (out == NULL)
        return NULL;

    assert(total_sz <= SSIZE_MAX);
    ssize_t out_sz = (ssize_t)total_sz;
    char* out_ptr = out;
    int printed;
    len = strlen(base_path);
    if (len && *(base_path + len - 1) == DIR_SEPARATOR_CHAR) {
        printed = snprintf(out_ptr, out_sz, "%s", base_path);
        remove_last = false;
    } else {
        printed = snprintf(out_ptr, out_sz, "%s" DIR_SEPARATOR_STR, base_path);
        remove_last = true;
    }
    out_sz -= printed;
    out_ptr += printed;

    va_start(args, base_path);
    while ((sub = va_arg(args, const char *)) != NULL) {
        len = strlen(sub);  // +1 for the path separator
        assert(len <= SSIZE_MAX);
        if (len && (*sub == DIR_SEPARATOR_CHAR)) {
            --len;
            ++sub;
        }
        if (len && *(sub + len - 1) == DIR_SEPARATOR_CHAR) {
            assert((ssize_t)len < out_sz);
            printed = snprintf(out_ptr, out_sz, "%s", sub);
            remove_last = false;
        } else {
            assert((ssize_t)len <= out_sz);
            printed = snprintf(out_ptr, out_sz, "%s" DIR_SEPARATOR_STR, sub);
            remove_last = true;
        }
        out_sz -= printed;
        out_ptr += printed;
    }
    assert(out_sz == 1);
    if (remove_last)
        --out_ptr;
    *out_ptr = '\x00';

    return out;
}

static void should_not_exist(const char* path) {
    struct stat statbuf;

    if (stat(path, &statbuf) == 0)
        errx(1, "%s unexpectedly exists", path);
    if (errno != ENOENT)
        err(1, "stat %s", path);
}

static void check_statbuf(const char* desc, struct stat* statbuf, size_t size) {
    assert(!OVERFLOWS(off_t, size));

    if (!S_ISREG(statbuf->st_mode) && !S_ISLNK(statbuf->st_mode))
        errx(1, "%s: wrong mode (0o%o)", desc, statbuf->st_mode);
    if (statbuf->st_size != (off_t)size)
        errx(1, "%s: wrong size: %lu, expected: %lu", desc, statbuf->st_size, size);
}

static void should_exist(const char* path, size_t size) {
    struct stat statbuf;

    if (stat(path, &statbuf) != 0)
        err(1, "stat %s", path);

    check_statbuf(path, &statbuf, size);
}

static void should_exist_dir(const char* path) {
    struct stat statbuf;

    if (stat(path, &statbuf) != 0)
        err(1, "stat %s", path);
    if (!S_ISDIR(statbuf.st_mode))
        err(1, "'%s' should be a directory.", path);
}

static void should_exist_symlink(const char* path, size_t size) {
    struct stat statbuf;

    if (lstat(path, &statbuf) != 0)
        err(1, "lstat %s", path);

    check_statbuf(path, &statbuf, size);
}

static int create_file(const char* path, const char* str, size_t len) {
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        err(1, "create_file::open '%s' (errno:%d)", path, errno);

    ssize_t n = posix_fd_write(fd, str, len);
    if (n < 0)
        errx(1, "posix_fd_write %s", path);
    if ((size_t)n != len)
        errx(1, "written less bytes than expected into %s", path);

    return fd;
}

static void create_file_and_close(const char* path, const char* str, size_t len) {
    int fd = create_file(path, str, len);
    if (close(fd) != 0)
        err(1, "close %s", path);
}

static int create_parent_dirs(int parent_fd, const char* file_path) {
    size_t len = strlen (file_path);
    int ret = 0;

    if (len <= 1) {
        /* no parent dir in fle_path */
        return 0;
    }

    char* path = strdup(file_path);
    if (path == NULL)
        err(1, "strdup %s", file_path);

    char* parent_end = path + len - 1;
    for (size_t i = len - 1; i>0; --i, --parent_end) {
        if (*parent_end == '/')
            break;
    }
    if ((*parent_end != '/') || (parent_end == path)) {
        goto out;
    }
    *parent_end = '\x00';

    /* try creating the directories backwards */
    char* current_end = parent_end;
    while (current_end != path) {
        size_t i;
        ret = 0;
        if (mkdirat(parent_fd, path, 0774) != 0)
            ret = errno;
        if ((ret == 0) || (ret == EEXIST)) {
            ret = 0;
            break;
        }

        for (i = current_end - path - 1; i>0; --i) {
            if (*(path + i) == '/')
                break;
        }
        if ((*(path + i) != '/') || (i == 0)) {
            goto out;
        }
        current_end = path + i;
    }
    if (current_end == parent_end) {
        goto out;
    }

    /* found the first existing dir, now create the rest */
    *current_end = '/';
    while (current_end < parent_end) {
        for (++current_end; current_end < parent_end; ++current_end) {
            if (*current_end == '/') {
                *current_end = '\x00';
                break;
            }
        }
        ret = 0;
        if (mkdirat(parent_fd, path, 0774) != 0)
            ret = errno;
        if ((ret != 0) && (ret != EEXIST)) {
            goto out;
        }
        *current_end = '/';
        ret = 0;
    }

out:
    if (path != NULL)
        free(path);

    return ret;
}

static void test_link_same_file(const char* path, bool is_sym_link) {
    const char* txt = is_sym_link ? "symlink": "hardlink";

    should_exist(path, message1_len);
    errno = 0;
    int ret = is_sym_link ? symlink(path, path): link(path, path);
    if ((ret == 0) || (errno != EEXIST)) //  && errno != ENOENT))
        err(1, "%s('%s') to the same file should fail. (errno: %d)", txt, path, errno);
}

static void test_simple_link(const char* path1, const char* path2, bool is_sym_link) {
    const char* txt = is_sym_link ? "symlink": "hardlink";

    errno = 0;
    int ret = is_sym_link ? symlink(path1, path2): link(path1, path2);
    if (ret != 0)
        err(1, "%s", txt);
    should_exist(path2, message1_len);
    if (is_sym_link)
        should_exist_symlink(path2, strlen(path1));

    return;
}

static void test_replace_link(const char* path3, const char* path2, bool is_sym_link) {
    const char* txt = is_sym_link ? "symlink": "hardlink";

    errno = 0;
    int ret = (is_sym_link ? symlink(path3, path2): link(path3, path2));
    if ((ret >= 0) || (errno != EEXIST))
        err(1, "%s(%s <- %s) existing should have failed.(%d)", txt, path3, path2, errno);
    should_exist(path2, message1_len);
//    if (is_sym_link)
//        should_exist_symlink(path2, strlen(path1));

    return;
}

static void test_dir_link(const char* path1, const char* path2, bool is_sym_link) {
    const char* txt = is_sym_link ? "symlink": "hardlink";

    errno = 0;
    int ret = (is_sym_link ? symlink(path1, path2): link(path1, path2));
    if (!is_sym_link) {
        if ((ret >= 0) || ((errno != EPERM) && (errno != ENOENT)))
            err(1, "%s(%s <- %s) creating hardlink to a directory should have failed.(%d)",
                   txt, path1, path2, errno);
        should_not_exist(path2);
    } else {
        if (ret != 0)
            err(1, "%s", txt);
        should_exist_dir(path2);
        should_exist_symlink(path2, strlen(path1));
    }

    return;
}

static void test_link_removal(const char* target, const char* targetpath, const char* linkpath,
                              bool is_sym_link) {
    const char* txt = is_sym_link ? "symlink": "hardlink";

    should_not_exist(linkpath);
    create_file_and_close(targetpath, message3, message3_len);
    should_exist(targetpath, message3_len);
    if ((is_sym_link ? symlink(target, linkpath): link(target, linkpath)) != 0)
        err(1, " create %s(errno:%d)", txt, errno);

    /* remove link first */
    errno = 0;
    int ret = unlink(linkpath);
    if ((ret < 0) || (errno != 0))
        err(1, "Deleting %s '%s' should succeed. (errno:%d)", txt, linkpath, errno);
    should_not_exist(linkpath);

    /* remove target second */
    errno = 0;
    ret = unlink(targetpath);
    if ((ret < 0) || (errno != 0))
        err(1, "Deleting the %s's target ('%s') should succeed. (errno:%d)", txt, targetpath, errno);
    should_not_exist(targetpath);

    return;
}

static void test_bad_symlink_removal(const char* target, const char* targetpath,
                                     const char* linkpath) {
    const char* txt = "symlink";

    create_file_and_close(targetpath, message3, message3_len);
    if (symlink(target, linkpath) != 0)
        err(1, "%s", txt);

    /* remove target first */
    errno = 0;
    int ret = unlink(targetpath);
    if ((ret < 0) || (errno != 0))
        err(1, "Deleting the %s's target ('%s') should succeed.(errno:%d)", txt, targetpath, errno);
    should_not_exist(targetpath);

    /* remove broken (pointing to noithing) symlink second */
    errno = 0;
    ret = unlink(linkpath);
    if ((ret < 0) || (errno != 0))
        err(1, "Deleting %s '%s' should succeed.(errno:%d)", txt, linkpath, errno);
    should_not_exist(linkpath);

    return;
}

int main(int argc, char* argv[]) {
//    int ret = 0;

    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    if (argc != 3)
        errx(1, "Usage: %s -h|s <test_dir_path>/", argv[0]);
    if (argv[1][0] != '-' || (argv[1][1] != 'h' && argv[1][1] != 's') || argv[1][2] != '\x00')
        errx(1, "ERROR: bad or missing link type: h - hardlink, s - softlink\n"
                "Usage: %s -h|s <test_dir_path>/", argv[0]);
    const char* dir = (argv[2][0] == '\x00') ? "./" : argv[2];
    size_t dir_len = strlen(dir);
    if (*(dir + dir_len - 1) != '/')
        errx(1, "ERROR: missing end of dir path terminator: '/'\n"
                "Usage: %s -h|s <test_dir_path>/", argv[0]);

    char* path1 = os_path_join(argv[2], FILENAME_PREFIX "1", NULL);
    if (path1 == NULL)
        err(1, "path1 path join fail");
    char* path2 = os_path_join(argv[2], FILENAME_PREFIX "2", NULL);
    if (path2 == NULL)
        err(1, "path2 path join fail");
    bool is_sym_link = (argv[1][1] != 'h') ? true : false;
    const char* oldpath = is_sym_link ? "./" FILENAME_PREFIX "1" : path1;
    char* path3 = os_path_join(argv[2], FILENAME_PREFIX "1b", NULL);
    if (path3 == NULL)
        err(1, "path1b path join fail");

    const char* oldpath3 = is_sym_link ? "./" FILENAME_PREFIX "1b" : oldpath;

    /* cleanup any potential files */
    remove_test_files_and_dirs_recursively(argv[2]);

    /* create any parent dirs */
    (void)create_parent_dirs(AT_FDCWD, path1);
    (void)create_parent_dirs(AT_FDCWD, path2);

    create_file_and_close(path1, message1, message1_len);
    should_exist(path1, message1_len);
    create_file_and_close(path3, message3, message3_len);
    should_exist(path3, message3_len);

#if 01
    if (!is_sym_link)
        test_link_same_file(path1, is_sym_link);

    should_exist(path1, message1_len); // assumes oldpath points to path1
    test_simple_link(oldpath, path2, is_sym_link);
    test_replace_link(oldpath3, path2, is_sym_link);
    unlink(path2);
#endif

    char* dir1 = os_path_join(argv[2], DIRNAME_PREFIX "1", NULL);
    char* dir1_file3 = os_path_join(argv[2], DIRNAME_PREFIX "1", FILENAME_PREFIX "3", NULL);
    const char* dir_symlink1 = "./" DIRNAME_PREFIX "1";
    const char* fil_symlink3 = "./" DIRNAME_PREFIX "1" "/" FILENAME_PREFIX "3";
    (void)create_parent_dirs(AT_FDCWD, dir1_file3);
    should_exist_dir(dir1);
    create_file_and_close(dir1_file3, message3, message3_len);
    should_exist(dir1_file3, message3_len);
    const char* dir_link = is_sym_link ? dir_symlink1: dir1;
    const char* file3_link = is_sym_link ? fil_symlink3: dir1_file3;
#if 1
    test_dir_link(dir_link, path2, is_sym_link);
    unlink(path2);
#endif

    test_link_removal(file3_link, dir1_file3, path2, is_sym_link);
    if (is_sym_link)
        test_bad_symlink_removal(fil_symlink3, dir1_file3, path2);

    /* cleanup */
    free(dir1_file3);
    free(dir1);
    free(path3);
    free(path2);
    free(path1);

    printf("TEST OK\n    Cleaning up ...\n");
    remove_test_files_and_dirs_recursively(argv[2]);
    return 0;
}
