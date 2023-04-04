#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CPUINFO_FILE   "/proc/cpuinfo"
#define BUF_SIZE       (10 * 1024) /* 10KB */
#define FLAGS_BUF_SIZE (8 * 1024) /* 8KB */

/* vendor_id, model_name size reference Linux kernel struct cpuinfo_x86
 * (see Linux's arch/x86/include/asm/processor.h) */
struct cpuinfo {
    int processor;
#if defined(__i386__) || defined(__x86_64__)
    char vendor_id[16];
    int cpu_family;
    int model;
    char model_name[64];
    int stepping;
    int core_id;
    int cpu_cores;
#endif
    char flags[FLAGS_BUF_SIZE];
};

static void init_cpuinfo(struct cpuinfo* ci) {
    ci->processor = -1;
#if defined(__i386__) || defined(__x86_64__)
    memset(&ci->vendor_id, 0, sizeof(ci->vendor_id));
    ci->cpu_family = -1;
    ci->model      = -1;
    memset(&ci->model_name, 0, sizeof(ci->model_name));
    ci->stepping  = -1;
    ci->core_id   = -1;
    ci->cpu_cores = -1;
#endif
    memset(ci->flags, 0, sizeof(ci->flags));
}

static int parse_line(char* line, struct cpuinfo* ci) {
    char *k, *v, *p;

    if ((p = strchr(line, ':')) == NULL)
        goto fmt_err;

    /* if the line does not have value string, p[1] should be '\n', otherwise
     * p[1] should be ' ' */
    if (p[1] == '\n' && !p[2])
        return 0; /* No value string */

    /* ':' should always be followed by a space */
    if (p[1] != ' ')
        goto fmt_err;

    /* skip ": " to get value string */
    v = p + 2;

    /* get key string */
    *p = '\0';
    if ((p = strchr(line, '\t')) != NULL)
        *p = '\0';
    k = line;

    if (!strcmp(k, "processor")) {
        sscanf(v, "%d\n", &ci->processor);
#if defined(__i386__) || defined(__x86_64__)
    } else if (!strcmp(k, "cpu family")) {
        sscanf(v, "%d\n", &ci->cpu_family);
    } else if (!strcmp(k, "model")) {
        sscanf(v, "%d\n", &ci->model);
    } else if (!strcmp(k, "stepping")) {
        sscanf(v, "%d\n", &ci->stepping);
    } else if (!strcmp(k, "core id")) {
        sscanf(v, "%d\n", &ci->core_id);
    } else if (!strcmp(k, "cpu cores")) {
        sscanf(v, "%d\n", &ci->cpu_cores);
    } else if (!strcmp(k, "vendor_id")) {
        snprintf(ci->vendor_id, sizeof(ci->vendor_id), "%s", v);
    } else if (!strcmp(k, "model name")) {
        snprintf(ci->model_name, sizeof(ci->model_name), "%s", v);
#endif
    } else if (!strcmp(k, "flags")) {
        snprintf(ci->flags, sizeof(ci->flags), "%s", v);
        size_t len = strlen(ci->flags);
        if (len > 0 && ci->flags[len - 1] == '\n') {
            /* Store `ci->flags` without the trailing `\n` for easier proper splitting */
            ci->flags[--len] = '\0';
        }
    }
    return 0;

fmt_err:
    fprintf(stderr, "format error in line: %s\n", line);
    return -1;
};

static int check_cpuinfo(struct cpuinfo* ci, const char* test_cpu_flags) {
    if (ci->processor == -1) {
        fprintf(stderr, "Could not get cpu index\n");
        return -1;
    }
#if defined(__i386__) || defined(__x86_64__)
    if (ci->core_id == -1) {
        fprintf(stderr, "Could not get core id\n");
        return -1;
    }

    if (ci->cpu_cores == -1) {
        fprintf(stderr, "Could not get cpu cores\n");
        return -1;
    }
#endif
    char* flags = NULL;
    char* state_flags = NULL;
    char* test_flags = NULL;
    char* state_test_flags = NULL;
    int ret;

    /* `strtok_r()` destroys strings so duplicate them first. */
    flags = strdup(ci->flags);
    if (!flags) {
        fprintf(stderr, "out of memory\n");
        ret = -1;
        goto out;
    }
    test_flags = strdup(test_cpu_flags);
    if (!test_flags) {
        fprintf(stderr, "out of memory\n");
        ret = -1;
        goto out;
    }

    char* test_flag = strtok_r(test_flags, " ", &state_test_flags);
    while (test_flag != NULL) {
        bool found = false;

        char* flag = strtok_r(flags, " ", &state_flags);
        while (flag != NULL) {
            if (!strcmp(flag, test_flag)) {
                found = true;
                break;
            }
            flag = strtok_r(NULL, " ", &state_flags);
        }

        if (!found) {
            fprintf(stderr, "Could not get cpu flag: %s\n", test_flag);
            ret = -1;
            goto out;
        }

        /* `strtok_r()` destroys `flags`, re-initialize it */
        strcpy(flags, ci->flags);

        test_flag = strtok_r(NULL, " ", &state_test_flags);
    }

    ret = 0;

out:
    free(test_flags);
    free(flags);
    return ret;
}

int main(int argc, char* argv[]) {
    FILE* fp = NULL;
    int cpu_cnt = 0, rv = 0;

    if (argc != 2)
        errx(1, "Usage: %s <CPU feature flags to validate>", argv[0]);

    char* line = calloc(1, BUF_SIZE);
    if (!line)
        errx(1, "out of memory");

    struct cpuinfo* ci = malloc(sizeof(*ci));
    if (!ci)
        errx(1, "out of memory");

    init_cpuinfo(ci);

    if ((fp = fopen(CPUINFO_FILE, "r")) == NULL)
        err(1, "fopen");

    while (fgets(line, BUF_SIZE, fp) != NULL) {
        if (line[0] == '\n') {
            if ((rv = check_cpuinfo(ci, argv[1])) != 0)
                break;
            cpu_cnt++;
            init_cpuinfo(ci);
            continue;
        }
        if ((rv = parse_line(line, ci)) != 0)
            break;
    }

    fclose(fp);
    free(ci);
    free(line);

    if (rv != 0)
        return 1;

    if (cpu_cnt == 0)
        errx(1, "could not get online cpu info");

    rv = unlink(CPUINFO_FILE);
    if (rv != -1 || errno != EACCES)
        errx(1, "Removing %s didn't fail with -EACCES", CPUINFO_FILE);

    puts("TEST OK");
    return 0;
}
