#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define STAT_FILE "/proc/stat"
#define BUFFSIZE  2048
#define KEYSIZE   32

/* see `man proc`, "/proc/stat" section */
struct procstat {
    uint64_t user;
    uint64_t nice;
    uint64_t system;
    uint64_t idle;
    uint64_t iowait;
    uint64_t irq;
    uint64_t softirq;
    uint64_t steal;
    uint64_t guest;
    uint64_t guest_nice;
};

static void init_procstat(struct procstat* ps) {
    ps->user       = UINT64_MAX;
    ps->nice       = UINT64_MAX;
    ps->system     = UINT64_MAX;
    ps->idle       = UINT64_MAX;
    ps->iowait     = UINT64_MAX;
    ps->irq        = UINT64_MAX;
    ps->softirq    = UINT64_MAX;
    ps->steal      = UINT64_MAX;
    ps->guest      = UINT64_MAX;
    ps->guest_nice = UINT64_MAX;
}

static int check_procstat(struct procstat* ps) {
    if (ps->user == UINT64_MAX) {
        fprintf(stderr, "Could not get 'user' time\n");
        return -1;
    }
    if (ps->nice == UINT64_MAX) {
        fprintf(stderr, "Could not get 'nice' time\n");
        return -1;
    }
    if (ps->system == UINT64_MAX) {
        fprintf(stderr, "Could not get 'system' time\n");
        return -1;
    }
    if (ps->idle == UINT64_MAX) {
        fprintf(stderr, "Could not get 'idle' time\n");
        return -1;
    }
    if (ps->iowait == UINT64_MAX) {
        fprintf(stderr, "Could not get 'iowait' time\n");
        return -1;
    }
    if (ps->irq == UINT64_MAX) {
        fprintf(stderr, "Could not get 'irq' time\n");
        return -1;
    }
    if (ps->softirq == UINT64_MAX) {
        fprintf(stderr, "Could not get 'softirq' time\n");
        return -1;
    }
    if (ps->steal == UINT64_MAX) {
        fprintf(stderr, "Could not get 'steal' time\n");
        return -1;
    }
    if (ps->guest == UINT64_MAX) {
        fprintf(stderr, "Could not get 'guest' time\n");
        return -1;
    }
    if (ps->guest_nice == UINT64_MAX) {
        fprintf(stderr, "Could not get 'guest_nice' time\n");
        return -1;
    }
    return 0;
}

static int parse_and_check_noncpu_line(char* line) {
    uint64_t val = UINT64_MAX;
    char key[KEYSIZE] = "<none>";

    if (!memcmp(line, "ctxt", sizeof("ctxt") - 1)) {
        sscanf(line, "%s %lu\n", key, &val);
    } else if (!memcmp(line, "btime", sizeof("btime") - 1)) {
        sscanf(line, "%s %lu\n", key, &val);
    } else if (!memcmp(line, "processes", sizeof("processes") - 1)) {
        sscanf(line, "%s %lu\n", key, &val);
    } else if (!memcmp(line, "procs_running", sizeof("procs_running") - 1)) {
        sscanf(line, "%s %lu\n", key, &val);
    } else if (!memcmp(line, "procs_blocked", sizeof("procs_blocked") - 1)) {
        sscanf(line, "%s %lu\n", key, &val);
    }

    if (val == UINT64_MAX) {
        fprintf(stderr, "unexpected value in '%s' line\n", key);
        return -1;
    }

    return 0;
}

int main(int argc, char* argv[]) {
    FILE* fp = NULL;
    char line[BUFFSIZE];
    char cpu[KEYSIZE];
    struct procstat ps;
    int cpu_cnt = 0, rv = 0;

    if ((fp = fopen(STAT_FILE, "r")) == NULL)
        err(1, "fopen");

    /* first line is "cpu" (system-wide stats on times) */
    init_procstat(&ps);

    if (fgets(line, sizeof(line), fp) == NULL)
        errx(1, "cannot read 'cpu' line");

    sscanf(line, "%s %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu\n", cpu, &ps.user, &ps.nice,
           &ps.system, &ps.idle, &ps.iowait, &ps.irq, &ps.softirq, &ps.steal, &ps.guest,
           &ps.guest_nice);

    if (strcmp(cpu, "cpu"))
        errx(1, "did not find 'cpu' line");

    if ((rv = check_procstat(&ps)) != 0)
        errx(1, "unexpected values in 'cpu' line");

    /* next lines are "cpuX" (per-CPU stats on times) */
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (memcmp(line, "cpu", sizeof("cpu") - 1))
            break;

        init_procstat(&ps);
        sscanf(line, "%s %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu\n", cpu, &ps.user, &ps.nice,
               &ps.system, &ps.idle, &ps.iowait, &ps.irq, &ps.softirq, &ps.steal, &ps.guest,
               &ps.guest_nice);
        if ((rv = check_procstat(&ps)) != 0)
            errx(1, "unexpected values in 'cpu%d' line", cpu_cnt);
        cpu_cnt++;
    }

    if (cpu_cnt == 0)
        errx(1, "no 'cpuX' lines found");

    /* next lines are 'ctxt', 'btime', 'processes', 'procs_running', 'procs_blocked' */
    if (line[0] == '\n')
        goto out;
    if ((rv = parse_and_check_noncpu_line(line)) != 0)
        errx(1, "checking non-cpu line failed");

    while (fgets(line, sizeof(line), fp) != NULL) {
        if (line[0] == '\n')
            goto out;
        if ((rv = parse_and_check_noncpu_line(line)) != 0)
            errx(1, "checking non-cpu line failed");
    }

out:
    fclose(fp);
    printf("/proc/stat test passed (found %d CPUs)\n", cpu_cnt);
    return 0;
}
