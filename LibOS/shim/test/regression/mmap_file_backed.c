#define _GNU_SOURCE
#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char** argv) {
    int ret;

    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size < 0)
        err(1, "sysconf");

    /* open the file (this executable's manifest) for read, find its size, mmap (with read-write
     * protections) at least one page more than the file size and mprotect the last page */
    FILE* fp = fopen(argv[0], "r");
    if (!fp)
        err(1, "fopen");

    ret = fseek(fp, 0, SEEK_END);
    if (ret < 0)
        err(1, "fseek");

    long fsize = ftell(fp);
    if (fsize < 0)
        err(1, "ftell");

    rewind(fp); /* for sanity */

    size_t mmap_size = fsize + page_size * 2; /* file size plus at least one full aligned page */
    mmap_size &= ~(page_size - 1);            /* align down */

    void* addr = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fileno(fp), 0);
    if (addr == MAP_FAILED)
        err(1, "mmap");

    ret = mprotect(addr + mmap_size - page_size, page_size, PROT_NONE);
    if (ret < 0)
        err(1, "mprotect");

    /* Below fork triggers checkpoint-and-restore logic in Gramine LibOS, which will send all VMAs
     * info and all corresponding memory contents to the child. These VMAs contain two VMAs that
     * were split from the file-backed mmap above: the first VMA with the lower part (backed by file
     * contents) and the second VMA with a single page (not backed by file contents).
     *
     * There was a bug in Gramine that forced LibOS to re-map the memory-region content of the
     * second VMA via mmap(..., <file-fd>, <offset-past-file-end>). This is incorrect because
     * private writable mappings must inherit memory content from the parent. It led to specific
     * checks for trusted/protected files on Linux-SGX to fail. So the below fork checks that this
     * bug was fixed (otherwise Gramine crashes). */
    int pid = fork();
    if (pid == -1)
        err(1, "fork");

    if (pid != 0) {
        /* parent */
        int st = 0;
        ret = wait(&st);
        if (ret < 0)
            err(1, "wait");

        if (!WIFEXITED(st) || WEXITSTATUS(st) != 0)
            errx(1, "abnormal child termination: %d\n", st);

        puts("Parent process done");
    } else {
        /* child does nothing interesting */
        puts("Child process done");
    }

    fclose(fp);
    return 0;
}
