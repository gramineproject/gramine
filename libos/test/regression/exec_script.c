#include <err.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    char* const argv[] = {(char*)"foo.sh", (char*)"STRING FROM EXECVE", NULL};

    /* The pathname arg to `execv()` differs from `argv[0]` on purpose: we want to test the corner
     * case where `argv[0]` is overridden by the file pathname for interpreter scripts in execve
     * family of syscalls. */
    execv("scripts/foo.sh", argv);
    err(EXIT_FAILURE, "execve failed");
}
