#include <err.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    char* const argv[] = {(char*)"foo.sh", (char*)"STRING FROM EXECVE", NULL};
    execv("scripts/foo.sh", argv);
    err(EXIT_FAILURE, "execve failed");
}
