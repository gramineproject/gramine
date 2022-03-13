#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    const char* argv[] = {"scripts/foo.sh", NULL};
    execve(argv[0], argv, NULL);
    err(EXIT_FAILURE, "execve failed");
}
