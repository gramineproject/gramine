#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>

int main(void) {
    const char* argv[] = {"scripts/foo.sh"};
    int ret = execve (argv[0], argv, NULL);
    printf ("ret = %d\n", ret);
    err(EXIT_FAILURE, "execve failed");
}
