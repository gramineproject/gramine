#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

static const char* message;
static void  SIGSEGV_handler(int sig) {
    puts(message);
    exit(0);
}

static void wait_for_child(int pid) {
    int status;

    pid_t child_pid = waitpid(pid, &status, 0);
    if (child_pid < 0) {
        err(1, "waitpid");
    } else if (child_pid != pid) {
        errx(1, "wrong child pid %d\n", child_pid);
    }

    if (!WIFEXITED(status)) {
        errx(1, "child died in an unknown manner: %d\n", status);
    }
    if (WEXITSTATUS(status) != 0) {
        errx(1, "child returned wrong error code: %d\n", status);
    }
}

static void foo (void) {
    puts("I am foo");
}

static int test_case1(void) {
    pid_t child_pid = fork();
    if (child_pid == 0) {
        message = "edmm test 1 passed: Segfault writing to code(RX) section!";
        *(int*)foo = 0;
    }

    return child_pid;
}

static int test_case2(void) {
    pid_t child_pid = fork();
    if (child_pid == 0) {
        message = "edmm test 2 passed: Segfault executing in data(RW) section!";
        int on_stack_var = 5;
        int *rw_addr = &on_stack_var;

        __asm__ volatile("jmp *%0" : : "r" (rw_addr));
    }

    return child_pid;
}

static int test_case3(void) {
    pid_t child_pid = fork();
    if (child_pid == 0) {
        message = "edmm test 3 passed: Segfault writing to RO section!";
        char *str = (char*)"Hello World!"; //Suppress warning by casting to char*

        str[3] = 'L';
    }

    return child_pid;
}

int main(int argc, const char** argv) {

    if (signal(SIGSEGV, SIGSEGV_handler) == SIG_ERR) {
        err(1, "setting signal handler failed");
    }

    pid_t child_pid = test_case1();
    if (child_pid < 0) {
        err(1, "fork");
    }
    wait_for_child(child_pid);

    child_pid = test_case2();
    if (child_pid < 0) {
        err(1, "fork");
    }
    wait_for_child(child_pid);

    child_pid = test_case3();
    if (child_pid < 0) {
        err(1, "fork");
    }
    wait_for_child(child_pid);

    if (signal(SIGSEGV, SIG_DFL) == SIG_ERR) {
        err(1, "Restoring signal handler failed");
    }

    puts("TEST OK");
    return 0;
}
