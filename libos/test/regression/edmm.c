#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

static void sigsegv_handler(int sig) {
    _exit(0);
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

static void foo(void) {
    puts("I am foo");
}

static int test_segfault_on_write_to_rx_page(void) {
    pid_t child_pid = fork();
    if (child_pid == 0) {
        int* ptr = (int*)foo;

        /* *ptr = 0; */
        __asm__ volatile("movq $0, (%0)\n" : "=r"(ptr) : : "memory");

        exit(1); /* child must not survive the write to RX page above */
    }

    return child_pid;
}

static int test_segfault_on_exec_to_rw_page(void) {
    pid_t child_pid = fork();
    if (child_pid == 0) {
        int on_stack_var = 5;
        int* rw_addr = &on_stack_var;

        __asm__ volatile("jmp *%0" : : "r" (rw_addr));

        exit(1); /* child must not survive exec attempt of RW page above */
    }

    return child_pid;
}

static int test_segfault_on_write_to_ro_page(void) {
    pid_t child_pid = fork();
    if (child_pid == 0) {
        char* str = (char*)"Hello World!"; /* suppress const warning by casting to char* */

        /* str[3] = 'L'; */
        __asm__ volatile("movq $104, (%0)\n" : "=r"(str) : : "memory");

        exit(1); /* child must not survive the write to RO page above */
    }

    return child_pid;
}

int main(void) {
    if (signal(SIGSEGV, sigsegv_handler) == SIG_ERR) {
        err(1, "setting signal handler failed");
    }

    pid_t child_pid = test_segfault_on_write_to_rx_page();
    if (child_pid < 0) {
        err(1, "fork");
    }
    wait_for_child(child_pid);

    child_pid = test_segfault_on_exec_to_rw_page();
    if (child_pid < 0) {
        err(1, "fork");
    }
    wait_for_child(child_pid);

    child_pid = test_segfault_on_write_to_ro_page();
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
