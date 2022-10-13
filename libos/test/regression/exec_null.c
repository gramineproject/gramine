#include <unistd.h>

int main(int argc, const char** argv, const char** envp) {
    execve("./exec_victim", NULL, NULL);
    return 1;
}
