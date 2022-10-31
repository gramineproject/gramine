#include "pal_regression.h"

int pal_regression_start_main(int argc, char** argv, char** envp,
                              int (*main)(int argc, char** argv, char** envp));

int pal_regression_start_main(int argc, char** argv, char** envp,
                              int (*main)(int argc, char** argv, char** envp)) {
    init_memory_management();
    return main(argc, argv, envp);
}
