#include "api.h"
#include "pal.h"
#include "pal_regression.h"

int main(int argc, char** argv, char** envp) {
    const char* args[1] = {NULL};

    // Hack to differentiate parent from child
    if (argc == 1) {
        PAL_HANDLE child = NULL;
        int ret = DkProcessCreate(args, &child);

        if (ret == 0 && child)
            pal_printf("Creating child OK\n");
    }

    return 0;
}
