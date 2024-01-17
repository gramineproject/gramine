#include "api.h"
#include "pal.h"
#include "pal_regression.h"

int main(int argc, char** argv, char** envp) {
    char buffer1[20] = "Hello World 1";
    char buffer2[20] = "Hello World 2";
    char buffer3[20];
    char buffer4[20];
    int ret;

    PAL_HANDLE pipe1 = NULL;
    ret = PalStreamOpen("pipe.srv:1", PAL_ACCESS_RDWR, /*share_flags=*/0, PAL_CREATE_IGNORED,
                        /*options=*/0, false, &pipe1);

    if (ret >= 0 && pipe1) {
        pal_printf("Pipe Creation 1 OK\n");

        // DEP 10/24/16: Try to read some attributes of the pipe
        PAL_STREAM_ATTR attr;
        ret = PalStreamAttributesQueryByHandle(pipe1, &attr);
        if (ret < 0) {
            pal_printf("Failed to get any attributes from the pipesrv\n");
            return 1;
        } else {
            pal_printf("Pipe Attribute Query 1 on pipesrv returned OK\n");
        }
        // DEP: would be nice to sanity check the attributes.
        // Job for another day...

        PAL_HANDLE pipe2 = NULL;
        ret = PalStreamOpen("pipe:1", PAL_ACCESS_RDWR, /*share_flags=*/0, PAL_CREATE_IGNORED,
                            /*options=*/0, false, &pipe2);

        if (ret >= 0 && pipe2) {
            PAL_HANDLE pipe3 = NULL;
            ret = PalStreamWaitForClient(pipe1, &pipe3, /*options=*/0);

            if (ret >= 0 && pipe3) {
                pal_printf("Pipe Connection 1 OK\n");

                size_t size = sizeof(buffer1);
                ret = PalStreamWrite(pipe3, 0, &size, buffer1);
                if (ret == 0 && size > 0)
                    pal_printf("Pipe Write 1 OK\n");

                size = sizeof(buffer3);
                ret = PalStreamRead(pipe2, 0, &size, buffer3);
                if (ret == 0 && size > 0)
                    pal_printf("Pipe Read 1: %s\n", buffer3);

                size = sizeof(buffer2);
                ret = PalStreamWrite(pipe2, 0, &size, buffer2);
                if (ret == 0 && size > 0)
                    pal_printf("Pipe Write 2 OK\n");

                size = sizeof(buffer4);
                ret = PalStreamRead(pipe3, 0, &size, buffer4);
                if (ret == 0 && size > 0)
                    pal_printf("Pipe Read 2: %s\n", buffer4);
            }
        }
    }

    return 0;
}
