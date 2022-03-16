#include <stdio.h>

int main(int argc, char* argv[]) {
    printf("Hello, world! Your secure arguments are: \n");
    for (int i = 0; i < argc; i++) {
        printf("argv[%d] = %s\n", i, argv[i]);
    }
    return 0;
}
