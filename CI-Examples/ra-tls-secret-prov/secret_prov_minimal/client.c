/* Copyright (C) 2023 Gramine contributors
 * SPDX-License-Identifier: BSD-3-Clause */

#include <stdio.h>
#include <stdlib.h>

int main(void) {
    char* secret = getenv("SECRET_PROVISION_SECRET_STRING");
    if (secret)
        printf("--- Received secret = '%s' ---\n", secret);
    else
        printf("--- Did not receive any secret! ---\n");

    return 0;
}
