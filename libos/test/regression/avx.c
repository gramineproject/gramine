/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation
 *                    Dmitrii Kuvaiskii <dmitrii.kuvaiskii@intel.com>
 */

/*
 * This tests that optional CPU features are enabled inside of Gramine.
 *
 * This is particularly important for Intel SGX: it has SIGSTRUCT.ATTRIBUTES.XFRM that prohibits
 * using CPU features unless they are explicitly set (during Gramine startup and only if
 * SIGSTRUCT.ATTRIBUTE_MASK.XFRM allows it).
 */

#include <immintrin.h>
#include <stdalign.h>
#include <stdio.h>

int main(void) {
    alignas(32) float floats[8] = {1.0, 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7};

    __m256 avx_vector = _mm256_load_ps(&floats[0]);
    avx_vector = _mm256_add_ps(avx_vector, avx_vector);
    _mm256_store_ps(&floats[0], avx_vector);

    puts("result: ");
    for (size_t i = 0; i < sizeof(floats)/sizeof(floats[0]); i++) {
        printf("%f ", floats[i]);
    }
    puts("");

    puts("TEST OK");
    return 0;
}
