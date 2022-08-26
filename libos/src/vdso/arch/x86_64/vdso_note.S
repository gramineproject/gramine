#include "gramine_hash.h"

    /* This .note section informs dynamic linker about vDSO */
    .section .note.Linux, "a", @note

    .balign 4
    .long   2f - 1f /* namesz */
    .long   4       /* descsz */
    .long   0       /* type */
1:  .asciz  "Linux" /* name */
2:  .balign 4
    .long   0x41300 /* desc: LINUX_VERSION_CODE */

    /* Already aligned to 4. */
    .long   2f - 1f /* namesz */
    .long   4f - 3f /* descsz */
    .long   0x100   /* type */
1:  .asciz  "Linux" /* name */
2:  .balign 4
3:  .asciz  GRAMINE_COMMIT_HASH
4:  .balign 4
