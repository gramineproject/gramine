#pragma once

/* mmap minimum address cannot start at zero (modern OSes do not allow this) */
#define MMAP_MIN_ADDR 0x10000

#define THREAD_STACK_SIZE (PRESET_PAGESIZE * 16) /* 64KB user stack */
#define ALT_STACK_SIZE    (PRESET_PAGESIZE * 16) /* 64KB signal stack */
