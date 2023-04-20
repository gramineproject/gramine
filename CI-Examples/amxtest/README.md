# AMX test

This directory contains a Makefile and a manifest template for running two
simple AMX tests in Gramine:

- The EEXIT/EENTER test performs 10,000,000 `sched_yield()` system calls. This
  system call is chosen because it maps 1:1 to the actual host syscall in case
  of Gramine. In other words, every `sched_yield()` in the test app results in
  one EEXIT -> host `sched_yield` -> EENTER in Gramine-SGX.

  Thus, this test can be used as a micro-benchmark of latency of EEXIT/EENTER
  SGX flows, including the XSAVE/XRSTOR done as part of these EEXIT/EENTER
  flows.

- The AEX/ERESUME test performs 10,000,000 AEXs due to the `ud2` illegal
  instruction. The Gramine PAL code is modified in such a way as to *not* EENTER
  the exception-handling stage of the SGX enclave but instead simply perform
  ERESUME. After 10,000,000 AEXs, Gramine PAL code terminates the enclave.

  Thus, this test can be used as a micro-benchmark of latency of AEX/ERESUME SGX
  flows, including the XSAVE/XRSTOR done as part of these AEX/ERESUME flows.

# Building

Run `make` or `make SGX=1` in the directory.

# Run with Gramine

- Modify `sgx.cpu_features.amx` manifest option to enable/disable AMX feature
  inside the SGX enclave (i.e., hide the AMX feature from XSAVE/XRSTOR flows).

- (Optional) Modify SSA frame size in Gramine to test different SSA sizes. For
  this, patch Gramine with: `#define SSA_FRAME_SIZE (PRESET_PAGESIZE * xxx)` and
  rebuild Gramine.

- Remove `sched_yield()` syscall invocation from Gramine PAL file
  `host_ocalls.c:sgx_ocall_sched_yield()`. This is to remove Linux-host side
  effects (of context switching the Gramine process) and thus to make the
  EEXIT/EENTER experiment cleaner.

- Don't forget to test with Gramine built *in release mode*!

- Pin the Gramine process to NUMA node 0: `numactl --membind 0 --cpunodebind 0
  gramine-sgx ...`.

## EEXIT/EENTER experiment

Without SGX (shown for sanity, actually has no difference):
```sh
# run without initializing AMX feature (so-called XINUSE)
gramine-direct amxtest eexit
# run with initializing AMX feature (argv[2] can be any string)
gramine-direct amxtest eexit inuse
```

With SGX:
```sh
# run without initializing AMX feature (so-called XINUSE)
gramine-sgx amxtest eexit
# run with initializing AMX feature (argv[2] can be any string)
gramine-sgx amxtest eexit inuse
```

## AEX/ERESUME experiment

With SGX:
```sh
# run without initializing AMX feature (so-called XINUSE)
gramine-sgx amxtest aex
# run with initializing AMX feature (argv[2] can be any string)
gramine-sgx amxtest aex inuse
```

For the AEX/ERESUME experiment, we need a patch like this in Gramine:
```diff
diff --git a/pal/src/host/linux-sgx/host_exception.c b/pal/src/host/linux-sgx/host_exception.c
@@ -102,6 +102,35 @@ static void handle_sync_signal(int signum, siginfo_t* info, struct ucontext* uc)

     __UNUSED(info);

+    extern bool g_start_aex_experiment;
+    if (g_start_aex_experiment && event == PAL_EVENT_ILLEGAL) {
+#define LOOPS (10 * 1000 * 1000)
+
+        static uint64_t g_aex_num = 0;
+        static uint64_t g_start_time_us = 0;
+        static uint64_t g_end_time_us   = 0;
+
+        if (g_aex_num == 0) {
+            struct timeval tv;
+            DO_SYSCALL(gettimeofday, &tv, NULL);
+            g_start_time_us = tv.tv_sec * (uint64_t)1000000 + tv.tv_usec;
+            log_always("Gramine PAL starts AEX/ERESUME experiment (for %d iterations)", LOOPS);
+        } else if (g_aex_num == LOOPS) {
+            struct timeval tv;
+            DO_SYSCALL(gettimeofday, &tv, NULL);
+            g_end_time_us = tv.tv_sec * (uint64_t)1000000 + tv.tv_usec;
+
+            log_always("done in %lu microseconds", g_end_time_us - g_start_time_us);
+
+            update_and_print_stats(/*process_wide=*/true);
+            DO_SYSCALL(exit_group, 0);
+            return;
+        }
+
+        g_aex_num++;
+        return;
+    }
+
     /* send dummy signal to RPC threads so they interrupt blocked syscalls */
     if (g_rpc_queue)
         for (size_t i = 0; i < g_rpc_queue->rpc_threads_cnt; i++)
diff --git a/pal/src/host/linux-sgx/host_ocalls.c b/pal/src/host/linux-sgx/host_ocalls.c
@@ -28,6 +28,8 @@

 #define DEFAULT_BACKLOG 2048

+bool g_start_aex_experiment = false;
+
 extern bool g_vtune_profile_enabled;

 rpc_queue_t* g_rpc_queue = NULL; /* pointer to untrusted queue */
@@ -630,7 +632,12 @@ static long sgx_ocall_gettime(void* args) {

 static long sgx_ocall_sched_yield(void* args) {
     __UNUSED(args);
+#if 1
+    g_start_aex_experiment = true;
+#endif
+#if 0 // To not have any additional overhead
     DO_SYSCALL_INTERRUPTIBLE(sched_yield);
+#endif
     return 0;
 }
```
