/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2024 Intel Corporation */

#include "api.h"
#include "libos_internal.h"
#include "toml.h"
#include "toml_utils.h"

static bool warn_about_allowed_files_usage(void) {
    toml_table_t* manifest_sgx = toml_table_in(g_pal_public_state->manifest_root, "sgx");
    if (!manifest_sgx)
        return false;
    toml_array_t* toml_allowed_files = toml_array_in(manifest_sgx, "allowed_files");
    if (!toml_allowed_files)
        return false;

    return true;
}

static bool warn_about_fs_insecure_keys(void) {
    toml_table_t* manifest_fs = toml_table_in(g_pal_public_state->manifest_root, "fs");
    if (!manifest_fs)
        return false;
    toml_table_t* manifest_fs_keys = toml_table_in(manifest_fs, "insecure__keys");
    if (!manifest_fs_keys)
        return false;
    return toml_table_nkval(manifest_fs_keys) > 0;
}

int print_warnings_on_insecure_configs(bool is_initial_process) {
    int ret;

    if (!g_pal_public_state->confidential_computing) {
        /* Warn only in confidential-computing environments. */
        return 0;
    }

    if (!is_initial_process) {
        /* Warn only in the first process. */
        return 0;
    }

    bool verbose_log_level    = false;
    bool sgx_debug            = false;
    bool use_cmdline_argv     = false;
    bool use_host_env         = false;
    bool disable_aslr         = false;
    bool allow_eventfd        = false;
    bool experimental_flock   = false;
    bool allow_all_files      = false;
    bool use_allowed_files    = warn_about_allowed_files_usage();
    bool encrypted_files_keys = warn_about_fs_insecure_keys();
    bool memfaults_without_exinfo_allowed = false;

    char* log_level_str = NULL;
    char* file_check_policy_str = NULL;

    ret = toml_string_in(g_pal_public_state->manifest_root, "loader.log_level", &log_level_str);
    if (ret < 0)
        goto out;
    if (log_level_str && strcmp(log_level_str, "none") && strcmp(log_level_str, "error"))
        verbose_log_level = true;

    ret = toml_bool_in(g_pal_public_state->manifest_root, "sgx.debug",
                       /*defaultval=*/false, &sgx_debug);
    if (ret < 0)
        goto out;

    ret = toml_bool_in(g_pal_public_state->manifest_root, "loader.insecure__use_cmdline_argv",
                       /*defaultval=*/false, &use_cmdline_argv);
    if (ret < 0)
        goto out;

    ret = toml_bool_in(g_pal_public_state->manifest_root, "loader.insecure__use_host_env",
                       /*defaultval=*/false, &use_host_env);
    if (ret < 0)
        goto out;

    ret = toml_bool_in(g_pal_public_state->manifest_root, "loader.insecure__disable_aslr",
                       /*defaultval=*/false, &disable_aslr);
    if (ret < 0)
        goto out;

    ret = toml_bool_in(g_pal_public_state->manifest_root, "sys.insecure__allow_eventfd",
                       /*defaultval=*/false, &allow_eventfd);
    if (ret < 0)
        goto out;

    ret = toml_bool_in(g_pal_public_state->manifest_root, "sys.experimental__enable_flock",
                       /*defaultval=*/false, &experimental_flock);
    if (ret < 0)
        goto out;

    ret = toml_string_in(g_pal_public_state->manifest_root, "sgx.file_check_policy",
                         &file_check_policy_str);
    if (ret < 0)
        goto out;
    if (file_check_policy_str && !strcmp(file_check_policy_str, "allow_all_but_log"))
        allow_all_files = true;

    ret = toml_bool_in(g_pal_public_state->manifest_root,
                       "sgx.insecure__allow_memfaults_without_exinfo",
                       /*defaultval=*/false, &memfaults_without_exinfo_allowed);
    if (ret < 0)
        goto out;

    if (!verbose_log_level && !sgx_debug && !use_cmdline_argv && !use_host_env && !disable_aslr &&
            !allow_eventfd && !experimental_flock && !allow_all_files && !use_allowed_files &&
            !encrypted_files_keys && !memfaults_without_exinfo_allowed) {
        /* there are no insecure configurations, skip printing */
        ret = 0;
        goto out;
    }

    log_always("-------------------------------------------------------------------------------"
               "----------------------------------------");
    log_always("Gramine detected the following insecure configurations:\n");

    if (sgx_debug)
        log_always("  - sgx.debug = true                           "
                   "(this is a debug enclave)");

    if (verbose_log_level)
        log_always("  - loader.log_level = warning|debug|trace|all "
                   "(verbose log level, may leak information)");

    if (use_cmdline_argv)
        log_always("  - loader.insecure__use_cmdline_argv = true   "
                   "(forwarding command-line args from untrusted host to the app)");

    if (use_host_env)
        log_always("  - loader.insecure__use_host_env = true       "
                   "(forwarding environment vars from untrusted host to the app)");

    if (disable_aslr)
        log_always("  - loader.insecure__disable_aslr = true       "
                   "(Address Space Layout Randomization is disabled)");

    if (allow_eventfd)
        log_always("  - sys.insecure__allow_eventfd = true         "
                   "(host-based eventfd is enabled)");

    if (experimental_flock)
        log_always("  - sys.experimental__enable_flock = true      "
                   "(flock syscall is enabled; still under development and may contain bugs)");

    if (memfaults_without_exinfo_allowed)
        log_always("  - sgx.insecure__allow_memfaults_without_exinfo "
                   "(allow memory faults even when SGX EXINFO is not supported by CPU)");

    if (allow_all_files)
        log_always("  - sgx.file_check_policy = allow_all_but_log  "
                   "(all files are passed through from untrusted host without verification)");

    if (use_allowed_files)
        log_always("  - sgx.allowed_files = [ ... ]                "
                   "(some files are passed through from untrusted host without verification)");

    if (encrypted_files_keys)
        log_always("  - fs.insecure__keys.* = \"...\"                "
                   "(keys hardcoded in manifest)");


    log_always("\nGramine will continue application execution, but this configuration must not be "
               "used in production!");
    log_always("-------------------------------------------------------------------------------"
               "----------------------------------------\n");

    ret = 0;
out:
    free(file_check_policy_str);
    free(log_level_str);
    return ret;
}

