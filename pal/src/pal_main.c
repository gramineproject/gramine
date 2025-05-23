/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains the main function of the PAL loader, which loads and processes environment,
 * arguments and manifest.
 */

#include <stdbool.h>

#include "api.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_rtld.h"
#include "toml.h"
#include "toml_utils.h"

struct pal_common_state g_pal_common_state;

extern struct pal_initial_mem_range g_initial_mem_ranges[];

struct pal_public_state g_pal_public_state = {
    /* Enable log to catch early initialization errors; it will be overwritten in pal_main(). */
    .log_level = PAL_LOG_DEFAULT_LEVEL,
    .dns_host = {
        .hostname = "localhost",
    },
    .initial_mem_ranges = g_initial_mem_ranges,
    .initial_mem_ranges_len = 0,
};

struct pal_public_state* PalGetPalPublicState(void) {
    return &g_pal_public_state;
}

/* Finds `loader.env.{key}` in the manifest and returns its value in `out_val`/`out_passthrough`.
 * Recognizes several formats:
 *   - `loader.env.{key} = "val"`
 *   - `loader.env.{key} = { value = "val" }`
 *   - `loader.env.{key} = { passthrough = true|false }`
 *
 * If `loader.env.{key}` doesn't exist, then returns 0 and `*out_exists = false`. If the key exists,
 * then `*out_exists = true` and:
 *   - if passthrough is specified, then `*out_val` is NULL and `*out_passthrough` is true/false;
 *   - if the value is specified, then `*out_val` is set and `*out_passthrough` is false.
 *
 * For any other format, returns negative error code. The caller is responsible to free `out_val`.
 */
static int get_env_value_from_manifest(toml_table_t* toml_envs, const char* key, bool* out_exists,
                                       char** out_val, bool* out_passthrough) {
    int ret;

    assert(out_exists);
    assert(out_val);
    assert(out_passthrough);

    toml_table_t* toml_env_table = toml_table_in(toml_envs, key);
    if (!toml_env_table) {
        /* not table like `loader.env.key = {...}`, must be string like `loader.env.key = "val"` */
        toml_raw_t toml_env_val_raw = toml_raw_in(toml_envs, key);
        if (!toml_env_val_raw) {
            *out_val = NULL;
            *out_passthrough = false;
            *out_exists = false;
            return 0;
        }

        ret = toml_rtos(toml_env_val_raw, out_val);
        if (ret < 0)
            return PAL_ERROR_NOMEM;

        *out_passthrough = false;
        *out_exists = true;
        return 0;
    }

    toml_raw_t toml_passthrough_raw = toml_raw_in(toml_env_table, "passthrough");
    toml_raw_t toml_value_raw = toml_raw_in(toml_env_table, "value");

    if (toml_passthrough_raw && toml_value_raw) {
        /* disallow `loader.env.key = { passthrough = true, value = "val" }` */
        return PAL_ERROR_INVAL;
    }

    if (!toml_passthrough_raw) {
        /* not passthrough like `loader.env.key = { passthrough = true }`, must be value-table like
         * `loader.env.key = { value = "val" }` */
        if (!toml_value_raw)
            return PAL_ERROR_INVAL;

        ret = toml_rtos(toml_value_raw, out_val);
        if (ret < 0)
            return PAL_ERROR_NOMEM;

        *out_passthrough = false;
        *out_exists = true;
        return 0;
    }

    /* at this point, it must be `loader.env.key = { passthrough = true|false }`*/
    int passthrough_int;
    ret = toml_rtob(toml_passthrough_raw, &passthrough_int);
    if (ret < 0)
        return PAL_ERROR_INVAL;

    *out_passthrough = !!passthrough_int;
    *out_val = NULL;
    *out_exists = true;
    return 0;
}

static int create_empty_envs(const char*** out_envp) {
    const char** new_envp = malloc(sizeof(*new_envp));
    if (!new_envp)
        return PAL_ERROR_NOMEM;

    new_envp[0] = NULL;
    *out_envp = new_envp;
    return 0;
}

/* This function leaks memory on failure (and this is non-trivial to fix), but the assumption is
 * that its failure finishes the execution of the whole process right away. */
static int deep_copy_envs(const char** envp, const char*** out_envp) {
    size_t orig_envs_cnt = 0;
    for (const char** orig_env = envp; *orig_env; orig_env++)
        orig_envs_cnt++;

    const char** new_envp = calloc(orig_envs_cnt + 1, sizeof(const char*));
    if (!new_envp)
        return PAL_ERROR_NOMEM;

    size_t idx = 0;
    for (const char** orig_env = envp; *orig_env; orig_env++) {
        new_envp[idx] = strdup(*orig_env);
        if (!new_envp[idx])
            return PAL_ERROR_NOMEM;
        idx++;
    }
    assert(idx == orig_envs_cnt);

    *out_envp = new_envp;
    return 0;
}

/* Build environment for Gramine process, based on original environment (from host or file) and
 * manifest. If `propagate` is true, copies all variables from `orig_envp`, except the ones
 * overriden in manifest. Otherwise, copies only the variables from `orig_envp` that the manifest
 * specifies as passthrough.
 *
 * This function leaks memory on failure (and this is non-trivial to fix), but the assumption is
 * that its failure finishes the execution of the whole process right away. */
static int build_envs(const char** orig_envp, bool propagate, const char*** out_envp) {
    int ret;

    toml_table_t* toml_loader = toml_table_in(g_pal_public_state.manifest_root, "loader");
    if (!toml_loader)
        return propagate ? deep_copy_envs(orig_envp, out_envp) : create_empty_envs(out_envp);

    toml_table_t* toml_envs = toml_table_in(toml_loader, "env");
    if (!toml_envs)
        return propagate ? deep_copy_envs(orig_envp, out_envp) : create_empty_envs(out_envp);

    ssize_t toml_envs_cnt = toml_table_nkval(toml_envs);
    if (toml_envs_cnt < 0)
        return PAL_ERROR_INVAL;

    ssize_t toml_env_tables_cnt = toml_table_ntab(toml_envs);
    if (toml_env_tables_cnt < 0)
        return PAL_ERROR_INVAL;

    toml_envs_cnt += toml_env_tables_cnt;
    if (toml_envs_cnt == 0)
        return propagate ? deep_copy_envs(orig_envp, out_envp) : create_empty_envs(out_envp);

    size_t orig_envs_cnt = 0;
    for (const char** orig_env = orig_envp; *orig_env; orig_env++)
        orig_envs_cnt++;

    /* For simplicity, overapproximate the number of envs by summing up the ones found in the
     * original environment and the ones found in the manifest. */
    size_t total_envs_cnt = orig_envs_cnt + toml_envs_cnt;
    const char** new_envp = calloc(total_envs_cnt + 1, sizeof(const char*));
    if (!new_envp)
        return PAL_ERROR_NOMEM;

    size_t idx = 0;

    /* First, go through original variables and copy the ones that we're going to use (because of
     * `propagate`, or because passthrough is specified for that variable in manifest). */
    for (const char** orig_env = orig_envp; *orig_env; orig_env++) {
        char* orig_env_key_end = strchr(*orig_env, '=');
        if (!orig_env_key_end)
            return PAL_ERROR_INVAL;

        char* env_key = alloc_substr(*orig_env, orig_env_key_end - *orig_env);
        if (!env_key)
            return PAL_ERROR_NOMEM;

        bool exists;
        char* env_val;
        bool passthrough;
        ret = get_env_value_from_manifest(toml_envs, env_key, &exists, &env_val, &passthrough);
        if (ret < 0) {
            log_error("Invalid environment variable in manifest: '%s'", env_key);
            return ret;
        }

        if ((propagate && !exists) || (exists && passthrough)) {
            new_envp[idx] = strdup(*orig_env);
            if (!new_envp[idx])
                return PAL_ERROR_NOMEM;
            idx++;
        }

        free(env_key);
        free(env_val);
    }

    /* Then, go through the manifest variables and copy the ones with value provided. */
    for (ssize_t i = 0; i < toml_envs_cnt; i++) {
        const char* toml_env_key = toml_key_in(toml_envs, i);
        assert(toml_env_key);

        bool exists;
        char* env_val;
        bool passthrough;
        ret = get_env_value_from_manifest(toml_envs, toml_env_key, &exists, &env_val, &passthrough);
        if (ret < 0) {
            log_error("Invalid environment variable in manifest: '%s'", toml_env_key);
            return ret;
        }

        assert(exists);
        if (!env_val && !passthrough) {
            log_error("Detected environment variable '%s' with `passthrough = false`. For security"
                      " reasons, Gramine doesn't allow this. Please see documentation on"
                      " 'loader.env' for details.", toml_env_key);
            return PAL_ERROR_DENIED;
        }

        if (!env_val) {
            /* this is envvar with passthrough = true, we accounted for it in previous loop */
            continue;
        }

        char* final_env = alloc_concat3(toml_env_key, -1, "=", 1, env_val, -1);
        if (!final_env)
            return PAL_ERROR_NOMEM;

        new_envp[idx++] = final_env;
        free(env_val);
    }
    assert(idx <= total_envs_cnt);

    *out_envp = new_envp;
    return 0;
}

static void configure_logging(void) {
    int ret = 0;
    int log_level = PAL_LOG_DEFAULT_LEVEL;

    char* log_level_str = NULL;
    ret = toml_string_in(g_pal_public_state.manifest_root, "loader.log_level", &log_level_str);
    if (ret < 0)
        INIT_FAIL_MANIFEST("Cannot parse 'loader.log_level'");

    if (log_level_str) {
        if (!strcmp(log_level_str, "none")) {
            log_level = LOG_LEVEL_NONE;
        } else if (!strcmp(log_level_str, "error")) {
            log_level = LOG_LEVEL_ERROR;
        } else if (!strcmp(log_level_str, "warning")) {
            log_level = LOG_LEVEL_WARNING;
        } else if (!strcmp(log_level_str, "debug")) {
            log_level = LOG_LEVEL_DEBUG;
        } else if (!strcmp(log_level_str, "trace")) {
            log_level = LOG_LEVEL_TRACE;
        } else if (!strcmp(log_level_str, "all")) {
            log_level = LOG_LEVEL_ALL;
        } else {
            INIT_FAIL_MANIFEST("Unknown 'loader.log_level'");
        }
    }
    free(log_level_str);

    char* log_file = NULL;
    ret = toml_string_in(g_pal_public_state.manifest_root, "loader.log_file", &log_file);
    if (ret < 0)
        INIT_FAIL_MANIFEST("Cannot parse 'loader.log_file'");

    if (log_file && log_level > LOG_LEVEL_NONE) {
        ret = _PalInitDebugStream(log_file);

        if (ret < 0)
            INIT_FAIL("Cannot open log file: %s", pal_strerror(ret));
    }
    free(log_file);

    g_pal_public_state.log_level = log_level;
}

/* Loads a file containing a concatenation of C-strings. The resulting array of pointers is
 * NULL-terminated. All C-strings inside it reside in a single malloc-ed buffer starting at
 * `(*res)[0]`. The caller must free `(*res)[0]` and then `*res` when done with the array. */
static int load_cstring_array(const char* uri, const char*** res) {
    PAL_HANDLE hdl;
    PAL_STREAM_ATTR attr;
    char* buf = NULL;
    const char** array = NULL;
    int ret;

    ret = _PalStreamOpen(&hdl, uri, PAL_ACCESS_RDONLY, /*share_flags=*/0, PAL_CREATE_NEVER,
                         /*options=*/0);
    if (ret < 0)
        return ret;
    ret = _PalStreamAttributesQueryByHandle(hdl, &attr);
    if (ret < 0)
        goto out_fail;
    size_t file_size = attr.pending_size;
    buf = malloc(file_size);
    if (!buf) {
        ret = PAL_ERROR_NOMEM;
        goto out_fail;
    }
    ret = _PalStreamRead(hdl, 0, file_size, buf);
    if (ret < 0)
        goto out_fail;
    if (file_size > 0 && buf[file_size - 1] != '\0') {
        ret = PAL_ERROR_INVAL;
        goto out_fail;
    }

    size_t count = 0;
    for (size_t i = 0; i < file_size; i++)
        if (buf[i] == '\0')
            count++;
    array = malloc(sizeof(char*) * (count + 1));
    if (!array) {
        ret = PAL_ERROR_NOMEM;
        goto out_fail;
    }
    array[count] = NULL;
    if (file_size > 0) {
        const char** argv_it = array;
        *(argv_it++) = buf;
        for (size_t i = 0; i < file_size - 1; i++)
            if (buf[i] == '\0')
                *(argv_it++) = buf + i + 1;
    }
    *res = array;
    _PalObjectDestroy(hdl);
    return 0;

out_fail:
    _PalObjectDestroy(hdl);
    free(buf);
    free(array);
    return ret;
}

/* 'pal_main' must be called by the host-specific loader.
 * At this point the manifest is assumed to be already parsed, because some PAL loaders use manifest
 * configuration for early initialization.
 */
noreturn void pal_main(uint64_t instance_id,       /* current instance id */
                       PAL_HANDLE parent_process,  /* parent process if it's a child */
                       PAL_HANDLE first_thread,    /* first thread handle */
                       const char** arguments,     /* application arguments */
                       const char** environments,  /* environment variables */
                       void (*post_callback)(void) /* callback into host-specific loader */) {
    if (!instance_id) {
        assert(!parent_process);
        if (_PalRandomBitsRead(&instance_id, sizeof(instance_id)) < 0) {
            INIT_FAIL("Could not generate random instance_id");
        }
    }
    g_pal_public_state.instance_id = instance_id;
    g_pal_common_state.parent_process = parent_process;

    ssize_t ret;

    assert(g_pal_public_state.manifest_root);
    assert(g_pal_public_state.alloc_align && IS_POWER_OF_2(g_pal_public_state.alloc_align));

    configure_logging();

    toml_table_t* manifest_loader = toml_table_in(g_pal_public_state.manifest_root, "loader");
    if (manifest_loader == NULL) {
        INIT_FAIL("'loader' section wasn't configured in the manifest, at least "
                  "'loader.entrypoint.uri' needs to be defined");
    }

    char* dummy_exec_str = NULL;
    ret = toml_string_in(manifest_loader, "exec", &dummy_exec_str);
    if (ret < 0 || dummy_exec_str) {
        INIT_FAIL("'loader.exec' is not supported anymore. Please update your manifest according "
                  "to the current documentation.");
    }
    free(dummy_exec_str);

    bool disable_aslr;
    ret = toml_bool_in(manifest_loader, "insecure__disable_aslr", /*defaultval=*/false,
                       &disable_aslr);
    if (ret < 0) {
        INIT_FAIL_MANIFEST("Cannot parse 'loader.insecure__disable_aslr' (the value must be "
                           "`true` or `false`)");
    }

    /* Load argv */
    bool use_cmdline_argv;
    ret = toml_bool_in(manifest_loader, "insecure__use_cmdline_argv", /*defaultval=*/false,
                       &use_cmdline_argv);
    if (ret < 0) {
        INIT_FAIL_MANIFEST("Cannot parse 'loader.insecure__use_cmdline_argv' (the value must be "
                           "`true` or `false`)");
    }
    char* argv_src_file = NULL;
    ret = toml_string_in(manifest_loader, "argv_src_file", &argv_src_file);
    if (ret < 0)
        INIT_FAIL_MANIFEST("Cannot parse 'loader.argv_src_file'");

    size_t manifest_argv_cnt = 0;
    toml_array_t* manifest_argv = toml_array_in(manifest_loader, "argv");
    if (manifest_argv) {
        int argv_nelem = toml_array_nelem(manifest_argv);
        if (argv_nelem < 0)
            INIT_FAIL_MANIFEST("Cannot parse 'loader.argv'");
        /* XXX: Remove this when the support of argc == 0 is added. */
        if (argv_nelem == 0)
            INIT_FAIL_MANIFEST("'loader.argv' has no arguments, this is unsupported");
        manifest_argv_cnt = argv_nelem;
    }

    if ((use_cmdline_argv ? 1 : 0) + (manifest_argv_cnt > 0 ? 1 : 0) + (argv_src_file ? 1 : 0) > 1) {
        INIT_FAIL_MANIFEST("Options loader.argv, loader.argv_src_file, and "
                           "loader.insecure__use_cmdline_argv are mutually exclusive");
    }

    char* argv0_override = NULL;
    ret = toml_string_in(g_pal_public_state.manifest_root, "libos.entrypoint", &argv0_override);
    if (ret < 0)
        INIT_FAIL_MANIFEST("Cannot parse 'libos.entrypoint'");

    if (!argv0_override) {
        /* possible in e.g. PAL regression tests, in this case use loader.entrypoint.uri */
        ret = toml_string_in(manifest_loader, "entrypoint.uri", &argv0_override);
        if (ret < 0)
            INIT_FAIL_MANIFEST("Cannot parse 'loader.entrypoint.uri'");

        if (!argv0_override)
            INIT_FAIL("'libos.entrypoint' and 'loader.entrypoint.uri' are not specified in "
                      "the manifest");
    }

    if (use_cmdline_argv) {
        if (!parent_process) {
            /* argv[0] in host cmdline args is the name of manifest, but app expects the entrypoint */
            if (!arguments[0])
                INIT_FAIL("Gramine started with no arguments, this is unsupported");
            arguments[0] = argv0_override;
        }
    } else if (manifest_argv_cnt > 0) {
        /* Load argv from a manifest and discard cmdline argv. */
        if (arguments[0] && arguments[1]) {
            log_error("Discarding cmdline arguments (%s %s [...]) because loader.argv was "
                      "specified in the manifest.", arguments[0], arguments[1]);
        }

        const char** new_args = malloc(sizeof(*new_args) * (manifest_argv_cnt + 1));
        if (new_args == NULL) {
            INIT_FAIL("Cannot allocate memory for arguments");
        }

        for (size_t i = 0; i < manifest_argv_cnt; i++) {
            toml_datum_t toml_arg = toml_string_at(manifest_argv, i);
            if (!toml_arg.ok) {
                INIT_FAIL("Cannot parse argv[%zd]", i);
            }
            new_args[i] = toml_arg.u.s;
        }
        new_args[manifest_argv_cnt] = NULL;
        arguments = new_args;
    } else if (argv_src_file) {
        /* Load argv from a file and discard cmdline argv. We trust the file contents (this can
         * be achieved using trusted files). */
         if (arguments[0] && arguments[1]) {
            log_error("Discarding cmdline arguments (%s %s [...]) because loader.argv_src_file "
                      "was specified in the manifest.", arguments[0], arguments[1]);
        }

        ret = load_cstring_array(argv_src_file, &arguments);
        if (ret < 0)
            INIT_FAIL("Cannot load arguments from 'loader.argv_src_file': %s", pal_strerror(ret));

        free(argv_src_file);
    } else if (arguments[0] && arguments[1]) {
        INIT_FAIL("argv handling wasn't configured in the manifest, but cmdline arguments were "
                  "specified.");
    } else if (!parent_process) {
        /* no argv handling and no cmdline args -- override argv[0] with entrypoint */
        arguments = malloc(sizeof(const char*) * 2);
        if (!arguments)
            INIT_FAIL("malloc() failed");

        arguments[0] = argv0_override;
        arguments[1] = NULL;
    }

    const char** orig_environments  = NULL;
    const char** final_environments = NULL;

    bool use_host_env;
    ret = toml_bool_in(manifest_loader, "insecure__use_host_env", /*defaultval=*/false,
                       &use_host_env);
    if (ret < 0) {
        INIT_FAIL_MANIFEST("Cannot parse 'loader.insecure__use_host_env' (the value must be `true` "
                           "or `false`)");
    }

    char* env_src_file = NULL;
    ret = toml_string_in(manifest_loader, "env_src_file", &env_src_file);
    if (ret < 0)
        INIT_FAIL_MANIFEST("Cannot parse 'loader.env_src_file'");

    if (use_host_env && env_src_file)
        INIT_FAIL("Wrong manifest configuration - cannot use loader.insecure__use_host_env and "
                  "loader.env_src_file at the same time.");

    if (env_src_file) {
        /* Insert environment variables from a file. We trust the file contents (this can be
         * achieved using trusted files). */
        ret = load_cstring_array(env_src_file, &orig_environments);
        if (ret < 0) {
            INIT_FAIL("Cannot load environment variables from 'loader.env_src_file': %s",
                      pal_strerror(ret));
        }
    } else {
        /* Environment variables are taken from the host. */
        orig_environments = environments;
    }

    // TODO: Envs from file should be able to override ones from the manifest, but current
    // code makes this hard to implement.
    ret = build_envs(orig_environments, /*propagate=*/use_host_env || env_src_file,
                     &final_environments);
    if (ret < 0) {
        INIT_FAIL("Building the final environment based on the original environment and the "
                  "manifest failed: %s", pal_strerror(ret));
    }

    if (orig_environments != environments) {
        free((char*)orig_environments[0]);
        free(orig_environments);
    }
    free(env_src_file);

    char* entrypoint_name = NULL;
    ret = toml_string_in(manifest_loader, "entrypoint.uri", &entrypoint_name);
    if (ret < 0)
        INIT_FAIL_MANIFEST("Cannot parse 'loader.entrypoint.uri'");

    if (!entrypoint_name)
        INIT_FAIL("No 'loader.entrypoint.uri' is specified in the manifest");

    if (!strstartswith(entrypoint_name, URI_PREFIX_FILE))
        INIT_FAIL("'loader.entrypoint.uri' is missing the 'file:' prefix");

    g_pal_public_state.host_type       = XSTRINGIFY(HOST_TYPE);
    g_pal_public_state.parent_process  = parent_process;
    g_pal_public_state.first_thread    = first_thread;
    g_pal_public_state.disable_aslr    = disable_aslr;

    if (_PalGetCPUInfo(&g_pal_public_state.cpu_info) < 0) {
        goto out_fail;
    }
    g_pal_public_state.mem_total = _PalMemoryQuota();

    ret = load_entrypoint(entrypoint_name);
    if (ret < 0)
        INIT_FAIL("Unable to load loader entrypoint: %ld", ret);
    free(entrypoint_name);

    if (post_callback)
        post_callback();

    pal_disable_early_memory_bookkeeping();

    /* Now we will start the execution */
    start_execution(arguments, final_environments);

out_fail:
    /* We wish we will never reached here */
    INIT_FAIL("unexpected termination");
}
