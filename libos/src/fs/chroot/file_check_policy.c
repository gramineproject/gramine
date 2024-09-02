/* Copyright (C) 2024 Intel Corporation
 *                    Dmitrii Kuvaiskii <dmitrii.kuvaiskii@intel.com>
 */

#include "api.h"
#include "libos_fs.h"
#include "toml_utils.h"

enum file_check_policy g_file_check_policy = FILE_CHECK_POLICY_STRICT;

int init_file_check_policy(void) {
    int ret;
    char* file_check_policy_str = NULL;

    assert(g_manifest_root);
    ret = toml_string_in(g_manifest_root, "sgx.file_check_policy", &file_check_policy_str);
    if (ret < 0) {
        log_error("Cannot parse 'sgx.file_check_policy'");
        return -EINVAL;
    }

    if (!file_check_policy_str)
        return 0;

    if (!strcmp(file_check_policy_str, "strict")) {
        g_file_check_policy = FILE_CHECK_POLICY_STRICT;
    } else if (!strcmp(file_check_policy_str, "allow_all_but_log")) {
        g_file_check_policy = FILE_CHECK_POLICY_ALLOW_ALL_BUT_LOG;
    } else {
        log_error("Unknown value for 'sgx.file_check_policy' "
                  "(allowed: `strict`, `allow_all_but_log`)'");
        free(file_check_policy_str);
        return -EINVAL;
    }

    log_debug("File check policy: %s", file_check_policy_str);
    free(file_check_policy_str);
    return 0;
}
