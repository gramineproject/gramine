/* SPDX-License-Identifier: LGPL-3.0-or-later */

#pragma once

void handle_ecall(long ecall_index, void* ecall_args, void* exit_target, void* enclave_base_addr);
