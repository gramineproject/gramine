/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 */

/*!
 * \brief Get CPU feature flags.
 *
 * \param[out] out_cpu_flags  On success, set to CPU feature flags.
 *
 * \returns 0 on success, negative on failure.
 *
 * This function returns a new buffer with CPU feature flags, the caller is responsible to free it
 * afterwards.
 */
int libos_get_cpu_flags(char** out_cpu_flags);
