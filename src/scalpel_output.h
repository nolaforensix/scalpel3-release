//
// SPDX-License-Identifier: GPL-3.0-only
//
// The Scalpel Project is Copyright (C) 2005-2026 by Golden G. Richard III
// and contributors.
//
// Scalpel3 is Copyright (C) 2021-2026 by Golden G. Richard III and the
// contributors listed in AUTHORS.
//
// This file is part of Scalpel3.
//
// Scalpel3 is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free
// Software Foundation, version 3 only.
//
// Scalpel3 is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along
// with Scalpel3. If not, see <https://www.gnu.org/licenses/>.
//
// For proprietary or commercial use cases that require integration or
// support, contact Golden G. Richard III (golden@cct.lsu.edu) to discuss
// commercial licensing.
//
// Please see LICENSE.md, README.md, and THIRD_PARTY_NOTICES for details.
//

#ifndef SCALPEL_OUTPUT_H
#define SCALPEL_OUTPUT_H

#include <stdarg.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

// Existing util.c output helpers, without the carving/ONNX types in scalpel.h.
// Do not call from state-print callbacks or code already holding the print lock.
void lock_fprintf(FILE *stream, const char *format, ...) __attribute__((format(printf, 2, 3)));
void lock_fprintf_argp(FILE *stream, const char *format, va_list argp);
void lock_fputc(char c, FILE *stream);

#ifdef __cplusplus
}
#endif

#endif
