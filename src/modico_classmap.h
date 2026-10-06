//
// SPDX-License-Identifier: GPL-3.0-only
//
// Scalpel3 is Copyright (C) 2021-2026 by Golden G. Richard III and contributors.
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

/**
 * @author James Ghawaly
 */

/*
 * modico_classmap.h — map MoDiCo class indices to Scalpel SearchSpec types.
 *
 * MoDiCo outputs a probability over 619 file-type classes (by index). Scalpel
 * carves a much smaller set of types (its SearchSpec list). This module reads
 * the MoDiCo class-names file (the SAME class_names.json the training/eval
 * pipeline uses — a flat JSON array of strings where the array index IS the
 * class index; a one-name-per-line .txt is also accepted) and, by matching
 * names against the live SearchSpec FILETYPE strings, builds the table the
 * populate step needs.
 *
 * The table is per-SearchSpec (spec -> MoDiCo class), not per class.
 *
 * No indices are hardcoded; retraining MoDiCo with a different class set only
 * requires shipping the matching class_names file.
 */
#ifndef MODICO_CLASSMAP_H
#define MODICO_CLASSMAP_H

#ifdef __cplusplus
extern "C" {
#endif

/* Build spec_to_class[num_specs]: entry i = the MoDiCo class index whose
 * confidence feeds SearchSpec i, or -1 if that spec has no corresponding
 * MoDiCo class (e.g. Scalpel's synthetic "abc" or "123"). Caller owns the
 * returned array and must free() it.
 *
 *   classmap_path     path to class_names.json (JSON array) or a .txt with
 *                     one class name per line; array index / line number is
 *                     the MoDiCo class index.
 *   spec_filetypes    array of the live SearchSpec FILETYPE strings
 *                     (scalpel_state.search_specs[i].FILETYPE).
 *   num_specs         length of spec_filetypes.
 *   out_parsed_classes  if non-NULL, receives the number of class names parsed
 *                       (caller should validate this equals the model's
 *                       num_classes, e.g. 619).
 *   out_num_mapped    if non-NULL, receives the count of specs that resolved
 *                     to a MoDiCo class (i.e. entries != -1).
 *
 * Returns NULL on failure (file missing / parse error / OOM); on NULL the
 * caller should disable MoDiCo prioritization and run vanilla Scalpel. */
int *modico_classmap_build(const char *classmap_path,
                           const char *const *spec_filetypes,
                           int num_specs,
                           int *out_parsed_classes,
                           int *out_num_mapped);

#ifdef __cplusplus
}
#endif

#endif /* MODICO_CLASSMAP_H */
