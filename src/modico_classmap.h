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
 * The table is per-SearchSpec (spec -> MoDiCo class), NOT per-class: several
 * specs may share one MoDiCo class (e.g. Scalpel's "zip" and "fzip" both draw
 * on MoDiCo's "zip" class), which a class->spec table could not represent.
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
