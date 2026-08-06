/*
 * modico_classmap.c — implementation. See modico_classmap.h.
 */

#define _POSIX_C_SOURCE 200809L

#include "modico_classmap.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MODICO_JSON_CLASS_NAME_MAX 255
#define MODICO_CLASSMAP_NAME_TOO_LONG -2

/* Non-identity aliases: Scalpel SearchSpec FILETYPE -> MoDiCo class name it
 * should borrow. fzip is Scalpel's fragmented-ZIP path; same byte content as
 * zip, so it draws on MoDiCo's "zip" confidence. Extend as needed. */
struct alias { const char *spec; const char *modico_name; };
static const struct alias ALIASES[] = {
    { "fzip", "zip" },
};
static const int N_ALIASES = (int)(sizeof(ALIASES) / sizeof(ALIASES[0]));

static const char *alias_lookup(const char *spec_filetype)
{
    for (int i = 0; i < N_ALIASES; ++i) {
        if (strcmp(ALIASES[i].spec, spec_filetype) == 0) {
            return ALIASES[i].modico_name;
        }
    }
    return spec_filetype;  /* identity */
}

/* Case-insensitive string compare (ASCII). */
static int ci_equal(const char *a, const char *b)
{
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return 0;
        ++a; ++b;
    }
    return *a == '\0' && *b == '\0';
}

/* Read an entire file into a NUL-terminated heap buffer. Returns NULL on
 * error; on success *out_len holds the byte length (excluding the NUL). */
static char *slurp(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return NULL; }
    rewind(f);
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (got != (size_t)sz) { free(buf); return NULL; }
    buf[sz] = '\0';
    if (out_len) *out_len = (size_t)sz;
    return buf;
}

/* Dynamic array of class-name strings (heap-owned). */
typedef struct { char **v; int n; int cap; } namelist_t;

static int namelist_push(namelist_t *nl, const char *start, size_t len)
{
    if (nl->n == nl->cap) {
        int ncap = nl->cap ? nl->cap * 2 : 64;
        char **nv = realloc(nl->v, (size_t)ncap * sizeof(char *));
        if (!nv) return -1;
        nl->v = nv;
        nl->cap = ncap;
    }
    char *s = malloc(len + 1);
    if (!s) return -1;
    memcpy(s, start, len);
    s[len] = '\0';
    nl->v[nl->n++] = s;
    return 0;
}

static void namelist_free(namelist_t *nl)
{
    for (int i = 0; i < nl->n; ++i) free(nl->v[i]);
    free(nl->v);
    nl->v = NULL; nl->n = nl->cap = 0;
}

/* Parse a flat JSON array of double-quoted strings: ["a","b",...].
 * Tolerant of arbitrary whitespace/newlines between tokens. Handles the
 * common backslash escapes \" and \\ defensively, though class names don't
 * use them. Returns 0 on success. */
static int parse_json_array(const char *buf, namelist_t *nl)
{
    const char *p = buf;
    while (*p && *p != '[') ++p;          /* skip to opening bracket */
    if (*p != '[') return -1;
    ++p;

    while (*p) {
        while (*p && isspace((unsigned char)*p)) ++p;
        if (*p == ']') return 0;          /* end of array */
        if (*p == ',') { ++p; continue; }
        if (*p != '"') {
            /* unexpected token; if we've already collected names, accept;
             * otherwise it's malformed. */
            return nl->n > 0 ? 0 : -1;
        }
        ++p;  /* opening quote */

        /* collect string contents into a bounded scratch (names are short). */
        char tmp[MODICO_JSON_CLASS_NAME_MAX + 1];
        size_t ti = 0;
        while (*p && *p != '"') {
            char c = *p;
            if (c == '\\' && p[1]) {       /* escape */
                ++p;
                c = *p;
            }
            if (ti == MODICO_JSON_CLASS_NAME_MAX) {
                return MODICO_CLASSMAP_NAME_TOO_LONG;
            }
            tmp[ti++] = c;
            ++p;
        }
        if (*p != '"') return -1;          /* unterminated string */
        ++p;                               /* closing quote */
        tmp[ti] = '\0';
        if (namelist_push(nl, tmp, ti) != 0) return -1;
    }
    return -1;  /* no closing ']' */
}

/* Parse one-name-per-line text. Trims surrounding whitespace; skips blank
 * lines. NOTE: blank lines are skipped, so this format must not contain
 * intentionally-empty class names (none exist). Returns 0 on success. */
static int parse_lines(const char *buf, namelist_t *nl)
{
    const char *p = buf;
    while (*p) {
        const char *start = p;
        while (*p && *p != '\n') ++p;
        const char *end = p;                /* [start,end) is the line */
        /* trim */
        while (start < end && isspace((unsigned char)*start)) ++start;
        while (end > start && isspace((unsigned char)end[-1])) --end;
        if (end > start) {
            if (namelist_push(nl, start, (size_t)(end - start)) != 0) return -1;
        }
        if (*p == '\n') ++p;
    }
    return 0;
}

int *modico_classmap_build(const char *classmap_path,
                           const char *const *spec_filetypes,
                           int num_specs,
                           int *out_parsed_classes,
                           int *out_num_mapped)
{
    if (out_parsed_classes) *out_parsed_classes = 0;
    if (out_num_mapped)     *out_num_mapped = 0;
    if (!classmap_path || !spec_filetypes || num_specs <= 0) return NULL;

    size_t len = 0;
    char *buf = slurp(classmap_path, &len);
    if (!buf) {
        fprintf(stderr, "[modico] classmap: cannot read %s\n", classmap_path);
        return NULL;
    }

    /* Detect format: first non-space char '[' => JSON array, else lines. */
    const char *q = buf;
    while (*q && isspace((unsigned char)*q)) ++q;

    namelist_t names = {0};
    int rc = (*q == '[') ? parse_json_array(buf, &names)
                         : parse_lines(buf, &names);
    free(buf);

    if (rc != 0 || names.n == 0) {
        if (rc == MODICO_CLASSMAP_NAME_TOO_LONG) {
            fprintf(stderr,
                    "[modico] classmap: JSON class name exceeds %d bytes in %s\n",
                    MODICO_JSON_CLASS_NAME_MAX, classmap_path);
        }
        else {
            fprintf(stderr, "[modico] classmap: failed to parse %s (%d names)\n",
                    classmap_path, names.n);
        }
        namelist_free(&names);
        return NULL;
    }

    int *spec_to_class = malloc((size_t)num_specs * sizeof(int));
    if (!spec_to_class) { namelist_free(&names); return NULL; }

    int mapped = 0;
    for (int s = 0; s < num_specs; ++s) {
        spec_to_class[s] = -1;
        if (!spec_filetypes[s]) continue;
        const char *want = alias_lookup(spec_filetypes[s]);
        for (int c = 0; c < names.n; ++c) {
            if (ci_equal(names.v[c], want)) {
                spec_to_class[s] = c;       /* first occurrence wins */
                ++mapped;
                break;
            }
        }
    }

    if (out_parsed_classes) *out_parsed_classes = names.n;
    if (out_num_mapped)     *out_num_mapped = mapped;

    namelist_free(&names);
    return spec_to_class;
}
