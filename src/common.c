//
// Scalpel3 is Copyright(C) 2021 - 2026 by Golden G.Richard III and contributors.
//
// This program is free software : you can redistribute it and / or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
// even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with this program. If
// not, see <https://www.gnu.org/licenses/>.
//
//-----------------------------
// Additional Integration Terms
// ----------------------------
//
// Linking or embedding Scalpel3 (statically or dynamically) into another program such that the
// resulting executable or library forms a single combined work constitutes creation of a derivative
// work under the GPL. Any party distributing such a combined work must make the entire source code
// available under the terms of the GPL as well.
//
// Commercial entities wishing to use Scalpel3 in a closed-source or proprietary product or
// requiring support must obtain a separate commercial license.
//
// For commercial licensing or questions about integration, contact: Golden G. Richard III
// (golden@cct.lsu.edu).
//
// Please see LICENSE.md and README.md for further information.
//
//

#include "scalpel.h"
#include <fnmatch.h>

// serialize one element of the kill queue
bool kill_queue_element_serialization(void **element, int64_t *priority, FILE *fp, StateSerialization mode) {

  size_t (*fb)(void *ptr, size_t size, size_t nitems,
               FILE *stream) = mode == SERIALIZE ? (size_t (*)(void *ptr, size_t size, size_t nitems, FILE *stream))fwrite
                                                 : (size_t (*)(void *ptr, size_t size, size_t nitems, FILE *stream))fread;

  void *slot = *element;
  uuid_t *uuid;
  uuid_t **tmp = (uuid_t **)slot;

  if (mode == SERIALIZE) {
    uuid = *tmp;
  }
  else {
    uuid = malloc(sizeof(*uuid));
    check_memory_allocation(uuid, __LINE__, __FILE__, "uuid");
    *tmp = uuid;
  }

  // priority field for queue element
  if (fb(priority, sizeof(*priority), 1, fp) != 1) {
    perror("couldn't serialize/deserialize priority");
    return false;
  }

  // uuid
  if (fb(*uuid, sizeof(*uuid), 1, fp) != 1) {
    perror("couldn't serialize/deserialize uuid");
    return false;
  }

  return true;
}


// deserialize a single EssentialCarveInfo element received via 'fp'.
bool read_essential_carveinfo_element(EssentialCarveInfo *e, FILE *fp) {
  // filetype:
  if (fread(e->filetype, sizeof(e->filetype), 1, fp) != 1) {
    perror("couldn't deserialize filetype");
    return false;
  }

  // num_blocks:
  if (fread(&(e->numblocks), sizeof(e->numblocks), 1, fp) != 1) {
    perror("couldn't deserialize numblocks");
    return false;
  }

  // qposition:
  if (fread(&(e->qposition), sizeof(e->qposition), 1, fp) != 1) {
    perror("couldn't deserialize qposition");
    return false;
  }

  // primary UUID:
  if (fread(e->binuuid, sizeof(e->binuuid), 1, fp) != 1) {
    perror("couldn't deserialize binuuid");
    return false;
  }

  // clone UUID:
  if (fread(e->clone_binuuid, sizeof(e->clone_binuuid), 1, fp) != 1) {
    perror("couldn't deserialize clone_binuuid");
    return false;
  }

  // active:
  if (fread(&(e->active), sizeof(e->active), 1, fp) != 1) {
    perror("couldn't deserialize active");
    return false;
  }

  return true;
}


// initializes 'q' if 'init' is true, then reads the number of elements followed by serialized
// EssentialCarveInfo elements from 'handle' and inserts these elements into the queue. If 'init' is
// false, this function simply loads the 'q' with additional elements but does not call
// init_queue().
bool read_essential_carveinfo_queue_h(Queue *q, int handle, bool init) {

  FILE *fp;
  bool ret;
  int h;

  h = dup(handle);
  fp = fdopen(h, "rb");

  if (! fp) {
    return false;
  }
  else {
    ret = read_essential_carveinfo_queue(q, fp, init);
    fclose(fp);
    return ret;
  }
}


// initializes 'q' if 'init' is true, then reads the number of elements followed by serialized
// EssentialCarveInfo elements from 'fp' and inserts these elements into the queue. If 'init' is
// false, this function simply loads the 'q' with additional elements but does not call
// init_queue().
bool read_essential_carveinfo_queue(Queue *q, FILE *fp, bool init) {

  uint64_t num_elements;
  EssentialCarveInfo e;

  if (init) {
    init_queue(q, sizeof(EssentialCarveInfo), false, essentialcarveinfo_match_both_uuids, false);
  }

  // read number of elements to process
  if (fread(&num_elements, sizeof(num_elements), 1, fp) != 1) {
    if (feof(fp)) {
      fprintf(stderr, "EOF while deserializing num_elements\n");
    }
    if (ferror(fp)) {
      fprintf(stderr, "ferror while deserializing num_elements (errno=%d)\n", errno);
    }
    perror("couldn't deserialize number of elements");
    return false;
  }

  while (num_elements--) {
    if (! read_essential_carveinfo_element(&e, fp)) {
      return false;
    }

    add_to_queue_priority_relaxed(q, &e, e.active);
  }

  return true;
}


// comparison function which compares master and clone UUIDs for CarveInfo structures. A match on
// *both* UUIDs is considered a match.
int carveinfo_match_both_uuids(const void *c1, const void *c2) {

  const CarveInfo *cand1 = *((CarveInfo **)c1);
  const CarveInfo *cand2 = *((CarveInfo **)c2);

  if (! uuid_compare(cand1->binuuid, cand2->binuuid) && ! uuid_compare(cand1->clone_binuuid, cand2->clone_binuuid)) {
    return 0;
  }
  else {
    return 1;
  }
}


// comparison function which compares master and clone UUIDs for CarveInfo structures. A match on
// *either* UUID is considered a match.
int carveinfo_match_either_uuid(const void *c1, const void *c2) {

  const CarveInfo *cand1 = *((CarveInfo **)c1);
  const CarveInfo *cand2 = *((CarveInfo **)c2);

  if (! uuid_compare(cand1->binuuid, cand2->binuuid) || ! uuid_compare(cand1->clone_binuuid, cand2->clone_binuuid)) {
    return 0;
  }
  else {
    return 1;
  }
}


// comparison function which compares master and clone UUIDs for EssentialCarveInfo structures. A
// match on *both* UUIDs is considered a match.
int essentialcarveinfo_match_both_uuids(const void *c1, const void *c2) {

  const EssentialCarveInfo *cand1 = (EssentialCarveInfo *)c1;
  const EssentialCarveInfo *cand2 = (EssentialCarveInfo *)c2;

  if (! uuid_compare(cand1->binuuid, cand2->binuuid) && ! uuid_compare(cand1->clone_binuuid, cand2->clone_binuuid)) {
    return 0;
  }
  else {
    return 1;
  }
}


// comparison function for UUIDs
int compare_uuids(const void *u1, const void *u2) {

  uuid_t uuid1;
  uuid_t uuid2;

  memcpy(uuid1, u1, sizeof(uuid_t));
  memcpy(uuid2, u2, sizeof(uuid_t));

  return uuid_compare(uuid1, uuid2);
}


// used in scalpel3 to check return values from malloc(), et al.
void check_memory_allocation(void *ptr, int line, const char *file, const char *structure) {

  if (ptr) {
    return;
  }
  else {
#if defined(SCALPEL3_EXTERNAL)
    lock_fprintf(stderr, "** MEMORY ALLOCATION FAILURE **\n");
#else
    fprintf(stderr, "** MEMORY ALLOCATION FAILURE **\n");
#endif
    perror("");
#if defined(SCALPEL3_EXTERNAL)
    lock_fprintf(stderr, "ERROR: Memory exhausted at line %d in file %s. Memory was being allocated\n", line, file);
    lock_fprintf(stderr, "for %s when this condition occurred.\n", structure);
#else
    fprintf(stderr, "ERROR: Memory exhausted at line %d in file %s. Memory was being allocated\n", line, file);
    fprintf(stderr, "for %s when this condition occurred.\n", structure);
#endif

    // fatal
    exit(-1);
  }
}


// fixed-increment constant for random number generator
#define SM64_CONSTANT UINT64_C(0x9e3779b97f4a7c15)

// global state for portable random number generator
static atomic_ullong global_random_state;

// SplitMix64 initialization. Initializes deterministic, thread-shared state.
void portable_srandom(uint64_t seed) { atomic_store(&global_random_state, seed); }

// SplitMix64 random number generator: returns the next uint64_t using atomic state updates.
uint64_t portable_random(void) {

  uint64_t old_state = atomic_fetch_add(&global_random_state, SM64_CONSTANT);
  uint64_t z = old_state + SM64_CONSTANT;

  z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
  z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
  return z ^ (z >> 31);
}


// returns current width of terminal
int get_terminal_width(void) {

  struct winsize w;

  ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);

  if (w.ws_col == 0) {
    return 132;
  }
  else {
    return w.ws_col;
  }
}


// recursive search for pattern and delete file. 'current_path' is dir currently being traversed.
// 'base_len' is length of original base dir string. 'pattern' is the pattern for file deletions.
static void traverse_and_delete(const char *current_path, size_t base_len, const char *pattern) {

  DIR *dir;
  struct dirent *entry;
  char path[PATH_MAX];
  struct stat statbuf;

  // first open directory
  if (! (dir = opendir(current_path))) {
    perror("opendir");
    return;
  }

  // loop through directory entries
  while ((entry = readdir(dir)) != NULL) {
    // skip special directories "." and ".."
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
      continue;
    }

    // construct full path
    int path_len = snprintf(path, sizeof(path), "%s/%s", current_path, entry->d_name);

    // check path length
    if (path_len >= PATH_MAX) {
      fprintf(stderr, "PATH TOO LONG IN traverse_and_delete(): %s/%s\n", current_path, entry->d_name);
      continue;
    }

    // check file type
    if (lstat(path, &statbuf) == -1) {
      continue;
    }

    // if it's a directory, recurse into it
    if (S_ISDIR(statbuf.st_mode)) {
      traverse_and_delete(path, base_len, pattern);
    }
    // ...else if it's a regular file, check the pattern
    else if (S_ISREG(statbuf.st_mode)) {
      // calculate relative path. Add 1 to base_len to skip the leading slash after the base
      // directory. Example: Full: "/tmp/B/foo.txt", Base: "/tmp/B" -> Relative: "foo.txt"
      const char *relative_path = path + base_len;

      // handle edge case where base path might end in /
      if (relative_path[0] == '/') {
        relative_path++;
      }

      // check for match
      if (fnmatch(pattern, relative_path, 0) == 0) {
        if (unlink(path) != 0) {
          perror("unlink");
        }
      }
    }
  }
  closedir(dir);
}


// primary function for recursive file deletion based on a pattern.
void delete_files_recursive(const char *base_dir, const char *pattern) {

  struct stat statbuf;

  // sanity check: does base directory exist?
  if (stat(base_dir, &statbuf) == -1 || ! S_ISDIR(statbuf.st_mode)) {
    fprintf(stderr, "Base directory invalid: %s\n", base_dir);
    return;
  }

  // remove trailing slash from base_dir for consistent relative path calculation
  char clean_base[PATH_MAX];

  strncpy(clean_base, base_dir, PATH_MAX);
  clean_base[PATH_MAX - 1] = '\0';

  size_t len = strlen(clean_base);

  if (len > 0 && clean_base[len - 1] == '/') {
    clean_base[len - 1] = '\0';
    len--;
  }

  traverse_and_delete(clean_base, len, pattern);
}


// reads a file and returns a comprehensive array of EssentialSearchSpecOffsets. The caller is
// responsible for a deep free of the returned array.
EssentialSearchSpecOffsets* deserialize_essential_offsets(char *filename, uint32_t *num_specs_out) {

  FILE *fp = fopen(filename, "rb");

  if (!fp) {
    perror("Failed to open file for deserialization.");
    return NULL;
  }

  uint32_t num_specs = 0;
  if (fread(&num_specs, sizeof(uint32_t), 1, fp) != 1) {
    fprintf(stderr, "Deserialization error: Failed to read num_specs from file %s.\n", filename);
    fclose(fp);
    return NULL;
  }

  EssentialSearchSpecOffsets *array = (EssentialSearchSpecOffsets *)calloc(num_specs, sizeof(EssentialSearchSpecOffsets));

  if (! array) {
    perror("Failed to allocate EssentialSearchSpecOffsets array.");
    fclose(fp);
    return NULL;
  }

  for (uint32_t i = 0; i < num_specs; i++) {

    uint32_t suffix_len = 0;
    if (fread(&suffix_len, sizeof(uint32_t), 1, fp) != 1) {
      fprintf(stderr, "Deserialization error: Failed to read suffix_len for spec %"PRIu32".\n", i);
      goto error_cleanup;
    }

    if (suffix_len > 0) {
      array[i].filetype = (char *)malloc(suffix_len * sizeof(char));
      if (!array[i].filetype) {
        perror("Memory allocation failed for filetype.");
        goto error_cleanup;
      }
      if (fread(array[i].filetype, sizeof(char), suffix_len, fp) != suffix_len) {
        fprintf(stderr, "Deserialization error: Failed to read filetype string for spec %"PRIu32".\n", i);
        goto error_cleanup;
      }
    }

    // --- headers ---
    if (fread(&array[i].numheaders, sizeof(uint64_t), 1, fp) != 1) {
      fprintf(stderr, "Deserialization Error: failed to read numheaders for spec %"PRIu32".\n", i);
      goto error_cleanup;
    }

    if (array[i].numheaders > 0) {
      array[i].headers = (uint64_t *)malloc(array[i].numheaders * sizeof(uint64_t));
      array[i].headerlens = (size_t *)malloc(array[i].numheaders * sizeof(size_t));

      if (!array[i].headers || !array[i].headerlens) {
        perror("Memory allocation failed for headers.");
        goto error_cleanup;
      }

      if (fread(array[i].headers, sizeof(uint64_t), array[i].numheaders, fp) != array[i].numheaders) {
        fprintf(stderr, "Deserialization error: Failed to read headers array for spec %"PRIu32".\n", i);
        goto error_cleanup;
      }
      if (fread(array[i].headerlens, sizeof(size_t), array[i].numheaders, fp) != array[i].numheaders) {
        fprintf(stderr, "Deserialization error: Failed to read headerlens array for spec %"PRIu32".\n", i);
        goto error_cleanup;
      }
    }

    // --- footers ---
    if (fread(&array[i].numfooters, sizeof(uint64_t), 1, fp) != 1) {
      fprintf(stderr, "Deserialization error: Failed to read numfooters for spec %"PRIu32".\n", i);
      goto error_cleanup;
    }

    if (array[i].numfooters > 0) {
      array[i].footers = (uint64_t *)malloc(array[i].numfooters * sizeof(uint64_t));
      array[i].footerlens = (size_t *)malloc(array[i].numfooters * sizeof(size_t));

      if (!array[i].footers || !array[i].footerlens) {
        perror("Memory allocation failed for footers.");
        goto error_cleanup;
      }

      if (fread(array[i].footers, sizeof(uint64_t), array[i].numfooters, fp) != array[i].numfooters) {
        fprintf(stderr, "Deserialization error: Failed to read footers array for spec %"PRIu32".\n", i);
        goto error_cleanup;
      }
      if (fread(array[i].footerlens, sizeof(size_t), array[i].numfooters, fp) != array[i].numfooters) {
        fprintf(stderr, "Deserialization error: Failed to read footerlens array for spec %"PRIu32".\n", i);
        goto error_cleanup;
      }
    }
  }

  fclose(fp);

  if (num_specs_out) {
    *num_specs_out = num_specs;
  }

  return array;

 error_cleanup:

  if (array) {
    for (uint32_t k = 0; k < num_specs; k++) {
      free(array[k].filetype);
      free(array[k].headers);
      free(array[k].headerlens);
      free(array[k].footers);
      free(array[k].footerlens);
    }
    free(array);
  }

  fclose(fp);

  return NULL;
}
