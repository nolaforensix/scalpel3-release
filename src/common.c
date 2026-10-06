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

#include "scalpel.h"
#include <fnmatch.h>
#include <openssl/evp.h>


static bool is_path_separator(char c);


// Save or restore MoDiCo's effective ranking metadata without an inference session.
// num_specs must already be restored. Leave existing state intact on read failure.
// Shared by scalpel3 and mergecps so both use the same checkpoint representation.
//
bool checkpoint_modico_serialization(ScalpelState *state, FILE *fp,
                                     StateSerialization mode) {

  uint8_t enabled = state->modico_enabled ? 1 : 0;
  uint32_t count = state->modico_num_specs;
  int *mapping = NULL;
  size_t (*fb)(void *, size_t, size_t, FILE *) = mode == SERIALIZE
      ? (size_t (*)(void *, size_t, size_t, FILE *))fwrite : fread;

  if (mode != SERIALIZE && mode != DESERIALIZE) {
    return false;
  }
  if (fb(&enabled, sizeof(enabled), 1, fp) != 1
      || fb(&count, sizeof(count), 1, fp) != 1) {
    return false;
  }
  if (enabled > 1 || count > state->num_specs
      || (enabled != (count != 0))
      || (count && SIZE_MAX / count < sizeof(*mapping))) {
    return false;
  }
  if (mode == SERIALIZE) {
    mapping = state->modico_spec_to_class;
    if (count && ! mapping) {
      return false;
    }
  }
  else if (count) {
    mapping = malloc((size_t)count * sizeof(*mapping));
    check_memory_allocation(mapping, __LINE__, __FILE__, "MoDiCo checkpoint mapping");
  }

  for (uint32_t i = 0; i < count; i++) {
    int32_t class_index = mode == SERIALIZE ? mapping[i] : -1;
    if (fb(&class_index, sizeof(class_index), 1, fp) != 1
        || class_index < -1) {
      if (mode == DESERIALIZE) {
        free(mapping);
      }
      return false;
    }
    if (mode == DESERIALIZE) {
      mapping[i] = class_index;
    }
  }

  if (mode == DESERIALIZE) {
    free(state->modico_spec_to_class);
    state->modico_spec_to_class = mapping;
    state->modico_num_specs = count;
    state->modico_enabled = enabled != 0;
  }
  return true;
}


// return true when 'c' separates pathname components on a supported platform.
//
static bool is_path_separator(char c) {

  return c == '/' || c == '\\';
}


// return a pointer to the final component of 'path'. Both '/' and '\\' are
// recognized as pathname separators, and an ASCII drive-letter prefix is
// skipped when present. The returned pointer refers to storage in 'path'. A
// NULL or empty path is returned unchanged.
//
char *scalpel_path_basename(const char *path) {

  const char *component;
  const char *end;
  const char *scan;

  if (! path || ! path[0]) {
    return (char *)path;
  }

  component = path;
  if ((((path[0] >= 'A') && (path[0] <= 'Z'))
       || ((path[0] >= 'a') && (path[0] <= 'z')))
      && path[1] == ':') {
    component += 2;
  }

  end = path + strlen(path);
  scan = end;
  while (scan > component && is_path_separator(scan[-1])) {
    scan--;
  }

  if (scan == component) {
    if (scan == end) {
      return (char *)end;
    }
    return (char *)(end - 1);
  }

  while (scan > component && ! is_path_separator(scan[-1])) {
    scan--;
  }

  return (char *)scan;
}


// return the length of 'name' after excluding redundant trailing pathname
// separators. A NULL name has length zero.
//
size_t scalpel_path_basename_len(const char *name) {

  size_t length;

  if (! name) {
    return 0;
  }

  length = strlen(name);
  while (length > 1 && is_path_separator(name[length - 1])) {
    length--;
  }

  return length;
}


// copy a string only when the complete value fits in the destination
bool copy_string_complete(char *destination, size_t destination_size,
                          const char *source) {

  size_t length;

  if (! destination || destination_size == 0 || ! source) {
    errno = EINVAL;
    return false;
  }

  length = strlen(source);
  if (length >= destination_size) {
    destination[0] = 0;
    errno = ENAMETOOLONG;
    return false;
  }

  memcpy(destination, source, length + 1);
  return true;
}


static const char *checkpoint_component_name(CheckpointComponent component) {

  switch (component) {
  case CHECKPOINT_COMPONENT_STATE:
    return CHECKPOINT_STATE_COMPONENT;
  case CHECKPOINT_COMPONENT_QUEUE:
    return CHECKPOINT_QUEUE_COMPONENT;
  case CHECKPOINT_COMPONENT_MANIFEST:
    return CHECKPOINT_MANIFEST_COMPONENT;
  }

  return NULL;
}


static bool checkpoint_slot_filename(char *filename, size_t filename_size,
                                     CheckpointComponent component, uint32_t slot) {

  const char *name = checkpoint_component_name(component);
  int written;

  if (! filename || filename_size == 0 || ! name || slot >= CHECKPOINT_SLOT_COUNT) {
    errno = EINVAL;
    return false;
  }

  written = snprintf(filename, filename_size, "%s.%" PRIu32 ".chk", name, slot);
  if (written < 0 || (size_t)written >= filename_size) {
    errno = ENAMETOOLONG;
    return false;
  }

  return true;
}


bool checkpoint_slot_path(char *path, size_t path_size, const char *directory,
                          CheckpointComponent component, uint32_t slot, bool temporary) {

  char filename[PATH_MAX];
  int written;

  if (! path || path_size == 0 || ! directory
      || ! checkpoint_slot_filename(filename, sizeof(filename), component, slot)) {
    errno = EINVAL;
    return false;
  }

  written = snprintf(path, path_size, "%s/%s%s", directory, filename,
                     temporary ? "_" : "");
  if (written < 0 || (size_t)written >= path_size) {
    errno = ENAMETOOLONG;
    return false;
  }

  return true;
}


static bool checkpoint_sync_fd(int fd) {

#if defined(__APPLE__) && defined(F_FULLFSYNC)
  if (fcntl(fd, F_FULLFSYNC) == 0) {
    return true;
  }

  if (errno != EINVAL && errno != ENOTSUP && errno != ENOTTY) {
    return false;
  }
#endif

  return fsync(fd) == 0;
}


static bool checkpoint_sync_directory(const char *directory) {

  int fd = open(directory, O_RDONLY);
  int saved_errno = 0;

  if (fd < 0) {
    return false;
  }

  if (! checkpoint_sync_fd(fd)) {
    saved_errno = errno;
  }
  if (close(fd) != 0 && saved_errno == 0) {
    saved_errno = errno;
  }

  if (saved_errno != 0) {
    errno = saved_errno;
    return false;
  }

  return true;
}


bool checkpoint_durable_close(FILE *fp) {

  int saved_errno = 0;

  if (! fp) {
    errno = EINVAL;
    return false;
  }

  if (fflush(fp) != 0) {
    saved_errno = errno;
  }
  if (! checkpoint_sync_fd(fileno(fp)) && saved_errno == 0) {
    saved_errno = errno;
  }
  if (fclose(fp) != 0 && saved_errno == 0) {
    saved_errno = errno;
  }

  if (saved_errno != 0) {
    errno = saved_errno;
    return false;
  }

  return true;
}


bool checkpoint_atomic_replace(const char *temporary_path, const char *final_path,
                               const char *directory) {

  if (! temporary_path || ! final_path || ! directory) {
    errno = EINVAL;
    return false;
  }

  if (rename(temporary_path, final_path) != 0) {
    return false;
  }

  return checkpoint_sync_directory(directory);
}


bool checkpoint_hash_file(const char *filepath, unsigned char hash[SHA256_DIGEST_LENGTH]) {

  unsigned char buffer[64 * 1024];
  EVP_MD_CTX *context = NULL;
  FILE *fp = NULL;
  unsigned int hash_length = 0;
  size_t count;
  bool ok = false;

  if (! filepath || ! hash) {
    errno = EINVAL;
    return false;
  }

  fp = fopen(filepath, "rb");
  context = EVP_MD_CTX_new();
  if (! fp || ! context || EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1) {
    goto done;
  }

  while ((count = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
    if (EVP_DigestUpdate(context, buffer, count) != 1) {
      goto done;
    }
  }

  if (ferror(fp)
      || EVP_DigestFinal_ex(context, hash, &hash_length) != 1
      || hash_length != SHA256_DIGEST_LENGTH) {
    goto done;
  }

  ok = true;

done:
  EVP_MD_CTX_free(context);
  if (fp && fclose(fp) != 0) {
    ok = false;
  }
  return ok;
}


void checkpoint_test_crash_after(const char *stage) {

  const char *requested = getenv("SCALPEL3_TEST_CHECKPOINT_CRASH_AFTER");
  ssize_t write_result;

  if (requested && stage && strcmp(requested, stage) == 0) {
    static const char message[] = "Checkpoint fault injection requested; terminating immediately.\n";
    write_result = write(STDERR_FILENO, message, sizeof(message) - 1);
    (void)write_result;
    _exit(86);
  }
}


bool checkpoint_invalidate_slot(const char *directory, uint32_t slot) {

  char path[PATH_MAX];
  char temporary_path[PATH_MAX];
  bool changed = false;

  if (! checkpoint_slot_path(path, sizeof(path), directory,
                             CHECKPOINT_COMPONENT_MANIFEST, slot, false)
      || ! checkpoint_slot_path(temporary_path, sizeof(temporary_path), directory,
                                CHECKPOINT_COMPONENT_MANIFEST, slot, true)) {
    return false;
  }

  if (unlink(path) == 0) {
    changed = true;
  }
  else if (errno != ENOENT) {
    return false;
  }

  if (unlink(temporary_path) == 0) {
    changed = true;
  }
  else if (errno != ENOENT) {
    return false;
  }

  return ! changed || checkpoint_sync_directory(directory);
}


bool checkpoint_write_slot_manifest(const char *directory, uint32_t slot,
                                    uint64_t sequence_number,
                                    const unsigned char scalpel_sha256[SHA256_DIGEST_LENGTH]) {

  CheckpointManifest manifest = {0};
  char path[PATH_MAX];
  char temporary_path[PATH_MAX];
  char filename[PATH_MAX];
  FILE *fp;

  if (! directory || ! scalpel_sha256 || slot >= CHECKPOINT_SLOT_COUNT) {
    errno = EINVAL;
    return false;
  }

  memcpy(manifest.magic, CHECKPOINT_MANIFEST_MAGIC, CHECKPOINT_MAGIC_SIZE);
  manifest.version = CHECKPOINT_FORMAT_VERSION;
  manifest.num_files = CHECKPOINT_MANIFEST_FILE_COUNT;
  manifest.sequence_number = sequence_number;
  manifest.timestamp = (int64_t)time(NULL);
  memcpy(manifest.scalpel_sha256, scalpel_sha256, SHA256_DIGEST_LENGTH);

  if (! checkpoint_slot_filename(filename, sizeof(filename), CHECKPOINT_COMPONENT_STATE, slot)
      || ! checkpoint_slot_path(path, sizeof(path), directory,
                                CHECKPOINT_COMPONENT_STATE, slot, false)) {
    return false;
  }
  memcpy(manifest.files[0].filename, filename, strlen(filename) + 1);
  if (! checkpoint_hash_file(path, manifest.files[0].sha256)) {
    return false;
  }

  if (! checkpoint_slot_filename(filename, sizeof(filename), CHECKPOINT_COMPONENT_QUEUE, slot)
      || ! checkpoint_slot_path(path, sizeof(path), directory,
                                CHECKPOINT_COMPONENT_QUEUE, slot, false)) {
    return false;
  }
  memcpy(manifest.files[1].filename, filename, strlen(filename) + 1);
  if (! checkpoint_hash_file(path, manifest.files[1].sha256)) {
    return false;
  }

  memcpy(manifest.files[2].filename, BLOCKCLASSIFICATION_FILENAME,
         sizeof(BLOCKCLASSIFICATION_FILENAME));
  int written = snprintf(path, sizeof(path), "%s/%s", directory,
                         BLOCKCLASSIFICATION_FILENAME);
  if (written < 0 || (size_t)written >= sizeof(path)
      || ! checkpoint_hash_file(path, manifest.files[2].sha256)) {
    return false;
  }

  if (! HMAC(EVP_sha256(), scalpel_sha256, SHA256_DIGEST_LENGTH,
             (unsigned char *)&manifest, offsetof(CheckpointManifest, hmac),
             manifest.hmac, NULL)) {
    return false;
  }

  if (! checkpoint_slot_path(path, sizeof(path), directory,
                             CHECKPOINT_COMPONENT_MANIFEST, slot, false)
      || ! checkpoint_slot_path(temporary_path, sizeof(temporary_path), directory,
                                CHECKPOINT_COMPONENT_MANIFEST, slot, true)) {
    return false;
  }

  unlink(temporary_path);
  fp = fopen(temporary_path, "wb");
  if (! fp) {
    return false;
  }
  bool write_ok = fwrite(&manifest, sizeof(manifest), 1, fp) == 1;
  bool close_ok = checkpoint_durable_close(fp);
  if (! write_ok || ! close_ok) {
    unlink(temporary_path);
    return false;
  }

  if (rename(temporary_path, path) != 0) {
    return false;
  }
  checkpoint_test_crash_after("manifest-renamed");
  return checkpoint_sync_directory(directory);
}


bool checkpoint_publish_slot(const char *directory, uint32_t slot,
                             uint64_t sequence_number) {

  CheckpointCurrent current = {0};
  char path[PATH_MAX];
  char temporary_path[PATH_MAX];
  FILE *fp;
  int written;

  if (! directory || slot >= CHECKPOINT_SLOT_COUNT) {
    errno = EINVAL;
    return false;
  }

  memcpy(current.magic, CHECKPOINT_CURRENT_MAGIC, CHECKPOINT_MAGIC_SIZE);
  current.version = CHECKPOINT_FORMAT_VERSION;
  current.slot = slot;
  current.sequence_number = sequence_number;
  SHA256((unsigned char *)&current, offsetof(CheckpointCurrent, sha256),
         current.sha256);

  written = snprintf(path, sizeof(path), "%s/%s", directory,
                     CHECKPOINT_CURRENT_FILENAME);
  if (written < 0 || (size_t)written >= sizeof(path)) {
    errno = ENAMETOOLONG;
    return false;
  }
  written = snprintf(temporary_path, sizeof(temporary_path), "%s_", path);
  if (written < 0 || (size_t)written >= sizeof(temporary_path)) {
    errno = ENAMETOOLONG;
    return false;
  }

  unlink(temporary_path);
  fp = fopen(temporary_path, "wb");
  if (! fp) {
    return false;
  }
  bool write_ok = fwrite(&current, sizeof(current), 1, fp) == 1;
  bool close_ok = checkpoint_durable_close(fp);
  if (! write_ok || ! close_ok) {
    unlink(temporary_path);
    return false;
  }

  if (rename(temporary_path, path) != 0) {
    return false;
  }
  checkpoint_test_crash_after("marker-renamed");
  return checkpoint_sync_directory(directory);
}


static bool checkpoint_read_current(const char *directory, CheckpointCurrent *current) {

  unsigned char hash[SHA256_DIGEST_LENGTH];
  char path[PATH_MAX];
  FILE *fp;
  int written;
  bool ok;

  written = snprintf(path, sizeof(path), "%s/%s", directory,
                     CHECKPOINT_CURRENT_FILENAME);
  if (written < 0 || (size_t)written >= sizeof(path)) {
    errno = ENAMETOOLONG;
    return false;
  }

  fp = fopen(path, "rb");
  if (! fp) {
    return false;
  }

  ok = fread(current, sizeof(*current), 1, fp) == 1;
  if (fclose(fp) != 0) {
    ok = false;
  }
  if (! ok
      || memcmp(current->magic, CHECKPOINT_CURRENT_MAGIC, CHECKPOINT_MAGIC_SIZE) != 0
      || current->version != CHECKPOINT_FORMAT_VERSION
      || current->slot >= CHECKPOINT_SLOT_COUNT) {
    return false;
  }

  SHA256((unsigned char *)current, offsetof(CheckpointCurrent, sha256), hash);
  return memcmp(hash, current->sha256, sizeof(hash)) == 0;
}


static bool checkpoint_verify_slot(const char *directory, uint32_t slot,
                                   const unsigned char expected_scalpel_sha256[SHA256_DIGEST_LENGTH],
                                   uint32_t integrity_file_count,
                                   CheckpointSelection *selection,
                                   char *reason, size_t reason_size) {

  CheckpointManifest manifest;
  unsigned char hmac[SHA256_DIGEST_LENGTH];
  unsigned char hash[SHA256_DIGEST_LENGTH];
  const unsigned char *key = expected_scalpel_sha256;
  char expected_name[PATH_MAX];
  char path[PATH_MAX];
  FILE *fp;

#define CHECKPOINT_REJECT(...)                         \
  do {                                                 \
    if (reason && reason_size > 0) {                   \
      snprintf(reason, reason_size, __VA_ARGS__);      \
    }                                                  \
    return false;                                      \
  } while (0)

  if (! checkpoint_slot_path(path, sizeof(path), directory,
                             CHECKPOINT_COMPONENT_MANIFEST, slot, false)) {
    CHECKPOINT_REJECT("manifest path is too long");
  }

  fp = fopen(path, "rb");
  if (! fp) {
    CHECKPOINT_REJECT("manifest is missing");
  }
  bool read_ok = fread(&manifest, sizeof(manifest), 1, fp) == 1;
  if (fclose(fp) != 0) {
    read_ok = false;
  }
  if (! read_ok) {
    CHECKPOINT_REJECT("manifest cannot be read");
  }

  if (memcmp(manifest.magic, CHECKPOINT_MANIFEST_MAGIC,
             CHECKPOINT_MAGIC_SIZE) != 0
      || manifest.version != CHECKPOINT_FORMAT_VERSION
      || manifest.num_files != CHECKPOINT_MANIFEST_FILE_COUNT
      || manifest.sequence_number == 0) {
    CHECKPOINT_REJECT("manifest format is invalid");
  }

  if (! checkpoint_slot_filename(expected_name, sizeof(expected_name),
                                  CHECKPOINT_COMPONENT_STATE, slot)
      || ! memchr(manifest.files[0].filename, '\0', PATH_MAX)
      || strcmp(manifest.files[0].filename, expected_name) != 0
      || ! checkpoint_slot_filename(expected_name, sizeof(expected_name),
                                    CHECKPOINT_COMPONENT_QUEUE, slot)
      || ! memchr(manifest.files[1].filename, '\0', PATH_MAX)
      || strcmp(manifest.files[1].filename, expected_name) != 0
      || ! memchr(manifest.files[2].filename, '\0', PATH_MAX)
      || strcmp(manifest.files[2].filename, BLOCKCLASSIFICATION_FILENAME) != 0) {
    CHECKPOINT_REJECT("manifest file set is invalid");
  }

  for (uint32_t i = 0; i < manifest.num_files; i++) {
    int written = snprintf(path, sizeof(path), "%s/%s", directory,
                           manifest.files[i].filename);
    if (written < 0 || (size_t)written >= sizeof(path)
        || access(path, R_OK) != 0) {
      CHECKPOINT_REJECT("%s is missing or unreadable",
                        manifest.files[i].filename);
    }
  }

  if (integrity_file_count > manifest.num_files) {
    CHECKPOINT_REJECT("integrity file count is invalid");
  }

  if (integrity_file_count > 0) {
    if (expected_scalpel_sha256
        && memcmp(manifest.scalpel_sha256, expected_scalpel_sha256,
                  SHA256_DIGEST_LENGTH) != 0) {
      CHECKPOINT_REJECT("checkpoint was created by a different scalpel3 executable");
    }
    if (! key) {
      key = manifest.scalpel_sha256;
    }
    if (! HMAC(EVP_sha256(), key, SHA256_DIGEST_LENGTH,
               (unsigned char *)&manifest, offsetof(CheckpointManifest, hmac),
               hmac, NULL)
        || memcmp(hmac, manifest.hmac, sizeof(hmac)) != 0) {
      CHECKPOINT_REJECT("manifest authentication failed");
    }

    for (uint32_t i = 0; i < integrity_file_count; i++) {
      int written = snprintf(path, sizeof(path), "%s/%s", directory,
                             manifest.files[i].filename);
      if (written < 0 || (size_t)written >= sizeof(path)
          || ! checkpoint_hash_file(path, hash)
          || memcmp(hash, manifest.files[i].sha256, sizeof(hash)) != 0) {
        CHECKPOINT_REJECT("%s failed its integrity check",
                          manifest.files[i].filename);
      }
    }
  }

  memset(selection, 0, sizeof(*selection));
  selection->slot = slot;
  selection->manifest = manifest;
  if (! checkpoint_slot_path(selection->state_path, sizeof(selection->state_path),
                             directory, CHECKPOINT_COMPONENT_STATE, slot, false)
      || ! checkpoint_slot_path(selection->queue_path, sizeof(selection->queue_path),
                                directory, CHECKPOINT_COMPONENT_QUEUE, slot, false)
      || ! checkpoint_slot_path(selection->manifest_path,
                                sizeof(selection->manifest_path), directory,
                                CHECKPOINT_COMPONENT_MANIFEST, slot, false)) {
    CHECKPOINT_REJECT("checkpoint path is too long");
  }

  if (reason && reason_size > 0) {
    reason[0] = '\0';
  }
  return true;

#undef CHECKPOINT_REJECT
}


static bool checkpoint_select_slot_internal(
    const char *directory,
    const unsigned char expected_scalpel_sha256[SHA256_DIGEST_LENGTH],
    uint32_t integrity_file_count, CheckpointSelection *selection,
    FILE *diagnostics) {

  CheckpointCurrent current;
  CheckpointSelection candidates[CHECKPOINT_SLOT_COUNT];
  bool valid[CHECKPOINT_SLOT_COUNT] = {false, false};
  char reasons[CHECKPOINT_SLOT_COUNT][256] = {{0}};
  bool have_current;
  uint32_t chosen;

  if (! directory || ! selection) {
    errno = EINVAL;
    return false;
  }

  have_current = checkpoint_read_current(directory, &current);
  if (have_current) {
    valid[current.slot] = checkpoint_verify_slot(
        directory, current.slot, expected_scalpel_sha256,
        integrity_file_count,
        &candidates[current.slot], reasons[current.slot], sizeof(reasons[current.slot]));
    if (valid[current.slot]
        && candidates[current.slot].manifest.sequence_number
               == current.sequence_number) {
      *selection = candidates[current.slot];
      if (diagnostics) {
        fprintf(diagnostics, "Using checkpoint slot %" PRIu32
                             " (sequence %" PRIu64 ").\n",
                selection->slot, selection->manifest.sequence_number);
      }
      return true;
    }
    if (diagnostics) {
      fprintf(diagnostics, "Published checkpoint slot %" PRIu32
                           " is not usable%s%s; searching fallback slots.\n",
              current.slot, reasons[current.slot][0] ? ": " : "",
              reasons[current.slot]);
    }
  }

  for (uint32_t slot = 0; slot < CHECKPOINT_SLOT_COUNT; slot++) {
    if (! valid[slot]) {
      valid[slot] = checkpoint_verify_slot(
          directory, slot, expected_scalpel_sha256, integrity_file_count,
          &candidates[slot], reasons[slot], sizeof(reasons[slot]));
    }
  }

  if (! valid[0] && ! valid[1]) {
    if (diagnostics) {
      fprintf(diagnostics, "No valid checkpoint slot found in %s.\n", directory);
      for (uint32_t slot = 0; slot < CHECKPOINT_SLOT_COUNT; slot++) {
        fprintf(diagnostics, "  slot %" PRIu32 ": %s\n", slot,
                reasons[slot][0] ? reasons[slot] : "invalid");
      }
    }
    return false;
  }

  if (valid[0] && valid[1]) {
    chosen = candidates[1].manifest.sequence_number
                     > candidates[0].manifest.sequence_number
                 ? 1U
                 : 0U;
  }
  else {
    chosen = valid[0] ? 0U : 1U;
  }

  *selection = candidates[chosen];
  if (diagnostics) {
    fprintf(diagnostics, "Using fallback checkpoint slot %" PRIu32
                         " (sequence %" PRIu64 ").\n",
            selection->slot, selection->manifest.sequence_number);
  }
  return true;
}


bool checkpoint_select_slot(const char *directory,
                            const unsigned char expected_scalpel_sha256[SHA256_DIGEST_LENGTH],
                            bool verify_integrity, CheckpointSelection *selection,
                            FILE *diagnostics) {

  return checkpoint_select_slot_internal(
      directory, expected_scalpel_sha256,
      verify_integrity ? CHECKPOINT_MANIFEST_FILE_COUNT : 0U,
      selection, diagnostics);
}


// select a slot that is safe to preserve while the other slot is replaced
bool checkpoint_select_slot_for_save(
    const char *directory,
    const unsigned char expected_scalpel_sha256[SHA256_DIGEST_LENGTH],
    CheckpointSelection *selection, FILE *diagnostics) {

  return checkpoint_select_slot_internal(
      directory, expected_scalpel_sha256,
      CHECKPOINT_MANIFEST_MUTABLE_FILE_COUNT, selection, diagnostics);
}

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
  if (h < 0) {
    return false;
  }

  fp = fdopen(h, "rb");
  if (! fp) {
    close(h);
    return false;
  }

  ret = read_essential_carveinfo_queue(q, fp, init);
  fclose(fp);
  return ret;
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

  struct winsize w = {0};

  if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) != 0 || w.ws_col == 0) {
    return 132;
  }

  return w.ws_col;
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


// report the unread byte count for a regular serialized file through 'remaining'.
// Streams and other non-regular files are rejected because their length is not known.
//
static bool serialized_file_bytes_remaining(FILE *fp, uint64_t *remaining) {

  struct stat statbuf;
  off_t position;
  int handle;

  if (! fp || ! remaining) {
    errno = EINVAL;
    return false;
  }

  handle = fileno(fp);
  position = ftello(fp);
  if (handle < 0 || position < 0 || fstat(handle, &statbuf) != 0
      || ! S_ISREG(statbuf.st_mode) || statbuf.st_size < position) {
    errno = EPROTO;
    return false;
  }

  *remaining = (uint64_t)(statbuf.st_size - position);
  return true;
}


// calculate the byte count for 'count' fixed-size serialized items and verify
// that the result fits both size_t and the unread portion of the input.
//
static bool serialized_item_bytes(uint64_t count, size_t item_size,
                                  uint64_t remaining, size_t *bytes) {

  if (! bytes || item_size == 0) {
    errno = EINVAL;
    return false;
  }
  if (count > SIZE_MAX / item_size) {
    errno = EOVERFLOW;
    return false;
  }

  *bytes = (size_t)count * item_size;
  if ((uint64_t)*bytes > remaining) {
    errno = EPROTO;
    return false;
  }

  return true;
}


// read 'count' fixed-size serialized items and update the unread byte count.
//
static bool read_serialized_items(FILE *fp, void *destination, uint64_t count,
                                  size_t item_size, uint64_t *remaining) {

  size_t bytes;

  if (! fp || ! remaining
      || ! serialized_item_bytes(count, item_size, *remaining, &bytes)) {
    return false;
  }
  if (count > 0
      && fread(destination, item_size, (size_t)count, fp) != (size_t)count) {
    if (errno == 0) {
      errno = EPROTO;
    }
    return false;
  }

  *remaining -= bytes;
  return true;
}


// deserialize paired offset and length arrays after validating their complete
// payload against the unread byte count.
//
static bool deserialize_offset_values(FILE *fp, uint64_t count,
                                      uint64_t **offsets, size_t **lengths,
                                      uint64_t *remaining) {

  uint64_t *new_offsets = NULL;
  size_t *new_lengths = NULL;
  size_t offset_bytes;
  size_t length_bytes;

  if (! offsets || ! lengths || ! remaining) {
    errno = EINVAL;
    return false;
  }
  if (count == 0) {
    return true;
  }
  if (! serialized_item_bytes(count, sizeof(*new_offsets), *remaining,
                              &offset_bytes)
      || ! serialized_item_bytes(count, sizeof(*new_lengths),
                                 *remaining - offset_bytes, &length_bytes)) {
    return false;
  }

  new_offsets = (uint64_t *)malloc(offset_bytes);
  new_lengths = (size_t *)malloc(length_bytes);
  if (! new_offsets || ! new_lengths) {
    free(new_offsets);
    free(new_lengths);
    errno = ENOMEM;
    return false;
  }

  if (! read_serialized_items(fp, new_offsets, count, sizeof(*new_offsets),
                              remaining)
      || ! read_serialized_items(fp, new_lengths, count, sizeof(*new_lengths),
                                 remaining)) {
    free(new_offsets);
    free(new_lengths);
    return false;
  }

  *offsets = new_offsets;
  *lengths = new_lengths;
  return true;
}


// reads a file and returns a comprehensive array of EssentialSearchSpecOffsets. The caller is
// responsible for a deep free of the returned array.
EssentialSearchSpecOffsets* deserialize_essential_offsets(char *filename, uint32_t *num_specs_out) {

  uint64_t remaining = 0;
  size_t array_bytes;
  uint32_t specs_to_free = 0;

  if (num_specs_out) {
    *num_specs_out = 0;
  }
  if (! filename) {
    errno = EINVAL;
    return NULL;
  }

  FILE *fp = fopen(filename, "rb");

  if (!fp) {
    perror("Failed to open file for deserialization.");
    return NULL;
  }

  if (! serialized_file_bytes_remaining(fp, &remaining)) {
    fprintf(stderr, "Deserialization error: File %s is not a regular database file.\n",
            filename);
    fclose(fp);
    return NULL;
  }

  uint32_t num_specs = 0;
  if (! read_serialized_items(fp, &num_specs, 1, sizeof(num_specs), &remaining)) {
    fprintf(stderr, "Deserialization error: Failed to read num_specs from file %s.\n", filename);
    fclose(fp);
    return NULL;
  }

  if (! serialized_item_bytes(num_specs,
                              sizeof(uint32_t) + 2 * sizeof(uint64_t),
                              remaining, &array_bytes)) {
    fprintf(stderr, "Deserialization error: Invalid num_specs in file %s.\n", filename);
    fclose(fp);
    return NULL;
  }
  if (! serialized_item_bytes(num_specs, sizeof(EssentialSearchSpecOffsets),
                              UINT64_MAX, &array_bytes)) {
    fprintf(stderr, "Deserialization error: num_specs is too large in file %s.\n", filename);
    fclose(fp);
    return NULL;
  }

  EssentialSearchSpecOffsets *array = (EssentialSearchSpecOffsets *)calloc(
      1, num_specs ? array_bytes : sizeof(EssentialSearchSpecOffsets));

  if (! array) {
    perror("Failed to allocate EssentialSearchSpecOffsets array.");
    fclose(fp);
    return NULL;
  }

  for (uint32_t i = 0; i < num_specs; i++) {

    uint32_t suffix_len = 0;
    specs_to_free = i + 1;
    if (! read_serialized_items(fp, &suffix_len, 1, sizeof(suffix_len),
                                &remaining)) {
      fprintf(stderr, "Deserialization error: Failed to read suffix_len for spec %"PRIu32".\n", i);
      goto error_cleanup;
    }

    if (suffix_len > 0) {
      size_t suffix_bytes;
      if (! serialized_item_bytes(suffix_len, sizeof(char), remaining,
                                  &suffix_bytes)) {
        fprintf(stderr, "Deserialization error: Invalid filetype length for spec %"PRIu32".\n", i);
        goto error_cleanup;
      }

      array[i].filetype = (char *)malloc(suffix_bytes);
      if (!array[i].filetype) {
        perror("Memory allocation failed for filetype.");
        goto error_cleanup;
      }
      if (! read_serialized_items(fp, array[i].filetype, suffix_len,
                                  sizeof(char), &remaining)) {
        fprintf(stderr, "Deserialization error: Failed to read filetype string for spec %"PRIu32".\n", i);
        goto error_cleanup;
      }
      if (array[i].filetype[suffix_len - 1] != '\0') {
        fprintf(stderr, "Deserialization error: Unterminated filetype for spec %"PRIu32".\n", i);
        goto error_cleanup;
      }
    }

    // --- headers ---
    if (! read_serialized_items(fp, &array[i].numheaders, 1,
                                sizeof(array[i].numheaders), &remaining)) {
      fprintf(stderr, "Deserialization Error: failed to read numheaders for spec %"PRIu32".\n", i);
      goto error_cleanup;
    }

    if (! deserialize_offset_values(fp, array[i].numheaders,
                                    &array[i].headers, &array[i].headerlens,
                                    &remaining)) {
      fprintf(stderr, "Deserialization error: Invalid headers for spec %"PRIu32".\n", i);
      goto error_cleanup;
    }

    // --- footers ---
    if (! read_serialized_items(fp, &array[i].numfooters, 1,
                                sizeof(array[i].numfooters), &remaining)) {
      fprintf(stderr, "Deserialization error: Failed to read numfooters for spec %"PRIu32".\n", i);
      goto error_cleanup;
    }

    if (! deserialize_offset_values(fp, array[i].numfooters,
                                    &array[i].footers, &array[i].footerlens,
                                    &remaining)) {
      fprintf(stderr, "Deserialization error: Invalid footers for spec %"PRIu32".\n", i);
      goto error_cleanup;
    }
  }

  fclose(fp);

  if (num_specs_out) {
    *num_specs_out = num_specs;
  }

  return array;

 error_cleanup:

  if (array) {
    for (uint32_t k = 0; k < specs_to_free; k++) {
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
