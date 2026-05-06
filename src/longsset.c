//
// Scalpel3 is Copyright(C) 2021 - 2026 by Golden G.Richard III and
// contributors.
//
// This program is free software : you can redistribute it and / or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option) any
// later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
// details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <https://www.gnu.org/licenses/>.
//
//-----------------------------
// Additional Integration Terms
// ----------------------------
//
// Linking or embedding Scalpel3 (statically or dynamically) into another
// program such that the resulting executable or library forms a single
// combined work constitutes creation of a derivative work under the GPL.
// Any party distributing such a combined work must make the entire source
// code available under the terms of the GPL as well.
//
// Commercial entities wishing to use Scalpel3 in a closed-source or proprietary
// product or requiring support must obtain a separate commercial license.
//
// For commercial licensing or questions about integration, contact:
// Golden G. Richard III (golden@cct.lsu.edu).
//
// Please see LICENSE.md and README.md for further information.
//
//
// uncompressed set of longs data structure, written by Golden G. Richard III
// (@nolaforensix), 2024.
//

#include "longsset.h"


// int64_t comparison function for qsort()
int compare_longs(const void *a, const void *b) {
  int64_t x = *(const int64_t *)a;
  int64_t y = *(const int64_t *)b;
  return (x > y) - (x < y);
}


// create new empty LongsSet
void create_LongsSet(LongsSet **set) {
  *set = malloc(sizeof(LongsSet));
  (*set)->len = 0;
  (*set)->set = NULL;
}


// deallocate resources associated with 'set'
void destroy_LongsSet(LongsSet **set) {
  free((*set)->set);
  free(*set);
  *set = NULL;
}


// linear search function for LongsSet
bool linear_in_LongsSet(const LongsSet *set, int64_t target) {
  for (int64_t i = 0; i < set->len; ++i) {
    if (set->set[i] == target) {
      return true;
    }
  }
  return false;
}


// binary search function for LongsSet
bool binary_in_LongsSet(const LongsSet *set, int64_t target) {
  int64_t left = 0;
  int64_t right = set->len - 1;

  while (left <= right) {
    int64_t mid = left + (right - left) / 2;

    if (set->set[mid] == target) {
      return true;
    }
    else if (set->set[mid] < target) {
      left = mid + 1;
    }
    else {
      if (mid == 0) {
        break;
      }
      right = mid - 1;
    }
  }

  return false;
}


// determine if the intersection between two sets of longs is
// non-empty.  The two sets are assumed to be sorted.  If there is any
// overlap between the two sets, the first common element is returned.
bool any_intersection_LongsSets(const LongsSet *set1,
                                const LongsSet *set2,
                                int64_t *common) {
  int64_t i = 0, j = 0;

  *common = 0;
  while (i < set1->len && j < set2->len) {
    if (set1->set[i] < set2->set[j]) {
      i++;
    }
    else if (set1->set[i] > set2->set[j]) {
      j++;
    }
    else {
      *common = set1->set[i];
      return true;
    }
  }

  return false;
}


// display the contents of a LongsSet
void display_LongsSet(const LongsSet *set) {
  if (set) {
    for (int64_t i = 0; i < set->len; i++) {
      fprintf(stdout, "%" PRId64 "%s", set->set[i], i == set->len - 1 ? "" : ",");
    }
  }
}


// add a range of long values to a set of longs, adjusting the size of
// the set as necessary and eliminating duplicates
void add_to_LongsSet(LongsSet *set, int64_t start, int64_t end) {
  if (set) {
    int64_t range_len = end - start + 1;
    if (range_len <= 0) return;

    // append all new values
    set->set = realloc(set->set, (set->len + range_len) * sizeof(int64_t));
    for (int64_t i = start; i <= end; i++) {
      set->set[set->len++] = i;
    }

    // sort once
    qsort(set->set, set->len, sizeof(int64_t), compare_longs);

    // deduplicate in-place
    if (set->len > 1) {
      int64_t write = 1;
      for (int64_t read = 1; read < set->len; read++) {
        if (set->set[read] != set->set[write - 1]) {
          set->set[write++] = set->set[read];
        }
      }
      set->len = write;
      set->set = realloc(set->set, set->len * sizeof(int64_t));
    }
  }
  else {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Fatal error: NULL set in add_to_LongsSet() on line %d.\n", __LINE__);
    fprintf(stderr, "%s", BLACK);
    // fatal
    exit(-1);
  }
}


// merge two sets containing longs and return a new set with no
// duplicate elements.  The set that is returned is sorted.
LongsSet *union_longsSets(const LongsSet *set1, const LongsSet *set2) {
  int64_t i = 0, j = 0;
  LongsSet *merged;

  create_LongsSet(&merged);

  merged->set = (int64_t *)malloc(((set1 ? set1->len : 0) +
                                   (set2 ? set2->len : 0)) *
                                  sizeof(int64_t));
  merged->len = 0;

  while (set1 && set2 && i < set1->len && j < set2->len) {
    if (set1->set[i] < set2->set[j]) {
      if (merged->len == 0 || merged->set[merged->len - 1] != set1->set[i]) {
        merged->set[merged->len++] = set1->set[i];
      }
      i++;
    }
    else if (set2->set[j] < set1->set[i]) {
      if (merged->len == 0 || merged->set[merged->len - 1] != set2->set[j]) {
        merged->set[merged->len++] = set2->set[j];
      }
      j++;
    }
    else {
      if (merged->len == 0 || merged->set[merged->len - 1] != set1->set[i]) {
        merged->set[merged->len++] = set1->set[i];
      }
      i++;
      j++;
    }
  }

  while (set1 && i < set1->len) {
    if (merged->len == 0 || merged->set[merged->len - 1] != set1->set[i]) {
      merged->set[merged->len++] = set1->set[i];
    }
    i++;
  }

  while (set2 && j < set2->len) {
    if (merged->len == 0 || merged->set[merged->len - 1] != set2->set[j]) {
      merged->set[merged->len++] = set2->set[j];
    }
    j++;
  }

  // adjust memory allocation to match size
  merged->set = realloc(merged->set, merged->len * sizeof(int64_t));

  return merged;
}

