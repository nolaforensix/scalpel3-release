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
// ----------------------------
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

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunused-parameter"

#if !defined(SCALPEL_FZIP_H)
#define SCALPEL_FZIP_H

#include "scalpel.h"

// Filetype-specific validation functions for filetype "fzip" (fragmented ZIP).

static inline char *fzip_footer_discovery(char *data,
					  uint64_t length,
					  char **matchpos,
					  uint32_t *matchlen,
					  uint32_t blocksize);

static inline uint32_t fzip_block_validate(char *data,
					   uint64_t length,
					   BlockValidationDecision *decision,
					   uint64_t *validates_to,
					   uint32_t needleidx,
					   uint32_t blocksize,
					   void *blockhashkey);

static inline void fzip_reassembly(ThreadWork *work,
				   CarveInfo **c,
				   uuid_string_t uuidp,
				   uuid_string_t uuidc);

static inline uint32_t fzip_block_validate(char *data,
					   uint64_t length,
					   BlockValidationDecision *decision,
					   uint64_t *validates_to,
					   uint32_t needleidx,
					   uint32_t blocksize,
					   void *blockhashkey) {

  *decision = BLOCK_CONFIDENCE_VALID;
  *validates_to = length - 1;

  if (scalpel_state.mode_verbose) {
    printf("fzip_block_validate() called on %p.\n", data);
  }

  return needleidx;
}

static inline void fzip_reassembly(ThreadWork *work,
				   CarveInfo **c,
				   uuid_string_t uuidp,
				   uuid_string_t uuidc) {

  lock_fprintf(stdout, "fzip_reassembly: THANKS FOR CALLING!  I have no idea what to do!\n");
  destroy_candidate(c);
}



#endif
#pragma GCC diagnostic pop

