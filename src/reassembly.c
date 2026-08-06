//
// Scalpel3 is Copyright(C) 2021 - 2026 by Golden G. Richard III and contributors.
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
//------------------------------
// Additional Integration Terms
// -----------------------------
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
// scalpel3 is a complete rewrite of the open source scalpel, which was originally developed by
// Golden G. Richard III in 2005 and then enhanced by both Vico Marziale and Golden G. Richard until
// ~2013. Earlier versions of scalpel had their roots in Foremost 0.69. The emphasis of scalpel3 is
// on *practical* solutions to solving file fragmentation for selected file types and making this
// process as fast as possible on modern hardware.
//
// IMPORTANT: scalpel3 internals differ significantly from earlier versions of scalpel and the
// configuration for scalpel3 is NOT compatible with earlier versions.
//

#include "scalpel.h"

// prototypes for private reassembly.c functions
static void LR_reassembly_init_candidate(int id, CarveInfo *candidate, uuid_string_t uuidp, uuid_string_t uuidc);

static void LR_reassembly_prepare_for_extension(int id, CarveInfo *candidate);
static int64_t LR_reassembly_get_block_choice(CarveInfo *candidate);

static void LR_reassembly_did_not_validate(int id, CarveInfo *candidate, uint64_t validates_to, int64_t block_choice);

static void LR_reassembly_extension_successful(int id, CarveInfo *candidate);
static int64_t LR_reassembly_backtrack(int id, CarveInfo *candidate, uuid_string_t uuidp, uuid_string_t uuidc);

static void LR_reassembly_gallop(int id, CarveInfo *candidate, uint64_t *validates_to, bool *validates, uint64_t *gallop,
                                 uuid_string_t uuidp, uuid_string_t uuidc);

//
// ***************************************************************************
// ***************************************************************************
// ****** This section is documented in a different fashion (with       ******
// ****** SCREAMING COMMENTS) to call attention to important            ******
// ****** requirements for custom reassembly functions, which are       ******
// ****** probably the most challenging customization feature in        ******
// ****** scalpel3. The default LR_reassembly() function below provides ******
// ****** a template for creating new custom reassembly functions.      ******
// ****** Functions prefixed with LR_ in LR_reassembly() are specific   ******
// ****** to the default left-right reassembly behavior, local to this  ******
// ****** source file only, and will require new or adapted             ******
// ****** implementations in custom reassembly functions.  Functions    ******
// ****** without this prefix can very likely be used without           ******
// ****** adaptation, with some care.                                   ******
// ***************************************************************************
// ***************************************************************************
//

// default left-to-right reassembly function. This function should be used as a template when
// designing custom reassembly functions.
void LR_reassembly(ThreadWork *work, CarveInfo **c, uuid_string_t uuidp, uuid_string_t uuidc) {

  bool validates = false;     // did the file candidate completely validate?
  uint64_t validates_to = 0;  // file candidate validates to this index
  int64_t block_choice;       // block under evaluation for inclusion in candidate
  uint64_t tick = 0;          // used to throttle progress dots
  CarveInfo *candidate = *c;  // carving candidate to process
  uint64_t oldlength;         // length of data in blockvector before tail block is
                              // evaluated
  uint64_t gallop = 0;        // tracks whether blocks that are added to
                              // extend a candidate are fully validating--this triggers "galloping"
                              // mode, where exponentially more blocks are added before each
                              // validation check

  // ***********************************************************************
  // ****** PERFORM ANY NECESSARY INIT ON CANDIDATE.  IMPLEMENTORS    ******
  // ****** OF CUSTOM REASSEMBLY FUNCTIONS SHOULD PAY CLOSE ATTENTION ******
  // ****** TO COMMENTS in LR_reassembly_init_candidate()!            ******
  // ****** IMPORTANTLY, THE INIT FUNCTION MUST CAREFULLY CHECK THE   ******
  // ****** CONFIGURATION OF THE CANDIDATE AND ANY ASSOCIATED STATE   ******
  // ****** STORED VIA THE STATE APIs, AS NEWLY COVERED BLOCKS MAY    ******
  // ****** HAVE BEEN REMOVED FROM THE CANDIDATE                      ******
  // ***********************************************************************

  LR_reassembly_init_candidate(work->id, candidate, uuidp, uuidc);

  // ******************************************
  // ****** TRY TO IMPROVE THE CANDIDATE ******
  // ******************************************

  // ************************************************************
  // ****** LOOP AND TRY CONFIGURATIONS UNTIL HOPE IS LOST ******
  // ************************************************************

  while (1) {
    // ***********************************************************
    // ****** DON'T ALLOW CANDIDATE TO EXCEEED MAXIMUM SIZE ******
    // ***********************************************************

    // check candidate against maximum size for file type and finish up if it has reached maximum
    // size
    if (reassembly_check_max_size(work->id, candidate, uuidp, uuidc)) {
      goto done_write_candidate;
    }

    // **********************************************************
    // ****** DO ANY INIT NECESSARY FOR THIS CONFIGURATION ******
    // **********************************************************

    // find appropriate block to attempt to extend candidate left to right. There's a check here for
    // zero block candidates--this should never happen in LR reassembly unless a faulty validator
    // returns validates_to = 0, which essentially undoes header discovery, but
    // LR_reassembly_prepare_for_extension() assumes that the blockvector is at least one block
    // long, so the check is here.

    if (blockvector_get_num_blocks(candidate->b) == 0) {
      // it's all over for this candidate
      destroy_candidate(&candidate);
      goto done_do_not_write_candidate;
    }

    LR_reassembly_prepare_for_extension(work->id, candidate);

    // Repeatedly try to improve the candidate by inserting a new block at the end that:
    //
    // (1) is relevant for this file type
    //
    // (2) is not already present in the blockvector
    //
    // (3) hasn't already been tried in this blockvector configuration
    //
    // ...and do backtracking as necessary...
    //
    // until the file validates or all combinations have been tried.

    // evaluate each remaining apparent block that remains in the choices array for this block index
    // (beginning with block_choice_start). The idea is to choose the one that extends the candidate
    // the most and then continue. Blocks that don't work are eliminated from consideration so they
    // won't be tried again during backtracking. There's a special case, where a selected block
    // validates all the way through, which activates "fast path" processing. This defers evaluation
    // of any other blocks in the current position.
    while (! candidate->fastpath && (block_choice = LR_reassembly_get_block_choice(candidate)) >= 0) {
      // ****************************************************************************
      // ****** CHECK KILL QUEUE TO SEE IF PROCESSING ON CANDIDATE SHOULD STOP ******
      // ****************************************************************************

      if (reassembly_check_kill_queue(work, &candidate, uuidp, uuidc)) {
        goto done_do_not_write_candidate;
      }

      // *****************************
      // ****** PROGRESS REPORT ******
      // *****************************

      // show progress so the user doesn't get nervous...
      if (tick++ % 100000 == 0 && ! scalpel_state.mode_verbose) {
        lock_fprintf(stdout, "%s.%s", BLUE, BLACK);
        fflush(stdout);
      }

      // *********************************************************************
      // ****** TRY A *SINGLE* NEW CONFIGURATION. IT IS NOT PERMISSIBLE ******
      // ****** IN REASSEMBLY FUNCTIONS THREADS TO SIGNIFICANTLY DELAY  ******
      // ****** RESPONSIVENESS TO CHECKPOINTING REQUESTS, SO AVOID      ******
      // ****** EVALUATING MULTIPLE CONFIGURATIONS BEFORE ALLOWING A    ******
      // ****** CHECKPOINT TO PROCEED, UNLESS THAT CAN BE DONE QUICKLY  ******
      // *********************************************************************

      // put the new block in place
      blockvector_set_apparent_blocknumber(candidate->b, blockvector_get_num_blocks(candidate->b) - 1, block_choice);

      // inflate only the block that was just inserted
      oldlength = inflate_blockvector_single_block(candidate->b, blockvector_get_num_blocks(candidate->b) - 1);

      if (scalpel_state.mode_verbose) {
        display_blockvector(candidate->b, "AFTER BLOCK INSERTION");
      }

      validates = reassembly_check_validation(work->id, candidate, &validates_to, uuidp, uuidc);

      if (validates) {
        // **************************************************************************
        // ***** 'candidate' IS FULLY PROCESSED--NO FURTHER ACTION IS REQUIRED ******
        // ***** REGARDLESS OF THE STATE OF REASS_RETURN_TO_IDLE, SINCE THE    ******
        // ***** THREAD IS RETURNING TO AN IDLE STATE ANYWAY NOW               ******
        // **************************************************************************
        goto done_write_candidate;
      }
      else {
        // ************************************************************************
        // ****** THIS CONFIGURATION DIDN'T FULLY VALIDATE.  REMEMBER HOW IT ******
        // ****** COMPARED TO OTHER CONFIGURATIONS AND DECIDE IF FASTPATH    ******
        // ****** IS APPROPRIATE                                             ******
        // ************************************************************************

        LR_reassembly_did_not_validate(work->id, candidate, validates_to, block_choice);
      }

      // *********************************************************************
      // ****** EITHER UNDO CHANGES SO A DIFFERENT CONFIGURATION CAN BE ******
      // ****** TRIED OR IF ON THE FASTPATH, STICK WITH THE CURRENT     ******
      // ****** TERMINAL BLOCK                                          ******
      // *********************************************************************

      if (! candidate->fastpath) {
        // undo the block inflation and length adjustment applied by
        // inflate_blockvector_single_block() so the next block can be evaluated
        deflate_blockvector_single_block(candidate->b, blockvector_get_num_blocks(candidate->b) - 1, oldlength);
      }

      // *************************************************************************
      // *************************************************************************
      // *************************************************************************
      // ****** IMPORTANT: EVERY REASSEMBLY THREAD IMPLEMENTATION MUST HAVE ******
      // ****** A STATE (LIKE THIS ONE) WHERE THE CURRENT 'candidate' IS    ******
      // ****** STABLE AND CAN BE RETURNED TO THE PROMISING QUEUE IF A      ******
      // ****** CHECKPOINT IS SIGNALED.  A RESPONSIVE CALL TO THE FUNCTION  ******
      // ****** reassembly_time_to_checkpoint() IS SUFFICIENT TO COMPLY     ******
      // ****** WITH THIS REQUIREMENT--SEE BELOW.                           ******
      // *************************************************************************
      // *************************************************************************
      // *************************************************************************

      // *************************************************************************
      // *************************************************************************
      // ****** here, 'candidate' is NOT fully processed, but the choices   ******
      // ****** array is stabilized and a restart of processing this        ******
      // ****** candidate will work as long as there's no extension of the  ******
      // ****** block vector size before processing restarts                ******
      // *************************************************************************
      // *************************************************************************

      // ********************************************************************************
      // ****** ALLOW A CHECKPOINT SIGNAL TO INDUCE MOVING 'candidate' BACK INTO   ******
      // ****** THE PROMISING QUEUE. IF reassembly_time_to_checkpoint() RETURNS    ******
      // ****** TRUE, THEN THE CANDIDATE WAS MOVED BACK TO THE PROMISING QUEUE AND ******
      // ****** THE REASSEMBLY FUNCTION MUST IMMEDIATELY EXIT WITHOUT WRITING      ******
      // ****** THE CANDIDATE.  YOUR CUSTOM REASSEMBLY THREAD *MUST* USE THE       ******
      // ****** THE DEFAULT reassembly_time_to_checkpoint() FUNCTION               ******
      // ********************************************************************************

      if (reassembly_time_to_checkpoint(work->id, candidate, uuidp, uuidc)) {
        goto done_do_not_write_candidate;
      }

      // **********************************************************************
      // ****** NOT YET TIME TO CHECKPOINT, CONTINUE EVALUATING BLOCKS   ******
      // ****** FOR CURRENT POSITION, OR IF FASTPATH, LOOP WILL COMPLETE ******
      // **********************************************************************
    }


    // ***************************************************************************
    // ****** IF THE CURRENT TERMINAL BLOCK IN THE CANDIDATE VALIDATED      ******
    // ****** COMPLETELY, TRY TO "GALLOP" AND VALIDATE CONTIGUOUS           ******
    // ****** REGIONS QUICKLY, WHILE REDUCING THE NUMBER OF CALLS TO        ******
    // ****** THE FILE VALIDATOR. THIS IS AN LR OPTIMIZATION AND CUSTOM     ******
    // ****** REASSEMBLY FUNCTIONS MAY NOT HAVE AN EQUIVALENT OPTIMIZATION. ******
    // ****** GALLOPING IS NOT RESPONSIVE TO CHECKPOINTING, BUT BECAUSE     ******
    // ****** THERE'S A REASONABLE LIMIT ON THE GALLOPING OPTIMIZATION,     ******
    // ****** CHECKPOINTING WON'T BE DEFERRED FOR TOO LONG.                 ******
    // ***************************************************************************

    if (candidate->fastpath) {
      LR_reassembly_gallop(work->id, candidate, &validates_to, &validates, &gallop, uuidp, uuidc);
    }
    else {
      gallop = 0;
    }

    if (validates) {
      // *********************************************************************************
      // ****** BECAUSE OF GALLOP, 'candidate' IS FULLY PROCESSED--NO FURTHER       ******
      // ****** ACTION IS REQUIRED REGARDLESS OF THE STATE OF REASS_RETURN_TO_IDLE  ******
      // ************************************************************************** ******
      goto done_write_candidate;
    }

    // reset all best choices as available choices (!) so they can be used during backtracking, as
    // required. The best_choices queue contains *actual* blocknumbers.
    rewind_queue(candidate->best_choices);
    while (! empty_queue(candidate->best_choices)) {
      remove_from_front(candidate->best_choices, &block_choice);
      blockvector_add_choice(candidate->b, blockvector_get_num_blocks(candidate->b) - 1,
                             filemirror_apparent_blocknumber(scalpel_state.filemirror, block_choice));
    }

    // ******************************************************************************
    // ******* WAS THE CANDIDATE SUCCESSFULLY EXTENDED BY AT LEAST ONE BLOCK? *******
    // ******************************************************************************

    if (candidate->newblock >= 0) {
      // **********************************************
      // ****** YES, FINALIZE THIS CONFIGURATION ******
      // ***********************************************

      LR_reassembly_extension_successful(work->id, candidate);

      // *****************************************************************************
      // ****** WHEN THINGS ARE PROMISING, REASSEMBLY THREADS SHOULD SHARE WORK ******
      // ****** BY CALLING reassembly_share_work()                              ******
      // *****************************************************************************

      // GGRIII: In both places

      // this path is still promising, so try to share the workload with idle threads unless
      // reassembly sharing is disabled

      if (scalpel_state.share_reassembly) {
        reassembly_share_work(work->id, candidate);
      }

    }
    else {
      // ************************************************************************************
      // ****** NO, DISCARD THE TERMINAL BLOCK SINCE IT DIDN'T PUSH VALIDATION FORWARD ******
      // ************************************************************************************

      resize_blockvector(candidate->b, blockvector_get_num_blocks(candidate->b) - 1);

      // *************************************************************
      // ****** DETERMINE IF A BACKTRACKING ATTEMPT IS POSSIBLE ******
      // *************************************************************

      if (! scalpel_state.backtrack || blockvector_get_num_blocks(candidate->b) == 1) {
        // ******************************************************************
        // ****** CANNOT BACKTRACK, END OF THE LINE FOR THIS CANDIDATE ******
        // ******************************************************************

        // lone header block or no backtracking--can't improve further
        lock_fprintf(stdout,
                     "\nReassembly thread # %1d: Abandoning work on candidate with blockvector %p"
                     " and UUIDs\n%s / %s.\n",
                     work->id, candidate->b, uuidp, uuidc);
        if (! scalpel_state.write_promising) {
          // destroy and abandon work on this candidate without writing--any block reservations are
          // released by destroy_candidate().
          destroy_candidate(&candidate);
          goto done_do_not_write_candidate;
        }
        else {
          // write and then abandon work on this candidate
          goto done_write_candidate;
        }
      }
      else {
        // *****************************************************************
        // ****** TRY BACKTRACKING TO GET A PROMISING PATH TO SUCCESS ******
        // *****************************************************************

        block_choice = LR_reassembly_backtrack(work->id, candidate, uuidp, uuidc);

        // ***************************************
        // ****** DID BACKTRACKING SUCCEED? ******
        // ***************************************

        if (block_choice != -1 && blockvector_get_num_blocks(candidate->b) > 1) {
          // **********************************************************
          // ****** YES, BACKTRACKING FOUND A NEW BLOCK FOR TAIL ******
          // **********************************************************

          // backtracking succeeded, so continue trying to expand the candidate put newly selected
          // block in place
          blockvector_set_apparent_blocknumber(candidate->b, blockvector_get_num_blocks(candidate->b) - 1, block_choice);

          // inflate_blockvector_single_block() can't be used here, because we may have drastically
          // changed the configuration of the blockvector during backtracking, so use the more
          // expensive inflate_blockvector() instead, which also normalizes the blockvector
          inflate_blockvector(candidate->b);

          if (scalpel_state.share_reassembly) {
            reassembly_share_work(work->id, candidate);
          }

          // and continue!
        }
        else {
          // *************************************************************************
          // ****** NO, BACKTRACKING FAILED, END OF THE LINE FOR THIS CANDIDATE ******
          // *************************************************************************

          // backtracking failed, destroy candidate without writing, since we already wrote a
          // pre-backtracking version of of the candidate. Any block reservations are released by
          // destroy_candidate().
          lock_fprintf(stdout,
                       "\nReassembly thread # %1d: Backtracking failed, abandoning work on"
                       " candidate with\n"
                       "blockvector %p and UUIDs\n%s / %s.\n",
                       work->id, candidate->b, uuidp, uuidc);
          destroy_candidate(&candidate);
          goto done_do_not_write_candidate;
        }
      }
    }
  }

  // done with this candidate, write
done_write_candidate:
  // write file and possibly blockvector and then free blockvector--blockvector will be freed as
  // appropriate, so we're off the hook. write_candidate() will also release any block reservations.
  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "\nReassembly thread # %1d: DWC exit on candidate (%s) with UUIDs\n%s / %s.\n", work->id,
                 candidate->flavor == PROMISING   ? "PROMISING" : candidate->flavor == VALIDATED ? "VALIDATED" : "INPROGRESS",
                 uuidp, uuidc);
  }
  write_candidate(c, false);
  goto done;

  // done with this candidate, do not write
done_do_not_write_candidate:
  // write was already completed or candidate work abandoned
  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "\nReassembly thread # %1d: DDNWC exit on candidate with UUIDs\n%s / %s.\n", work->id, uuidp, uuidc);
  }

done:;
}

//
// ****************************************************************
// ****************************************************************
// ****** GENERIC, PUBLIC REASSEMBLY SUPPORT FUNCTIONS BELOW ******
// ****************************************************************
// ****************************************************************
//

// returns true if reassembly candidate has reached maximum size, otherwise false
bool reassembly_check_max_size(int id, CarveInfo *candidate, uuid_string_t uuidp, uuid_string_t uuidc) {

  if (blockvector_get_data_length(candidate->b) > scalpel_state.search_specs[candidate->needleidx].MAXIMUMSIZE) {
    // 'candidate' has exceeded maximum size and is therefore fully processed--no further action
    // required, regardless of state of REASS_RETURN_TO_IDLE in thread, so stop and write candidate
    candidate->chopped = true;
    lock_fprintf(stdout,
                 "Reassembly thread # %1d writing and abandoning work on candidate with blockvector %p "
                 "and UUIDs\n%s / %s\nbecause size %" PRIu64 " exceeds maximum for file type %" PRIu64 ".\n",
                 id, candidate->b, uuidp, uuidc, blockvector_get_data_length(candidate->b),
                 scalpel_state.search_specs[candidate->needleidx].MAXIMUMSIZE);
    return true;
  }
  else {
    return false;
  }
}


// check kill queue to see if current candidate being processed by reassembly thread should be
// destroyed. Returns true if the candidate should be destroyed, otherwise false.
bool reassembly_check_kill_queue(ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp, uuid_string_t uuidc) {

  char buf[MAX_STRING_LENGTH];
  unsigned char *killuuid;
  uint64_t generation;
  bool clone_killed = false;
  bool primary_killed = false;
  bool has_clone;

  generation = atomic_load_explicit(&kill_queue_generation, memory_order_acquire);
  if (work->last_kill_generation_checked == generation) {
    return false;
  }

  has_clone = ! uuid_is_null((*candidate)->clone_binuuid);

  lock_queue(&kill_queue);
  generation = atomic_load_explicit(&kill_queue_generation, memory_order_acquire);
  nolock_rewind_queue(&kill_queue);
  while (! nolock_end_of_queue(&kill_queue)) {
    killuuid = nolock_pointer_to_current(&kill_queue);
    if (uuid_compare((*candidate)->binuuid, killuuid) == 0) {
      primary_killed = true;
      break;
    }
    if (has_clone && uuid_compare((*candidate)->clone_binuuid, killuuid) == 0) {
      clone_killed = true;
      nolock_delete_current(&kill_queue);
      break;
    }
    nolock_next_element(&kill_queue);
  }

  if (! primary_killed && ! clone_killed) {
    work->last_kill_generation_checked = generation;
  }
  unlock_queue(&kill_queue);

  if (primary_killed) {
    // primary UUIDs may identify both a primary candidate and clones, so retain the order for aging
    snprintf(buf, MAX_STRING_LENGTH, "DESTROYING CANDIDATE WITH PRIMARY UUID \"%s\"", uuidp);
    frame_message(buf);
    destroy_candidate(candidate);
    return true;
  }

  if (clone_killed) {
    // clone UUIDs are unique, so their kill orders are consumed with the matching candidate
    snprintf(buf, MAX_STRING_LENGTH, "DESTROYING CANDIDATE WITH CLONE UUID \"%s\"", uuidc);
    frame_message(buf);
    destroy_candidate(candidate);
    return true;
  }

  return false;
}

// determine if it's time to checkpoint.  If it is, return the candidate to the promising
// queue. This function also updates critical thread scheduling priorities for the
// candidate. Returns true if the thread must return to idle state to allow a checkpoint to proceed,
// otherwise false.
bool reassembly_time_to_checkpoint(int id, CarveInfo *candidate, uuid_string_t uuidp, uuid_string_t uuidc) {
  struct timespec end;

  if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
    candidate->no_initial_block_extension = true;

    // candidate must be returned to the promising queue
    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout,
                   "\nReassembly thread # %1d: returning candidate with blockvector %p and UUIDs"
                   "\n%s / %s\nto promising queue during checkpoint.\n",
                   id, candidate->b, uuidp, uuidc);
    }

    delete_from_reassembly_queue(candidate);

    clock_gettime(CLOCK_MONOTONIC, &end);
    candidate->qposition -= (end.tv_sec - candidate->last_start.tv_sec)
                              * NANOSECONDS_PER_SECOND
                            + (end.tv_nsec - candidate->last_start.tv_nsec);

    if (scalpel_state.reduce_aggressive_allocation) {
      deflate_blockvector(candidate->b);
    }

    add_to_queue_priority_relaxed(&promising_queue, &candidate, candidate->qposition);

    return true;
  }

  return false;
}


// handle work sharing between reassembly threads
void reassembly_share_work(int id, CarveInfo *candidate) {

  uuid_string_t uuidp;
  uuid_string_t uuidc;
  void *state;

  // first determine if other reassembly threads are idle *and* the promising queue is empty. If so,
  // clone current candidate and add it to the promising queue to give them something to do.
  // Otherwise, just return.

  int32_t idle;
  int shares = 0;

  // fast, no locks exit for common case
  if (nolock_queue_length(&promising_queue) || atomic_load_explicit(&num_idle_reassembly_threads, memory_order_acquire) == 0) {
    return;
  }

  while ((idle = atomic_load_explicit(&num_idle_reassembly_threads, memory_order_acquire)) > 0
         && nolock_queue_length(&promising_queue) <= 1 && ++shares <= MAX_REASSEMBLY_SHARES) {
    // clone candidate
    CarveInfo *clone = (CarveInfo *)malloc(sizeof(CarveInfo));
    check_memory_allocation(clone, __LINE__, __FILE__, "clone");

    // top level copy first
    memcpy(clone, candidate, sizeof(CarveInfo));

    // original candidate gets marked as contributing work to another thread
    candidate->cloned = true;

    // clone gets marked as such
    clone->clone = true;
    clone->cloned = true;
    clone->no_initial_block_extension = false;
    // randomize only the clone's first extension so it diverges from the parent without
    // sacrificing locality for the remainder of its path. This cursor is checkpointed.
    clone->block_choice_start = -1;

    // clone gets a new UUID, but also keeps the original "parent" UUID for association
    uuid_generate_random(clone->clone_binuuid);

    // clone blockvector including choice info
    clone_blockvector(candidate->b, &clone->b, true);

    // get textual UUIDs for status message
    uuid_unparse_lower(candidate->binuuid, uuidp);
    uuid_unparse_lower(clone->clone_binuuid, uuidc);
    lock_fprintf(stdout, "\nReassembly thread # %1d sharing work with UUIDs\n%s / %s\nwith idle reassembly threads.\n", id, uuidp,
                 uuidc);

    // new best_choices queue for clone
    clone->best_choices = malloc(sizeof(Queue));
    check_memory_allocation(clone->best_choices, __LINE__, __FILE__, "clone->best_choices");
    init_queue(clone->best_choices, sizeof(int64_t), true, NULL, true);

    // clone needs a new hash key
    gen_carve_hash_key(clone->carvehashkey, clone);

    // clone carve state, if it exists. For get_state, use the hashkey of the original carve
    // candidate. For put_state, use the clone's hashkey.
    if (scalpel_state.search_specs[candidate->needleidx].carve_state && (state = carve_get_state(candidate->carvehashkey))) {
      void *cloned_state = scalpel_state.search_specs[candidate->needleidx].CLONECARVESTATEFUNC(state);
      carve_put_state(clone->carvehashkey, cloned_state);
      // carve_put_state clones again internally (val_ops.cp); free the intermediate copy
      scalpel_state.search_specs[candidate->needleidx].FREECARVESTATEFUNC(&cloned_state);
      // carve_get_state returns a heap-allocated copy; free it
      scalpel_state.search_specs[candidate->needleidx].FREECARVESTATEFUNC(&state);
    }

    // force clone to get a new, unique INPROGRESS filename
    clone->inprogress_pathname[0] = 0;

    // let idle threads know more work is available
    MUTEX_ERROR_CHECK(pthread_mutex_lock(&reassembly_work_is_available), __LINE__, __FILE__);

    // add to promising queue
    add_to_queue_priority_relaxed(&promising_queue, &clone, candidate->qposition);
    pthread_cond_broadcast(&reassembly_check_work_available);
    MUTEX_ERROR_CHECK(pthread_mutex_unlock(&reassembly_work_is_available), __LINE__, __FILE__);
  }
}


// determine if 'candidate' fully validates and handle some cleanup if it does. Returns true if the
// candidate validates, otherwise false.
bool reassembly_check_validation(int id, CarveInfo *candidate, uint64_t *validates_to, uuid_string_t uuidp, uuid_string_t uuidc) {

  bool validates = false;
  bool promising;

  // use the file validation function to see if adding this block results in a longer validated
  // segment of the candidate

#if VALIDATOR_PERFORMANCE_STATS > 0
  struct timespec FV_starttime;
  struct timespec FV_endtime;

  clock_gettime(CLOCK_MONOTONIC, &FV_starttime);
#endif

#if PRINT_CARVE_STATE > 0

  char output[CARVE_HASH_KEY_PRINTABLE_SIZE];

  if ((scalpel_state.mode_verbose || PRINT_CARVE_STATE > 0)
      && scalpel_state.search_specs[candidate->needleidx].SERIALIZECARVESTATEFUNC
      && scalpel_state.search_specs[candidate->needleidx].PRINTCARVESTATEFUNC) {
    // locking is used to generate coherent output when multiple threads are active--this reduces
    // performance, but PRINT_CARVE_STATE should only be used for debugging.
    MUTEX_ERROR_CHECK(pthread_mutex_lock(&printf_is_available), __LINE__, __FILE__);

    fprintf(stdout,
            "\nStored state for reassembly candidate with UUIDs\n"
            "%s and %s and\n"
            "hash key %s\n"
            "BEFORE file validation:\n",
            uuidp, uuidc, displayable_carve_hash_key(candidate->carvehashkey, output));
    void *tmp_state = carve_get_state(candidate->carvehashkey);
    scalpel_state.search_specs[candidate->needleidx].PRINTCARVESTATEFUNC(tmp_state);
    // carve_get_state returns a heap-allocated copy; free it
    if (tmp_state) {
      scalpel_state.search_specs[candidate->needleidx].FREECARVESTATEFUNC(&tmp_state);
    }
    fprintf(stdout, "\n");

    MUTEX_ERROR_CHECK(pthread_mutex_unlock(&printf_is_available), __LINE__, __FILE__);
  }
#endif

  // call validator
  scalpel_state.search_specs[candidate->needleidx].FILEVALIDATOR(blockvector_get_data_pointer(candidate->b),
                                                                 blockvector_get_data_length(candidate->b), &validates,
                                                                 validates_to, &promising, candidate->needleidx,
                                                                 scalpel_state.blocksize, candidate->carvehashkey);


#if PRINT_CARVE_STATE > 0
  if (scalpel_state.search_specs[candidate->needleidx].SERIALIZECARVESTATEFUNC
      && scalpel_state.search_specs[candidate->needleidx].PRINTCARVESTATEFUNC) {
    // locking is used to generate coherent output when multiple threads are active--this reduces
    // performance, but PRINT_CARVE_STATE should only be used for debugging.
    MUTEX_ERROR_CHECK(pthread_mutex_lock(&printf_is_available), __LINE__, __FILE__);

    fprintf(stdout,
            "\nStored state for reassembly candidate with UUIDs\n"
            "%s and %s and\n"
            "hash key %s\n"
            "AFTER file validation:\n",
            uuidp, uuidc, displayable_carve_hash_key(candidate->carvehashkey, output));
    void *tmp_state2 = carve_get_state(candidate->carvehashkey);
    scalpel_state.search_specs[candidate->needleidx].PRINTCARVESTATEFUNC(tmp_state2);
    // carve_get_state returns a heap-allocated copy; free it
    if (tmp_state2) {
      scalpel_state.search_specs[candidate->needleidx].FREECARVESTATEFUNC(&tmp_state2);
    }
    fprintf(stdout, "\n");

    MUTEX_ERROR_CHECK(pthread_mutex_unlock(&printf_is_available), __LINE__, __FILE__);
  }
#endif


#if VALIDATOR_PERFORMANCE_STATS > 0
  // update file validator performance stats
  clock_gettime(CLOCK_MONOTONIC, &FV_endtime);
  uint64_t FV_elapsed = (FV_endtime.tv_sec - FV_starttime.tv_sec) * NANOSECONDS_PER_SECOND
                        + (FV_endtime.tv_nsec - FV_starttime.tv_nsec);

  atomic_fetch_add_explicit(&scalpel_state.search_specs[candidate->needleidx].FV_calls, 1, memory_order_acq_rel);
  atomic_max_u64_pub(&scalpel_state.search_specs[candidate->needleidx].FV_longest, FV_elapsed);
  atomic_fetch_add_explicit(&scalpel_state.search_specs[candidate->needleidx].FV_total, FV_elapsed, memory_order_acq_rel);
#endif


  if (validates) {
    candidate->flavor = VALIDATED;
    blockvector_set_data_length(candidate->b, *validates_to + 1);
    // Trim blockvector to only the blocks needed for the validated data length,
    // discarding any extra trailing block added during reassembly.
    resize_blockvector(candidate->b, CEILDIV(blockvector_get_data_length(candidate->b), scalpel_state.blocksize));
    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout,
                   "Reassembly thread # %1d writing validated candidate with"
                   " blockvector %p and UUIDs\n%s / %s.\n.",
                   id, candidate->b, uuidp, uuidc);
    }

    return true;
  }

  return false;
}

//
// *********************************************************************************
// *********************************************************************************
// ****** SUPPORT FUNCTIONS SPECIFIC TO DEFAULT LR REASSEMBLY FUNCTION APPEAR ******
// ****** BELOW. CUSTOM REASSEMBLY FUNCTIONS WILL NEED SIMILAR PROCESSING,    ******
// ****** BUT IT IS LIKELY THAT CUSTOM SUPPORT FUNCTIONS WILL BE REQUIRED.    ******
// *********************************************************************************
// *********************************************************************************
//


// prepare a candidate removed from the promising queue for processing by a reassembly thread. This
// is where validation of the candidate and setup for a reassembly effort should be performed.
//
// VERY IMPORTANT: IF YOU ARE WRITING A CUSTOM REASSEMBLY FUNCTION, READ ALL OF THE FOLLOWING
// CAREFULLY UNTIL IT MAKES SENSE!

// VERY IMPORTANT: the default LR reassembly function has more support from the scalpel3 backend
// than custom reassembly functions for candidate initialization and maintenance, but there are
// important considerations here for both LR and custom reassembly functions.
//
// The default LR reassembly function can assume at this point the candidate is either:
//
// (1) a new fragment that was created during a contiguous file carving effort
//
// (2) a new "header-only" candidate generated in the D2 phase in fragmented reassembly
//
// (3) a candidate that was previously presented to a default LR reassembly function and which might
//     have been lengthened or shortened during processing by that function OR truncated by the
//     scalpel3 backend
//
// VERY IMPORTANT: When blocks in a candidate become covered (because they were associated with a
// validated file, for example), the scalpel3 backend automatically truncates default LR reassembly
// candidates just before the first block that was covered. See validate_promising_queue() in
// carve.c and validate_blockvector() in filemirror.c for more details. This means that for LR
// reassembly candidates, there's little validation to do here.
//
// HOWEVER: If a custom reassembly function is used for a file type, TRUNCATION IS NOT PERFORMED
// WHEN BLOCKS IN THE CANDIDATE BECOME COVERED. Instead, any blocks in the candidate that become
// covered are simply marked invalid by setting their apparent and actual blocknumbers to -1. The
// length of the candidate is not impacted by these changes.
//
// Custom reassembly functions MUST address several challenges because of the backend invalidation
// of covered blocks:
//
// (1) Critical portions of the candidate (e.g., the footer, for SEARCHTYPE_BACKWARD file types) may
//     have been invalidated because blocks in the candidate became covered.  Custom reassembly
//     functions functions MUST check the candidate to see if it is viable, because blocks
//     invalidated by coverage events may have removed critical elements of the candidate's
//     structure!  You must destroy the candidate if recovery is now hopeless.
//
// (2) If you are using the state APIs, state may need to be updated because the candidate lost
//     blocks described by the state due to coverage events.  It is essential that state be verified
//     in your init_candidate() function.
//
static void LR_reassembly_init_candidate(int id, CarveInfo *candidate, uuid_string_t uuidp, uuid_string_t uuidc) {

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "\nReassembly thread # %1d waking up to process candidate with blockvector %p and UUIDs\n%s / %s.\n", id,
                 candidate->b, uuidp, uuidc);
  }

  // in fragmented reassembly, chopped will be set when a partially validated file actually reaches
  // maximum size
  candidate->chopped = false;

  // inflate blockvector in case it was previously deflated to save memory
  inflate_blockvector(candidate->b);
}


// set up reassembly candidate length and block choice start. A newly shared clone carries -1 so its
// first extension begins randomly. After that choice advances the cursor, clone identity remains
// intact but later extensions resume from the apparent block following the current tail. If the
// cursor is -2, the block two beyond the terminal block is chosen.
static void LR_reassembly_prepare_for_extension(int id, CarveInfo *candidate) {
  (void)id;

  // fastpath is deactivated
  candidate->fastpath = false;

  // increase the size of the blockvector by one block UNLESS candidate->no_initial_block_extension
  // is true, which means that processing of the current terminal block wasn't complete when a
  // REASS_RETURN_TO_IDLE occurred and this candidate was dumped back into the promising queue. In
  // that case, starting length is already correct, so don't adjust.

  if (! candidate->no_initial_block_extension) {
    resize_blockvector(candidate->b, blockvector_get_num_blocks(candidate->b) + 1);
    candidate->newblock = -1;
    candidate->best_validates_to = blockvector_get_data_length(candidate->b) - 1;
  }
  else {
    // back to normal
    candidate->no_initial_block_extension = false;
  }

  // figure out where to start searching for a block to extend this candidate
  // leave the one-shot random-start sentinel in place for a clone's first extension
  if (! candidate->clone || candidate->block_choice_start != -1) {
    // this works because it's guaranteed that the current length is at least 2 blocks--the header
    // block is never swapped out for another block
    candidate->block_choice_start = blockvector_get_apparent_blocknumber(candidate->b, blockvector_get_num_blocks(candidate->b) - 2)
                                    + (candidate->block_choice_start == -2 ? 2 : 1);
  }
}


// get a block choice for the current terminal block index in an LR reassembly effort.
//
// IMPORTANT: If you are writing a custom reassembly function, note that the primitive filemirror
// block choice API does NOT consider block types, reservations, or duplication of blocks in the
// blockvector. You must specifically address these issues, as below.
//
static int64_t LR_reassembly_get_block_choice(CarveInfo *candidate) {

  int64_t block_choice = -1;
  int64_t best_choice = -1;
  int64_t adjacent_choice = -1;
  int64_t actualblocknumber;
  int64_t reserved;
  int64_t count;
  uint64_t slot;
  uint64_t evaluated;
  bool viable;
  bool adjacent;
  bool terminal_choice = false;
  BlockValidationDecision confidence;
  BlockValidationDecision best_confidence = BLOCK_CONFIDENCE_INVALID;
  BlockValidationDecision adjacent_confidence = BLOCK_CONFIDENCE_INVALID;
  int64_t best_reserved = INT64_MAX;
  int64_t adjacent_reserved = INT64_MAX;

#if BLOCK_SELECTION_PERFORMANCE_STATS > 0
  struct timespec BLK_starttime;
  struct timespec BLK_endtime;
  uint64_t BLK_examined = 0;

  clock_gettime(CLOCK_MONOTONIC, &BLK_starttime);
#endif

  // maximum # of blocks that must be evaluated as choices
  count = filemirror_apparent_blocks(scalpel_state.filemirror);
  slot = blockvector_get_num_blocks(candidate->b) - 1;

  // calculate the only apparent-adjacent choice once. The scan cursor advances below and is not a
  // reliable indication of adjacency after the first lookup.
  if (slot > 0) {
    int64_t previous = blockvector_get_apparent_blocknumber(candidate->b, slot - 1);
    if (previous >= 0 && previous + 1 < count) {
      adjacent_choice = previous + 1;
    }
  }

  // make at most one pass through all choices to find a good block choice
  while (count > 0) {
    // get a potential block choice from the filemirror
    block_choice = blockvector_get_choice(candidate->b, slot, candidate->block_choice_start,
                                          count, &evaluated);

#if BLOCK_SELECTION_PERFORMANCE_STATS > 0
    BLK_examined += evaluated;
#endif

    if (block_choice == -1) {
      // no more choices
      break;
    }

    adjacent = block_choice == adjacent_choice;

    candidate->block_choice_start = (block_choice + 1) % filemirror_apparent_blocks(scalpel_state.filemirror);

    // reduce number of blocks to evaluate
    count -= evaluated;

    actualblocknumber = filemirror_actual_blocknumber(scalpel_state.filemirror, block_choice);

    confidence = filemirror_get_blocktype(scalpel_state.filemirror, actualblocknumber, candidate->needleidx);

    // see if the choice is a viable candidate--the filemirror API block choices API doesn't verify
    // block types or duplication of blocks--must explicitly check for blocks that are already in
    // use for this candidate and for correct type
    viable = confidence != BLOCK_CONFIDENCE_INVALID
             && ! apparent_block_in_blockvector(candidate->b, block_choice);

    // see how many reservations are associated with the potential choice if reservation system is
    // active
    reserved = scalpel_state.reservations ? filemirror_actual_block_reserved(scalpel_state.filemirror, actualblocknumber) : 0;

    if (! viable) {
      // non-viable blocks are always removed as future choices
      blockvector_remove_choice(candidate->b, slot, block_choice);
      continue;
    }

    // accept an unbeatable choice immediately. Confidence cannot exceed VALID and reservation
    // pressure cannot be lower than zero, so no later choice can rank above this one.
    if (confidence == BLOCK_CONFIDENCE_VALID && reserved == 0) {
      best_choice = block_choice;
      best_confidence = confidence;
      best_reserved = reserved;
      terminal_choice = true;
      break;
    }

    // keep the apparent-adjacent candidate separately so locality is evaluated against a stable
    // target rather than the moving scan cursor.
    if (adjacent) {
      adjacent_confidence = confidence;
      adjacent_reserved = reserved;
    }

    // Track the best viable candidate by type confidence first, then reservation count.
    // Reservations are advisory: they break ties or penalize weaker options, but do not hard-reject
    // a viable block.
    if (best_choice == -1
        || confidence > best_confidence
        || (confidence == best_confidence && reserved < best_reserved)) {
      best_choice = block_choice;
      best_confidence = confidence;
      best_reserved = reserved;
    }
  }

  // allow apparent adjacency to make up one confidence point when it does not add reservation
  // pressure. An exact VALID/zero-reservation choice above remains terminal.
  if (! terminal_choice && adjacent_confidence != BLOCK_CONFIDENCE_INVALID
      && best_choice != -1 && best_choice != adjacent_choice) {
    int best_conf = (int)best_confidence;
    int adjacent_conf = (int)adjacent_confidence;
    if (best_conf <= adjacent_conf + 1 && adjacent_reserved <= best_reserved) {
      best_choice = adjacent_choice;
      best_confidence = adjacent_confidence;
      best_reserved = adjacent_reserved;
    }
  }

  if (best_choice != -1) {
    // advance block choice
    blockvector_remove_choice(candidate->b, slot, best_choice);
  }

#if BLOCK_SELECTION_PERFORMANCE_STATS > 0
  // update block selection performance stats
  clock_gettime(CLOCK_MONOTONIC, &BLK_endtime);
  uint64_t BLK_elapsed = (BLK_endtime.tv_sec - BLK_starttime.tv_sec) * NANOSECONDS_PER_SECOND
                         + (BLK_endtime.tv_nsec - BLK_starttime.tv_nsec);

  atomic_fetch_add_explicit(&scalpel_state.search_specs[candidate->needleidx].BLK_calls, 1, memory_order_acq_rel);
  atomic_max_u64_pub(&scalpel_state.search_specs[candidate->needleidx].BLK_longest, BLK_elapsed);
  atomic_fetch_add_explicit(&scalpel_state.search_specs[candidate->needleidx].BLK_total, BLK_elapsed, memory_order_acq_rel);
  atomic_max_u64_pub(&scalpel_state.search_specs[candidate->needleidx].BLK_most_blocks, BLK_examined);
#endif

  return best_choice;
}


// handle successful reassembly candidate extension. There's nothing to do here if fastpath was
// enabled, because the terminal block in the blockvector is already in place for fastpath
// processing.
static void LR_reassembly_extension_successful(int id, CarveInfo *candidate) {
  (void)id;

  if (! candidate->fastpath) {
    // candidate->newblock is an *actual* blocknumber, so translate it before adding it to the
    // blockvector
    blockvector_set_apparent_blocknumber(candidate->b, blockvector_get_num_blocks(candidate->b) - 1,
                                         filemirror_apparent_blocknumber(scalpel_state.filemirror, candidate->newblock));

    // inflate only the new block
    inflate_blockvector_single_block(candidate->b, blockvector_get_num_blocks(candidate->b) - 1);

    // new length
    blockvector_set_data_length(candidate->b, candidate->best_validates_to + 1);
  }
}


// candidate did not fully validate--remember how good this configuration was compared to others
static void LR_reassembly_did_not_validate(int id, CarveInfo *candidate, uint64_t validates_to, int64_t block_choice) {

  int64_t actualblocknumber;
  bool better = false;

  (void)id;

  // is it the best choice so far?
  if (validates_to > candidate->best_validates_to) {
    // this is the best block so far for the current block index. If there were previous bests,
    // forget about them...
    if (candidate->newblock >= 0) {
      destroy_queue(candidate->best_choices);
    }

    // ... and remember this block as the best
    candidate->best_validates_to = validates_to;

    // candidate->newblock is an *actual* blocknumber
    candidate->newblock = filemirror_actual_blocknumber(scalpel_state.filemirror, block_choice);

    better = true;
  }
  else if (validates_to == candidate->best_validates_to && candidate->newblock >= 0) {
    // matches the previous best so far, so remember as a candidate for backtracking. The
    // best_choices queue contains *actual* blocknumbers to survive blockmap swaps.
    actualblocknumber = filemirror_actual_blocknumber(scalpel_state.filemirror, block_choice);
    add_to_queue(candidate->best_choices, &actualblocknumber, 0);

    better = true;
  }

  // fastpath is activated if the *new* block validates completely
  if (better && validates_to == blockvector_get_data_length(candidate->b) - 1) {
    candidate->fastpath = true;
  }

  // GGRIII: be sure stale new_block values are destroyed if (! better &&
  // candidate->best_validates_to <= blockvector_get_data_length(candidate->b) - 1) {
  // candidate->newblock = -1; }
}


// try to backtrack to find a promising path to extend 'candidate'. Returns a new block choice or -1
// to indicate backtracking failed.
static int64_t LR_reassembly_backtrack(int id, CarveInfo *candidate, uuid_string_t uuidp, uuid_string_t uuidc) {

  int64_t block_choice = -1;

  if (scalpel_state.mode_verbose) {
    display_blockvector(candidate->b, "BACKTRACKING");
  }

  // will try backtracking
  atomic_fetch_add_explicit(&scalpel_state.search_specs[candidate->needleidx].backtracked, 1, memory_order_acq_rel);

  if (scalpel_state.write_promising) {
    // backtracking might not do a better job, so write a copy of candidate before proceeding
    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout,
                   "\nReassembly thread # %1d: candidate with blockvector %p and UUIDs"
                   "\n%s / %s\ndidn't validate, writing currrent version and backtracking.\n",
                   id, candidate->b, uuidp, uuidc);
    }
    write_candidate(&candidate, true);
  }
  else {
    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout,
                   "\nReassembly thread # %1d: candidate with blockvector %p and UUIDs"
                   "\n%s / %s\ndidn't validate, not writing and backtracking.\n",
                   id, candidate->b, uuidp, uuidc);
    }
  }

  // try to backtrack, since this is the end of the line for current sequence of blocks. Current
  // choice for tail doesn't work, so mark it as already tried.

  blockvector_remove_choice(candidate->b, blockvector_get_num_blocks(candidate->b) - 1,
                            blockvector_get_apparent_blocknumber(candidate->b, blockvector_get_num_blocks(candidate->b) - 1));

  while (blockvector_get_num_blocks(candidate->b) > 1 && block_choice == -1) {
    // find a new tail to use in backtracking
    candidate->block_choice_start = blockvector_get_apparent_blocknumber(candidate->b, blockvector_get_num_blocks(candidate->b) - 1)
                                    + 1;
    block_choice = LR_reassembly_get_block_choice(candidate);

    if (block_choice == -1) {
      // need to backtrack more
      resize_blockvector(candidate->b, blockvector_get_num_blocks(candidate->b) - 1);
    }
  }

  if (scalpel_state.mode_verbose) {
    display_blockvector(candidate->b, "AFTER BACKTRACKING");
  }

  return block_choice;
}


// galloping mode is a an optimization for LR reassembly to attempt to quickly validate groups of
// contiguous blocks. When an appended block results in validation through the end of that block,
// galloping mode is entered, where an exponentially increasing number of *contiguous* apparent
// blocks are appended to the candidate before a subsequent validation. The idea is to try to
// quickly validate fragments of the candidate composed of logically contiguous blocks. When
// validation doesn't reach the end of a candidate's blockvector, galloping mode is exited.
static void LR_reassembly_gallop(int id, CarveInfo *candidate, uint64_t *validates_to, bool *validates, uint64_t *gallop,
                                 uuid_string_t uuidp, uuid_string_t uuidc) {
  int64_t pregallop_newblock;     // block choice before galloping is attempted
  uint64_t pregallop_num_blocks;  // number of blocks in blockvector before gallop attempt
  uint64_t gallop_count;          // number of new blocks added during gallop attempt
  int64_t last_block;             // last apparent block in filemirror
  int64_t next;                   // next contiguous block to try
  uint64_t idx;


  // enter or increase speed of gallop mode

  if (*gallop == 0) {
    *gallop = scalpel_state.gallop_factor;
  }
  else {
    *gallop *= scalpel_state.gallop_factor;
    if (*gallop > scalpel_state.gallop_limit) {
      *gallop = scalpel_state.gallop_limit;
    }
  }

  // try to add 'gallop' additional contiguous blocks and then revalidate, to attempt to decrease
  // the number of calls to the validator for contiguous regions of the candidate

  gallop_count = 0;
  pregallop_newblock = candidate->newblock;
  pregallop_num_blocks = blockvector_get_num_blocks(candidate->b);

  last_block = filemirror_apparent_blocks(scalpel_state.filemirror);
  next = blockvector_get_apparent_blocknumber(candidate->b, blockvector_get_num_blocks(candidate->b) - 1) + 1;

  // try to find adjacent blocks for new tail of blockvector--we don't use
  // LR_reassembly_get_block_choice() because more control over block selection is needed
  while (gallop_count < *gallop && next < last_block
         && next == blockvector_get_apparent_blocknumber(candidate->b, blockvector_get_num_blocks(candidate->b) - 1) + 1
         && filemirror_get_blocktype(scalpel_state.filemirror, filemirror_actual_blocknumber(scalpel_state.filemirror, next),
                                     candidate->needleidx) != BLOCK_CONFIDENCE_INVALID
         && ! filemirror_actual_block_covered(scalpel_state.filemirror,
                                              filemirror_actual_blocknumber(scalpel_state.filemirror, next))
         && ! apparent_block_in_blockvector(candidate->b, next)) {
    // add space for new block
    resize_blockvector(candidate->b, blockvector_get_num_blocks(candidate->b) + 1);

    // put the new block in place
    blockvector_set_apparent_blocknumber(candidate->b, blockvector_get_num_blocks(candidate->b) - 1, next);

    next = next + 1;

    // ...and inflate only the block that was just inserted
    inflate_blockvector_single_block(candidate->b, blockvector_get_num_blocks(candidate->b) - 1);
    gallop_count++;
  }

  // only proceed with galloping if some contiguous blocks were added
  if (! gallop_count) {
    // couldn't even identify contiguous blocks to try, so stop galloping and signal a change in
    // block selection strategy in LR_reassembly_prepare_for_extension() via block_choice_start =
    // -2.
    candidate->block_choice_start = -2;
  }
  else {
    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout, "For candidate %p, GALLOPING %" PRIu64 " BLOCKS!!!!\n", (void *)candidate, gallop_count);
    }

    // try to gallop--see if contiguous blocks push validation forward
    *validates = reassembly_check_validation(id, candidate, validates_to, uuidp, uuidc);

    if (*validates) {
      // this is necessary because galloping likely introduces extra blocks at the end of the
      // candidate and we don't want these removed from consideration for other candidates!
      // Trim data length to actual validated size, not the inflated gallop length.
      blockvector_set_data_length(candidate->b, *validates_to + 1);
      resize_blockvector(candidate->b, CEILDIV(blockvector_get_data_length(candidate->b), scalpel_state.blocksize));
    }
    else if (*validates_to > candidate->best_validates_to) {
      // galloping worked, adjust length and trim blocks that aren't part of validation
      blockvector_set_data_length(candidate->b, *validates_to + 1);
      resize_blockvector(candidate->b, CEILDIV(blockvector_get_data_length(candidate->b), scalpel_state.blocksize));

      // remove choices for blocks that stayed
      for (idx = pregallop_num_blocks - 1; idx < blockvector_get_num_blocks(candidate->b); idx++) {
        blockvector_remove_choice(candidate->b, idx, blockvector_get_apparent_blocknumber(candidate->b, idx));
      }

      // this is the best so far
      candidate->best_validates_to = blockvector_get_data_length(candidate->b) - 1;

      // update newblock to indicate new tail; candidate->newblock is an *actual* blocknumber
      candidate->newblock = filemirror_actual_blocknumber(scalpel_state.filemirror,
							  blockvector_get_apparent_blocknumber(candidate->b,
                                                                                               blockvector_get_num_blocks(candidate->b)
                                                                                               - 1));

      if (blockvector_get_data_length(candidate->b) % scalpel_state.blocksize) {
        // even though galloping worked, validation didn't go through the end of the last block in
        // the blockvector, so galloping stops and reassembly must be open to better choices for the
        // current tail of this candidate. We can at least suggest a new starting point for block
        // selection, which is the block after the current terminal block.
        *gallop = 0;
        candidate->block_choice_start = blockvector_get_apparent_blocknumber(candidate->b,
                                                                             blockvector_get_num_blocks(candidate->b) - 1) + 1;
      }

      // must destroy best_choices queue, as it applied to the old terminal block before galloping
      destroy_queue(candidate->best_choices);
    }
    else {
      // galloping didn't work at all, so the next apparent block isn't part of this candidate. Stop
      // galloping, restore the prior-to-gallop state, and also signal a change in block selection
      // strategy in LR_reassembly_prepare_for_extension() via block_choice_start = -2.
      candidate->newblock = pregallop_newblock;
      resize_blockvector(candidate->b, pregallop_num_blocks);
      candidate->fastpath = false;
      candidate->block_choice_start = -2;
    }
  }
}

