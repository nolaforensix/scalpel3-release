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

// scalpel3 file type configuration and information file.
//
// This configuration file defines important information about specific file types that scalpel3
// supports and isolates this information from the bulk of the scalpel3 source code. The format of
// this file is NOT compatible with earlier versions of scalpel.
//
// If you are adding a new file type to scalpel3, please read this file carefully. Each file type
// must have an element in the INITIAL_SEARCH_SPECS array (defined below) and a separate .h file
// (e.g., for gif files, gif.h) that contains the implementation of file-type specific functions.
// Studying the synthetic "abc" file type (with functions defined in "abc.h") will be useful in
// getting started.
//
//
// *************************************
// ****** DEFINING NEW FILE TYPES ******
// *************************************
//
// The definition for each file type contains a number of components:
//
// o A unique FILETYPE, which is a standard C string. The FILETYPE keyword must be first when
// defining a new file type and must not begin with '-'. The FILETYPE also serves as the file
// extension for carving operations (e.g., jpg) and the name for subdirectories containing recovered
// files.
//
// o If MoDiCo support is desired for this file type, FILETYPE must either match a class name in
// exe_vision/unix/class_names.json or be explicitly mapped to one in modico_classmap.c. The class
// names file is model metadata; it is not the list of Scalpel file types. Do NOT add names to
// class_names.json unless the MoDiCo model has been retrained/exported with the same class order.
// For alternate Scalpel names that share an existing byte-level class, add an
// alias in modico_classmap.c instead. If no mapping exists, Scalpel still works normally, but MoDiCo
// will not populate block confidence values for that file type.
//
// o A boolean MASTER tag which must be set to true or false. Master file types are templates that
// support dynamic creation of new file subtypes during runtime (in the block verification phase).
//
// o A HEADER (which consists of a binary string or a regular expression) or a HEADERFUNC (which is
// a header validation function) for this file type. HEADER is required in all cases and should be
// set to {0} if there is no valid header or if a HEADERFUNC will be used. If a HEADERFUNC is
// specified, the HEADER is required to be {0}.
//
// o A FOOTER (which consists of a binary string or a regular expression) or a FOOTERFUNC (which is
// a footer validation function) for this file type. FOOTER is required in all cases and should be
// set to {0} if there is no valid footer or if a FOOTERFUNC will be used. If a FOOTERFUNC is
// specified, the FOOTER is required to be {0}.
//
// o For header/footer-based searches based on HEADER or FOOTER matches, whether the header and
// footer binary strings/regular expressions are CASESENSITIVE. The flag applies to both headers and
// footers for a file type.
//
// o The MINIMUMSIZE for this file type. This value MUST be specified. Files smaller than
// MINIMUMSIZE will not be recovered.
//
// o The MAXIMUMSIZE for this file type. This value MUST be specified. Files larger than MAXIMUMSIZE
// will be truncated to MAXIMUMSIZE bytes.
//
// o SEARCHTYPE, which defines the carving strategy. The available options are SEARCHTYPE_FORWARD
// (this is the default and most commonly used option, which initially matches a header with the
// most distant footer within max file size, and builds recoverable files left to right),
// SEARCHTYPE_BLOCK_ONLY (carve individual blocks as validated files), and SEARCHTYPE_BACKWARD
// (creates initial carving candidates solely based on the footer and requires a custom
// REASSEMBLYFUNC [see below]).
//
// o BLOCKVALIDATOR defines the corresponding block validation function. This function must be
// thread-safe. It must also be stateless, aside from the use of the block state API (see below).
// Block validators are presented with individual blocks from the image file and should make a
// determination about whether the block of data might potentially be a component of an instance of
// the associated file type. See scalpel.h for a function prototype for BLOCKVALIDATOR and then look
// at one of the established file types (e.g., "abc.h") for an example. NULL is permissible for
// BLOCKVALIDATOR; this marks every block as a potential candidate for inclusion in a file of this
// type. NULL is better than a block validator that simply validates every block without
// scrutinizing the associated data.
//
// The value RETURNED by a block validator is the needleidx under which the block's decision is
// recorded. (The confidence value itself is carried in and out via the 'decision' argument: on
// entry it holds the confidence currently stored for the block, which may be a prior set by an
// earlier classifier such as MoDiCo, and on return it holds the confidence the validator wants
// stored.) A validator normally returns the same needleidx it was passed. However, if it recognizes
// the block as a more specific SUBTYPE of its file type, it returns that subtype's needleidx and the
// framework records the decision against the subtype rather than the base file type. For example,
// csv_master_block_validate() creates an "<N>-col.csv" subtype via add_file_subtype() and returns the
// new subtype's needleidx.
//
// o BATCHEDBLOCKVALIDATOR is an alternative to BLOCKVALIDATOR and is MUTUALLY EXCLUSIVE with it (a
// file type may define one or the other, never both; scalpel3 aborts at startup if both are set).
// Whereas a BLOCKVALIDATOR is handed one block at a time by the validation threads, a
// BATCHEDBLOCKVALIDATOR is invoked once and iterates the apparent blocks itself, deciding each
// block's type and recording the decision directly via the block state API. It runs on the main
// thread, in parallel with the validation threads that service the single-block validators. Like a
// single-block validator, it may create subtypes with add_file_subtype(). Because it records its
// own decisions, it returns nothing. See modico_populate_blocktypes() for the model it follows.
//
// IMPORTANT: validation backed by an ONNX model (or any GPU resource) must use a
// BATCHEDBLOCKVALIDATOR, never a BLOCKVALIDATOR. Because the batched form owns its iteration, it
// can initialize its model once at the top of its body (reading the run-wide execution provider
// and GPU device list through the read-only onnx_providers.h accessors), batch its inference, and
// tear everything down at the bottom of its body. Nothing outside the validator's own .h file is
// involved: no scalpel.c changes, no additional hooks here. See elf.h's batched validator for a
// complete example.
//
// o BLOCKVALIDATIONSCOPE declares when BLOCKVALIDATOR or BATCHEDBLOCKVALIDATOR runs.
// BLOCK_VALIDATION_ALWAYS is the default and runs in all recovery modes.
// BLOCK_VALIDATION_REASSEMBLY_ONLY is skipped under -c, and BLOCK_VALIDATION_DISABLED never runs.
// When a validator is skipped, previously unclassified blocks are marked valid for that file type;
// confidence values already supplied by MoDiCo are preserved. The -D option can override this
// disposition for a run.
//
// o FILEVALIDATOR defines the corresponding file validation function. This function must be
// thread-safe. It must also be stateless, aside from the use of the scalpel API for associating
// state with carving candidates (see below). See scalpel.h for a function prototype for
// FILEVALIDATOR and then look at one of the established file types (e.g., "abc.h") for an example.
//
// o CANDIDATEVALIDATOR is optional. Leave it unset when FILEVALIDATOR provides the complete
// decision. Define it when candidate processing additionally requires the block mapping or changes
// to the candidate that FILEVALIDATOR cannot perform, such as assigning an output subtype or
// preserving a partial recovery's mapping. See elf_candidate_validate_layout() for a mapping check.
// The backend calls it after FILEVALIDATOR during contiguous validation and generic reassembly,
// passing the current validates, validates_to and promising results, which it may revise.
// validates_to is an inclusive byte offset, just as for FILEVALIDATOR. The candidate belongs to the
// caller; the callback must not destroy it. Like FILEVALIDATOR, this function must be thread-safe
// and keep persistent candidate state through the carve state API. A custom REASSEMBLYFUNC that
// bypasses reassembly_check_validation() must apply the same candidate checks before accepting a
// result. Checks performed only during reassembly do not protect contiguous validation.
// This is not a checkpoint callback. Supporting fragmentation or checkpoints alone does not require
// it, and saved validator state must still be reconciled with any candidate changes after a
// blockmap update.
//
// o REASSEMBLYFUNC defines an optional custom reassembly function. The default (if unspecified) is
// the generic LR_reassembly() function, which performs best-effort, left-to-right reassembly. This
// function must be thread-safe. It must also be stateless, aside from the use of the API for
// 'state' in carving candidates. If files associated with a file type cannot be generated in a
// left-to-right fashion (e.g., ZIP files, which contain critical metadata at the end of the file),
// then a custom reassembly function must be written. See LR_reassembly() in reassembly.c for
// extensive documentation on this process.
//
// o DONTCARVE defines an optional "don't carve" function for a file type. This function can
// evaluate the data associated with a file or its SHA256 hash value (which is passed to the
// function) to determine whether the file should be recovered or ignored.
//
// o NO_DEFRAG can be set to true or false (the default is false). If NO_DEFRAG is true, no attempt
// is made to reassemble fragmented files of this type or to deal with partially validated files.
//
// ************************************
// ****** GLOBAL CARVE STATE API ******
// ************************************
//
// scalpel3 provides a provides a global storage facility that file validators and reassembly
// threads can use to associate state with a particular carving operation. See "123.h" for a simple
// example of how to use the global carve state API.
//
// The carve state API includes these functions:
//
// void *carve_get_state(void *hashkey);
//
// void carve_put_state(void *hashkey, void *state);
//
// The gen_carve_hash_key() function generates an opaque key based on an instance of a CarveInfo
// structure associated with a file validation operation. File validators are passed a key
// corresponding to the carving operation they are supporting and can save and retrieve state using
// this key.
//
// IMPORTANT:
//
// (a) carve_put_state() inserts a *deep *copy* of the 'state', using your CLONECARVESTATEFUNC (see
// below).
//
// (b) carve_get_state() returns a *deep copy* of the stored state. You MUST call your
// FREECARVESTATE function when you are finished with the copy of the state.  A typical workflow
// looks like:
//
// p = carve_get_state(key);
// ...modify state...
// carve_put_state(key, p);
// your_free_function(p);
//
// The copy of the state in the hash table is free automatically when the carving candidate is
// destroyed.
//
// If the carve state API functions are used to store state associated with carving operations, then
// these user-defined functions are required:
//
// o SERIALIZECARVESTATEFUNC defines a function that can serialize or deserialize state inserted
// into global storage via carve_put_state(), to support scalpel3 checkpointing operations. This
// function must be thread-safe and stateless.  If it's *impossible* to serialize state--because for
// example, the carve state is associated with deep state in a separate library, then follow the
// example in png.h.  This loses state after a checkpoint restore in a graceful way, requiring the
// state to be built from scratch after the restore.
//
// o CLONECARVESTATEFUNC defines a function that allocates space for a destination 'state' and then
// clones the source state and returns a pointer to the cloned state. This function must perform a
// deep copy that results in a clone that is free from internal pointer aliasing with the source.
// This function must be thread-safe and stateless.
//
// o FREECARVESTATEFUNC defines a function that frees all resources associated with 'state'. This
// function must be thread-safe and stateless. This function is required because these resources
// can be freed automatically at appropriate times.
//
// The following function is optional, but allows optimization of state storage and retrieval for a
// *specific class* of state types. You should only define this function if the state you are
// storing has a fixed size and a call to memcpy() results in a fully-independent clone. If your
// CLONECARVESTATEFUNC boils down to performing a single memcpy(), then you should define
// SIZEOFCARVESTATEFUNC.
//
// o SIZEOFCARVESTATEFUNC defines a function that returns the size of one element of the base type
// of 'state'. This function should NOT be defined for complex types with internal pointers.
//
// The following function is optional, but allows use of internal scalpel3 debugging facilities to
// ensure that state is being managed properly. Whether state is displayed is controlled by the
// PRINT_CARVE_STATE symbol in scalpel.h.
//
// o PRINTCARVESTATEFUNC defines a function that can display a representation of state saved using
// carve_put_state(). This function must be thread-safe and stateless and should output to stdout
// using printf.
//
// IMPORTANT: lock_fprintf() MUST NOT BE USED BY PRINTCARVESTATEFUNC, as this will result in
// deadlock.
//
// The function should properly handle a NULL state, by printing something appropriate (e.g.,
// "NULL").
//
// See scalpel.h for function prototypes for these user-defined functions.
//
// ************************************
// ****** GLOBAL BLOCK STATE API ******
// ************************************
//
// scalpel3 also provides access to the global storage facility for block validators, so they can
// associate state with particular blocks. See "123.h" for a simple example of how to use the global block
// state API.
//
// The API includes these functions:
//
// void *block_get_state(void *hashkey);
//
// bool block_state_exists(void *hashkey);
//
// void block_put_state(void *hashkey, void *state);
//
// IMPORTANT:
//
// (a) block_put_state() inserts a *deep *copy* of the 'state', using your CLONEBLOCKSTATEFUNC (see
// below).
//
// (b) block_get_state() returns a *deep copy* of the stored state. You MUST call your
// FREEBLOCKSTATE function when you are finished with the copy of the state.  A typical workflow
// looks like:
//
// p = block_get_state(key);
// ...modify state...
// block_put_state(key, p);
// your_free_function(p);
//
// When only presence matters, block_state_exists() avoids allocating a copy and does not transfer
// ownership of any state to the caller.
//
// The copy of the state in the hash table is free automatically when the blocks are covered.
//
// The gen_block_hash_key() function generates an opaque key based on a block number and file type.
// For duplicate blocks, state is always associated with the exemplar block. Put another way,
// duplicate blocks always have the same associated state. Block validators are passed a key for the
// block they are currently evaluating and can use this key to store and retrieve state.
//
// IMPORTANT: The global block state becomes read-only after block validation is complete. While
// block validators may update or read the state associated with blocks, the state may not be
// modified once all blocks are validated. Calling block_put_state() outside of a block validator
// will cause scalpel3 to abort with an error message.

// If the block state API functions are used to store state associated with blocks, then these
// user-defined functions are required:
//
// o SERIALIZEBLOCKSTATEFUNC defines a function that can serialize or deserialize state inserted
// into global storage via block_put_state(), to support scalpel3 checkpointing operations. This
// function must be thread-safe and stateless.
//
// o CLONEBLOCKSTATEFUNC defines a function that allocates space for a destination 'state' and then
// clones the source state and returns a pointer to the cloned state. This function must perform a
// deep copy that results in a clone that is free from internal pointer aliasing with the source.
// This function must be thread-safe and stateless.
//
// o FREEBLOCKSTATEFUNC defines a function that frees all resources associated with 'state'. This
// function must be thread-safe and stateless. This function is required because these resources
// will be freed automatically as appropriate.
//
// The following function is optional, but allows optimization of state storage and retrieval for a
// *specific class* of state types. You should only define this function if the state you are
// storing has a fixed size and a call to memcpy() results in a fully-independent clone. If your
// CLONEBLOCKSTATEFUNC boils down to performing a single memcpy(), then you should define
// SIZEOFBLOCKSTATEFUNC.
//
// o SIZEOFBLOCKSTATEFUNC defines a function that returns sizeof() on the base type of 'state'.
// Please see the note above. This function should NOT be defined for complex types with internal
// pointers.
//
// The following function is optional, but allows use of internal scalpel3 debugging facilities to
// ensure that state is being managed properly. Whether state is displayed is controlled by the
// PRINT_BLOCK_STATE symbol in scalpel.h.
//
// o PRINTBLOCKSTATEFUNC defines a function that can display a representation of the state
// associated with a block, which was inserted using block_put_state(). This function must be
// thread-safe and stateless and output to stdout using printf().
//
// IMPORTANT: lock_fprintf() MUST NOT BE USED BY PRINTCARVESTATEFUNC, as this will result in
// deadlock.
//
// The function should properly handle a NULL state, by printing something appropriate (e.g.,
// "NULL").
//
// See scalpel.h for function prototypes for these user-defined functions.
//
// *****************************
// ****** IMPORTANT NOTES ******
// *****************************
//
// ** To optimize performance, scalpel3 requires that headers and footers be at ** most one block in
// size. This is because headers and footers that lay ** across a block boundary are only detected
// if they are at most a single ** block long.
//
// Headers and footers are decoded before use. To specify a value in hexadecimal use \x[0-f][0-f].
// OCTAL NOTATION FOR EMBEDDED CHARACTERS IS NOT SUPPORTED. Welcome to the 21st century! Spaces can
// be represented by \s.
//
// To match any single character (aka a wildcard) in a non-regular expression header/footer, use a
// '?'.
//
// Headers and footers that are not regular expressions should be enclosed within double quotes and
// bracketed within '|' characters, e.g. "|HEADER|". IMPORTANT: Failure to include the bracketing
// vertical bars will cause a memory leak and Scalpel will crash.
//
// Regular expressions should be enclosed in double quotes and bracketed within a pair of '/'
// characters. For example, to specify that a file must begin with three G's followed by a non-G
// character and terminate with at least one digit character (0-9) followed by five H characters,
// the HEADER would be "/GGG[^G]/" and the FOOTER would be "/[0-9]HHHHH/".


//////////////////////////////////////////////////////////////////////////
// MP3 reassembly is currently a work in progress, setting this to zero //
// causes individual blocks to be recovered separately                  //
//////////////////////////////////////////////////////////////////////////

#define MP3_BLOCK_RECOVERY 0

////////////////////////
// BEGIN .h inclusion //
///////////////////////

// IMPORTANT: There should be a separate .h file included here for every file type, which defines
// the necessary file and block validator functions, header and footer functions, etc.

#include "gif.h"
#include "jpg.h"
#include "png.h"
#include "abc.h"
#include "csv.h"
#include "elf.h"
#include "exe.h"
#include "avi.h"
#include "mov.h"
#include "asf.h"
#include "flv.h"
#include "mpeg.h"
#include "mbox.h"
#include "html.h"
#include "text.h"
#include "sqlite.h"
#include "mp3.h"
#include "zip.h"
#include "cfbf.h"
#include "rtf.h"
#include "tnef.h"
#include "calendar.h"
#include "biff.h"
#include "onenote.h"
#include "access.h"
#include "pst.h"
#include "rar.h"
#include "123.h"
#include "pdf.h"
// #include "fpdf.h"
#include "scalpel.h"

////////////////////////
// END .h inclusion //
////////////////////////

SearchSpec INITIAL_SEARCH_SPECS[] = {

    // JPG images
    //
    {
        .FILETYPE = "jpg",
        .MASTER = false,
        .CASESENSITIVE = true,
        .MINIMUMSIZE = 1024,
        .MAXIMUMSIZE = 25000000,
        .HEADER = "/\xff\xd8\xff\xe0|\xff\xd8\xff\xe1/",
        //.HEADER = "/\xff\xd8\xff\xe0/",
        .FOOTER = "|\xff\xd9|",
        .SEARCHTYPE = SEARCHTYPE_FORWARD,
        // JPG reassembly does not currently use a block validator.
        .FILEVALIDATOR = jpg_file_validate,
        .SERIALIZEBLOCKSTATEFUNC = NULL,
        .CLONEBLOCKSTATEFUNC = NULL,
        .FREEBLOCKSTATEFUNC = NULL,
        .SIZEOFBLOCKSTATEFUNC = NULL,
        .PRINTBLOCKSTATEFUNC = NULL,
        .SERIALIZECARVESTATEFUNC = jpg_serialize_carve_state,
        .CLONECARVESTATEFUNC = jpg_clone_carve_state,
        .FREECARVESTATEFUNC = jpg_free_carve_state,
        .SIZEOFCARVESTATEFUNC = jpg_sizeof_carve_state,
        .PRINTCARVESTATEFUNC = jpg_print_carve_state,
        .REASSEMBLYFUNC = jpg_reassembly,
        .PRIORITY = PRIORITY_PI,
        .NO_DEFRAG = false,
    },

    // PNG images
    //
    // NOTES: Block/cluster sizes less than 4K seriously impact correct PNG reassembly, as there are
    // critical data structures (e.g., the iTxT cluster) that can cause reassembly failure if they
    // span a non-contiguous block boundary.
    {
      .FILETYPE = "png",
      .MASTER = false,
      .CASESENSITIVE = true,
      .MINIMUMSIZE = 1024,
      .MAXIMUMSIZE = 35000000,
      .HEADER = "|\x89\x50\x4e\x47\x0d\x0a\x1a\x0a|",
      .FOOTER = "/IEND..../",
      //.HEADERFUNC = png_header_discovery,        // these are provided as examples of simple
      //.FOOTERFUNC = png_footer_discovery,        // header and footer functions
      .DONTCARVE = png_no_carve,
      .SEARCHTYPE = SEARCHTYPE_FORWARD,
      .BLOCKVALIDATOR = png_block_validate,
      .BLOCKVALIDATIONSCOPE = BLOCK_VALIDATION_REASSEMBLY_ONLY,
      .FILEVALIDATOR = png_file_validate,
      .SERIALIZEBLOCKSTATEFUNC = png_serialize_block_state,
      .CLONEBLOCKSTATEFUNC = png_clone_block_state,
      .FREEBLOCKSTATEFUNC = png_free_block_state,
      .SIZEOFBLOCKSTATEFUNC = png_sizeof_block_state,
      .PRINTBLOCKSTATEFUNC = png_print_block_state,
      .SERIALIZECARVESTATEFUNC = png_serialize_carve_state,
      .CLONECARVESTATEFUNC = png_clone_carve_state,
      .FREECARVESTATEFUNC = png_free_carve_state,
      .PRINTCARVESTATEFUNC = png_print_carve_state,
      .REASSEMBLYFUNC = png_reassembly,
      .PRIORITY = PRIORITY_HIGHEST
    },

    // GIF images
    //
    // NOTES: Note the format of the footer, which contains an embedded NULL character.

    {
      .FILETYPE = "gif",
      .MASTER = false,
      .CASESENSITIVE = true,
      .MINIMUMSIZE = 1024,
      .MAXIMUMSIZE = 100000000,
      .HEADER = "/\x47\x49\x46\x38\x37\x61|\x47\x49\x46\x38\x39\x61/",
      .FOOTER = "/\\x{00}\x3b/",
      .SEARCHTYPE = SEARCHTYPE_FORWARD,
      .BLOCKVALIDATOR = gif_block_validate,
      .BLOCKVALIDATIONSCOPE = BLOCK_VALIDATION_REASSEMBLY_ONLY,
      .FILEVALIDATOR = gif_file_validate,
      .PRIORITY = PRIORITY_PI,
      .SERIALIZEBLOCKSTATEFUNC = NULL,
      .CLONEBLOCKSTATEFUNC = NULL,
      .FREEBLOCKSTATEFUNC = NULL,
      .SIZEOFBLOCKSTATEFUNC = NULL,
      .PRINTBLOCKSTATEFUNC = NULL,
      .SERIALIZECARVESTATEFUNC = gif_serialize_carve_state,
      .CLONECARVESTATEFUNC = gif_clone_carve_state,
      .FREECARVESTATEFUNC = gif_free_carve_state,
      .SIZEOFCARVESTATEFUNC = NULL,
      .PRINTCARVESTATEFUNC = gif_print_carve_state,
      .REASSEMBLYFUNC = gif_reassembly
    },

    // CSV files
    //
    // NOTES: SEARCHTYPE_BLOCK_ONLY is used. Blocks containing repeated records with a consistent
    // dialect and field count are recovered individually; no attempt is made to reassemble them.
    //
    {
      .FILETYPE = "csv",
      .HEADER = {0},
      .FOOTER = {0},
      .MASTER = true,
      .SEARCHTYPE = SEARCHTYPE_BLOCK_ONLY,
      .BLOCKVALIDATOR = csv_master_block_validate
    },

    // "abc"
    //
    // NOTES: Simple synthetic file type intended to help new developers learn how to write
    // block/file validators (see "abc.h")
    //
    {
      .FILETYPE = "abc",
      .MASTER = false,
      .CASESENSITIVE = true,
      .MINIMUMSIZE = 512,
      .MAXIMUMSIZE = 1755000,
      .HEADER = "|\x23\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x23|",
      .HEADERFUNC = NULL,
      .FOOTER = "|\x23\x39\x38\x37\x36\x35\x34\x33\x32\x31\x30\x23|",
      .FOOTERFUNC = NULL,
      .SEARCHTYPE = SEARCHTYPE_FORWARD,
      .BLOCKVALIDATOR = abc_block_validate_alt,
      .FILEVALIDATOR = abc_file_validate_alt,
      .PRIORITY = PRIORITY_HIGHEST
    },

    // ELF format executables
    //
    {
      .FILETYPE = "elf",
      .MASTER = false,
      .CASESENSITIVE = true,
      .MINIMUMSIZE = 4096,
      .MAXIMUMSIZE = EXE_MAXIMUM_FILE_SIZE,
      .HEADER = {0},
      .HEADERFUNC = elf_header_discovery,
      .FOOTER = {0},
      .FOOTERFUNC = NULL,
      .SEARCHTYPE = SEARCHTYPE_FORWARD,
      .BATCHEDBLOCKVALIDATOR = elf_batched_block_validate,
      .BLOCKVALIDATIONSCOPE = BLOCK_VALIDATION_REASSEMBLY_ONLY,
      .FILEVALIDATOR = elf_file_validate,
      .CANDIDATEVALIDATOR = elf_candidate_validate_layout,
      .PRIORITY = PRIORITY_HIGHEST,
      .SERIALIZEBLOCKSTATEFUNC = elf_serialize_block_state,
      .CLONEBLOCKSTATEFUNC = elf_clone_block_state,
      .FREEBLOCKSTATEFUNC = elf_free_block_state,
      .PRINTBLOCKSTATEFUNC = elf_print_block_state,
      .SERIALIZECARVESTATEFUNC = elf_serialize_carve_state,
      .CLONECARVESTATEFUNC = elf_clone_carve_state,
      .FREECARVESTATEFUNC = elf_free_carve_state,
      .PRINTCARVESTATEFUNC = elf_print_carve_state,
      .REASSEMBLYFUNC = elf_reassembly
    },

    // Microsoft Portable Executable images, including executables, libraries,
    // drivers, and managed assemblies.
    //
    {
      .FILETYPE = "exe",
      .MASTER = false,
      .CASESENSITIVE = true,
      .MINIMUMSIZE = 512,
      .MAXIMUMSIZE = 268435456,
      .HEADER = {0},
      .HEADERFUNC = exe_header_discovery,
      .FOOTER = {0},
      .FOOTERFUNC = NULL,
      .SEARCHTYPE = SEARCHTYPE_FORWARD,
      .FILEVALIDATOR = exe_file_validate,
      .PRIORITY = PRIORITY_HIGHEST,
      .NO_DEFRAG = false,
      .SERIALIZECARVESTATEFUNC = exe_serialize_carve_state,
      .CLONECARVESTATEFUNC = exe_clone_carve_state,
      .FREECARVESTATEFUNC = exe_free_carve_state,
      .PRINTCARVESTATEFUNC = exe_print_carve_state,
      .REASSEMBLYFUNC = exe_reassembly
    },

    // Audio Video Interleave containers, including classic AVI and OpenDML AVI files.
    //
    {
      .FILETYPE = "avi",
      .MASTER = false,
      .CASESENSITIVE = true,
      .MINIMUMSIZE = AVI_RIFF_HEADER_SIZE + AVI_CHUNK_HEADER_SIZE,
      .MAXIMUMSIZE = AVI_MAX_ARCHIVE_SIZE,
      .HEADER = {0},
      .HEADERFUNC = avi_header_discovery,
      .FOOTER = {0},
      .FOOTERFUNC = avi_footer_discovery,
      .SEARCHTYPE = SEARCHTYPE_FORWARD,
      .BLOCKVALIDATOR = avi_block_validate,
      .BLOCKVALIDATIONSCOPE = BLOCK_VALIDATION_REASSEMBLY_ONLY,
      .FILEVALIDATOR = avi_file_validate,
      .PRIORITY = PRIORITY_HIGHEST,
      .NO_DEFRAG = false,
      .SERIALIZECARVESTATEFUNC = avi_serialize_carve_state,
      .CLONECARVESTATEFUNC = avi_clone_carve_state,
      .FREECARVESTATEFUNC = avi_free_carve_state,
      .PRINTCARVESTATEFUNC = avi_print_carve_state,
      .REASSEMBLYFUNC = avi_reassembly
    },

    // QuickTime containers, including MOV files without an ftyp box.
    //
    {
      .FILETYPE = "mov",
      .MASTER = false,
      .CASESENSITIVE = true,
      .MINIMUMSIZE = ISOBMFF_MINIMUM_SIZE,
      .MAXIMUMSIZE = ISOBMFF_MAXIMUM_SIZE,
      .HEADER = {0},
      .HEADERFUNC = mov_header_discovery,
      .FOOTER = {0},
      .FOOTERFUNC = isobmff_footer_discovery,
      .SEARCHTYPE = SEARCHTYPE_FORWARD,
      .BLOCKVALIDATOR = isobmff_block_validate,
      .BLOCKVALIDATIONSCOPE = BLOCK_VALIDATION_REASSEMBLY_ONLY,
      .FILEVALIDATOR = mov_file_validate,
      .CANDIDATEVALIDATOR = isobmff_candidate_validate,
      .PRIORITY = PRIORITY_HIGHEST,
      .NO_DEFRAG = false,
      .SERIALIZECARVESTATEFUNC = isobmff_serialize_carve_state,
      .CLONECARVESTATEFUNC = isobmff_clone_carve_state,
      .FREECARVESTATEFUNC = isobmff_free_carve_state,
      .SIZEOFCARVESTATEFUNC = isobmff_sizeof_carve_state,
      .PRINTCARVESTATEFUNC = isobmff_print_carve_state,
      .REASSEMBLYFUNC = isobmff_reassembly
    },

    // ISO Base Media File Format containers, including MP4 and fragmented MP4.
    //
    {
      .FILETYPE = "mp4",
      .MASTER = false,
      .CASESENSITIVE = true,
      .MINIMUMSIZE = ISOBMFF_MINIMUM_SIZE,
      .MAXIMUMSIZE = ISOBMFF_MAXIMUM_SIZE,
      .HEADER = {0},
      .HEADERFUNC = mp4_header_discovery,
      .FOOTER = {0},
      .FOOTERFUNC = isobmff_footer_discovery,
      .SEARCHTYPE = SEARCHTYPE_FORWARD,
      .BLOCKVALIDATOR = isobmff_block_validate,
      .BLOCKVALIDATIONSCOPE = BLOCK_VALIDATION_REASSEMBLY_ONLY,
      .FILEVALIDATOR = mp4_file_validate,
      .CANDIDATEVALIDATOR = isobmff_candidate_validate,
      .PRIORITY = PRIORITY_HIGHEST,
      .NO_DEFRAG = false,
      .SERIALIZECARVESTATEFUNC = isobmff_serialize_carve_state,
      .CLONECARVESTATEFUNC = isobmff_clone_carve_state,
      .FREECARVESTATEFUNC = isobmff_free_carve_state,
      .SIZEOFCARVESTATEFUNC = isobmff_sizeof_carve_state,
      .PRINTCARVESTATEFUNC = isobmff_print_carve_state,
      .REASSEMBLYFUNC = isobmff_reassembly
    },

    // Advanced Systems Format containers. ASF files containing a Windows
    // Media video codec are assigned to the dormant wmv subtype after
    // validation.
    //
    {
      .FILETYPE = "asf",
      .MASTER = false,
      .CASESENSITIVE = true,
      .MINIMUMSIZE = ASF_MINIMUM_SIZE,
      .MAXIMUMSIZE = ASF_MAXIMUM_SIZE,
      .HEADER = {0},
      .HEADERFUNC = asf_header_discovery,
      .FOOTER = {0},
      .FOOTERFUNC = NULL,
      .SEARCHTYPE = SEARCHTYPE_FORWARD,
      .BLOCKVALIDATOR = asf_block_validate,
      .BLOCKVALIDATIONSCOPE = BLOCK_VALIDATION_REASSEMBLY_ONLY,
      .FILEVALIDATOR = asf_file_validate,
      .CANDIDATEVALIDATOR = asf_candidate_validate,
      .PRIORITY = PRIORITY_HIGHEST,
      .NO_DEFRAG = false,
      .SERIALIZECARVESTATEFUNC = asf_serialize_carve_state,
      .CLONECARVESTATEFUNC = asf_clone_carve_state,
      .FREECARVESTATEFUNC = asf_free_carve_state,
      .SIZEOFCARVESTATEFUNC = asf_sizeof_carve_state,
      .PRINTCARVESTATEFUNC = asf_print_carve_state,
      .REASSEMBLYFUNC = asf_reassembly
    },

    {
      .FILETYPE = "wmv",
      .MASTER = false,
      .CASESENSITIVE = true,
      .MINIMUMSIZE = ASF_MINIMUM_SIZE,
      .MAXIMUMSIZE = ASF_MAXIMUM_SIZE,
      .HEADER = {0},
      .HEADERFUNC = asf_no_header_discovery,
      .FOOTER = {0},
      .FOOTERFUNC = NULL,
      .SEARCHTYPE = SEARCHTYPE_FORWARD,
      .BLOCKVALIDATOR = NULL,
      .BLOCKVALIDATIONSCOPE = BLOCK_VALIDATION_DISABLED,
      .FILEVALIDATOR = asf_file_validate,
      .CANDIDATEVALIDATOR = asf_candidate_validate,
      .PRIORITY = PRIORITY_HIGHEST,
      .NO_DEFRAG = false,
      .SERIALIZECARVESTATEFUNC = asf_serialize_carve_state,
      .CLONECARVESTATEFUNC = asf_clone_carve_state,
      .FREECARVESTATEFUNC = asf_free_carve_state,
      .SIZEOFCARVESTATEFUNC = asf_sizeof_carve_state,
      .PRINTCARVESTATEFUNC = asf_print_carve_state,
      .REASSEMBLYFUNC = asf_reassembly
    },

    // Flash Video containers.
    //
    {
      .FILETYPE = "flv",
      .MASTER = false,
      .CASESENSITIVE = true,
      .MINIMUMSIZE = FLV_MINIMUM_SIZE,
      .MAXIMUMSIZE = FLV_MAXIMUM_SIZE,
      .HEADER = {0},
      .HEADERFUNC = flv_header_discovery,
      .FOOTER = {0},
      .FOOTERFUNC = flv_footer_discovery,
      .SEARCHTYPE = SEARCHTYPE_FORWARD,
      .BLOCKVALIDATOR = flv_block_validate,
      .BLOCKVALIDATIONSCOPE = BLOCK_VALIDATION_REASSEMBLY_ONLY,
      .FILEVALIDATOR = flv_file_validate,
      .PRIORITY = PRIORITY_HIGHEST,
      .NO_DEFRAG = false,
      .SERIALIZECARVESTATEFUNC = flv_serialize_carve_state,
      .CLONECARVESTATEFUNC = flv_clone_carve_state,
      .FREECARVESTATEFUNC = flv_free_carve_state,
      .PRINTCARVESTATEFUNC = flv_print_carve_state,
      .REASSEMBLYFUNC = flv_reassembly
    },

    // MPEG program streams, transport streams, and elementary video streams.
    //
    {
      .FILETYPE = "mpg",
      .MASTER = false,
      .CASESENSITIVE = true,
      .MINIMUMSIZE = MPEG_MINIMUM_SIZE,
      .MAXIMUMSIZE = MPEG_MAXIMUM_SIZE,
      .HEADER = {0},
      .HEADERFUNC = mpeg_header_discovery,
      .FOOTER = {0},
      .FOOTERFUNC = mpeg_footer_discovery,
      .SEARCHTYPE = SEARCHTYPE_FORWARD,
      .BLOCKVALIDATOR = mpeg_block_validate,
      .BLOCKVALIDATIONSCOPE = BLOCK_VALIDATION_REASSEMBLY_ONLY,
      .FILEVALIDATOR = mpeg_file_validate,
      .CANDIDATEVALIDATOR = mpeg_candidate_validate,
      .PRIORITY = PRIORITY_HIGHEST,
      .NO_DEFRAG = false,
      .SERIALIZECARVESTATEFUNC = mpeg_serialize_carve_state,
      .CLONECARVESTATEFUNC = mpeg_clone_carve_state,
      .FREECARVESTATEFUNC = mpeg_free_carve_state,
      .SIZEOFCARVESTATEFUNC = mpeg_sizeof_carve_state,
      .PRINTCARVESTATEFUNC = mpeg_print_carve_state,
      .REASSEMBLYFUNC = mpeg_reassembly
    },

    // RFC messages and Unix mbox streams.
    //
    {
      .FILETYPE = "mbox",
      .MASTER = false,
      .CASESENSITIVE = true,
      .MINIMUMSIZE = MBOX_MINIMUM_SIZE,
      .MAXIMUMSIZE = MBOX_MAXIMUM_SIZE,
      .HEADER = {0},
      .HEADERFUNC = mbox_header_discovery,
      .FOOTER = {0},
      .FOOTERFUNC = mbox_footer_discovery,
      .SEARCHTYPE = SEARCHTYPE_FORWARD,
      .BLOCKVALIDATOR = mbox_block_validate,
      .BLOCKVALIDATIONSCOPE = BLOCK_VALIDATION_REASSEMBLY_ONLY,
      .FILEVALIDATOR = mbox_file_validate,
      .CANDIDATEVALIDATOR = mbox_candidate_validate,
      .REASSEMBLYFUNC = mbox_reassembly,
      .SERIALIZECARVESTATEFUNC = mbox_serialize_carve_state,
      .CLONECARVESTATEFUNC = mbox_clone_carve_state,
      .FREECARVESTATEFUNC = mbox_free_carve_state,
      .SIZEOFCARVESTATEFUNC = mbox_sizeof_carve_state,
      .PRINTCARVESTATEFUNC = mbox_print_carve_state,
      .PRIORITY = PRIORITY_HIGHEST,
      .NO_DEFRAG = false
    },

    // HTML documents, including legacy HTML and XHTML syntax.
    //
    {
      .FILETYPE = "html",
      .MASTER = false,
      .CASESENSITIVE = false,
      .MINIMUMSIZE = HTML_MINIMUM_SIZE,
      .MAXIMUMSIZE = HTML_MAXIMUM_SIZE,
      .HEADER = {0},
      .HEADERFUNC = html_header_discovery,
      .FOOTER = {0},
      .FOOTERFUNC = html_footer_discovery,
      .SEARCHTYPE = SEARCHTYPE_FORWARD,
      .BLOCKVALIDATOR = html_block_validate,
      .BLOCKVALIDATIONSCOPE = BLOCK_VALIDATION_REASSEMBLY_ONLY,
      .FILEVALIDATOR = html_file_validate,
      .CANDIDATEVALIDATOR = html_candidate_validate,
      .REASSEMBLYFUNC = html_reassembly,
      .SERIALIZECARVESTATEFUNC = html_serialize_carve_state,
      .CLONECARVESTATEFUNC = html_clone_carve_state,
      .FREECARVESTATEFUNC = html_free_carve_state,
      .SIZEOFCARVESTATEFUNC = html_sizeof_carve_state,
      .PRINTCARVESTATEFUNC = html_print_carve_state,
      .PRIORITY = PRIORITY_HIGHEST,
      .NO_DEFRAG = false
    },

    // Strongly textual, block-aligned runs with a non-text terminal boundary.
    // Plain text has no reliable intrinsic fragmentation evidence.
    //
    {
      .FILETYPE = "txt",
      .MASTER = false,
      .CASESENSITIVE = true,
      .MINIMUMSIZE = TEXT_MINIMUM_SIZE,
      .MAXIMUMSIZE = TEXT_MAXIMUM_SIZE,
      .HEADER = {0},
      .HEADERFUNC = text_header_discovery,
      .FOOTER = {0},
      .FOOTERFUNC = NULL,
      .SEARCHTYPE = SEARCHTYPE_FORWARD,
      .BLOCKVALIDATOR = text_block_validate,
      .BLOCKVALIDATIONSCOPE = BLOCK_VALIDATION_REASSEMBLY_ONLY,
      .FILEVALIDATOR = text_file_validate,
      .REASSEMBLYFUNC = text_reassembly,
      .PRIORITY = PRIORITY_HIGHEST,
      .NO_DEFRAG = false
    },

    // SQLite 3 databases.
    //
    {
      .FILETYPE = "sqlite",
      .MASTER = false,
      .CASESENSITIVE = true,
      .MINIMUMSIZE = SQLITE_MINIMUM_PAGE_SIZE,
      .MAXIMUMSIZE = UINT64_C(1099511627776),
      .HEADER = {0},
      .HEADERFUNC = sqlite_header_discovery,
      .FOOTER = {0},
      .FOOTERFUNC = NULL,
      .SEARCHTYPE = SEARCHTYPE_FORWARD,
      .BLOCKVALIDATOR = sqlite_block_validate,
      .BLOCKVALIDATIONSCOPE = BLOCK_VALIDATION_REASSEMBLY_ONLY,
      .FILEVALIDATOR = sqlite_file_validate,
      .PRIORITY = PRIORITY_HIGHEST,
      .NO_DEFRAG = false,
      .SERIALIZECARVESTATEFUNC = sqlite_serialize_carve_state,
      .CLONECARVESTATEFUNC = sqlite_clone_carve_state,
      .FREECARVESTATEFUNC = sqlite_free_carve_state,
      .SIZEOFCARVESTATEFUNC = sqlite_sizeof_carve_state,
      .PRINTCARVESTATEFUNC = sqlite_print_carve_state,
      .REASSEMBLYFUNC = sqlite_reassembly
    },

    // ZIP, ZIP64, and modern Microsoft Office package formats.
    //
    {
      .FILETYPE = "zip",
      .MASTER = false,
      .CASESENSITIVE = true,
      .MINIMUMSIZE = ZIP_LOCAL_HEADER_SIZE + ZIP_CENTRAL_HEADER_SIZE
                     + ZIP_EOCD_SIZE,
      .MAXIMUMSIZE = UINT64_C(1099511627776),
      .HEADER = "/\x50\x4b\x03\x04|\x50\x4b\x30\x30\x50\x4b\x03\x04/",
      .HEADERFUNC = NULL,
      .FOOTER = {0},
      .FOOTERFUNC = zip_footer_discovery,
      .SEARCHTYPE = SEARCHTYPE_FORWARD,
      .FILEVALIDATOR = zip_file_validate_seed,
      .CANDIDATEVALIDATOR = cfbf_zip_candidate_validate,
      .SERIALIZECARVESTATEFUNC = zip_serialize_carve_state,
      .CLONECARVESTATEFUNC = zip_clone_carve_state,
      .FREECARVESTATEFUNC = zip_free_carve_state,
      .PRINTCARVESTATEFUNC = zip_print_carve_state,
      .REASSEMBLYFUNC = zip_reassembly,
      .PRIORITY = PRIORITY_SIGMA},

    // RAR4 and RAR5 archives.
    //
    {
      .FILETYPE = "rar",
      .MASTER = false,
      .CASESENSITIVE = true,
      .MINIMUMSIZE = 20,
      .MAXIMUMSIZE = UINT64_C(1099511627776),
      .HEADER = "/\x52\x61\x72\x21\x1a\x07\\x{00}|\x52\x61\x72\x21\x1a\x07\x01\\x{00}/",
      .FOOTER = "/\xc4\x3d\x7b\\x{00}\x40\x07\\x{00}|\x1d\x77\x56\x51\x03\x05\x04\\x{00}/",
      .SEARCHTYPE = SEARCHTYPE_FORWARD,
      .FILEVALIDATOR = rar_file_validate,
      .CANDIDATEVALIDATOR = rar_candidate_validate,
      .SERIALIZECARVESTATEFUNC = rar_serialize_carve_state,
      .CLONECARVESTATEFUNC = rar_clone_carve_state,
      .FREECARVESTATEFUNC = rar_free_carve_state,
      .PRINTCARVESTATEFUNC = rar_print_carve_state,
      .REASSEMBLYFUNC = rar_reassembly,
      .PRIORITY = PRIORITY_SIGMA,
      .NO_DEFRAG = false},

    // Microsoft Compound File Binary containers. The generic CFBF entry is
    // the only entry that performs header discovery. Once a container fully
    // validates, cfbf_candidate_classify() assigns it to one of the dormant
    // semantic entries below without creating duplicate carving candidates.
    //
    {
      .FILETYPE = "cfbf",
      .MASTER = false,
      .CASESENSITIVE = true,
      .MINIMUMSIZE = 512,
      .MAXIMUMSIZE = UINT64_C(4294967296),
      .HEADER = "|\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1|",
      .FOOTER = {0},
      .SEARCHTYPE = SEARCHTYPE_FORWARD,
      .FILEVALIDATOR = cfbf_file_validate,
      .CANDIDATEVALIDATOR = cfbf_candidate_classify,
      .REASSEMBLYFUNC = cfbf_reassembly,
      .SERIALIZECARVESTATEFUNC = cfbf_serialize_carve_state,
      .CLONECARVESTATEFUNC = cfbf_clone_carve_state,
      .FREECARVESTATEFUNC = cfbf_free_carve_state,
      .SIZEOFCARVESTATEFUNC = cfbf_sizeof_carve_state,
      .PRINTCARVESTATEFUNC = cfbf_print_carve_state,
      .PRIORITY = PRIORITY_SIGMA
    },

#define CFBF_SEMANTIC_SEARCH_SPEC(type_name)                    \
    {                                                           \
      .FILETYPE = type_name,                                    \
      .MASTER = false,                                          \
      .CASESENSITIVE = true,                                    \
      .MINIMUMSIZE = 512,                                       \
      .MAXIMUMSIZE = UINT64_C(4294967296),                      \
      .HEADER = {0},                                            \
      .HEADERFUNC = cfbf_no_header_discovery,                   \
      .FOOTER = {0},                                            \
      .SEARCHTYPE = SEARCHTYPE_FORWARD,                         \
      .FILEVALIDATOR = cfbf_file_validate,                      \
      .CANDIDATEVALIDATOR = cfbf_candidate_classify,            \
      .REASSEMBLYFUNC = cfbf_reassembly,                        \
      .SERIALIZECARVESTATEFUNC = cfbf_serialize_carve_state,    \
      .CLONECARVESTATEFUNC = cfbf_clone_carve_state,            \
      .FREECARVESTATEFUNC = cfbf_free_carve_state,              \
      .SIZEOFCARVESTATEFUNC = cfbf_sizeof_carve_state,          \
      .PRINTCARVESTATEFUNC = cfbf_print_carve_state,            \
      .PRIORITY = PRIORITY_SIGMA                                \
    }

    CFBF_SEMANTIC_SEARCH_SPEC("doc"),
    CFBF_SEMANTIC_SEARCH_SPEC("dot"),
    CFBF_SEMANTIC_SEARCH_SPEC("xls"),
    CFBF_SEMANTIC_SEARCH_SPEC("xlt"),
    CFBF_SEMANTIC_SEARCH_SPEC("xla"),
    CFBF_SEMANTIC_SEARCH_SPEC("ppt"),
    CFBF_SEMANTIC_SEARCH_SPEC("ppa"),
    CFBF_SEMANTIC_SEARCH_SPEC("msg"),
    CFBF_SEMANTIC_SEARCH_SPEC("oft"),
    CFBF_SEMANTIC_SEARCH_SPEC("pub"),
    CFBF_SEMANTIC_SEARCH_SPEC("vsd"),
    CFBF_SEMANTIC_SEARCH_SPEC("mpp"),
    CFBF_SEMANTIC_SEARCH_SPEC("obd"),
    CFBF_SEMANTIC_SEARCH_SPEC("office-encrypted"),

#undef CFBF_SEMANTIC_SEARCH_SPEC

    // Rich Text Format documents. The validator parses nested groups,
    // escaped delimiters, control words, and binary payloads.
    //
    {
      .FILETYPE = "rtf",
      .MASTER = false,
      .CASESENSITIVE = true,
      .MINIMUMSIZE = RTF_MINIMUM_SIZE,
      .MAXIMUMSIZE = UINT64_C(1073741824),
      .HEADER = "|\x7b\x5c\x72\x74\x66|",
      .FOOTER = {0},
      .FOOTERFUNC = rtf_footer_discovery,
      .SEARCHTYPE = SEARCHTYPE_FORWARD,
      .BLOCKVALIDATOR = rtf_block_validate,
      .BLOCKVALIDATIONSCOPE = BLOCK_VALIDATION_REASSEMBLY_ONLY,
      .FILEVALIDATOR = rtf_file_validate,
      .CANDIDATEVALIDATOR = rtf_candidate_validate,
      .REASSEMBLYFUNC = rtf_reassembly,
      .SERIALIZECARVESTATEFUNC = rtf_serialize_carve_state,
      .CLONECARVESTATEFUNC = rtf_clone_carve_state,
      .FREECARVESTATEFUNC = rtf_free_carve_state,
      .SIZEOFCARVESTATEFUNC = rtf_sizeof_carve_state,
      .PRINTCARVESTATEFUNC = rtf_print_carve_state,
      .NO_DEFRAG = false,
      .PRIORITY = PRIORITY_SIGMA
    },

    // Transport Neutral Encapsulation Format streams. Each attribute carries
    // its own length and checksum, allowing exact validation of complete
    // contiguous streams and verified progress during fragmented recovery.
    //
    {
      .FILETYPE = "tnef",
      .MASTER = false,
      .CASESENSITIVE = true,
      .MINIMUMSIZE = TNEF_MINIMUM_SIZE,
      .MAXIMUMSIZE = UINT64_C(4294967296),
      .HEADER = "|\x78\x9f\x3e\x22|",
      .FOOTER = {0},
      .SEARCHTYPE = SEARCHTYPE_FORWARD,
      .FILEVALIDATOR = tnef_file_validate,
      .CANDIDATEVALIDATOR = tnef_candidate_validate,
      .REASSEMBLYFUNC = tnef_reassembly,
      .SERIALIZECARVESTATEFUNC = tnef_serialize_carve_state,
      .CLONECARVESTATEFUNC = tnef_clone_carve_state,
      .FREECARVESTATEFUNC = tnef_free_carve_state,
      .SIZEOFCARVESTATEFUNC = tnef_sizeof_carve_state,
      .PRINTCARVESTATEFUNC = tnef_print_carve_state,
      .PRIORITY = PRIORITY_SIGMA
    },

    // iCalendar records, including nested event, task, journal, alarm, and
    // timezone components.
    //
    {
      .FILETYPE = "ics",
      .MASTER = false,
      .CASESENSITIVE = false,
      .MINIMUMSIZE = CALENDAR_MINIMUM_ICS_SIZE,
      .MAXIMUMSIZE = UINT64_C(1073741824),
      .HEADER = "/\xef\xbb\xbf" "BEGIN:VCALENDAR|BEGIN:VCALENDAR/",
      .FOOTER = {0},
      .FOOTERFUNC = ics_footer_discovery,
      .SEARCHTYPE = SEARCHTYPE_FORWARD,
      .BLOCKVALIDATOR = calendar_block_validate,
      .BLOCKVALIDATIONSCOPE = BLOCK_VALIDATION_REASSEMBLY_ONLY,
      .FILEVALIDATOR = ics_file_validate,
      .CANDIDATEVALIDATOR = calendar_candidate_validate,
      .REASSEMBLYFUNC = calendar_reassembly,
      .SERIALIZECARVESTATEFUNC = calendar_serialize_carve_state,
      .CLONECARVESTATEFUNC = calendar_clone_carve_state,
      .FREECARVESTATEFUNC = calendar_free_carve_state,
      .SIZEOFCARVESTATEFUNC = calendar_sizeof_carve_state,
      .PRINTCARVESTATEFUNC = calendar_print_carve_state,
      .PRIORITY = PRIORITY_SIGMA
    },

    // vCard contact records. Sequential cards in one source file are parsed
    // as one recoverable stream.
    //
    {
      .FILETYPE = "vcf",
      .MASTER = false,
      .CASESENSITIVE = false,
      .MINIMUMSIZE = CALENDAR_MINIMUM_VCF_SIZE,
      .MAXIMUMSIZE = UINT64_C(1073741824),
      .HEADER = "/\xef\xbb\xbf" "BEGIN:VCARD|BEGIN:VCARD/",
      .FOOTER = {0},
      .FOOTERFUNC = vcf_footer_discovery,
      .SEARCHTYPE = SEARCHTYPE_FORWARD,
      .BLOCKVALIDATOR = calendar_block_validate,
      .BLOCKVALIDATIONSCOPE = BLOCK_VALIDATION_REASSEMBLY_ONLY,
      .FILEVALIDATOR = vcf_file_validate,
      .CANDIDATEVALIDATOR = calendar_candidate_validate,
      .REASSEMBLYFUNC = calendar_reassembly,
      .SERIALIZECARVESTATEFUNC = calendar_serialize_carve_state,
      .CLONECARVESTATEFUNC = calendar_clone_carve_state,
      .FREECARVESTATEFUNC = calendar_free_carve_state,
      .SIZEOFCARVESTATEFUNC = calendar_sizeof_carve_state,
      .PRINTCARVESTATEFUNC = calendar_print_carve_state,
      .PRIORITY = PRIORITY_SIGMA
    },

    // Raw BIFF2-BIFF4 worksheets and related pre-CFBF Excel streams.
    //
    {
      .FILETYPE = "xls-raw",
      .MASTER = false,
      .CASESENSITIVE = true,
      .MINIMUMSIZE = BIFF_MINIMUM_SIZE,
      .MAXIMUMSIZE = UINT64_C(1073741824),
      .HEADER = {0},
      .HEADERFUNC = biff_header_discovery,
      .FOOTER = {0},
      .SEARCHTYPE = SEARCHTYPE_FORWARD,
      .FILEVALIDATOR = biff_file_validate,
      .CANDIDATEVALIDATOR = biff_candidate_validate,
      .REASSEMBLYFUNC = biff_reassembly,
      .SERIALIZECARVESTATEFUNC = biff_serialize_carve_state,
      .CLONECARVESTATEFUNC = biff_clone_carve_state,
      .FREECARVESTATEFUNC = biff_free_carve_state,
      .SIZEOFCARVESTATEFUNC = biff_sizeof_carve_state,
      .PRINTCARVESTATEFUNC = biff_print_carve_state,
      .NO_DEFRAG = false,
      .PRIORITY = PRIORITY_SIGMA
    },

    // OneNote section files. Both revision stores and package stores use the
    // same file type GUID but carry different internal storage formats.
    //
    {
      .FILETYPE = "one",
      .MASTER = false,
      .CASESENSITIVE = true,
      .MINIMUMSIZE = ONENOTE_MINIMUM_PACKAGE_SIZE,
      .MAXIMUMSIZE = UINT64_C(4294967296),
      .HEADER = {0},
      .HEADERFUNC = onenote_section_header_discovery,
      .FOOTER = {0},
      .FOOTERFUNC = onenote_section_footer_discovery,
      .SEARCHTYPE = SEARCHTYPE_FORWARD,
      .FILEVALIDATOR = onenote_section_file_validate,
      .CANDIDATEVALIDATOR = onenote_candidate_validate,
      .REASSEMBLYFUNC = onenote_reassembly,
      .SERIALIZECARVESTATEFUNC = onenote_serialize_carve_state,
      .CLONECARVESTATEFUNC = onenote_clone_carve_state,
      .FREECARVESTATEFUNC = onenote_free_carve_state,
      .SIZEOFCARVESTATEFUNC = onenote_sizeof_carve_state,
      .PRINTCARVESTATEFUNC = onenote_print_carve_state,
      .PRIORITY = PRIORITY_SIGMA
    },

    // OneNote table-of-contents files.
    //
    {
      .FILETYPE = "onetoc2",
      .MASTER = false,
      .CASESENSITIVE = true,
      .MINIMUMSIZE = ONENOTE_MINIMUM_PACKAGE_SIZE,
      .MAXIMUMSIZE = UINT64_C(4294967296),
      .HEADER = {0},
      .HEADERFUNC = onenote_toc_header_discovery,
      .FOOTER = {0},
      .FOOTERFUNC = onenote_toc_footer_discovery,
      .SEARCHTYPE = SEARCHTYPE_FORWARD,
      .FILEVALIDATOR = onenote_toc_file_validate,
      .CANDIDATEVALIDATOR = onenote_candidate_validate,
      .REASSEMBLYFUNC = onenote_reassembly,
      .SERIALIZECARVESTATEFUNC = onenote_serialize_carve_state,
      .CLONECARVESTATEFUNC = onenote_clone_carve_state,
      .FREECARVESTATEFUNC = onenote_free_carve_state,
      .SIZEOFCARVESTATEFUNC = onenote_sizeof_carve_state,
      .PRINTCARVESTATEFUNC = onenote_print_carve_state,
      .PRIORITY = PRIORITY_SIGMA
    },

    // Microsoft Jet and ACE databases. The access entry performs discovery;
    // validated databases are assigned to the appropriate dormant subtype.
    // Microsoft Project MPD databases are identified by their internal schema.
    //
    {
      .FILETYPE = "access",
      .MASTER = false,
      .CASESENSITIVE = true,
      .MINIMUMSIZE = ACCESS_JET3_PAGE_SIZE * UINT64_C(2),
      .MAXIMUMSIZE = ACCESS_MAXIMUM_DATABASE_SIZE,
      .HEADER = {0},
      .HEADERFUNC = access_header_discovery,
      .FOOTER = {0},
      .SEARCHTYPE = SEARCHTYPE_FORWARD,
      .BLOCKVALIDATOR = access_block_validate,
      .BLOCKVALIDATIONSCOPE = BLOCK_VALIDATION_REASSEMBLY_ONLY,
      .FILEVALIDATOR = access_file_validate,
      .CANDIDATEVALIDATOR = access_candidate_classify,
      .REASSEMBLYFUNC = access_reassembly,
      .SERIALIZECARVESTATEFUNC = access_serialize_carve_state,
      .CLONECARVESTATEFUNC = access_clone_carve_state,
      .FREECARVESTATEFUNC = access_free_carve_state,
      .SIZEOFCARVESTATEFUNC = access_sizeof_carve_state,
      .PRINTCARVESTATEFUNC = access_print_carve_state,
      .PRIORITY = PRIORITY_SIGMA
    },

#define ACCESS_SEMANTIC_SEARCH_SPEC(type_name)                  \
    {                                                           \
      .FILETYPE = type_name,                                    \
      .MASTER = false,                                          \
      .CASESENSITIVE = true,                                    \
      .MINIMUMSIZE = ACCESS_JET3_PAGE_SIZE * UINT64_C(2),       \
      .MAXIMUMSIZE = ACCESS_MAXIMUM_DATABASE_SIZE,              \
      .HEADER = {0},                                            \
      .HEADERFUNC = access_no_header_discovery,                 \
      .FOOTER = {0},                                            \
      .SEARCHTYPE = SEARCHTYPE_FORWARD,                         \
      .BLOCKVALIDATOR = access_block_validate,                  \
      .BLOCKVALIDATIONSCOPE = BLOCK_VALIDATION_REASSEMBLY_ONLY, \
      .FILEVALIDATOR = access_file_validate,                    \
      .CANDIDATEVALIDATOR = access_candidate_classify,          \
      .REASSEMBLYFUNC = access_reassembly,                      \
      .SERIALIZECARVESTATEFUNC = access_serialize_carve_state,   \
      .CLONECARVESTATEFUNC = access_clone_carve_state,           \
      .FREECARVESTATEFUNC = access_free_carve_state,             \
      .SIZEOFCARVESTATEFUNC = access_sizeof_carve_state,          \
      .PRINTCARVESTATEFUNC = access_print_carve_state,           \
      .PRIORITY = PRIORITY_SIGMA                                \
    }

    ACCESS_SEMANTIC_SEARCH_SPEC("mdb"),
    ACCESS_SEMANTIC_SEARCH_SPEC("accdb"),
    ACCESS_SEMANTIC_SEARCH_SPEC("mpd"),

#undef ACCESS_SEMANTIC_SEARCH_SPEC

    // Personal Folder File containers. The PFF entry performs discovery;
    // validated containers are assigned to PST, OST, or PAB output.
    //
    {
      .FILETYPE = "pff",
      .MASTER = false,
      .CASESENSITIVE = true,
      .MINIMUMSIZE = PST_HEADER_MINIMUM_SIZE,
      .MAXIMUMSIZE = PST_MAXIMUM_FILE_SIZE,
      .HEADER = "|\x21\x42\x44\x4e|",
      .FOOTER = {0},
      .SEARCHTYPE = SEARCHTYPE_FORWARD,
      .BLOCKVALIDATOR = pst_block_validate,
      .BLOCKVALIDATIONSCOPE = BLOCK_VALIDATION_REASSEMBLY_ONLY,
      .FILEVALIDATOR = pst_file_validate,
      .CANDIDATEVALIDATOR = pst_candidate_classify,
      .REASSEMBLYFUNC = pst_reassembly,
      .SERIALIZECARVESTATEFUNC = pst_serialize_carve_state,
      .CLONECARVESTATEFUNC = pst_clone_carve_state,
      .FREECARVESTATEFUNC = pst_free_carve_state,
      .SIZEOFCARVESTATEFUNC = NULL,
      .PRINTCARVESTATEFUNC = pst_print_carve_state,
      .PRIORITY = PRIORITY_SIGMA
    },

#define PST_SEMANTIC_SEARCH_SPEC(type_name)                    \
    {                                                          \
      .FILETYPE = type_name,                                   \
      .MASTER = false,                                         \
      .CASESENSITIVE = true,                                   \
      .MINIMUMSIZE = PST_HEADER_MINIMUM_SIZE,                  \
      .MAXIMUMSIZE = PST_MAXIMUM_FILE_SIZE,                    \
      .HEADER = {0},                                           \
      .HEADERFUNC = pst_no_header_discovery,                   \
      .FOOTER = {0},                                           \
      .SEARCHTYPE = SEARCHTYPE_FORWARD,                        \
      .BLOCKVALIDATOR = pst_block_validate,                    \
      .BLOCKVALIDATIONSCOPE = BLOCK_VALIDATION_REASSEMBLY_ONLY,\
      .FILEVALIDATOR = pst_file_validate,                      \
      .CANDIDATEVALIDATOR = pst_candidate_classify,            \
      .REASSEMBLYFUNC = pst_reassembly,                        \
      .SERIALIZECARVESTATEFUNC = pst_serialize_carve_state,    \
      .CLONECARVESTATEFUNC = pst_clone_carve_state,            \
      .FREECARVESTATEFUNC = pst_free_carve_state,              \
      .SIZEOFCARVESTATEFUNC = NULL,                          \
      .PRINTCARVESTATEFUNC = pst_print_carve_state,            \
      .PRIORITY = PRIORITY_SIGMA                               \
    }

    PST_SEMANTIC_SEARCH_SPEC("pst"),
    PST_SEMANTIC_SEARCH_SPEC("ost"),
    PST_SEMANTIC_SEARCH_SPEC("pab"),

#undef PST_SEMANTIC_SEARCH_SPEC

    // MP3 files
    //
    {
      .FILETYPE = "mp3",
      .MASTER = false,
      .HEADER = {0},
      .FOOTER = {0},
      .BLOCKVALIDATOR = mp3_block_validate,
      #if MP3_BLOCK_RECOVERY > 0
        .SEARCHTYPE = SEARCHTYPE_BLOCK_ONLY,
      #endif
        #if MP3_BLOCK_RECOVERY == 0
        .MINIMUMSIZE = 72,
      .MAXIMUMSIZE = 500000000,  // there is no maximum size to mp3 files, set to half a GB for now
      .HEADERFUNC = mp3_header_discovery,
      .SEARCHTYPE = SEARCHTYPE_FORWARD,
      .FILEVALIDATOR = mp3_file_validate,
      .REASSEMBLYFUNC = mp3_custom_reassembly,
      .SERIALIZEBLOCKSTATEFUNC = mp3_serialize_block_state,
      .CLONEBLOCKSTATEFUNC = mp3_clone_block_state,
      .FREEBLOCKSTATEFUNC = mp3_free_block_state,
      .PRINTBLOCKSTATEFUNC = mp3_print_block_state,
      .SERIALIZECARVESTATEFUNC = mp3_serialize_carve_state,
      .CLONECARVESTATEFUNC = mp3_clone_carve_state,
      .FREECARVESTATEFUNC = mp3_free_carve_state,
      .PRINTCARVESTATEFUNC = mp3_print_carve_state,
      .PRIORITY = PRIORITY_PI,
      #endif
    },

    // "123" — synthetic file type with custom reassembly (see "123.h")
    //
    // NOTES: This is an advanced example that demonstrates custom reassembly
    // threads, block state, carve state, and metadata-driven layout.  It
    // complements the simpler "abc" example.
    //
    {
      .FILETYPE                 = "123",
      .MASTER                   = false,
      .CASESENSITIVE            = true,
      .MINIMUMSIZE              = 1024,
      .MAXIMUMSIZE              = 15000000,
      .HEADER                   = "|\x23\x48\x45\x41\x44\x45\x52\x23|",
      .FOOTER                   = "|\x23\x46\x4F\x4F\x54\x45\x52\x23|",
      .SEARCHTYPE               = SEARCHTYPE_FORWARD,
      .BLOCKVALIDATOR           = file_123_block_validate,
      .FILEVALIDATOR            = file_123_file_validate,
      .SERIALIZEBLOCKSTATEFUNC  = file_123_serialize_block_state,
      .CLONEBLOCKSTATEFUNC      = file_123_clone_block_state,
      .FREEBLOCKSTATEFUNC       = file_123_free_block_state,
      .SIZEOFBLOCKSTATEFUNC     = file_123_sizeof_block_state,
      .PRINTBLOCKSTATEFUNC      = file_123_print_block_state,
      .SERIALIZECARVESTATEFUNC  = file_123_serialize_carve_state,
      .CLONECARVESTATEFUNC      = file_123_clone_carve_state,
      .FREECARVESTATEFUNC       = file_123_free_carve_state,
      .SIZEOFCARVESTATEFUNC     = file_123_sizeof_carve_state,
      .PRINTCARVESTATEFUNC      = file_123_print_carve_state,
      .REASSEMBLYFUNC           = file_123_reassembly,
      .PRIORITY                 = PRIORITY_HIGHEST,
    },

    {
      .FILETYPE = "pdf",
      .MASTER = false,
      .CASESENSITIVE = true,
      .MINIMUMSIZE = 182,
      .MAXIMUMSIZE = 2147483648,  // No practical max size for PDFs so set to 2GB
      .HEADER = "/\x25\x50\x44\x46\x2d[\x31-\x32]\x2e[\x30-\x37]/",
      .HEADERFUNC = NULL,
      .FOOTER = "/%%EOF/",
      .FOOTERFUNC = NULL,
      .SEARCHTYPE = SEARCHTYPE_FORWARD,
      .BLOCKVALIDATOR = pdf_block_validate,
      .FILEVALIDATOR = pdf_file_validate,
      .CANDIDATEVALIDATOR = pdf_candidate_preserve_prefix,
      .SERIALIZEBLOCKSTATEFUNC   = pdf_serialize_block_state,
      .CLONEBLOCKSTATEFUNC       = pdf_clone_block_state,
      .FREEBLOCKSTATEFUNC        = pdf_free_block_state,
      .PRINTBLOCKSTATEFUNC       = pdf_print_block_state,
      .SERIALIZECARVESTATEFUNC   = pdf_serialize_carve_state,
      .CLONECARVESTATEFUNC       = pdf_clone_carve_state,
      .FREECARVESTATEFUNC        = pdf_free_carve_state,
      .PRINTCARVESTATEFUNC       = pdf_print_carve_state,
      .REASSEMBLYFUNC            = pdf_reassembly,
      .PRIORITY = PRIORITY_SIGMA,
      .NO_DEFRAG = false
    },

    /////////////////////////////////////////////////////////////////
    // this array MUST end with an entry with .FILETYPE set to {0} //
    /////////////////////////////////////////////////////////////////

    {.FILETYPE = {0}}

};
