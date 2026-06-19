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
// BLOCKVALIDATOR--this marks every block as a potential candidate for inclusion in a file of this
// type. NULL is better than a block validator that simply validates every block without
// scrutinizing the associated data.
//
// o FILEVALIDATOR defines the corresponding file validation function. This function must be
// thread-safe. It must also be stateless, aside from the use of the scalpel API for associating
// state with carving candidates (see below). See scalpel.h for a function prototype for
// FILEVALIDATOR and then look at one of the established file types (e.g., "abc.h") for an example.
//
// o REASSEMBLYFUNC defines an optional custom reassembly function. The default (if unspecified) is
// the generic LR_reassembly() function, which performs best-effort, left-to-right reassembly. This
// function must be thread-safe. It must also be stateless, aside from the use of the API for
// 'state' in carving candidates. If files associated with a file type cannot be generated in a
// left-to-right fashion (e.g., ZIP files, which contain critial metata at the end of the file),
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
#include "fzip.h"
#include "mp3.h"
#include "zip.h"
// #include "rar.h"
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
    // NOTES: SEARCHTYPE_BLOCK_ONLY is used and no attempt is made to reassemble identified blocks
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
      .MAXIMUMSIZE = 268435456,
      .HEADER = {0},
      .HEADERFUNC = elf_header_discovery,
      .FOOTER = {0},
      .FOOTERFUNC = NULL,
      .SEARCHTYPE = SEARCHTYPE_FORWARD,
      .BLOCKVALIDATOR = elf_block_validate,
      .FILEVALIDATOR = elf_file_validate,
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

    // Unfragmented 32-bit ZIP files + modern Microsoft Office file formats (e.g., .docx, .pptx,
    // etc.)
    //
    {
      .FILETYPE = "zip",
      .MASTER = false,
      .CASESENSITIVE = true,
      .MINIMUMSIZE = 512,
      .MAXIMUMSIZE = 500000000,
      .HEADER = "|\x50\x4b\x03\x04|",
      .HEADERFUNC = NULL,
      .FOOTER = {0},
      .FOOTERFUNC = NULL,
      .SEARCHTYPE = SEARCHTYPE_FORWARD,
      .BLOCKVALIDATOR = zip_block_validate,
      .FILEVALIDATOR = zip_file_validate,
      .PRIORITY = PRIORITY_SIGMA,
      .NO_DEFRAG = true},

    // Fragmented ZIP files
    //
    {
      .FILETYPE = "fzip",
      .MASTER = false,
      .MINIMUMSIZE = 1024,
      .MAXIMUMSIZE = 1000000000,
      .HEADER = {0},
      .FOOTER = "|somethingsomethingsomething|",
      .FOOTERFUNC = NULL,
      .BLOCKVALIDATOR = fzip_block_validate,
      .SEARCHTYPE = SEARCHTYPE_BACKWARD,
      .REASSEMBLYFUNC = fzip_reassembly,
      .PRIORITY = PRIORITY_SIGMA,
    },

  //   {
  //     .FILETYPE = "rar",
  //     .MASTER = false,
  //     .MINIMUMSIZE = 512,
  //       .MAXIMUMSIZE = 500000000,
  //       // RAR 5, RAR 4, Legacy RAR
  //       .HEADER = "/\x52\x61\x72\x21\x1A\x07\x01\\x{00}|\x52\x61\x72\x21\x1A\x07\\x{00}|\x52\x45\x7E\x5E/",
  //       .FOOTER = {0}, // Legacy RAR having no footer requires us to process footer discovery in the validators
  //       // .FOOTER = "/\x1D\x77\x56\x51\x03\x05\x04\\x{00}|\xC4\x3D\x7B\\x{00}\x40\x07\\x{00}|\\x{00}/",
  //       .SEARCHTYPE = SEARCHTYPE_FORWARD,
  //       .BLOCKVALIDATOR = rar_block_validate,
  //       .FILEVALIDATOR = rar_file_validate,
  //       // .REASSEMBLYFUNC = LR_reassembly,
	// .PRIORITY = PRIORITY_SIGMA,
  //       .NO_DEFRAG = true,
  //   },

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
      .NO_DEFRAG = true
    },

    /////////////////////////////////////////////////////////////////
    // this array MUST end with an entry with .FILETYPE set to {0} //
    /////////////////////////////////////////////////////////////////

    {.FILETYPE = {0}}

};
