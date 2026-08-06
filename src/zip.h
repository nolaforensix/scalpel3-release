//
// Scalpel3 is Copyright(C) 2021 - 2026 by Golden G. Richard III and contributors.
//
// This program is free software : you can redistribute it and / or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
// even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have  received a copy of the  GNU General Public License along with  this program.  If
// not, see <https://www.gnu.org/licenses/>.
//
//-----------------------------
// Additional Integration Terms
// ----------------------------
//
// Linking or embedding Scalpel3 (statically or dynamically) into another program such that the
// resulting executable or library forms a single combined work constitutes creation of a derivative
// work under the GPL.  Any party distributing such a combined work must make the entire source code
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


/**
 * @author Tyler Saizan
 *
 * This file contains code for carving ZIP files, which follow this general format:
 *
 *  [local file header 1]
 *  [encryption header 1]
 *  [file data 1]
 *  (data descriptor 1)
 *  ...
 *  [local file header n]
 *  [encryption header n]
 *  [file data n]
 *  (data descriptor n)
 *  [archive decryption header]
 *  [archive extra data record]
 *  [central directory header 1]
 *  ...
 *  [central directory header n]
 *  [zip64 end of central directory record]
 *  [zip64 end of central directory locator]
 *  [end of central directory record]
 *
 * The initial goal is to support CONTIGUOUS, UNENCRYPTED files that are NOT Zip64 (large files).
 */

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunused-parameter"

#include "scalpel.h"
#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdint.h>
#include <string.h>

// for testing: gcc -x c -o zip-test zip.h -I /opt/homebrew/include -I /opt/homebrew/Cellar/python@3.11/3.11.9/Frameworks/Python.framework/Versions/3.11/include/python3.11
// better yet: ./TESTS/zip-test-files/src/test.sh
// #define ZIP_TEST

// defines
#define LOCAL_FILE_HEADER_SIG 0x04034b50
#define CENTRAL_DIR_FILE_HEADER_SIG 0x02014b50
#define END_OF_CENTRAL_DIR_RECORD_SIG 0x06054b50
#define COMPATABILITY_LOW 0
#define COMPATABILITY_HI 19
#define VERSION_LOW 10
#define VERSION_HI 63
#define COMP_METHOD_LOW 0
#define COMP_METHOD_GAP_LOW 20
#define COMP_METHOD_GAP_HI 93
#define COMP_METHOD_HI 99
#define CRC_MAGIC 0xdebb20e3
#define MAX_COMMENT_SIZE 65535 // EOCD
#define EOCD_SIZE 22
#define CD_FILE_HEADER_SIZE 46
#define LOCAL_FILE_HEADER_SIZE 30

// structs
typedef struct
{
  uint16_t is_encrypted : 1;
  uint16_t is_comp_options_modified : 1;
  uint16_t is_dynamic_huffman_codes : 1;
  uint16_t has_data_descriptor : 1;
  uint16_t reserved_enhanced_deflating : 1; // method 8
  uint16_t is_compressed_patched_data : 1;
  uint16_t is_strongly_encrypted : 1; // if set, bit 0 must be set, and ver > 50, 51 for AES
  uint16_t unused : 4;
  uint16_t is_UTF8_encoded : 1;
  uint16_t reserved_enhanced_comp : 1;
  uint16_t is_encrypted_central_dir : 1;
  uint16_t reserved : 2;
} BitFlags;

typedef struct __attribute__((packed))
{ // @TODO Find a better way than packing! stream bytes in one at a time?
  uint32_t signature;
  uint16_t min_ver_needed;
  BitFlags bit_flags; // possible bit-map
  uint16_t compression_method;
  uint16_t last_mod_time;
  uint16_t last_mod_date;
  uint32_t crc_32;
  uint32_t compressed_size;
  uint32_t uncompressed_size;
  uint16_t name_length;
  uint16_t extra_field_length;
  // file name
  // extra field
} LocalFileHeader;

typedef struct __attribute__((packed))
{
  uint32_t signature;
  uint16_t ver_made_by;
  uint16_t min_ver_needed;
  BitFlags bit_flags;
  uint16_t compression_method;
  uint16_t last_mod_time;
  uint16_t last_mod_date;
  uint32_t crc_32;
  uint32_t compressed_size;
  uint32_t uncompressed_size;
  uint16_t name_length;
  uint16_t extra_field_length;
  uint16_t comment_length;
  uint16_t disk_num_file_starts;
  uint16_t internal_file_attributes;
  uint32_t external_file_attributes;
  uint32_t rel_offset_local_file_header; // num bytes b/w start of first disk file occurs, and start of local file header (read central dir to find file in ZIP file)
  // file name
  // extra field
  // file comment
} CentralDirFileHeader;

typedef struct
{
  uint32_t signature; // 0x05054b50
  uint16_t size_of_data;
  // signature data
} DigitalSignature;

typedef struct __attribute__((packed))
{
  uint32_t signature; // 0x06054b50
  uint16_t disk_num;
  uint16_t central_dir_start_disk;
  uint16_t num_central_dir_records_this_disk;
  uint16_t total_num_central_dir_records;
  uint32_t central_dir_size; // in bytes
  uint32_t central_dir_start_rel_offset;
  uint16_t comment_length;
  // comment
} EndOfCentralDirRecord;

typedef struct
{
  uint32_t signature; // 0x06064b50
  uint64_t size;      // of the remainder of this record, total header - 12 bytes
  uint16_t ver_made_by;
  uint16_t min_ver;
  uint32_t disk_num;
  uint32_t central_dir_start_disk;
  uint64_t num_central_dir_entries_this_disk;
  uint64_t total_central_dir_entries;
  uint64_t central_dir_size;
  uint64_t central_dir_start_rel_offset; // w.r.t. starting disk num
  // zip64 extensible data sector, size = ->size - 44
  // extensible data sector should contain header blocks:
  //  header ID (2 bytes), data size (4 bytes)
} Zip64EndOfCentralDirRecord;

typedef struct
{
  uint32_t signature; // 0x07064b50
  uint32_t zip64_end_of_central_dir_start_disk;
  uint64_t zip64_end_of_central_dir_start_offset;
  uint32_t total_num_disks;
} Zip64EndOfCentralDirLocator;

typedef struct
{
  uint32_t crc_32;
  uint32_t compressed_size;
  uint32_t uncompressed_size;
} DataDescriptor; // must exist if bit 3 of big flags is set
                  // immediately follows last byte of compressed data
// NOTE: data descriptor MAY or MAY NOT have signature: 0x08074b50
// signature will directly precede Data Descriptor

typedef struct
{
  uint32_t crc_32;
  uint64_t compressed_size;
  uint64_t uncompressed_size;
} Zip64DataDescriptor; // if file's size exceeds 0xFFFFFFFF, required
                       // used if zip64 extended info extra field is present for a file

typedef struct
{
  uint32_t signature; // 0x08064b50
  uint32_t extra_field_len;
  // extra field data
} ArchiveExtraDataRecord;

// function prototypes
EndOfCentralDirRecord *EOCD_validate(char *data,
                                     uint64_t length,
                                     uint64_t EOCD_offset);

CentralDirFileHeader **CD_validate(char *data,
                                   uint64_t length,
                                   uint64_t CD_head_offset,
                                   uint16_t num_entries,
                                   EndOfCentralDirRecord *EOCD);

LocalFileHeader **LFH_validate(char *data,
                               uint64_t length,
                               uint16_t num_entries,
                               CentralDirFileHeader **central_dir_headers);

static inline uint32_t zip_block_validate(char *data,
					  uint64_t length,
					  BlockValidationDecision *decision,
					  uint64_t *validates_to,
					  uint32_t needleidx,
					  uint32_t blocksize,
					  void *blockhashkey);


static inline void zip_file_validate(char *data,
				     uint64_t length,
				     bool *validates,
				     uint64_t *validates_to,
				     bool *promising,
				     uint32_t needleidx,
				     uint32_t blocksize,
				     void *carvehashkey);


// function definitions
EndOfCentralDirRecord *EOCD_validate(char *data, uint64_t length, uint64_t EOCD_offset)
{
  // // malloc a char array big enough to hold the EOCD
  // char *EOCD_bytes = (char *)malloc(sizeof(EndOfCentralDirRecord));
  // // memcpy data into this array; start from offset ..
  // if (EOCD_offset + EOCD_SIZE <= length)
  // {
  //   memcpy(EOCD_bytes, &data[EOCD_offset], EOCD_SIZE);
  // }
  // else
  // {
  //   return NULL;
  // }
  // // malloc a EOCD struct
  // EndOfCentralDirRecord *EOCD = (EndOfCentralDirRecord *)malloc(sizeof(EndOfCentralDirRecord));
  // // cast copied bytes to EOCD
  // EOCD = (EndOfCentralDirRecord *)EOCD_bytes;
  EndOfCentralDirRecord *EOCD;
  EOCD = (EndOfCentralDirRecord *)&data[EOCD_offset];

  // do any validations -- not much to be done, signature was already checked
  // print some stuff here for testing
  // printf("__________________EOCD HEADER__________________\n");
  // printf("Signature: %04x\n", EOCD->signature);
  // printf("Disk Number: %hu\n", EOCD->disk_num);
  // printf("Central Dir Start Disk: %hu\n", EOCD->central_dir_start_disk);
  // printf("Number of Central Dir Records on this Disk: %hu\n", EOCD->num_central_dir_records_this_disk);
  // printf("Total Central Dir Records: %hu\n", EOCD->total_num_central_dir_records);
  // printf("Central Dir Size in Bytes: %u\n", EOCD->central_dir_size);
  // printf("Central Dir Start (rel offset): %u\n", EOCD->central_dir_start_rel_offset);
  // printf("Comment Length: %hu\n", EOCD->comment_length);
  // printf("____________________________________\n");

  return EOCD;
}

CentralDirFileHeader **CD_validate(char *data, uint64_t length, uint64_t offset, uint16_t num_entries, EndOfCentralDirRecord *EOCD)
{
  uint64_t first_offset = offset;
  if (offset == 0)
  {
    // may miss empty ZIP files, but do we care? probably not
    return NULL;
  }
  // allocate the array of CD records
  CentralDirFileHeader **CD_records = (CentralDirFileHeader **)malloc(num_entries * sizeof(CentralDirFileHeader *));
  for (int i = 0; i < num_entries; i++)
  {
    // char *file_header_bytes = malloc(sizeof(CentralDirFileHeader));

    // // memcpy the data into this array as long as offset falls within length
    // if (offset + CD_FILE_HEADER_SIZE <= length)
    // {
    //   memcpy(file_header_bytes, &data[offset], CD_FILE_HEADER_SIZE); // padding is hard...
    // }
    // else
    // {
    //   return NULL;
    // }
    // // cast to CentralDirFileHeader
    // CentralDirFileHeader *file_header = (CentralDirFileHeader *)file_header_bytes;
    CentralDirFileHeader *file_header;
    if(offset + CD_FILE_HEADER_SIZE <= length) {
      file_header = (CentralDirFileHeader *)&data[offset];
    }
    else {
      return NULL;
    }

    if (file_header->signature != CENTRAL_DIR_FILE_HEADER_SIG)
    {
      //printf("Central Dir Signature Misaligned\n");
      return NULL;
    }
    if (file_header->rel_offset_local_file_header > first_offset)
    {
      //printf("Invalid local header offset\n");
      return NULL;
    }
    if ((file_header->compression_method > COMP_METHOD_GAP_LOW && file_header->compression_method < COMP_METHOD_GAP_HI) ||
        file_header->compression_method > COMP_METHOD_HI)
    {
      //printf("Invalid compression method\n");
      return NULL;
    }

    // testing
    // printf("Headers found: %d\n", i+1);
    if (i == 0)
    {
      // printf("------------First CD Header-----------\n");
      // printf("Local Header Offset: %u\n", file_header->rel_offset_local_file_header);
      // printf("Compression Method: %hu\n", file_header->compression_method);
      // printf("Compressed size: %u\n", file_header->compressed_size);
      // printf("Uncompressed size: %u\n", file_header->uncompressed_size);
      // printf("Name size: %hu\n", file_header->name_length);
      // printf("Extra size: %hu\n", file_header->extra_field_length);
      // printf("Comment size: %hu\n", file_header->comment_length);
      // printf("CRC: 0x%04x\n", file_header->crc_32);
      // printf("---------------------------------------\n");
    }
    // end testing
    // add entry to array
    CD_records[i] = file_header;
    offset += CD_FILE_HEADER_SIZE + file_header->name_length + file_header->extra_field_length + file_header->comment_length;
  }

  return CD_records;
}

LocalFileHeader **LFH_validate(char *data, uint64_t length, uint16_t num_entries, CentralDirFileHeader **central_dir_headers)
{
  LocalFileHeader **file_headers = malloc(num_entries * LOCAL_FILE_HEADER_SIZE);
  for (int i = 0; i < num_entries; i++)
  {
    // char *file_header_bytes = malloc(sizeof(LocalFileHeader));
    uint32_t offset = central_dir_headers[i]->rel_offset_local_file_header;

    // // memcpy the data into this array as long as offset falls within length
    // if (offset + LOCAL_FILE_HEADER_SIZE <= length)
    // {
    //   memcpy(file_header_bytes, &data[offset], LOCAL_FILE_HEADER_SIZE); // padding is hard...
    // }
    // else
    // {
    //   return NULL;
    // }
    // // cast to LocalFileHeader
    // LocalFileHeader *file_header = (LocalFileHeader *)file_header_bytes;
    LocalFileHeader *file_header;
    if (offset + LOCAL_FILE_HEADER_SIZE <= length) {
      file_header = (LocalFileHeader *)&data[offset];
    }
    else {
      return NULL;
    }

    // validate some fields
    if (file_header->signature != LOCAL_FILE_HEADER_SIG)
    {
      //printf("Invalid local header signature\n");
      return NULL;
    }
    if (file_header->min_ver_needed != central_dir_headers[i]->min_ver_needed)
    {
      //printf("Min Ver mismatch\n");
      return NULL;
    }
    if (file_header->compression_method != central_dir_headers[i]->compression_method)
    {
      //printf("Compression Method mismatch\n");
      return NULL;
    }
    if (file_header->last_mod_date != central_dir_headers[i]->last_mod_date)
    {
      //printf("Mod date mismatch\n");
      return NULL;
    }
    if (file_header->last_mod_time != central_dir_headers[i]->last_mod_time)
    {
      //printf("Mod time mismatch\n");
      return NULL;
    }
    if (!file_header->bit_flags.has_data_descriptor)
    {
      if (file_header->crc_32 != central_dir_headers[i]->crc_32)
      {
        //printf("CRC: 0x%04x\n", file_header->crc_32);
        //printf("CRC mismatch\n");
        return NULL;
      }
      if (file_header->compressed_size != central_dir_headers[i]->compressed_size)
      {
        //printf("Compressed size mismatch\n");
        return NULL;
      }
      if (file_header->uncompressed_size != central_dir_headers[i]->uncompressed_size)
      {
        //printf("Uncompressed size mismatch\n");
        return NULL;
      }
    }
    if (file_header->name_length != central_dir_headers[i]->name_length)
    {
      // printf("Header starts at: 0x%04x\n", central_dir_headers[i]->rel_offset_local_file_header);
      // printf("Offset = %u\n", offset);
      // printf("Name Length: %hu\n", file_header->name_length);
      //printf("Name Length mismatch\n");
      // packing issues...
      return NULL;
    }
    // if(file_header->extra_field_length != central_dir_headers[i]->extra_field_length) {
    //   printf("EFL: %hu vs. %hu\n", file_header->extra_field_length, central_dir_headers[i]->extra_field_length);
    //   printf("Extra Field Length mismatch\n");
    //   return NULL;
    // }

    // testing
    // printf("**Checked entry %d**\n", i);
    // end testing
    // add entry to array
    file_headers[i] = file_header;
  }

  return file_headers;
}

static inline uint32_t zip_block_validate(char *data,
					  uint64_t length,
					  BlockValidationDecision *decision,
					  uint64_t *validates_to,
					  uint32_t needleidx,
					  uint32_t blocksize,
					  void *blockhashkey) {

  *decision = BLOCK_CONFIDENCE_VALID;
  *validates_to = length - 1;
  return needleidx;
}

static inline void zip_file_validate(char *data,
				     uint64_t length,
				     bool *validates,
				     uint64_t *validates_to,
				     bool *promising,
				     uint32_t needleidx,
				     uint32_t blocksize,
				     void *carvehashkey) {

  if (!(data[0] == 'P' && data[1] == 'K' && data[2] == 0x03 && data[3] == 0x04)) {
    *promising = false;
    //printf("Invalid ZIP file signature\n");
    return;
  }

  // find the EOCD by searching backwards from end of file
  // for search_range, we will be given more than just the file (len - search_range)
  // uint64_t search_range = (length < (MAX_COMMENT_SIZE + sizeof(EndOfCentralDirRecord)) ? length : MAX_COMMENT_SIZE + sizeof(EndOfCentralDirRecord));
  uint64_t EOCD_offset = 0;
  // for (uint64_t i = length - 1; i >= 4; i--) {
  // searching forward, backwards breaks things!
  for (uint64_t i = 4; i < length - 4; i++)
  {
    if (!memcmp(&data[i], "\x50\x4b\x05\x06", 4))
    {
      // printf("EOCD signature found at offset: %llu\n", i);
      EOCD_offset = i;
      break;
    }
  }
  if (!EOCD_offset)
  {
    *promising = false;
    //printf("No EOCD signature found\n");
    return;
  }
  // validate the EOCD
  EndOfCentralDirRecord *EOCD = EOCD_validate(data, length, EOCD_offset);
  if (EOCD == NULL)
  {
    *promising = false;
    //printf("EOCD Validation Failed\n");
    return;
  }
  uint32_t CD_offset = 0;
  uint32_t CD_size = 0;
  // now look at central directory with offset and size from EOCD
  if (EOCD->disk_num == EOCD->central_dir_start_disk)
  {
    CD_offset = EOCD->central_dir_start_rel_offset;
    CD_size = EOCD->central_dir_size;
  }

  // now loop through the central directory to get all the files
  CentralDirFileHeader **central_dir_headers = CD_validate(data, length, CD_offset, EOCD->total_num_central_dir_records, EOCD);

  if (central_dir_headers == NULL)
  {
    *promising = false;
    //printf("Central Directory Validation Failed\n");
    return;
  }
  // now for each CD record, validate the local file headers they point to
  LocalFileHeader **local_file_headers = LFH_validate(data, length, EOCD->total_num_central_dir_records, central_dir_headers);

  // testing: list all file names
  #ifdef ZIP_TEST
  for (int i = 0; i < EOCD->total_num_central_dir_records; i++)
  {
    LocalFileHeader *header = local_file_headers[i];
    uint16_t name_len = header->name_length;
    uint32_t name_loc = central_dir_headers[i]->rel_offset_local_file_header + LOCAL_FILE_HEADER_SIZE;
    char *name = malloc(header->name_length);
    memcpy(name, &data[name_loc], name_len);
    // printf("%s\n", name);
  }
  // end testing: works! - can use this to identify if office file
  #endif

  uint64_t end_of_EOCD = EOCD_offset + EOCD_SIZE + EOCD->comment_length;
  // printf("END: %llu\n", end_of_EOCD);
  *validates_to = end_of_EOCD - 1;
  *validates = true;
  // printf("Valid so far!\n");
  free(central_dir_headers);
  free(local_file_headers);
  return;
}

// testing
#ifdef ZIP_TEST
int main(int argc, char *argv[])
{
  struct stat file_info;
  BlockValidationDecision decision;
  int i, j, rc;
  uint32_t blocksize;
  uint32_t needleidx = 0;
  bool validates;
  bool promising;
  uint64_t validates_to;
  char *file_buf, *block_buf;
  uint64_t len;

  if (argc != 3)
  {
    fprintf(stderr, "USAGE: %s filename.exe [blocksize]\n", argv[0]);
    return 0;
  }

  rc = stat(argv[1], &file_info);
  if (rc)
  {
    printf("Couldn't open PE file.\n");
    return 0;
  }
  blocksize = atoi(argv[2]);
  len = file_info.st_size;
  block_buf = (char *)malloc(blocksize + 100);
  file_buf = (char *)malloc(len + 100);

  int fd = open(argv[1], O_RDONLY);
  lseek(fd, 0, SEEK_SET);
  // load entire file
  read(fd, file_buf, len);
  // see if a full file successfully validates
  zip_file_validate(file_buf, len, &validates, &validates_to, &promising, needleidx, blocksize, NULL);
  printf("====================== FILE VALIDATION RESULTS ==========================\n");
  printf("VALIDATES: %u\nVALIDATES_TO: %llu\nPROMISING: %u\n", validates, validates_to, promising);
  return 0;
}

#endif

#pragma GCC diagnostic pop

