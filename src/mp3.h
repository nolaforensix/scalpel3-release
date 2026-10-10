//
// SPDX-License-Identifier: GPL-3.0-only
//
// The Scalpel Project is Copyright (C) 2005-2026 by Golden G. Richard III
// and contributors.
//
// Scalpel3 is Copyright (C) 2021-2026 by Golden G. Richard III and the
// contributors listed in AUTHORS.
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

/**
* @author George H.
* @discussion
*
* This file contains functionality for an MP3 file validator and defragmentator.
* Comments last updated: 11/21/25
*
* MP3 reassembly is currently an experimental feature, and is togglable inside 
* of this file under REASSEMBLY_ON
*
* ------------------------------------------------------------------------------------------
*
* LIMITATIONS:
* Currently does not support APE headers/footers.
* Testing has been done on MPEG-1 Layer III files, CRC for other
* layers and other MPEG versions have yet to be implemented.
* MP3 defragmentation assumes that audio must be present and that the 
* audio has some type of frequency progression.
* Decisions based on frequency analysis struggles to recover audio files 
* with similar frequencies throughout. Unlike CRC checks and offset consideration, 
* can only give an estimate. 
*
* ------------------------------------------------------------------------------------------
*
* Information about MP3 files and my approach:
* MP3 files are composed of a series of frames. Each frame contains a portion of
* the audio data, including headers that contain details about the encoded audio and
* decompression details. Frames are relatively small compared to the entire file,
* meaning we can utilize these frames to indicate a valid block of an MP3 file. MP3 frames
* include synchronization information, which assists the decoder in locating the next frame
* to read. This means if the whole frame is contained within one block, we can determine the
* location where a valid MP3 frame header can be expected.
* However, there are cases where even in random data, a valid MP3 frame header can be
* found and its length could very easily point to another MP3 frame header, despite just
* being random data. Because of this, we must verify the validity of the MP3 frame by finding
* as many consecutive MP3 frame headers as possible. I refer to this as the MP3 frame chain.
* The longer the chain, the more likely a block is to be a valid MP3 file section.
* Currently, it decides when to validate the block by taking the block size, dividing it
* by the largest possible frame size, then setting a comparable number as the limit.
*
* ------------------------------------------------------------------------------------------
*
* MP3 is a strange file type:
* - Technically every MP3 frame is a valid MP3 file. If you isolate a valid MP3 frame from a
*   file, it will be playable by any media player (assuming no bit reservoir).
* - MP3 files have no mandatory header or footer. There are optional headers such as ID3v2,
*   but the only thing close to a conventional MP3 header are the frame headers.
* - Blocks can be constructed out of order and the resulting MP3 file will validate.
*   (and will even be playable)
*
**/

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunused-parameter"

#include "scalpel.h"
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdint.h>
#include <inttypes.h>
#include <fcntl.h>

#include <math.h>
#include <mpg123.h>
#include "pocketfft_mdct.h"
#include <assert.h>

//block validation
#define DECODE_FAILURE_TOLERANCE	2			//amount of frames in a block allowed to fail to decode, one is expected if bit reservoir
#define MAYBE_FRAME_LIMIT			2
#define MP3_FILE_VALIDATION_MINIMUM_COMPATIBLE_FRAMES UINT32_C(2)
#define MP3_FRAGMENT_CATALOG_MINIMUM_COMPATIBLE_FRAMES UINT32_C(3)

//reassembly
#define REASSEMBLY_ON				true

// Peak scoring: select one mode for the whole build, then rebuild Scalpel3.
// Both modes use the same extracted peaks and stereo aggregation. Mode 1
// preserves the current index-only score; mode 2 uses thesis section 4.5.1's
// exponential weights with an additional one-to-one matching constraint.
#define MP3_SCORE_MODE_INDEX_ONLY 1
#define MP3_SCORE_MODE_THESIS 2
// Rank full-prefix-decoded seams with the selected MDCT equation by default.
// Define MP3_PATH_SCORE_MDCT=0 explicitly to use the alternative FFT ranking.
#ifndef MP3_PATH_SCORE_MDCT
#define MP3_PATH_SCORE_MDCT 1
#endif
#ifndef MP3_SCORE_TRACE
#define MP3_SCORE_TRACE 0
#endif
#ifndef MP3_SCORE_MODE
#define MP3_SCORE_MODE MP3_SCORE_MODE_THESIS
#endif
#if MP3_SCORE_MODE != MP3_SCORE_MODE_INDEX_ONLY && MP3_SCORE_MODE != MP3_SCORE_MODE_THESIS
#error "MP3_SCORE_MODE must be MP3_SCORE_MODE_INDEX_ONLY or MP3_SCORE_MODE_THESIS"
#endif

// Thesis alpha/beta defaults follow the original mp3recovery.h. Use finite,
// nonnegative weights. Keep T equal to the existing index tolerance by default
// so changing modes compares equations without also changing the search window.
#ifndef MP3_SCORE_THESIS_ALPHA
#define MP3_SCORE_THESIS_ALPHA 5.0
#endif
#ifndef MP3_SCORE_THESIS_BETA
#define MP3_SCORE_THESIS_BETA 1.0
#endif
#ifndef MP3_SCORE_THESIS_TOLERANCE
#define MP3_SCORE_THESIS_TOLERANCE TOLERANCE
#endif
#define TOLERANCE 					1			//max index difference still counted as "nearly coincident" (Steinebach et al. 2015, Handbook of Digital Forensics of Multimedia Data and Devices, pp.234-235)
#define EDGE_GUARD_BINS				4			//bins excluded from each end of the MDCT/FFT spectrum during peak detection

//file type specific
#define FRAME_HEADER_SIZE 			4
#define ID3V1_TAG_SIZE 			128
#define ID3V2_HEADER_SIZE 			10
#define FRAME_FOOTER_SIZE 			16
#define MDCT_COEFFS 				576
#define GP                      	0x18005		/* x^16 + x^15 + x^2 + 1 */
#define CRC16_CMS_POLY          	0x8005
#define CRC16_INIT					0xFFFF
#define MP3_XING_TAG_CRC_BYTES	190
#define MP3_AUDIO_CRC16_POLY		0xA001
#define MP3_SEAM_SIGNATURE_BANDS	256
#define MP3_SEAM_FFT_MAX		2048
#define MP3_SEAM_SCORE_TIE_EPSILON 1.0e-9
#define MP3_HEADER_PREDECESSOR_SCAN_BYTES 4096
#define MP3_MAXIMUM_FRAME_BYTES UINT32_C(2881)
#define MP3_MINIMUM_TERMINAL_ZERO_PADDING_BYTES UINT32_C(16)

#define MP3_MAX_SUPPORTED_BLOCKSIZE UINT16_MAX

//debug
//#define DEBUG_ID3v2 1
//#define DEBUG_GET_FRAME_DATA 1
//#define DEBUG_BLOCK_VALIDATE 1
//#define DEBUG_FRAGMENT_VALIDATE 1
//#define DEBUG_FILE_VALIDATE 1
//#define DEBUG_REASSEMBLY_FRAG 1
//#define DEBUG_REASSEMBLY_CONST 1
//#define DEBUG_REASSEMBLY_THREAD 1
//#define DEBUG_FREQUENCY_ANALYSIS

/***** TABLES *****/

static uint16_t crc16_table[256]; /* 8-bit table */
static pthread_once_t crc16_table_once = PTHREAD_ONCE_INIT;
static uint16_t mp3_audio_crc16_table[256];
static pthread_once_t mp3_audio_crc16_table_once = PTHREAD_ONCE_INIT;
static uint16_t mp3_audio_crc16_zero_powers[64][16];
static pthread_once_t mp3_audio_crc16_zero_once = PTHREAD_ONCE_INIT;
static void crc16_init_table(void) {
  uint16_t crc2;
  for (int i = 0; i < 256; i++) {
    crc2 = (i << 8);
    for (int j = 0; j < 8; j++) {
      if (crc2 & 0x8000)
        crc2 = (crc2 << 1) ^ CRC16_CMS_POLY;
      else
        crc2 <<= 1;
    }
    crc16_table[i] = crc2 & 0xFFFF;
  }
}

// Thread-safe one-time initialization of mpg123 library.
static pthread_once_t mp3_init_once = PTHREAD_ONCE_INIT;
static bool mp3_init_ok = false;
static void mp3_do_init(void) {
	if(MP3_SCORE_TRACE){
		lock_fprintf(stdout, "MP3_SCORE_CONFIG mode=%d path_mdct=%d trace=1\n",
			MP3_SCORE_MODE, MP3_PATH_SCORE_MDCT);
	}
	mp3_init_ok = (mpg123_init() == MPG123_OK);
	if(!mp3_init_ok){
		fprintf(stderr, "mpg123_init() failed -- mp3 audio decoding will be unavailable\n");
	}
}
// returns true if mpg123 is (or already was) successfully initialized
static inline bool mp3_ensure_init(void) { pthread_once(&mp3_init_once, mp3_do_init); return mp3_init_ok; }

// Mutex protecting mpg123_new/mpg123_delete — these are NOT thread-safe
// on macOS ARM64 (corrupt shared internal state when called concurrently).
static pthread_mutex_t mp3_handle_mutex = PTHREAD_MUTEX_INITIALIZER;

static pthread_key_t  mp3_tls_key;
static pthread_once_t mp3_tls_once = PTHREAD_ONCE_INIT;
static bool mp3_tls_key_ok = false;
static void mp3_tls_delete(void *p) {
	if (p) {
	pthread_mutex_lock(&mp3_handle_mutex);
	mpg123_delete((mpg123_handle *)p);
	pthread_mutex_unlock(&mp3_handle_mutex);
	}
}
static void mp3_tls_init(void) {
	mp3_tls_key_ok = (pthread_key_create(&mp3_tls_key, mp3_tls_delete) == 0);
	if(!mp3_tls_key_ok){
		fprintf(stderr, "pthread_key_create() failed -- mp3 audio decoding will be unavailable\n");
	}
}
// returns this thread's reusable handle, in closed state; NULL on failure
static mpg123_handle *mp3_thread_handle(void) {
	pthread_once(&mp3_tls_once, mp3_tls_init);
	if(!mp3_tls_key_ok || !mp3_ensure_init()){
		return NULL;
	}
	mpg123_handle *mh = (mpg123_handle *)pthread_getspecific(mp3_tls_key);
	if (!mh) {
		int err;
		pthread_mutex_lock(&mp3_handle_mutex);
		mh = mpg123_new(NULL, &err);
		pthread_mutex_unlock(&mp3_handle_mutex);
		if (mh) {
			mpg123_param(mh, MPG123_FLAGS, MPG123_QUIET, 0.0);
			if(pthread_setspecific(mp3_tls_key, mh) != 0){
				// TLS slot couldn't be set: this handle won't be found on the next call (a new
				// one would be created instead) and won't be auto-freed by mp3_tls_delete on
				// thread exit (that destructor only runs for whatever IS stored in the slot).
				// Free it now and fail this call rather than leak it -- callers already handle
				// a NULL handle.
				pthread_mutex_lock(&mp3_handle_mutex);
				mpg123_delete(mh);
				pthread_mutex_unlock(&mp3_handle_mutex);
				return NULL;
			}
		}
	}
	return mh;
}

// Per-thread reusable scoring workspace for getPeaks()
typedef struct {
	unsigned char *pcm_bytes;
	float *time;
	float *freq;
	void *pfft_m_plan;
	int pcm_byte_num;
	int fft_N;
} Mp3PeakWorkspace;

static pthread_key_t mp3_peak_ws_key;
static pthread_once_t mp3_peak_ws_once = PTHREAD_ONCE_INIT;
static bool mp3_peak_ws_key_ok = false;
static void mp3_peak_ws_delete(void *p) {
	if(p){
		Mp3PeakWorkspace *ws = (Mp3PeakWorkspace *)p;
		if(ws->pfft_m_plan) pfft_mdctf_free(ws->pfft_m_plan);
		free(ws->pcm_bytes);
		free(ws->time);
		free(ws->freq);
		free(ws);
	}
}
static void mp3_peak_ws_init(void) {
	mp3_peak_ws_key_ok = (pthread_key_create(&mp3_peak_ws_key, mp3_peak_ws_delete) == 0);
	if(!mp3_peak_ws_key_ok){
		fprintf(stderr, "pthread_key_create() failed -- mp3 peak workspace reuse disabled\n");
	}
}
// Returns this thread's reusable peak-analysis workspace (zero-initialized on first use by
// this thread), or NULL if the TLS key couldn't be created -- callers must fall back to a
// local, call-scoped workspace in that case rather than fail outright.
static Mp3PeakWorkspace *mp3_peak_workspace(void) {
	pthread_once(&mp3_peak_ws_once, mp3_peak_ws_init);
	if(!mp3_peak_ws_key_ok) return NULL;
	Mp3PeakWorkspace *ws = (Mp3PeakWorkspace *)pthread_getspecific(mp3_peak_ws_key);
	if(!ws){
		ws = calloc(1, sizeof(Mp3PeakWorkspace));
		if(ws){
			if(pthread_setspecific(mp3_peak_ws_key, ws) != 0){
				free(ws);
				return NULL;
			}
		}
	}
	return ws;
}

const uint16_t bitrate_table[] = {
	32,	32,	32,	32,	8,
	64,	48,	40,	48,	16,
	96,	56,	48,	56,	24,
	128,64,	56,	64,	32,
	160,80,	64,	80,	40,
	192,96,	80,	96,	48,
	224,112,96,	112,56,
	256,128,112,128,64,
	288,160,128,144,80,
	320,192,160,160,96,
	352,224,192,176,112,
	384,256,224,192,128,
	416,320,256,224,144,
	448,384,320,256,160
};

/**** DEFINITIONS ****/

typedef struct {
    char *data;
    int bitPos;
    uint64_t bytePos;
    uint64_t length;
    bool truncated; //set by readBits/skipBits once a read/skip is asked to advance past length--
                     //distinguishes bytePos landing on length because the data cleanly ended there
                     //from bytePos landing on length only because reads/skips got clamped mid-frame
} Bitstream;

typedef enum _ChannelMode {
    stereo,
    jointStereo,
    dualChannel,
    singleChannel
} ChannelMode;

typedef struct{
    double val;
    int index;
} Peak;

typedef struct{
	double bands[4][MP3_SEAM_SIGNATURE_BANDS];
	Peak peaks[2][6];
	uint8_t channels;
	bool valid;
} Mp3SeamSignature;

// Stream parameters and surviving bytes at one physical fragment boundary.
typedef struct {
	uint8_t mpegVersion;
	uint8_t layer;
	uint16_t samplingrate;
	uint8_t bytes[3];
} Mp3HeaderBreakContext;

typedef struct{
	uint16_t frontOffset;
	uint16_t rearOffset;
	uint8_t frontFrameHeaderBreak;
	uint8_t rearFrameHeaderBreak;
	Mp3HeaderBreakContext frontHeaderContext;
	Mp3HeaderBreakContext rearHeaderContext;
	bool headerContextKnown;
	size_t size; //in blocks
	bool isHeader;
	bool isTail;
	bool active; //if true, not in candidate, if false, in candidate
	bool preserveFrontContext;
	uint64_t secondToLastFramePosition;
	uint64_t lastFramePosition;
	uint64_t offsetFramePosition;
	Peak peaks[2][6]; //[0] = left channel (or the sole channel, if mono); [1] = right channel
	bool peaksStereo; //true if peaks[1] holds valid right-channel peaks
	int64_t firstActBlock;
	int64_t lastActBlock;
} Mp3Fragment;

typedef struct{
	bool maybe;
} Mp3BlockState;

typedef struct {
	uint16_t zero_crc;
	uint16_t shifted_basis[16];
} Mp3ChecksumCrcTransform;

typedef enum {
	MP3_CHECKSUM_FULL_TRANSFORM = 1,
	MP3_CHECKSUM_TAIL_TRANSFORM = 2
} Mp3ChecksumTransformFlags;

typedef enum {
	MP3_CHECKSUM_PREPARE = 1,
	MP3_CHECKSUM_GAPS,
	MP3_CHECKSUM_PATHS_INIT,
	MP3_CHECKSUM_PATHS,
	MP3_CHECKSUM_COMPLETE
} Mp3ChecksumPhase;

// Search arrays refer to the ordered fragment catalog, not apparent blocks.
// Transforms and the best mapping survive checkpoints along with the DFS stack.
typedef struct {
	uint64_t signature;
	uint16_t count;
	uint8_t phase;
	uint16_t depth;
	uint16_t best_depth;
	uint32_t prepare_next;
	uint32_t search_limit;
	bool rank_all_matches;
	uint64_t examined;
	uint64_t checksum_matches;
	uint64_t validated_matches;
	double best_score;
	uint16_t *path;
	uint16_t *best_path;
	uint32_t *next_choice;
	uint64_t *blocks_at_depth;
	uint16_t *crc_at_depth;
	uint8_t *transform_flags;
	Mp3ChecksumCrcTransform *full_transforms;
	Mp3ChecksumCrcTransform *tail_transforms;
} Mp3ChecksumState;

typedef enum {
	MP3_GREEDY_INACTIVE = 0,
	MP3_GREEDY_BEGIN,
	MP3_GREEDY_CRC,
	MP3_GREEDY_COUNT,
	MP3_GREEDY_SCORE,
	MP3_GREEDY_FINISHED
} Mp3GreedyPhase;

// Retain decisions and comparison results, not transient decoder buffers.
typedef struct {
	uint64_t signature;
	uint32_t phase;
	uint32_t next;
	uint32_t matches;
	int32_t best_index;
	uint32_t best_peaks_ok;
	uint32_t best_stereo;
	Peak best_peaks[2][6];
} Mp3GreedySearch;

typedef struct{
	Mp3Fragment *fragments;
	uint16_t num_frags;
	//construction record of candidate
	uint16_t *indexes; //assuming fragment count won't exceed 65535
	uint16_t cur_index;
	uint64_t structural_signature;
	uint64_t structural_next_combination;
	bool structural_search_complete;
	uint64_t direct_signature;
	uint32_t direct_first;
	uint32_t direct_second;
	bool direct_search_complete;
	Mp3ChecksumState checksum;
	Mp3GreedySearch greedy;
	uint8_t fragment_discovery_phase;
	int64_t fragment_discovery_next_actual;
	uint32_t fragment_discovery_peak_index;
	bool fragment_discovery_open;
	uint64_t fragment_discovery_apparent_blocks;
} Mp3CarveState;

typedef struct{
	uint8_t mpegVersion;
	uint8_t layer;
	bool crc;
	uint32_t bitrate;
	uint16_t samplingrate;
	enum _ChannelMode channel;
	uint8_t padding;
} FrameArgs;

typedef struct{
	bool validates;
	bool promising;
	uint64_t validates_to;
	uint32_t needleidx;
	uint16_t frontOffset;
	uint16_t rearOffset;
	bool isHeader;
	bool isTail;
	uint64_t secondToLastFramePosition;
	uint64_t lastFramePosition;
	uint64_t offsetFramePosition;
	bool maybe;
} ValidationArgs;

typedef struct {
	bool present;
	uint64_t first_frame_offset;
	uint16_t first_frame_length;
	uint64_t audio_end;
	uint16_t audio_crc;
} Mp3XingChecksum;

typedef enum {
	MP3_CHECKSUM_SEARCH_NOT_FOUND = 0,
	MP3_CHECKSUM_SEARCH_FOUND,
	MP3_CHECKSUM_SEARCH_CHECKPOINT
} Mp3ChecksumSearchResult;

typedef enum {
	MP3_STRUCTURAL_SEARCH_NOT_APPLICABLE = 0,
	MP3_STRUCTURAL_SEARCH_COMPLETE,
	MP3_STRUCTURAL_SEARCH_CHECKPOINT
} Mp3StructuralSearchResult;

typedef enum {
	MP3_FRAGMENT_DISCOVERY_UNINITIALIZED = 0,
	MP3_FRAGMENT_DISCOVERY_SCANNING,
	MP3_FRAGMENT_DISCOVERY_PEAKS,
	MP3_FRAGMENT_DISCOVERY_COMPLETE
} Mp3FragmentDiscoveryPhase;

typedef enum {
	MP3_FRAGMENT_DISCOVERY_FAILED = 0,
	MP3_FRAGMENT_DISCOVERY_FINISHED,
	MP3_FRAGMENT_DISCOVERY_CHECKPOINT
} Mp3FragmentDiscoveryResult;

typedef enum {
	MP3_FRAGMENT_CATALOG_IDLE = 0,
	MP3_FRAGMENT_CATALOG_BUILDING,
	MP3_FRAGMENT_CATALOG_READY,
	MP3_FRAGMENT_CATALOG_FAILED
} Mp3FragmentCatalogState;

typedef struct {
	pthread_mutex_t mutex;
	pthread_cond_t condition;
	Mp3FragmentCatalogState state;
	FileMirror *filemirror;
	int32_t needleidx;
	uint32_t blocksize;
	uint64_t actual_blocks;
	Mp3Fragment *fragments;
	uint16_t count;
	uint16_t capacity;
	uint64_t scan_offset;
	uint32_t peak_index;
	bool consolidation_complete;
	uint64_t source_runs;
} Mp3FragmentCatalog;

typedef struct {
	bool occupied;
	int64_t end;
	int64_t first;
	uint16_t front_offset;
	uint16_t rear_offset;
	bool is_header;
	bool is_id3_header;
	bool is_tail;
	bool preserve_front_context;
	uint64_t second_to_last_frame_position;
	uint64_t last_frame_position;
	uint64_t offset_frame_position;
} Mp3FragmentChain;

typedef struct {
	Mp3FragmentChain *earliest;
	Mp3FragmentChain *latest;
	Mp3FragmentChain *boundary_earliest;
	Mp3FragmentChain *boundary_latest;
	size_t capacity;
} Mp3FragmentChainTables;

static Mp3FragmentCatalog mp3_fragment_catalog = {
	.mutex = PTHREAD_MUTEX_INITIALIZER,
	.condition = PTHREAD_COND_INITIALIZER,
	.state = MP3_FRAGMENT_CATALOG_IDLE
};

typedef struct {
	uint16_t local_position;
	uint16_t *choices;
	uint16_t choice_count;
} Mp3StructuralGap;

typedef struct {
	uint16_t index;
	uint64_t distance;
} Mp3ChecksumFragmentOrder;

/******* FUNCTION PROTOTYPES *******/

static inline uint32_t mp3_block_validate(char* data,
	uint64_t length,
	BlockValidationDecision* decision,
	uint64_t* validates_to,
	uint32_t needleidx,
	uint32_t blocksize,
	void *blockhashkey);

static inline uint32_t mp3_fragment_validate(char* data,
	uint64_t length,
	bool *validates,
	uint64_t* validates_to,
	uint32_t needleidx,
	uint16_t* frontOffset,
	uint16_t* rearOffset,
	bool* isHeader,
	bool* isTail,
	uint64_t* secondToLastFramePosition,
	uint64_t* lastFramePosition,
	uint64_t* offsetFramePosition,
	bool* maybe
);

static inline uint32_t mp3_fragment_validate_from(char *data,
	uint64_t length,
	bool *validates,
	uint64_t *validates_to,
	uint32_t needleidx,
	uint16_t *frontOffset,
	uint16_t *rearOffset,
	bool *isHeader,
	bool *isTail,
	uint64_t *secondToLastFramePosition,
	uint64_t *lastFramePosition,
	uint64_t *offsetFramePosition,
	bool *maybe,
	uint64_t search_start);

static inline void mp3_file_validate(char *data,
	uint64_t length,
	bool *validates,
	uint64_t *validates_to,
	bool *promising,
	uint32_t needleidx,
	uint32_t blocksize,
	void *carvehashkey);

static inline char *mp3_header_discovery(char *data,
	uint64_t offset,
	uint64_t length,
	char **matchpos,
	uint32_t *matchlen,
	uint32_t blocksize);

static inline unsigned int readBits(Bitstream *bs, int n);
static inline void skipBits(Bitstream *bs, int n);
static inline void rewindBits(Bitstream *bs, int n);

static void crc16(uint16_t *crc, unsigned char m);
static bool check_crc(Bitstream *bs, uint8_t protectedBytes);
static void mp3_audio_crc16_init_table(void);
static uint16_t mp3_audio_crc16_update(uint16_t crc,
	const unsigned char *data,
	uint64_t length);
static uint16_t mp3_audio_crc16(const unsigned char *data, uint64_t length);
static uint16_t mp3_audio_crc16_matrix_apply(const uint16_t *matrix,
	uint16_t value);
static void mp3_audio_crc16_init_zero_powers(void);
static uint16_t mp3_audio_crc16_advance_zeros(uint16_t crc,
	uint64_t length);
static void mp3_checksum_build_crc_transform(const unsigned char *data,
	uint64_t length,
	Mp3ChecksumCrcTransform *transform);
static uint16_t mp3_checksum_apply_crc_transform(
	const Mp3ChecksumCrcTransform *transform,
	uint16_t crc);
static bool mp3_get_xing_checksum(const char *data,
	uint64_t length,
	Mp3XingChecksum *checksum);
static bool mp3_xing_checksum_matches(const char *data,
	uint64_t length,
	const Mp3XingChecksum *checksum);
static bool mp3_frame_has_independent_start(const char *data,
	uint64_t length,
	const FrameArgs *args);

static inline uint32_t bitRateIndexer(uint8_t mpegVersion,
	uint8_t layer,
	unsigned int bitrateVal);

static inline bool frameByteLengthCalc(uint8_t mpegVersion,
	uint8_t layer,
	uint32_t bitrate,
	uint16_t samplerate,
	uint8_t padding,
	uint16_t *frameLengthInBytes);

static bool areBytesNULL(char* data, uint64_t bytesToCheck);

static int get_pcm_byte_count(int mpeg_version, int layer, int channels);

static bool mp3_getpeaks_resize_for_channels(int mpeg_version, int layer, int channels,
	int *pcm_byte_num, unsigned char **pcm_bytes,
	int *N, int *fft_N, float **time, float **freq, void **pfft_m_plan);

static void mp3_detect_peaks_for_channel(unsigned char *pcm_bytes, int channels, int channel_index,
	int fft_N, float *time, float *freq, void *pfft_m_plan, Peak peaks_out[]);

static bool getPeaks(char *file_buf, int len, Peak peaksL[], Peak peaksR[], bool *is_stereo);
static int comparePeaks(const void *a, const void *b);
static int filter(const struct dirent *name);
static double getScore(const Peak *peaks1, const Peak *peaks2);
static double mp3_score_index_only(const Peak *peaks1, const Peak *peaks2);
static double mp3_score_thesis(const Peak *peaks1, const Peak *peaks2);
static double mp3_stereo_score(const Peak *peaksL1, const Peak *peaksR1,
	bool isStereo1, const Peak *peaksL2, const Peak *peaksR2,
	bool isStereo2);

static bool getFrameData(Bitstream *bs,
	uint8_t *mpegVersion,
	uint8_t *layer,
	bool *crc,
	uint32_t *bitrate,
	uint16_t *samplerate,
	uint8_t *padding,
	enum _ChannelMode *channel);

static bool mp3_parse_complete_frame_at(const char *data,
	uint64_t length,
	uint64_t offset,
	FrameArgs *args,
	uint16_t *frame_length);

static void mp3_skip_leading_zero_prefix(Bitstream *bs);

static bool mp3_zero_prefixed_frame_header(const char *data,
	uint64_t length,
	uint64_t *frame_offset,
	FrameArgs *args);

static bool mp3_frame_stream_parameters_match(const FrameArgs *left,
	const FrameArgs *right);

static bool mp3_has_compatible_frame_chain(const char *data,
	uint64_t length,
	uint64_t offset,
	uint32_t minimum_frames);

static bool mp3_find_frame_chain_start(const char *data,
	uint64_t length,
	uint64_t first,
	uint64_t end,
	uint64_t *frame_offset);

static bool mp3_complete_compatible_frame_prefix(const char *data,
	uint64_t length);

static bool mp3_is_interior_frame_start(const char *data,
	uint64_t length,
	uint64_t offset,
	const FrameArgs *current);

static bool mp3_find_terminal_id3v1(const char *data,
	uint64_t length,
	uint64_t search_start,
	uint64_t search_end,
	bool require_zero_tail,
	uint64_t *tag_offset,
	uint64_t *tag_end);

static bool mp3_id3v2_header_size(const uint8_t *data,
	uint64_t length,
	uint32_t *size);

static uint32_t mp3_tag_u32(const uint8_t *data);

static int mp3_ape_tag_extent(const char *data, uint64_t length,
	uint64_t start, bool leading, uint64_t *end);

static bool mp3_skip_leading_tags(Bitstream *bs);

static bool skipID3v1(Bitstream *bs);
static bool skipID3v2(Bitstream *bs);

static inline bool mp3_serialize_block_state(void **state, FILE *fp,
											StateSerialization mode);
static inline void *mp3_clone_block_state(const void *srcstate);
static inline void mp3_free_block_state(void **state);
static inline bool mp3_compare_block_state(const void *state1, const void *state2);
static inline void mp3_print_block_state(const void *state);

static inline bool mp3_serialize_carve_state(void **state, FILE *fp,
	StateSerialization mode);
static inline bool mp3_states_equal(Mp3CarveState *a, Mp3CarveState *b);
static inline void *mp3_clone_carve_state(const void *srcstate);
static inline void mp3_free_carve_state(void **state);
static inline bool mp3_compare_carve_state(const void *state1, const void *state2);
static inline void mp3_print_carve_state(const void *state);
static uint64_t mp3_fragment_search_signature(const Mp3CarveState *state,
	uint32_t blocksize);
static uint64_t mp3_greedy_search_signature(const Mp3CarveState *state,
	uint32_t blocksize);
static bool mp3_greedy_search_resume(Mp3CarveState *state, uint32_t blocksize);
static void mp3_greedy_search_begin(Mp3CarveState *state, uint32_t blocksize,
	uint32_t phase);
static void mp3_greedy_search_io(Mp3GreedySearch *search, uint16_t count,
	FILE *fp, StateSerialization mode);
static bool mp3_greedy_search_equal(const Mp3GreedySearch *a,
	const Mp3GreedySearch *b);
static void mp3_checksum_state_allocate(Mp3ChecksumState *state);
static void mp3_checksum_state_free(Mp3ChecksumState *state);
static void mp3_checksum_state_clone(Mp3ChecksumState *target,
	const Mp3ChecksumState *source);
static bool mp3_checksum_states_equal(const Mp3ChecksumState *left,
	const Mp3ChecksumState *right);
static void mp3_checksum_state_io(Mp3ChecksumState *state, FILE *fp,
	StateSerialization mode);

static Mp3Fragment *init_fragments(int num_fragments);
static Mp3Fragment *add_fragment(Mp3Fragment *old_fragments, int old_count, uint16_t *capacity);
static Mp3Fragment *remove_fragment(Mp3Fragment *old_fragments, int old_count, int frag_index);
static FrameArgs get_frame_args(void);
static ValidationArgs get_validation_args(void);

static bool mp3_reassembly_init_candidate(int id,
	CarveInfo *candidate,
	uuid_string_t uuidp,
	uuid_string_t uuidc,
	Mp3CarveState **state);

static void mp3_reassembly_refresh_frag_data(BlockVector *b_read,
	Mp3Fragment *frag);

static void mp3_reassembly_normalize_fragment(Mp3Fragment *fragment,
	uint32_t blocksize);

static bool mp3_reassembly_frame_stream(BlockVector *b,
	const Mp3Fragment *fragment,
	uint32_t blocksize,
	Bitstream *stream);

static bool mp3_reassembly_boundary_peaks(BlockVector *b,
	uint64_t offset,
	Peak left[],
	Peak right[],
	bool *stereo);

static bool mp3_reassembly_trim_seed_candidate(BlockVector *b);

static bool mp3_reassembly_rebuild_seed_candidate(CarveInfo *candidate,
	const Mp3Fragment *fragment);

static bool mp3_reassembly_check_fragment(BlockVector *b_read,
	Mp3CarveState *carve_state,
	Mp3Fragment *frag,
	int frag_index);

static bool mp3_reassembly_check_fragments(BlockVector *b_read,
	Mp3CarveState *carve_state);

static void mp3_rebuild_committed_blockvector(CarveInfo *candidate, Mp3CarveState *carve_state);

static bool mp3_write_hypothesis(CarveInfo *candidate,
	BlockVector *trial,
	uint64_t length);

static void mp3_extend_terminal_footer_extent(BlockVector *b,
	uint32_t blocksize);

static bool mp3_reassembly_complete_terminal_frame(CarveInfo *candidate,
	uint32_t blocksize,
	ValidationArgs *validation);

static bool mp3_preserve_single_fragment_tail(CarveInfo *candidate,
	uint32_t blocksize);

static uint64_t mp3_build_terminal_zero_padding_hypothesis(
	BlockVector *source,
	uint64_t prefix_length,
	uint32_t blocksize,
	BlockVector **trial);

static bool mp3_preserve_terminal_zero_padding_hypothesis(
	CarveInfo *candidate,
	BlockVector *source,
	uint64_t prefix_length,
	uint32_t blocksize);

static Mp3StructuralSearchResult mp3_reassembly_preserve_direct_paths(
	ThreadWork *work,
	CarveInfo *candidate,
	Mp3CarveState *carve_state,
	uint32_t blocksize,
	uuid_string_t uuidp,
	uuid_string_t uuidc);

static Mp3StructuralSearchResult mp3_reassembly_preserve_structural_paths(
	ThreadWork *work,
	CarveInfo *candidate,
	Mp3CarveState *carve_state,
	uint32_t blocksize,
	uuid_string_t uuidp,
	uuid_string_t uuidc);

static Mp3ChecksumSearchResult mp3_reassembly_find_checksum_path(
	ThreadWork *work,
	CarveInfo *candidate,
	Mp3CarveState *carve_state,
	uint32_t blocksize,
	uuid_string_t uuidp,
	uuid_string_t uuidc);

static int mp3_checksum_fragment_order_compare(const void *left,
	const void *right);

static bool mp3_build_seam_signature(const unsigned char *pcm,
	size_t bytes,
	int channels,
	Mp3SeamSignature *signature);

static double mp3_seam_signature_cost(const Mp3SeamSignature *left,
	const Mp3SeamSignature *right);

static bool mp3_checksum_path_seam_score(const char *data,
	uint64_t length,
	const Mp3CarveState *carve_state,
	const uint16_t *path,
	uint16_t depth,
	uint32_t blocksize,
	double *score);

static double mp3_checksum_path_score(const char *data,
	uint64_t length,
	const Mp3CarveState *carve_state,
	const uint16_t *path,
	uint16_t depth,
	uint32_t blocksize);

static bool mp3_reassembly_score_extension(CarveInfo *candidate,
	const Mp3CarveState *carve_state,
	uint16_t fragment_index,
	uint32_t blocksize,
	double *score);

static Mp3FragmentDiscoveryResult mp3_reassembly_generate_fragments(
	ThreadWork *work,
	BlockVector *b,
	BlockVector *b_read,
	CarveInfo *candidate,
	Mp3CarveState *carve_state,
	uint32_t *blocksize,
	uuid_string_t uuidp,
	uuid_string_t uuidc);

static bool mp3_fragment_measure_range(BlockVector *b_read,
	int64_t first_actual,
	int64_t last_actual,
	uint32_t blocksize,
	uint64_t maximum_length,
	uint64_t search_start,
	Mp3Fragment *fragment,
	bool *validates,
	bool *maybe);

static void mp3_fragment_measure_peaks(BlockVector *b_read,
	Mp3Fragment *fragment,
	uint32_t blocksize);

static Mp3FragmentDiscoveryResult mp3_fragment_catalog_get(
	ThreadWork *work,
	CarveInfo *candidate,
	Mp3CarveState *carve_state,
	BlockVector *b_read,
	uint32_t blocksize,
	uuid_string_t uuidp,
	uuid_string_t uuidc,
	const Mp3Fragment **fragments,
	uint16_t *count);

static Mp3FragmentDiscoveryResult mp3_fragment_catalog_import(
	ThreadWork *work,
	CarveInfo *candidate,
	Mp3CarveState *carve_state,
	BlockVector *b_read,
	uint32_t blocksize,
	const Mp3Fragment *fragments,
	uint16_t count,
	uuid_string_t uuidp,
	uuid_string_t uuidc);

static void mp3_fragment_refresh_header_context(Mp3Fragment *fragment);
static bool mp3_reassembly_fragment_boundaries_match(
	const Mp3Fragment *left, const Mp3Fragment *right);

static void mp3_custom_reassembly(ThreadWork *work,
	CarveInfo **c,
	uuid_string_t uuidp,
	uuid_string_t uuidc);

static void print_validation_args(ValidationArgs va);

/******* FUNCTION DEFINITIONS *******/

void print_validation_args(ValidationArgs va){
	lock_fprintf(stdout, "validates = %s\npromising = %s\nvalidates_to = %"PRIu64
	"\nfrontOffset = %"PRIu16"\nrearOffset = %"PRIu16
	"\nisHeader = %s\nisTail = %s\nsecondToLastFramePosition = %"PRIu64
	"\nlastFramePosition = %"PRIu64"\noffsetFramePosition = %"PRIu64
	"\nmaybe = %s\n",
	va.validates ? "TRUE" : "FALSE",
	va.promising ? "TRUE" : "FALSE",
	va.validates_to,
	va.frontOffset,
	va.rearOffset,
	va.isHeader ? "TRUE" : "FALSE",
	va.isTail ? "TRUE" : "FALSE",
	va.secondToLastFramePosition,
	va.lastFramePosition,
	va.offsetFramePosition,
	va.maybe ? "TRUE" : "FALSE"
	);
}

// Bitstream functions:
// invariant: bs->bytePos never exceeds bs->length--once the stream is exhausted, readBits stops
// dereferencing bs->data and returns 0 bits instead, and skipBits simply stops advancing.
unsigned int readBits(Bitstream *bs, int n) {
    unsigned int value = 0;
    for(int i = 0; i < n; i++){
        int bit = 0;
        if(bs->bytePos < bs->length){
            bit = (bs->data[bs->bytePos] >> (7 - bs->bitPos)) & 1;
            bs->bitPos++;
            if(bs->bitPos == 8){
                bs->bitPos = 0;
                bs->bytePos++;
            }
        }
        else{
            bs->truncated = true;
        }
        value = (value << 1) | bit;
    }
    return value;
}

void skipBits(Bitstream *bs, int n){
	//unlike readBits, skipBits never dereferences bs->data--it's pure position bookkeeping--so it's
	//safe (and, for callers like rearOffset that measure how far a skip overshoots length, required)
	//to let bytePos advance past length here. It still flags truncated so EOF checks elsewhere stay correct.
	for(int i = 0; i < n; i++){
		if(bs->bytePos >= bs->length){
			bs->truncated = true;
		}
		bs->bitPos++;
		if(bs->bitPos == 8){
			bs->bitPos = 0;
			bs->bytePos++;
		}
	}
}

void rewindBits(Bitstream *bs, int n){
	for(int i = 0; i < n; i++){
		//already at the very start of the stream--rewinding further would underflow bytePos
		if(bs->bytePos == 0 && bs->bitPos == 0){
			break;
		}
		bs->bitPos = bs->bitPos - 1;
		if(bs->bitPos == -1){
			bs->bitPos = 7;
			bs->bytePos = bs->bytePos - 1;
		}
	}
}

//CRC related functions:
void crc16(uint16_t *crc, unsigned char m)
//for a byte array whose accumulated crc value is stored in *crc, computes
//resultant crc obtained by appending m to the byte array
{
	pthread_once(&crc16_table_once, crc16_init_table);
	*crc = crc16_table[(((*crc) >> 8) ^ m) & 0xFF] ^ (((*crc) << 8) & 0xFFFF);
}

bool check_crc(Bitstream *bs, uint8_t protectedBytes){
	//when called, the pointer will be at the crc checksum, right after the frame header
	//take this into account. bytePos-2 and bytePos-1 (the frame header's last two bytes) must be
	//valid, and so must bytePos..bytePos+1+protectedBytes (the crc field plus protected bytes)
	if(bs->bytePos < 2 || bs->bytePos + 2 + (uint64_t)protectedBytes > bs->length) return false;
	uint16_t crc_origin = (uint16_t)((unsigned char)bs->data[bs->bytePos] << 8 | (unsigned char)bs->data[bs->bytePos+1]);
	uint16_t crc_computed;

	unsigned char input[protectedBytes + 2];
	input[0] = (unsigned char)bs->data[bs->bytePos - 2];
	input[1] = (unsigned char)bs->data[bs->bytePos - 1];
	for(int i = 0; i < protectedBytes; i++){
		input[i+2] = (unsigned char)bs->data[bs->bytePos+2+i];
	}
	crc_computed = CRC16_INIT;
	for(int i = 0; i < protectedBytes+2; i++){
		crc16(&crc_computed, input[i]);
	}
	if(crc_origin == crc_computed){
		return true;
	}
	return false;
}

//Frame reading functions:
//Gets bitrate from table
uint32_t bitRateIndexer(uint8_t mpegVersion, uint8_t layer, unsigned int bitrateVal) {
	uint8_t index = (bitrateVal - 1) * 5;
	if (mpegVersion == 1) {
		switch (layer) {
			case 1:
				return bitrate_table[index];
			case 2:
				return bitrate_table[index + 1];
			case 3:
				return bitrate_table[index + 2];
			default:
				return 0;
		}
	}
	else if (mpegVersion >= 2) {
		if (layer == 1) {
			return bitrate_table[index + 3];
		}
		else if (layer == 2 || layer == 3) {
			return bitrate_table[index + 4];
		}
		else { //valid file should never reach this point
			return 0;
		}
	}
	else { // so no warning
		return 0;
	}
}

bool frameByteLengthCalc(uint8_t mpegVersion, uint8_t layer,
	uint32_t bitrate, uint16_t samplingrate, uint8_t padding,
	uint16_t *frameLengthInBytes){
	if (samplingrate == 0 || ! frameLengthInBytes) {
		return false;
	}
	// Frame Byte Length Calculation
	bitrate = bitrate * 1000;
	if (layer == 1) {
		*frameLengthInBytes = (12 * bitrate / samplingrate + padding) * 4;
	}
	else if (layer == 2 || (layer == 3 && mpegVersion == 1)) {
		*frameLengthInBytes = 144 * bitrate / samplingrate + padding;
	}
	else if (layer == 3 && (mpegVersion == 2 || mpegVersion == 3)) {
		*frameLengthInBytes = 72 * bitrate / samplingrate + padding;
	}
	else{
		return false;
	}
	return true;
}

bool areBytesNULL(char* data, uint64_t bytesToCheck){
	for(uint64_t i = 0; i < bytesToCheck; i++){
		if(data[i] != 0x00){
			return false;
		}
	}
	return true;
}

// function used to determine how much memory should be allocated to account for output PCM data
// assumes 16-bit samples
// samples-per-frame depends on mpeg_version and layer
int get_pcm_byte_count(int mpeg_version, int layer, int channels){
    int samples_per_frame = 0;
    if(mpeg_version == 1){
        if(layer == 1){
            samples_per_frame = 384;
        } else if(layer == 2 || layer == 3){
            samples_per_frame = 1152;
        } else{
            return -1;
        }
    } else if(mpeg_version == 2 || mpeg_version == 3){
        if(layer == 1){
            samples_per_frame = 384;
        } else if(layer == 2){
            samples_per_frame = 1152;
        } else if(layer == 3){
            samples_per_frame = 576;
        } else{
            return -1;
        }
    } else{
        return -1;
    }
    int bytes_per_sample = 2; //Assuming 16-bit samples
    return samples_per_frame * channels * bytes_per_sample;
}

// function used in getting peaks from coefficients
int comparePeaks (const void *a, const void *b){
    const Peak *p1 = (const Peak *)a;
    const Peak *p2 = (const Peak *)b;
    return (p2->val > p1->val) - (p2->val < p1->val);
}

// (Re)computes pcm_byte_num/N/fft_N for 'channels' and resizes pcm_bytes/time/freq/pfft_m_plan
// to match, reusing existing allocations via realloc. 
// Must be called every time mpg123 reports MPG123_NEW_FORMAT and updates 'channels'
// Returns false (nothing to clean up beyond what the caller already owns) on any 
// allocation/init failure.
static bool mp3_getpeaks_resize_for_channels(int mpeg_version, int layer, int channels,
	int *pcm_byte_num, unsigned char **pcm_bytes,
	int *N, int *fft_N, float **time, float **freq, void **pfft_m_plan){

	unsigned char *new_pcm_bytes;
	float *new_time, *new_freq;
	int old_fft_N = *fft_N;
	int new_pcm_byte_num, new_N, new_fft_N;

	new_pcm_byte_num = get_pcm_byte_count(mpeg_version, layer, channels);
	if(new_pcm_byte_num == -1){
		return false;
	}
	new_N = new_pcm_byte_num / sizeof(short);
	new_fft_N = (channels == 2) ? (new_N / 2) : new_N;

	// If the transform size (and therefore buffer sizing) hasn't actually changed, there's
	// nothing to reallocate or reinitialize
	// Avoids needlessly tearing down and rebuilding the MDCT plan (expensive) every time 
	// this is called mid-decode even when the format change didn't actually alter the sample counts.
	if(new_fft_N == old_fft_N && *pcm_byte_num == new_pcm_byte_num &&
		*pcm_bytes != NULL && *time != NULL && *freq != NULL && *pfft_m_plan != NULL){
		return true;
	}

	*pcm_byte_num = new_pcm_byte_num;
	new_pcm_bytes = realloc(*pcm_bytes, (*pcm_byte_num) * sizeof(unsigned char));
	if(new_pcm_bytes == NULL){
		perror("Failed to allocate memory\n");
		return false;
	}
	*pcm_bytes = new_pcm_bytes;

	*N = new_N;
	*fft_N = new_fft_N;

	new_time = (float*)realloc(*time, sizeof(float) * (*fft_N));
	if(new_time == NULL){
		perror("Failed to allocate memory\n");
		return false;
	}
	*time = new_time;

	new_freq = (float*)realloc(*freq, sizeof(float) * (*fft_N >> 1));
	if(new_freq == NULL){
		perror("Failed to allocate memory\n");
		return false;
	}
	*freq = new_freq;

	if(*pfft_m_plan != NULL){
		pfft_mdctf_free(*pfft_m_plan);
	}
	*pfft_m_plan = pfft_mdctf_init(*fft_N);
	if(*pfft_m_plan == NULL){
		return false;
	}

	return true;
}

// Extracts one channel (channel_index: 0 = left/mono, 1 = right) from pcm_bytes
// Each channel is a real, uncorrupted mono signal in its own right
// Callers combine both channels' scores (see mp3_stereo_score()) rather than favoring one 
// over the other.
static void mp3_detect_peaks_for_channel(unsigned char *pcm_bytes, int channels, int channel_index,
	int fft_N, float *time, float *freq, void *pfft_m_plan, Peak peaks_out[]){

	uint16_t size = 6;

	// peaks_out[size-1] (index 5) is used below as the insertion/scratch slot for the
	// top-5 selection, not just the first 5 "real" output slots -- it must be zeroed too,
	// or the very first candidate peak gets compared against whatever garbage the caller's
	// stack array happened to hold there.
	for(int i = 0; i < size; i++){
		peaks_out[i].val = 0;
		peaks_out[i].index = -1;
	}

	if(channels == 2){
		for(int i = 0; i < fft_N; i++){
			time[i] = ((short *)pcm_bytes)[2*i + channel_index] / 32768.0;
		}
	}
	else{
		for(int i = 0; i < fft_N; i++){
			time[i] = ((short *)pcm_bytes)[i] / 32768.0;
		}
	}

	pfft_mdctf(freq, time, pfft_m_plan);

	for(int i = 0; i < (fft_N >> 1); i++){
		freq[i] = fabs(freq[i]);
	}

	for(int i = 0; i < (fft_N >> 1); i++){
		//if peak detected, compare to other peaks, if bigger then add
		if(i >= EDGE_GUARD_BINS && i < (fft_N/2) - EDGE_GUARD_BINS){
			if(freq[i-1] < freq[i] && freq[i+1] < freq[i] && freq[i] > peaks_out[size-1].val){
				peaks_out[size-1] = (Peak){freq[i],i};
				qsort(peaks_out, size, sizeof(Peak), comparePeaks);
			}
		}
	}
}

// Uses MPG123 decoder with PocketFFT library, works for layers 1-3, however layer 3 is suboptimal
// *file_buf - IMPORTANT: MUST point to beginning of frame BEFORE the frame you want to read
//      - Why is it like this? To account for the bit reservoir.
//      - If a frame uses a bit reservoir, by reading the first frame, it will fail but the data will be loaded into the decoder.
//      - The second read will be able to use that data, and this method was found to be better than doing any manual alterations
//      - to the decoder library.
// len - length of file (or data being read?)
// peaksL[]/peaksR[] - where each channel's peaks are stored, currently MUST have 6 elements
//      each. peaksL always holds the sole channel's peaks (mono) or the left channel's peaks
//      (stereo). peaksR is only populated, and only meaningful, when *is_stereo is true.
// is_stereo - set to true if the source was stereo (so peaksR is valid), false otherwise

// Involves a two step process:
// STEP 1: decode the frame BEFORE the one we actually want (file_buf points to it).
// Since we start feeding mpg123 mid-stream, it has none of the true bit-reservoir
// history for this frame, so its Huffman data can come out wrong and mpg123_read()
// is EXPECTED to often return an error here - that is not fatal. mpg123 still
// advances its internal bitstream position while parsing this frame, which is what
// lets STEP 2 below decode the frame we actually want using the correct reservoir
// bits. Its output and result code are therefore discarded, aside from handling a
// format change so the buffers/plan stay correctly sized for STEP 2.

bool getPeaks(char *file_buf, int len, Peak peaksL[], Peak peaksR[], bool *is_stereo){
    mpg123_handle *mh;
    int mpeg_version, channels, encoding, pcm_byte_num, err = 0;
    int feed_result, N, fft_N, read_result;
    unsigned char *pcm_bytes;
    long rate;
    size_t done;
	float* time;
	float* freq;
    bool output = false;
	void* pfft_m_plan;
	FrameArgs fa = get_frame_args();
	Bitstream bs = {file_buf, 0, 0, len, false};

	// Reuse this thread's scoring workspace (buffers + MDCT plan) across calls instead of
	// allocating/tearing it down every time -- see Mp3PeakWorkspace. Falls back to a
	// call-scoped workspace (freed at 'finish' below) if the TLS key couldn't be created.
	Mp3PeakWorkspace *ws = mp3_peak_workspace();
	if(ws){
		pcm_bytes = ws->pcm_bytes;
		time = ws->time;
		freq = ws->freq;
		pfft_m_plan = ws->pfft_m_plan;
		pcm_byte_num = ws->pcm_byte_num;
		fft_N = ws->fft_N;
	}
	else{
		pcm_bytes = NULL;
		time = NULL;
		freq = NULL;
		pfft_m_plan = NULL;
		pcm_byte_num = 0;
		fft_N = 0;
	}

	*is_stereo = false;
	for(int i = 0; i < 6; i++){
		peaksL[i].val = 0;
		peaksL[i].index = -1;
		peaksR[i].val = 0;
		peaksR[i].index = -1;
	}

	#ifdef DEBUG_FREQUENCY_ANALYSIS
		printf("getPeaks:");
	#endif

	//Not super important since the decoder will update the format if it detects a mismatch
	//However, lets us allocate memory for PCM data properly.
	if(!getFrameData(&bs, &fa.mpegVersion, &fa.layer, &fa.crc,
		&fa.bitrate, &fa.samplingrate, &fa.padding, &fa.channel)){
		return false;
	}
	mpeg_version = fa.mpegVersion;

    //INITIALIZATION
    //Creates a handle with an optional choice of decoder and an optional retrieval of
    //an error code to feed to mpg123_plain_strerror().
    mp3_ensure_init();
	mh = mp3_thread_handle();
    if(mh == NULL){
        fprintf(stderr,"Failed to create mpg123 handle: %s\n",mpg123_plain_strerror(err));
        return false;
    }
	if(fa.channel == singleChannel){
		channels = 1;
	}
	else{
		channels = 2;
	}
	// mh is a per-thread handle reused across every fragment comparison and every candidate
	// this thread processes (see mp3_thread_handle()). The allowed-format table set by
	// mpg123_format()/_none()/_all() is handle-lifetime state, NOT reset by
	// mpg123_close()/open_feed() -- per mpg123.h's own docs, it only takes effect on mpg123's
	// next *natural* format change, so it must be reset on every call regardless of what a
	// previous call on this thread left behind.
	//
	// This used to restrict the allowed format to exactly (fa.samplingrate, mpg123_channel)
	// computed from the *first* ("STEP 1", throwaway) frame's header below -- but getPeaks()
	// is specifically called across candidate fragment boundaries, including wrong/rejected
	// candidates, where STEP 1's frame and STEP 2's frame (the one whose peaks we actually
	// want) can legitimately belong to two different files with two different native rates.
	// When that happens, mpg123 correctly detects the real format change mid-decode
	// (MPG123_NEW_FORMAT, already handled below by re-fetching the format and resizing
	// buffers) but can't satisfy it against a table restricted to STEP 1's rate, producing
	// "Unable to set up output format" and failing the whole comparison -- for exactly the
	// boundaries most useful to evaluate. mpg123_format_all() removes the restriction and
	// lets mpg123 decode using whatever format it actually detects; the code below already
	// adapts to that via mpg123_getformat() + buffer reallocation on MPG123_NEW_FORMAT.
	mpg123_format_all(mh);
    mpg123_open_feed(mh);
    //Feeds data for a stream opened with mpg123_open_feed()
    //We provide the bytestream, mpg123 gives the decoded samples.
	#ifdef DEBUG_FREQUENCY_ANALYSIS
		printf("Trying to feed data\n");
	#endif
    feed_result = mpg123_feed(mh, (unsigned char *)file_buf, len);
    if(feed_result != MPG123_OK){
        #ifdef DEBUG_FREQUENCY_ANALYSIS
			fprintf(stderr,"Failed to feed data: %s\n",mpg123_plain_strerror(feed_result));
		#endif
		mpg123_close(mh);
        return false;
    }
    #ifdef DEBUG_FREQUENCY_ANALYSIS
		printf("Data fed successfully\n");
	#endif

    //Memory allocation for decoder output. pcm_bytes/time/freq/pfft_m_plan may already be
	//sized correctly from this thread's reused workspace (see Mp3PeakWorkspace above) --
	//mp3_getpeaks_resize_for_channels() only reallocates/reinitializes what actually needs
	//to change for this frame's (mpeg_version, layer, channels). From here on, any failure
	//must go through 'finish' (not an early return) so the workspace -- which may already
	//own these pointers -- is always left holding whatever they currently are, never a
	//stale pointer from before a realloc moved the block.
    #ifdef DEBUG_FREQUENCY_ANALYSIS
		printf("Allocating memory for pcm data\n");
	#endif
	if(!mp3_getpeaks_resize_for_channels(fa.mpegVersion, fa.layer, channels, &pcm_byte_num, &pcm_bytes,
		&N, &fft_N, &time, &freq, &pfft_m_plan)){
		perror("Failed to allocate memory for pcm/fft data\n");
		goto finish;
	}
    #ifdef DEBUG_FREQUENCY_ANALYSIS
		printf("Allocating memory for pcm data success\n");
	#endif
    done = 0;
	// N is the raw interleaved sample count (both channels, if stereo). Each channel is
	// analyzed as its own independent signal (see mp3_detect_peaks_for_channel() below), so
	// the FFT/MDCT size is the number of samples *per channel*: half of N if stereo (one
	// channel's worth of a stereo pair), or N itself if the source is already mono.

    read_result = mpg123_read(mh,pcm_bytes,pcm_byte_num,&done);
    if(read_result == MPG123_NEW_FORMAT){
        //Format isn't what the decoder expected, very likely this will happen
		//Since the data has been read, we can update the format.
		//Memory allocated to store the PCM data will still be consistent.
        mpg123_getformat(mh,&rate,&channels,&encoding);
        #ifdef DEBUG_FREQUENCY_ANALYSIS
			printf("New format for first frame detected: rate=%ld Hz, channels=%d, encoding=%d\n",rate,channels,encoding);
		#endif
		// channels just changed -- resize everything to match now, not just after a
		// possible second format change in STEP 2 below. Without this, a format change
		// seen only here left every buffer sized for the old channel count while the
		// per-channel peak extraction later reads pcm_bytes using the new one.
		if(!mp3_getpeaks_resize_for_channels(mpeg_version, fa.layer, channels, &pcm_byte_num, &pcm_bytes,
			&N, &fft_N, &time, &freq, &pfft_m_plan)){
			goto finish;
		}
    	// Flush frame 1's queued samples now that the buffers match its format. The
        // result is still discarded - this only keeps frame alignment intact for STEP 2.
        read_result = mpg123_read(mh,pcm_bytes,pcm_byte_num,&done);
    }
	if(read_result != MPG123_OK){
		#ifdef DEBUG_FREQUENCY_ANALYSIS
			fprintf(stderr, "Error decoding first frame: %s\n", mpg123_plain_strerror(read_result));
		#endif
		goto finish;
	}
	// STEP 2: decode the frame we actually want. This is the read whose output we use.
	read_result = mpg123_read(mh,pcm_bytes,pcm_byte_num,&done);
	if(read_result == MPG123_NEW_FORMAT){
		//Means MP3 file is VBR, which is a huge hassle
		mpg123_getformat(mh,&rate,&channels,&encoding);
		#ifdef DEBUG_FREQUENCY_ANALYSIS
			lock_fprintf(stdout, "New format for second frame detected: rate=%ld Hz, channels=%d, encoding=%d\n",rate,channels,encoding);
		#endif
		if(!mp3_getpeaks_resize_for_channels(mpeg_version, fa.layer, channels, &pcm_byte_num, &pcm_bytes,
			&N, &fft_N, &time, &freq, &pfft_m_plan)){
			goto finish;
		}
		read_result = mpg123_read(mh,pcm_bytes,pcm_byte_num,&done);
	}
	if(read_result == MPG123_OK){
		#ifdef DEBUG_FREQUENCY_ANALYSIS
			lock_fprintf(stdout, "Decoded %zu bytes of audio data\n",done);
        	lock_fprintf(stdout, "-------------------------------\n");
		#endif

		// mpg123_read() can legitimately decode fewer bytes than pcm_byte_num (the buffer/
		// fft_N are sized for the theoretical max samples-per-frame; actual output can come in
		// smaller). fft_N is fixed by the MDCT plan set up via pfft_mdctf_init(fft_N) above, so
		// rather than reinitializing the plan to match 'done' on every call, pad whatever
		// mpg123 didn't fill with silence -- otherwise mp3_detect_peaks_for_channel() would
		// read stale/uninitialized bytes from the tail of pcm_bytes as if they were real
		// samples, corrupting the peaks with garbage energy.
		if((size_t)pcm_byte_num > done){
			memset(pcm_bytes + done, 0, (size_t)pcm_byte_num - done);
		}

		/*
		for(int i = 0; i < pcm_byte_num; i++){
			printf("%x ",pcm_bytes[i]);
			if(i%16==15){
				printf("\n");
			}
		}
		*/

		//pcm_bytes holds interleaved L/R samples if stereo (LRLRLR...). Each channel is
		//analyzed independently (see mp3_detect_peaks_for_channel())
		mp3_detect_peaks_for_channel(pcm_bytes, channels, 0, fft_N, time, freq, pfft_m_plan, peaksL);
		if(channels == 2){
			mp3_detect_peaks_for_channel(pcm_bytes, channels, 1, fft_N, time, freq, pfft_m_plan, peaksR);
			*is_stereo = true;
		}

		#ifdef DEBUG_FREQUENCY_ANALYSIS
			lock_fprintf(stdout, "PocketFFT MDCT peaks (left/mono channel):\n");
			for(size_t i = 0; i < 5; i++){
				lock_fprintf(stdout, "Value: %.2f, Index: %d\n",peaksL[i].val,peaksL[i].index);
			}
			if(*is_stereo){
				lock_fprintf(stdout, "PocketFFT MDCT peaks (right channel):\n");
				for(size_t i = 0; i < 5; i++){
					lock_fprintf(stdout, "Value: %.2f, Index: %d\n",peaksR[i].val,peaksR[i].index);
				}
			}
			lock_fprintf(stdout, "\n");
			printf("---------------------------------\n");
		#endif

		output = true;
	}
	else{
		#ifdef DEBUG_FREQUENCY_ANALYSIS
			fprintf(stderr, "Error decoding second frame: %s\n",
				mpg123_plain_strerror(read_result));
		#endif
		goto finish;
	}

    finish:
	if(ws){
		// Hand the (possibly resized) buffers and plan back to this thread's reusable
		// workspace instead of tearing them down -- see Mp3PeakWorkspace above. This runs
		// on every exit through 'finish' (success or failure), so ws never ends up holding
		// a stale pointer to a block a realloc() above already moved or freed.
		ws->pcm_bytes = pcm_bytes;
		ws->time = time;
		ws->freq = freq;
		ws->pfft_m_plan = pfft_m_plan;
		ws->pcm_byte_num = pcm_byte_num;
		ws->fft_N = fft_N;
	}
	else{
		// No reusable workspace (TLS key creation failed) -- fall back to the previous
		// allocate-and-free-every-call behavior.
		if(pfft_m_plan != NULL) pfft_mdctf_free(pfft_m_plan);
		free(freq);
		free(time);
		free(pcm_bytes);
	}
	mpg123_close(mh);
    return output;
}

int filter(const struct dirent *name){
	return 1;
}

// Feature and similarity measure follow Steinebach, Yannikos, Zmudzinski & Winter (2015),
// Handbook of Digital Forensics of Multimedia Data and Devices, pp.234-235: the feature is
// the *set of indices* of the N=5 highest MDCT coefficients, and similarity is the count of
// indices that coincide (or nearly coincide, within TOLERANCE) between the two frames' peak
// sets -- the coefficient values themselves are deliberately not part of the comparison.
double mp3_score_index_only(const Peak *peaks1, const Peak *peaks2){
	int pairI[25], pairJ[25], pairDiff[25];
	int numPairs = 0;

	for(int i = 0; i < 5; i++){
		if(peaks1[i].index == -1) continue;
		for(int j = 0; j < 5; j++){
			if(peaks2[j].index == -1) continue;
			int indexDiff = abs(peaks1[i].index - peaks2[j].index);
			if(indexDiff <= TOLERANCE){
				pairI[numPairs] = i;
				pairJ[numPairs] = j;
				pairDiff[numPairs] = indexDiff;
				numPairs++;
			}
		}
	}

	//greedily assign the closest-index pairs first so each peaks2 index backs at most one
	//peaks1 index (insertion sort ascending by index difference--numPairs is at most 25)
	for(int a = 1; a < numPairs; a++){
		int ki = pairI[a], kj = pairJ[a], kd = pairDiff[a];
		int b = a - 1;
		while(b >= 0 && pairDiff[b] > kd){
			pairI[b+1] = pairI[b];
			pairJ[b+1] = pairJ[b];
			pairDiff[b+1] = pairDiff[b];
			b--;
		}
		pairI[b+1] = ki;
		pairJ[b+1] = kj;
		pairDiff[b+1] = kd;
	}

	bool usedI[5] = {false, false, false, false, false};
	bool usedJ[5] = {false, false, false, false, false};
	int matchedCount = 0;
	for(int p = 0; p < numPairs; p++){
		int i = pairI[p], j = pairJ[p];
		if(!usedI[i] && !usedJ[j]){
			usedI[i] = true;
			usedJ[j] = true;
			matchedCount++;
		}
	}

	return (double)matchedCount;
}

// Thesis exponential weights, adapted to maximum-weight one-to-one matching.
// Unlike the PDF's independent maxima, neither side can reuse a peak. Missing
// or unmatched peaks contribute zero and the divisor stays 5.
// Peak magnitudes are used as extracted: no additional normalization or ranking.
double mp3_score_thesis(const Peak *peaks1, const Peak *peaks2){
	// Each mask records which of the five peaks in the second set are used.
	// Retaining a state also permits leaving the current first-set peak unmatched.
	double totals[32];
	for(int mask = 0; mask < 32; mask++){
		totals[mask] = -1.0;
	}
	totals[0] = 0.0;
	for(int i = 0; i < 5; i++){
		if(peaks1[i].index < 0 || !isfinite(peaks1[i].val)){
			continue;
		}
		double scores[5] = {0};
		for(int j = 0; j < 5; j++){
			if(peaks2[j].index < 0 || !isfinite(peaks2[j].val)){
				continue;
			}
			const double index_difference = fabs((double)peaks1[i].index
				- (double)peaks2[j].index);
			if(index_difference > MP3_SCORE_THESIS_TOLERANCE){
				continue;
			}
			const double value_similarity = exp(-MP3_SCORE_THESIS_ALPHA
				* fabs(peaks1[i].val - peaks2[j].val));
			const double index_similarity = exp(-MP3_SCORE_THESIS_BETA
				* index_difference);
			scores[j] = value_similarity * index_similarity;
		}
		// Descending masks prevent a state created for this peak from being
		// extended again in the same iteration, so the first set cannot reuse it.
		for(int mask = 31; mask >= 0; mask--){
			if(totals[mask] < 0.0){
				continue;
			}
			for(int j = 0; j < 5; j++){
				const int bit = 1 << j;
				if((mask & bit) != 0 || scores[j] <= 0.0){
					continue;
				}
				const double score = totals[mask] + scores[j];
				if(score > totals[mask | bit]){
					totals[mask | bit] = score;
				}
			}
		}
	}
	double best = 0.0;
	for(int mask = 0; mask < 32; mask++){
		if(totals[mask] > best){
			best = totals[mask];
		}
	}
	return best / 5.0;
}

// Higher is better in both modes. Preserve each equation's native range:
// index-only returns 0..5; the thesis equation returns 0..1.
double getScore(const Peak *peaks1, const Peak *peaks2){
	if(MP3_SCORE_MODE == MP3_SCORE_MODE_THESIS){
		return mp3_score_thesis(peaks1, peaks2);
	}
	return mp3_score_index_only(peaks1, peaks2);
}

// Combines two candidates' peak comparisons across both stereo channels. If both sides are
// stereo, each channel is a real, independent signal, so L-vs-L and R-vs-R are both genuine
// evidence -- averaging them uses both without letting either dominate. If either side isn't
// stereo (mono, or a mismatch between two candidates decoded under different channel
// counts), there's no second channel to compare, so this falls back to a single comparison
// using peaksL1/peaksL2 (which hold the sole channel's peaks when mono).
double mp3_stereo_score(const Peak *peaksL1, const Peak *peaksR1,
	bool isStereo1, const Peak *peaksL2, const Peak *peaksR2,
	bool isStereo2){

	if(isStereo1 && isStereo2){
		return (getScore(peaksL1, peaksL2) + getScore(peaksR1, peaksR2)) / 2.0;
	}

	return getScore(peaksL1, peaksL2);
}

// Function that should return all frame data from a frame header
// If provided data that isn't a frame header, it should reset bitstream
// to original position.
bool getFrameData(Bitstream *bs, uint8_t *mpegVersion, uint8_t *layer, bool *crc,
	uint32_t *bitrate, uint16_t *samplerate, uint8_t *padding,
	enum _ChannelMode *channel) {
		uint8_t bitsRead = 0;
		unsigned int bits = readBits(bs,11);
		bitsRead += 11;
		if (bits == 2047){
			#ifdef DEBUG_GET_FRAME_DATA
				printf("Possibly valid frame\n");
			#endif

			//Read MPEG version bits
			bits = readBits(bs,2);
			bitsRead += 2;
			switch(bits){
				case 0: //MPEG version 2.5
					*mpegVersion = 3;
					break;
				case 1: //Invalid
					#ifdef DEBUG_GET_FRAME_DATA
						printf("Invalid mpegVersion\n");
					#endif
					rewindBits(bs, bitsRead);
					return false;
				case 2: //MPEG version 2
					*mpegVersion = 2;
					break;
				case 3: //MPEG version 1
					*mpegVersion = 1;
					break;
				default: //Invalid
					#ifdef DEBUG_GET_FRAME_DATA
						printf("Invalid mpegVersion\n");
					#endif
					rewindBits(bs, bitsRead);
					return false;
			}

			//Read layer
			bits = readBits(bs,2);
			bitsRead += 2;
			switch(bits){
				case 0: //Invalid
					#ifdef DEBUG_GET_FRAME_DATA
						printf("Invalid layer\n");
					#endif
					rewindBits(bs, bitsRead);
					return false;
				case 1: //Layer III
					*layer = 3;
					break;
				case 2: //Layer II
					*layer = 2;
					break;
				case 3: //Layer I
					*layer = 1;
					break;
				default: //Invalid
					#ifdef DEBUG_GET_FRAME_DATA
						printf("Invalid layer\n");
					#endif
					rewindBits(bs, bitsRead);
					return false;
			}

			//Read CRC
			bits = readBits(bs,1);
			bitsRead += 1;
			if(bits == 0) *crc = true;
			else *crc = false;
			#ifdef DEBUG_GET_FRAME_DATA
				if(*crc) printf("CRC is present and will be skipped\n");
				else printf("CRC is not present and will not be skipped\n");
			#endif

			//Read bitrate
			bits = readBits(bs,4);
			bitsRead += 4;
			switch(bits){
				case 0:
					#ifdef DEBUG_GET_FRAME_DATA
						printf("Bitrate unknown\n");
					#endif
					rewindBits(bs, bitsRead);
					return false;
				case 15:
					#ifdef DEBUG_GET_FRAME_DATA
						printf("Bitrate unknown\n");
					#endif
					rewindBits(bs, bitsRead);
					return false;
				default:
					*bitrate = bitRateIndexer(*mpegVersion, *layer, bits);
					break;
			}

			//Read sample rate
			bits = readBits(bs,2);
			bitsRead += 2;
			switch(bits){
				case 0:
					switch(*mpegVersion){
						case 1: *samplerate = 44100; break;
						case 2: *samplerate = 22050; break;
						case 3: *samplerate = 11025; break;
						default: //Invalid
							#ifdef DEBUG_GET_FRAME_DATA
								printf("Sample rate unknown\n");
							#endif
							rewindBits(bs, bitsRead);
							return false;
					}
					break;
				case 1:
					switch(*mpegVersion){
						case 1: *samplerate = 48000; break;
						case 2: *samplerate = 24000; break;
						case 3: *samplerate = 12000; break;
						default: //Invalid
							#ifdef DEBUG_GET_FRAME_DATA
								printf("Sample rate unknown\n");
							#endif
							rewindBits(bs, bitsRead);
							return false;
					}
					break;
				case 2:
					switch(*mpegVersion){
						case 1: *samplerate = 32000; break;
						case 2: *samplerate = 16000; break;
						case 3: *samplerate = 8000; break;
						default: //Invalid
							#ifdef DEBUG_GET_FRAME_DATA
								printf("Sample rate unknown\n");
							#endif
							rewindBits(bs, bitsRead);
							return false;
					}
					break;
				default: //If bits are 3
					#ifdef DEBUG_GET_FRAME_DATA
						printf("Sample rate unknown\n");
					#endif
					rewindBits(bs, bitsRead);
					return false;
			}

			//Read padding bit
			bits = readBits(bs,1);
			bitsRead += 1;
			if(bits == 1){
				if(*layer==1) *padding = 4;
				else *padding = 1;
			}
			else *padding = 0;

			//Skip private bit
			skipBits(bs,1);
			bitsRead += 1;

			//Read channel mode
			bits = readBits(bs,2);
			bitsRead += 2;
			switch(bits){
				case 0:
					*channel = stereo;
					break;
				case 1:
					*channel = jointStereo;
					break;
				case 2:
					*channel = dualChannel;
					break;
				case 3:
					*channel = singleChannel;
					break;
				default:
					#ifdef DEBUG_GET_FRAME_DATA
						printf("Channel mode unknown\n");
					#endif
					rewindBits(bs, bitsRead);
					return false;
			}

			//Skip rest of header
			//Things being skipped: mode extension, copyright, original/home, emphasis
			skipBits(bs,6);
			bitsRead += 6;

			#ifdef DEBUG_GET_FRAME_DATA
				printf("Yep, header seems legit.\n");
			#endif
			return true;
		}
		#ifdef DEBUG_GET_FRAME_DATA
			printf("Invalid frame detected\n");
		#endif
		rewindBits(bs, bitsRead);
		return false;
}

static bool mp3_parse_complete_frame_at(const char *data,
	uint64_t length,
	uint64_t offset,
	FrameArgs *args,
	uint16_t *frame_length) {

	if (! data || ! args || ! frame_length || offset > length
		|| length - offset < FRAME_HEADER_SIZE) {
		return false;
	}

	Bitstream bs = {(char *)data, 0, offset, length, false};
	*args = get_frame_args();
	if (! getFrameData(&bs, &args->mpegVersion, &args->layer, &args->crc,
		&args->bitrate, &args->samplingrate, &args->padding, &args->channel)
		|| bs.truncated
		|| ! frameByteLengthCalc(args->mpegVersion, args->layer, args->bitrate,
			args->samplingrate, args->padding, frame_length)
		|| *frame_length < FRAME_HEADER_SIZE
		|| *frame_length > length - offset) {
		return false;
	}

	return true;
}

// Parse only the four-byte MPEG header at offset. A frame header can be
// wholly present at the end of a physical run while its payload continues in
// a different physical run; the catalog must retain that overrun as a join
// offset instead of treating the run as ending cleanly.
static bool mp3_parse_frame_header_at(const char *data,
	uint64_t length,
	uint64_t offset,
	FrameArgs *args,
	uint16_t *frame_length) {
	if (!data || !args || !frame_length || offset > length
		|| length - offset < FRAME_HEADER_SIZE) {
		return false;
	}
	Bitstream bs = {(char *)data, 0, offset, length, false};
	*args = get_frame_args();
	if (!getFrameData(&bs, &args->mpegVersion, &args->layer, &args->crc,
		&args->bitrate, &args->samplingrate, &args->padding, &args->channel)
		|| !frameByteLengthCalc(args->mpegVersion, args->layer, args->bitrate,
			args->samplingrate, args->padding, frame_length)
		|| *frame_length < FRAME_HEADER_SIZE) {
		return false;
	}
	return true;
}


// A frame header may straddle a physical fragment boundary.  Preserve that
// evidence separately from ordinary byte offsets: k means k header bytes are
// present at the rear/front boundary and the complementary bytes are in the
// adjoining fragment.
static bool mp3_frame_length_is_possible(uint8_t mpegVersion,
	uint8_t layer, uint16_t samplingrate, uint64_t expected_length){
	for(unsigned int bitrate_index = 1; bitrate_index <= 14; bitrate_index++){
		uint32_t bitrate = bitRateIndexer(mpegVersion, layer, bitrate_index);
		for(uint8_t padding = 0; padding <= 1; padding++){
			uint16_t frame_length = 0;
			if(bitrate > 0 && frameByteLengthCalc(mpegVersion, layer, bitrate,
				samplingrate, padding, &frame_length)
				&& frame_length == expected_length){
				return true;
			}
		}
	}
	return false;
}

static uint8_t mp3_version_layer_byte(uint8_t mpegVersion, uint8_t layer){
	// Set only the three sync bits before inserting the version and layer.
	// 0xf8 would force version 11 (MPEG-1), even for MPEG-2 and MPEG-2.5.
	// Leave protection at zero; rear comparisons mask it off. The sampling
	// rate is in byte three, retained from the fragment and checked against
	// the frame chain by mp3_complete_header_matches().
	uint8_t version_bits;
	if(mpegVersion == 1){
		version_bits = 3;
	}
	else if(mpegVersion == 2){
		version_bits = 2;
	}
	else if(mpegVersion == 3){
		version_bits = 0;
	}
	else{
		return 0;
	}
	if(layer == 3){
		return (uint8_t)(0xe0 | (version_bits << 3) | 2);
	}
	if(layer == 2){
		return (uint8_t)(0xe0 | (version_bits << 3) | 4);
	}
	if(layer == 1){
		return (uint8_t)(0xe0 | (version_bits << 3) | 6);
	}
	return 0;
}

static bool mp3_complete_header_matches(char header[FRAME_HEADER_SIZE],
	uint8_t expected_mpeg_version, uint8_t expected_layer,
	uint16_t expected_samplingrate, uint64_t expected_frame_length){
	Bitstream header_stream = {header, 0, 0, FRAME_HEADER_SIZE, false};
	uint8_t mpegVersion = 0, layer = 0, padding = 0;
	bool crc = false;
	uint32_t bitrate = 0;
	uint16_t samplingrate = 0, frame_length = 0;
	enum _ChannelMode channel = stereo;
	return getFrameData(&header_stream, &mpegVersion, &layer, &crc, &bitrate,
		&samplingrate, &padding, &channel)
		&& mpegVersion == expected_mpeg_version
		&& layer == expected_layer
		&& samplingrate == expected_samplingrate
		&& frameByteLengthCalc(mpegVersion, layer, bitrate, samplingrate,
			padding, &frame_length)
		&& frame_length == expected_frame_length;
}

static uint8_t mp3_detect_front_frame_header_break(const char *data,
	uint64_t length, uint64_t first_frame_position, uint8_t mpegVersion,
	uint8_t layer, uint16_t samplingrate, bool isHeader){
	if(isHeader || first_frame_position == 0 || length == 0){
		return 0;
	}
	char header[FRAME_HEADER_SIZE];
	if(length >= 3){
		header[0] = (char)0xff;
		memcpy(&header[1], data, 3);
		if(mp3_complete_header_matches(header, mpegVersion, layer, samplingrate,
			first_frame_position + 1)){
			return 1;
		}
	}
	uint8_t version_layer = mp3_version_layer_byte(mpegVersion, layer);
	if(length >= 2 && version_layer != 0){
		header[0] = (char)0xff;
		header[1] = (char)version_layer;
		header[2] = data[0];
		header[3] = data[1];
		if(mp3_complete_header_matches(header, mpegVersion, layer, samplingrate,
			first_frame_position + 2)){
			return 2;
		}
	}
	if(mp3_frame_length_is_possible(mpegVersion, layer, samplingrate,
		first_frame_position + 3)){
		return 3;
	}
	return 0;
}

static uint8_t mp3_detect_rear_frame_header_break(const char *data,
	uint64_t length, uint64_t next_frame_position, uint8_t mpegVersion,
	uint8_t layer, uint16_t samplingrate){
	if(next_frame_position >= length){
		return 0;
	}
	uint64_t available = length - next_frame_position;
	if(available < 1 || available > 3){
		return 0;
	}
	const unsigned char *partial = (const unsigned char *)data + next_frame_position;
	if(partial[0] != 0xff){
		return 0;
	}
	if(available >= 2){
		uint8_t expected = mp3_version_layer_byte(mpegVersion, layer);
		if(expected == 0 || (partial[1] & 0xfe) != (expected & 0xfe)){
			return 0;
		}
	}
	if(available == 3){
		char header[FRAME_HEADER_SIZE] = {
			(char)partial[0], (char)partial[1], (char)partial[2], 0};
		Bitstream header_stream = {header, 0, 0, FRAME_HEADER_SIZE, false};
		uint8_t parsed_version = 0, parsed_layer = 0, padding = 0;
		bool crc = false;
		uint32_t bitrate = 0;
		uint16_t parsed_rate = 0;
		enum _ChannelMode channel = stereo;
		if(!getFrameData(&header_stream, &parsed_version, &parsed_layer, &crc,
			&bitrate, &parsed_rate, &padding, &channel)
			|| parsed_version != mpegVersion || parsed_layer != layer
			|| parsed_rate != samplingrate){
			return 0;
		}
	}
	return (uint8_t)available;
}

static void mp3_update_frame_header_breaks(const char *data, uint64_t length,
	uint16_t frontOffset, uint64_t firstFramePosition,
	uint64_t lastFramePosition, uint16_t lastFrameLength,
	uint8_t mpegVersion, uint8_t layer, uint16_t samplingrate,
	bool isHeader, uint8_t *frontBreak, uint8_t *rearBreak){
	*frontBreak = mp3_detect_front_frame_header_break(data, length,
		firstFramePosition, mpegVersion, layer, samplingrate, isHeader);
	uint64_t next_frame = lastFramePosition;
	if(lastFrameLength > 0 && next_frame <= UINT64_MAX - lastFrameLength){
		next_frame += lastFrameLength;
	}
	*rearBreak = mp3_detect_rear_frame_header_break(data, length, next_frame,
		mpegVersion, layer, samplingrate);
	(void)frontOffset;
}

// Front breaks are hypotheses, never a restriction on ordinary offset joins.
// For a rear split, use the real bytes from both sides instead of trusting the
// front detector's first (possibly ambiguous) hypothesis. This also tests the
// three-byte split's bitrate/rate bits, which are absent from its front half.
static bool mp3_reassembly_fragment_boundaries_match(
	const Mp3Fragment *left, const Mp3Fragment *right){
	if(left == NULL || right == NULL){
		return false;
	}
	Mp3Fragment left_refreshed;
	Mp3Fragment right_refreshed;
	// Older checkpoints did not store this evidence. Recover it lazily once
	// the image is available, without discarding their candidate progress.
	if(!left->headerContextKnown){
		left_refreshed = *left;
		mp3_fragment_refresh_header_context(&left_refreshed);
		left = &left_refreshed;
	}
	if(!right->headerContextKnown){
		right_refreshed = *right;
		mp3_fragment_refresh_header_context(&right_refreshed);
		right = &right_refreshed;
	}
	const uint8_t split = left->rearFrameHeaderBreak;
	if(split == 0){
		return right->frontOffset == left->rearOffset;
	}
	const Mp3HeaderBreakContext *rear = &left->rearHeaderContext;
	const Mp3HeaderBreakContext *front = &right->frontHeaderContext;
	if(split > 3 || !left->headerContextKnown || !right->headerContextKnown
		|| right->isHeader || right->frontOffset == 0
		|| rear->mpegVersion == 0 || rear->layer == 0 || rear->samplingrate == 0
		|| rear->mpegVersion != front->mpegVersion
		|| rear->layer != front->layer || rear->samplingrate != front->samplingrate){
		return false;
	}
	char header[FRAME_HEADER_SIZE];
	memcpy(header, rear->bytes, split);
	memcpy(header + split, front->bytes, FRAME_HEADER_SIZE - split);
	return mp3_complete_header_matches(header, front->mpegVersion,
		front->layer, front->samplingrate, (uint64_t)right->frontOffset + split);
}

// Cache boundary evidence from the original physical run, not from a guessed
// successor. Each end is tied to its own observed frame-chain parameters.
static void mp3_fragment_refresh_header_context(Mp3Fragment *fragment){
	memset(&fragment->frontHeaderContext, 0, sizeof(fragment->frontHeaderContext));
	memset(&fragment->rearHeaderContext, 0, sizeof(fragment->rearHeaderContext));
	fragment->headerContextKnown = false;
	const uint64_t blocksize = scalpel_state.blocksize;
	if(scalpel_state.filemirror == NULL || blocksize == 0
		|| fragment->firstActBlock < 0 || fragment->size == 0
		|| (uint64_t)fragment->firstActBlock > UINT64_MAX / blocksize
		|| fragment->size > UINT64_MAX / blocksize){
		return;
	}
	const uint64_t base = (uint64_t)fragment->firstActBlock * blocksize;
	const uint64_t image_length = filemirror_filesize(scalpel_state.filemirror);
	if(base >= image_length){
		return;
	}
	uint64_t length = fragment->size * blocksize;
	if(length > image_length - base){
		length = image_length - base;
	}
	uint64_t first_block_length = 0;
	const char *data = filemirror_actual_block_data_pointer(
		scalpel_state.filemirror, fragment->firstActBlock, &first_block_length);
	if(data == NULL || first_block_length == 0 || length < FRAME_HEADER_SIZE){
		return;
	}
	fragment->headerContextKnown = true;
	FrameArgs args;
	uint16_t frame_length = 0;
	if(mp3_parse_frame_header_at(data, length, fragment->frontOffset,
		&args, &frame_length)){
		fragment->frontHeaderContext.mpegVersion = args.mpegVersion;
		fragment->frontHeaderContext.layer = args.layer;
		fragment->frontHeaderContext.samplingrate = args.samplingrate;
		memcpy(fragment->frontHeaderContext.bytes, data, 3);
		fragment->frontFrameHeaderBreak = mp3_detect_front_frame_header_break(
			data, length, fragment->frontOffset, args.mpegVersion,
			args.layer, args.samplingrate, fragment->isHeader);
	}
	uint64_t last_frame = fragment->offsetFramePosition;
	if(!mp3_parse_frame_header_at(data, length, last_frame, &args, &frame_length)){
		last_frame = fragment->lastFramePosition;
		if(!mp3_parse_frame_header_at(data, length, last_frame, &args, &frame_length)){
			return;
		}
	}
	fragment->rearHeaderContext.mpegVersion = args.mpegVersion;
	fragment->rearHeaderContext.layer = args.layer;
	fragment->rearHeaderContext.samplingrate = args.samplingrate;
	if(last_frame <= UINT64_MAX - frame_length){
		const uint64_t next_frame = last_frame + frame_length;
		fragment->rearFrameHeaderBreak = mp3_detect_rear_frame_header_break(
			data, length, next_frame, args.mpegVersion, args.layer, args.samplingrate);
		if(fragment->rearFrameHeaderBreak != 0){
			memcpy(fragment->rearHeaderContext.bytes, data + next_frame,
				fragment->rearFrameHeaderBreak);
		}
	}
}

static void mp3_skip_leading_zero_prefix(Bitstream *bs) {

	if (! bs || bs->bitPos != 0 || bs->bytePos > bs->length) {
		return;
	}

	uint64_t start = bs->bytePos;
	while (bs->bytePos < bs->length
		&& bs->bytePos - start < MP3_HEADER_PREDECESSOR_SCAN_BYTES
		&& (unsigned char)bs->data[bs->bytePos] == 0) {
		bs->bytePos++;
	}
}

static bool mp3_zero_prefixed_frame_header(const char *data,
	uint64_t length,
	uint64_t *frame_offset,
	FrameArgs *args) {

	if (! data || ! frame_offset || ! args) {
		return false;
	}

	uint64_t position = 0;
	while (position < length
		&& position < MP3_HEADER_PREDECESSOR_SCAN_BYTES
		&& (unsigned char)data[position] == 0) {
		position++;
	}
	if (position == 0 || position > length
		|| length - position < FRAME_HEADER_SIZE) {
		return false;
	}

	Bitstream bs = {(char *)data, 0, position, length, false};
	*args = get_frame_args();
	if (! getFrameData(&bs, &args->mpegVersion, &args->layer, &args->crc,
		&args->bitrate, &args->samplingrate, &args->padding, &args->channel)
		|| bs.truncated) {
		return false;
	}

	uint16_t frame_length;
	if (! frameByteLengthCalc(args->mpegVersion, args->layer, args->bitrate,
		args->samplingrate, args->padding, &frame_length)
		|| frame_length < FRAME_HEADER_SIZE) {
		return false;
	}

	*frame_offset = position;
	return true;
}

static bool mp3_frame_stream_parameters_match(const FrameArgs *left,
	const FrameArgs *right) {

	return left->mpegVersion == right->mpegVersion
		&& left->layer == right->layer
		&& left->samplingrate == right->samplingrate;
}

static bool mp3_has_compatible_frame_chain(const char *data,
	uint64_t length,
	uint64_t offset,
	uint32_t minimum_frames) {

	FrameArgs first_args;
	uint64_t position = offset;
	for (uint32_t frame = 0; frame < minimum_frames; frame++) {
		FrameArgs args;
		uint16_t frame_length;
		if (! mp3_parse_complete_frame_at(data, length, position,
			&args, &frame_length)) {
			return false;
		}
		if (frame == 0) {
			first_args = args;
		}
		else if (! mp3_frame_stream_parameters_match(&first_args, &args)) {
			return false;
		}
		position += frame_length;
	}

	return true;
}

static bool mp3_complete_compatible_frame_prefix(const char *data,
	uint64_t length) {

	if (!data || length < FRAME_HEADER_SIZE) {
		return false;
	}

	Bitstream tags = {(char *)data, 0, 0, length, false};
	(void)mp3_skip_leading_tags(&tags);
	uint64_t position = tags.bytePos;
	uint32_t id3_size;
	while (position < length
		&& position < MP3_HEADER_PREDECESSOR_SCAN_BYTES
		&& (uint8_t)data[position] == 0) {
		position++;
	}
	if (position < length && position < scalpel_state.blocksize) {
		FrameArgs args;
		uint16_t frame_length;
		if (!mp3_parse_complete_frame_at(data, length, position,
				&args, &frame_length)
			&& !mp3_id3v2_header_size((const uint8_t *)data, length,
				&id3_size)) {
			// A retained block may begin inside a missing MPEG frame. This
			// checks the following audio for PROMISING output, not completeness.
			(void)mp3_find_frame_chain_start(data, length, position + 1,
				scalpel_state.blocksize, &position);
		}
	}

	FrameArgs first_args = get_frame_args();
	bool have_first = false;
	uint32_t frame_count = 0;
	while (position < length) {
		uint64_t ape_end = 0;
		if (mp3_ape_tag_extent(data, length, position, false, &ape_end) == 1) {
			position = ape_end;
			continue;
		}
		if (length - position == 128
			&& memcmp(data + position, "TAG", 3) == 0) {
			position = length;
			break;
		}

		FrameArgs args;
		uint16_t frame_length;
		if (!mp3_parse_complete_frame_at(data, length, position,
			&args, &frame_length)) {
			return false;
		}
		if (!have_first) {
			first_args = args;
			have_first = true;
		}
		else if (!mp3_frame_stream_parameters_match(&first_args, &args)) {
			return false;
		}
		position += frame_length;
		frame_count++;
	}

	return position == length
		&& frame_count >= MP3_FILE_VALIDATION_MINIMUM_COMPATIBLE_FRAMES;
}

// Find a Layer III frame chain whose first frame lies in [first, end).
// The chain may extend beyond that interval, but never beyond available data.
static bool mp3_find_frame_chain_start(const char *data,
	uint64_t length,
	uint64_t first,
	uint64_t end,
	uint64_t *frame_offset) {

	if (data == NULL || frame_offset == NULL || length < FRAME_HEADER_SIZE
		|| first >= end || first > length - FRAME_HEADER_SIZE) {
		return false;
	}
	if (end > length - FRAME_HEADER_SIZE + 1) {
		end = length - FRAME_HEADER_SIZE + 1;
	}
	while (first < end) {
		const char *sync = memchr(data + first, 0xff, (size_t)(end - first));
		if (sync == NULL) {
			return false;
		}
		const uint64_t position = (uint64_t)(sync - data);
		FrameArgs args;
		uint16_t frame_length;
		if (((uint8_t)data[position + 1] & UINT8_C(0xe0)) == UINT8_C(0xe0)
			&& mp3_parse_complete_frame_at(data, length, position,
				&args, &frame_length)
			&& args.layer == 3
			&& mp3_has_compatible_frame_chain(data, length, position,
				MP3_FILE_VALIDATION_MINIMUM_COMPATIBLE_FRAMES)) {
			*frame_offset = position;
			return true;
		}
		first = position + 1;
	}
	return false;
}

static bool mp3_is_interior_frame_start(const char *data,
	uint64_t length,
	uint64_t offset,
	const FrameArgs *current) {

	if (! data || ! current || length < FRAME_HEADER_SIZE
		|| offset < 2 * FRAME_HEADER_SIZE
		|| offset > length - FRAME_HEADER_SIZE) {
		return false;
	}

	uint64_t first_scan = offset > MP3_HEADER_PREDECESSOR_SCAN_BYTES
		? offset - MP3_HEADER_PREDECESSOR_SCAN_BYTES : 0;
	for (uint64_t previous = first_scan; previous < offset; previous++) {
		if ((uint8_t)data[previous] != UINT8_C(0xff)
			|| ((uint8_t)data[previous + 1] & UINT8_C(0xe0)) != UINT8_C(0xe0)) {
			continue;
		}
		FrameArgs previous_args;
		uint16_t previous_length;
		if (! mp3_parse_complete_frame_at(data, length, previous,
			&previous_args, &previous_length)
			|| previous_length > offset - previous
			|| previous + previous_length != offset
			|| ! mp3_frame_stream_parameters_match(&previous_args, current)) {
			continue;
		}

		uint64_t second_scan = previous > MP3_HEADER_PREDECESSOR_SCAN_BYTES
			? previous - MP3_HEADER_PREDECESSOR_SCAN_BYTES : 0;
		for (uint64_t second = second_scan; second < previous; second++) {
			if ((uint8_t)data[second] != UINT8_C(0xff)
				|| ((uint8_t)data[second + 1] & UINT8_C(0xe0)) != UINT8_C(0xe0)) {
				continue;
			}
			FrameArgs second_args;
			uint16_t second_length;
			if (mp3_parse_complete_frame_at(data, length, second,
				&second_args, &second_length)
				&& second_length <= previous - second
				&& second + second_length == previous
				&& mp3_frame_stream_parameters_match(&second_args, current)) {
				return true;
			}
		}
	}

	return false;
}

static bool mp3_find_terminal_id3v1(const char *data,
	uint64_t length,
	uint64_t search_start,
	uint64_t search_end,
	bool require_zero_tail,
	uint64_t *tag_offset,
	uint64_t *tag_end) {

	if (data == NULL || tag_offset == NULL || tag_end == NULL
		|| search_start > length || search_end <= search_start
		|| length - search_start < ID3V1_TAG_SIZE) {
		return false;
	}
	uint64_t last_start = length - ID3V1_TAG_SIZE;
	if (search_end - 1 < last_start) {
		last_start = search_end - 1;
	}
	for (uint64_t position = search_start; position <= last_start;) {
		const char *match = memchr(data + position, 'T',
			(size_t)(last_start - position + 1));
		if (match == NULL) {
			return false;
		}
		position = (uint64_t)(match - data);
		const uint64_t end = position + ID3V1_TAG_SIZE;
		if (data[position + 1] == 'A' && data[position + 2] == 'G'
			&& (! require_zero_tail
				|| areBytesNULL((char *)data + end, length - end))) {
			*tag_offset = position;
			*tag_end = end;
			return true;
		}
		position++;
	}

	return false;
}

static uint32_t mp3_tag_u32(const uint8_t *data) {
	return (uint32_t)data[0] | ((uint32_t)data[1] << 8)
		| ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
}

// Parse APE items and cross-check their count and length against the tag footer
// or header. Return 1 for a complete tag, -1 for truncation, or 0 for no valid tag.
static int mp3_ape_tag_extent(const char *data, uint64_t length,
	uint64_t start, bool leading, uint64_t *end) {

	if (!data || !end || start >= length) {
		return 0;
	}
	const uint8_t *bytes = (const uint8_t *)data;
	uint64_t cursor = start;
	uint64_t item_start = start;
	uint64_t limit = length;
	uint32_t header_size = 0;
	uint32_t header_count = 0;
	uint32_t header_flags = 0;
	uint32_t header_version = 0;
	uint32_t items = 0;
	bool header = false;
	bool no_footer = false;
	if (length - cursor >= 8 && !memcmp(bytes + cursor, "APETAGEX", 8)) {
		if (length - cursor < 32) {
			return -1;
		}
		header_version = mp3_tag_u32(bytes + cursor + 8);
		header_size = mp3_tag_u32(bytes + cursor + 12);
		header_count = mp3_tag_u32(bytes + cursor + 16);
		header_flags = mp3_tag_u32(bytes + cursor + 20);
		if ((header_version != 1000 && header_version != 2000)
			|| (header_flags & UINT32_C(0x1ffffffe)) != 0
			|| memcmp(bytes + cursor + 24, "\0\0\0\0\0\0\0\0", 8)) {
			return 0;
		}
		header = (header_flags & UINT32_C(0x20000000)) != 0;
		if (header) {
			if (header_version != 2000
				|| !(header_flags & UINT32_C(0x80000000))) {
				return 0;
			}
			no_footer = (header_flags & UINT32_C(0x40000000)) != 0;
			if ((!no_footer && header_size < 32)
				|| header_count > (header_size - (no_footer ? 0 : 32)) / 11) {
				return 0;
			}
			cursor += 32;
			item_start = cursor;
			if (header_size > length - cursor) {
				return -1;
			}
			limit = cursor + header_size;
		} else if (leading) {
			return 0;
		}
	} else if (leading) {
		return 0;
	}
	for (;;) {
		if (header && no_footer && items == header_count) {
			if (cursor != limit) {
				return 0;
			}
			*end = cursor;
			return 1;
		}
		if (limit - cursor >= 8 && !memcmp(bytes + cursor, "APETAGEX", 8)) {
			if (limit - cursor < 32) {
				return -1;
			}
			uint32_t version = mp3_tag_u32(bytes + cursor + 8);
			uint32_t size = mp3_tag_u32(bytes + cursor + 12);
			uint32_t count = mp3_tag_u32(bytes + cursor + 16);
			uint32_t flags = mp3_tag_u32(bytes + cursor + 20);
			if ((version != 1000 && version != 2000)
				|| (flags & UINT32_C(0x7ffffffe)) != 0
				|| memcmp(bytes + cursor + 24, "\0\0\0\0\0\0\0\0", 8)
				|| count != items || (uint64_t)size != cursor - item_start + 32
				|| (header && (cursor + 32 != limit || version != header_version
					|| count != header_count || size != header_size
					|| flags != (header_flags & ~UINT32_C(0x20000000))))
				|| (!header && (flags & UINT32_C(0x80000000)))) {
				return 0;
			}
			*end = cursor + 32;
			return 1;
		}
		if ((header && items == header_count) || items == UINT32_MAX) {
			return 0;
		}
		if (limit - cursor < 8) {
			return header || items > 0 ? -1 : 0;
		}
		uint32_t value_length = mp3_tag_u32(bytes + cursor);
		uint32_t flags = mp3_tag_u32(bytes + cursor + 4);
		if ((flags & ~UINT32_C(7)) != 0 || (flags & 6) == 6) {
			return 0;
		}
		cursor += 8;
		uint64_t key = cursor;
		while (cursor < limit && bytes[cursor] >= 0x20 && bytes[cursor] <= 0x7e
			&& cursor - key < 255) {
			cursor++;
		}
		if (cursor == limit) {
			return -1;
		}
		if (cursor - key < 2 || bytes[cursor++] != 0) {
			return 0;
		}
		if (value_length > limit - cursor) {
			return -1;
		}
		cursor += value_length;
		items++;
	}
}

// Consume complete leading ID3/APE metadata before inspecting MPEG frames.
static bool mp3_skip_leading_tags(Bitstream *bs) {
	bool skipped = false;
	for (;;) {
		uint64_t end = 0;
		if (skipID3v2(bs)) {
			skipped = true;
		} else if (mp3_ape_tag_extent(bs->data, bs->length, bs->bytePos,
			true, &end) == 1) {
			bs->bytePos = end;
			bs->bitPos = 0;
			skipped = true;
		} else {
			return skipped;
		}
	}
}

// Function should detect if ID3v1 footer is present and skip it if detected
bool skipID3v1(Bitstream *bs){
	if (!bs || !bs->data || bs->bytePos > bs->length
		|| bs->length - bs->bytePos < ID3V1_TAG_SIZE) {
		return false;
	}
	uint8_t *bytes = (uint8_t *)bs->data + bs->bytePos;
	if(bytes[0] == 0x54 && bytes[1] == 0x41 && bytes[2] == 0x47){
		#ifdef DEBUG_ID3v2
			printf("ID3v1 Footer Detected\n");
		#endif
		#ifdef DEBUG_ID3v2
			printf("Skipping 128 bytes\n");
		#endif
		skipBits(bs, ID3V1_TAG_SIZE * 8);
		return true;
	}
	return false;
}

static bool mp3_id3v2_header_size(const uint8_t *data,
	uint64_t length,
	uint32_t *size) {

	if (! data || ! size || length < ID3V2_HEADER_SIZE) {
		return false;
	}
	if (data[0] != 0x49 || data[1] != 0x44 || data[2] != 0x33
		|| data[3] == 0xff || data[4] == 0xff || (data[5] & 0x3f) != 0
		|| data[6] >= 0x80 || data[7] >= 0x80
		|| data[8] >= 0x80 || data[9] >= 0x80) {
		return false;
	}

	*size = ((uint32_t)data[6] << 21)
		| ((uint32_t)data[7] << 14)
		| ((uint32_t)data[8] << 7)
		| (uint32_t)data[9];
	*size += ID3V2_HEADER_SIZE;
	if (data[3] == 4 && (data[5] & 0x10) != 0) {
		*size += ID3V2_HEADER_SIZE;
	}

	return true;
}

// Function detects if an ID3v2 header is present at bitstream position and skips it if complete.
bool skipID3v2(Bitstream *bs){
	uint32_t size;

	if (! bs || bs->bytePos > bs->length
		|| ! mp3_id3v2_header_size(
			(const uint8_t *)bs->data + bs->bytePos,
			bs->length - bs->bytePos, &size)
		|| size > bs->length - bs->bytePos) {
		return false;
	}

	#ifdef DEBUG_ID3v2
		printf("ID3v2 Header Detected\n");
		printf("Skipping %"PRIu32" bytes\n",size);
	#endif
	skipBits(bs, size*8);
	return true;
}

static void mp3_audio_crc16_init_table(void){
	for(uint16_t i = 0; i < 256; i++){
		uint16_t crc = i;
		for(int bit = 0; bit < 8; bit++){
			if((crc & 1) != 0){
				crc = (crc >> 1) ^ MP3_AUDIO_CRC16_POLY;
			}
			else{
				crc >>= 1;
			}
		}
		mp3_audio_crc16_table[i] = crc;
	}
}

static uint16_t mp3_audio_crc16_update(uint16_t crc,
	const unsigned char *data,
	uint64_t length){
	pthread_once(&mp3_audio_crc16_table_once, mp3_audio_crc16_init_table);
	for(uint64_t i = 0; i < length; i++){
		crc = mp3_audio_crc16_table[(crc ^ data[i]) & 0xff] ^ (crc >> 8);
	}
	return crc;
}

static uint16_t mp3_audio_crc16(const unsigned char *data, uint64_t length){
	return mp3_audio_crc16_update(0, data, length);
}

// Apply a zero-byte shift through its images of the sixteen CRC basis bits.
static uint16_t mp3_audio_crc16_matrix_apply(const uint16_t *matrix,
	uint16_t value){
	uint16_t result = 0;
	for(uint32_t bit = 0; value != 0; bit++, value >>= 1){
		if((value & 1) != 0){
			result ^= matrix[bit];
		}
	}
	return result;
}

// The operator at index p advances a CRC by 2^p zero bytes. Squaring the
// preceding operator builds the next one without scanning synthetic data.
static void mp3_audio_crc16_init_zero_powers(void){
	pthread_once(&mp3_audio_crc16_table_once, mp3_audio_crc16_init_table);
	for(uint32_t bit = 0; bit < 16; bit++){
		const uint16_t crc = (uint16_t)(1U << bit);
		mp3_audio_crc16_zero_powers[0][bit] =
			mp3_audio_crc16_table[crc & 0xff] ^ (crc >> 8);
	}
	for(uint32_t power = 1; power < 64; power++){
		for(uint32_t bit = 0; bit < 16; bit++){
			mp3_audio_crc16_zero_powers[power][bit] =
				mp3_audio_crc16_matrix_apply(mp3_audio_crc16_zero_powers[power - 1],
					mp3_audio_crc16_zero_powers[power - 1][bit]);
		}
	}
}

static uint16_t mp3_audio_crc16_advance_zeros(uint16_t crc,
	uint64_t length){
	pthread_once(&mp3_audio_crc16_zero_once, mp3_audio_crc16_init_zero_powers);
	for(uint32_t power = 0; length != 0; power++, length >>= 1){
		if((length & 1) != 0){
			crc = mp3_audio_crc16_matrix_apply(mp3_audio_crc16_zero_powers[power], crc);
		}
	}
	return crc;
}

static void mp3_checksum_build_crc_transform(const unsigned char *data,
	uint64_t length,
	Mp3ChecksumCrcTransform *transform){
	transform->zero_crc = mp3_audio_crc16(data, length);
	for(unsigned int bit = 0; bit < 16; bit++){
		transform->shifted_basis[bit] =
			mp3_audio_crc16_advance_zeros((uint16_t)(1U << bit), length);
	}
}

static uint16_t mp3_checksum_apply_crc_transform(
	const Mp3ChecksumCrcTransform *transform,
	uint16_t crc){
	return transform->zero_crc
		^ mp3_audio_crc16_matrix_apply(transform->shifted_basis, crc);
}

static bool mp3_get_xing_checksum(const char *data,
	uint64_t length,
	Mp3XingChecksum *checksum){
	Bitstream bs = {(char *)data, 0, 0, length, false};
	uint8_t mpeg_version = 0;
	uint8_t layer = 0;
	bool has_frame_crc = false;
	uint32_t bitrate = 0;
	uint16_t sampling_rate = 0;
	uint8_t padding = 0;
	enum _ChannelMode channel = singleChannel;
	uint16_t frame_length = 0;
	uint64_t first_frame_offset;
	uint64_t frame_end;
	uint64_t xing_offset;
	uint64_t extension_offset;
	uint64_t tag_crc_offset;
	uint32_t flags;
	uint32_t audio_size;
	uint16_t stored_tag_crc;
	unsigned char tag_data[MP3_XING_TAG_CRC_BYTES];

	memset(checksum, 0, sizeof(*checksum));
	if(data == NULL || length < FRAME_HEADER_SIZE){
		return false;
	}

	(void)mp3_skip_leading_tags(&bs);
	mp3_skip_leading_zero_prefix(&bs);
	first_frame_offset = bs.bytePos;
	if(!getFrameData(&bs, &mpeg_version, &layer, &has_frame_crc,
		&bitrate, &sampling_rate, &padding, &channel)
		|| layer != 3
		|| !frameByteLengthCalc(mpeg_version, layer, bitrate,
			sampling_rate, padding, &frame_length)
		|| first_frame_offset > UINT64_MAX - frame_length){
		return false;
	}

	frame_end = first_frame_offset + frame_length;
	if(frame_end > length
		|| first_frame_offset > UINT64_MAX - MP3_XING_TAG_CRC_BYTES
		|| first_frame_offset + MP3_XING_TAG_CRC_BYTES > frame_end){
		return false;
	}

	if(mpeg_version == 1){
		xing_offset = first_frame_offset + FRAME_HEADER_SIZE
			+ (has_frame_crc ? 2 : 0)
			+ (channel == singleChannel ? 17 : 32);
	}
	else{
		xing_offset = first_frame_offset + FRAME_HEADER_SIZE
			+ (has_frame_crc ? 2 : 0)
			+ (channel == singleChannel ? 9 : 17);
	}
	if(xing_offset > frame_end || frame_end - xing_offset < 8){
		return false;
	}
	if(memcmp(data + xing_offset, "Xing", 4) != 0
		&& memcmp(data + xing_offset, "Info", 4) != 0){
		return false;
	}

	flags = ((uint32_t)(unsigned char)data[xing_offset + 4] << 24)
		| ((uint32_t)(unsigned char)data[xing_offset + 5] << 16)
		| ((uint32_t)(unsigned char)data[xing_offset + 6] << 8)
		| (uint32_t)(unsigned char)data[xing_offset + 7];
	extension_offset = xing_offset + 8;
	if((flags & 0x1) != 0){
		extension_offset += 4;
	}
	if((flags & 0x2) != 0){
		extension_offset += 4;
	}
	if((flags & 0x4) != 0){
		extension_offset += 100;
	}
	if((flags & 0x8) != 0){
		extension_offset += 4;
	}
	if(extension_offset > frame_end || frame_end - extension_offset < 36){
		return false;
	}

	audio_size = ((uint32_t)(unsigned char)data[extension_offset + 28] << 24)
		| ((uint32_t)(unsigned char)data[extension_offset + 29] << 16)
		| ((uint32_t)(unsigned char)data[extension_offset + 30] << 8)
		| (uint32_t)(unsigned char)data[extension_offset + 31];
	if(audio_size < frame_length
		|| first_frame_offset > UINT64_MAX - audio_size){
		return false;
	}

	tag_crc_offset = extension_offset + 34;
	if(tag_crc_offset < first_frame_offset
		|| tag_crc_offset - first_frame_offset
			> MP3_XING_TAG_CRC_BYTES - 2){
		return false;
	}
	stored_tag_crc = ((uint16_t)(unsigned char)data[tag_crc_offset] << 8)
		| (uint16_t)(unsigned char)data[tag_crc_offset + 1];
	memcpy(tag_data, data + first_frame_offset, sizeof(tag_data));
	tag_data[tag_crc_offset - first_frame_offset] = 0;
	tag_data[tag_crc_offset - first_frame_offset + 1] = 0;
	if(mp3_audio_crc16(tag_data, sizeof(tag_data)) != stored_tag_crc){
		return false;
	}

	checksum->present = true;
	checksum->first_frame_offset = first_frame_offset;
	checksum->first_frame_length = frame_length;
	checksum->audio_end = first_frame_offset + audio_size;
	checksum->audio_crc = ((uint16_t)(unsigned char)data[extension_offset + 32] << 8)
		| (uint16_t)(unsigned char)data[extension_offset + 33];
	return true;
}

static bool mp3_xing_checksum_matches(const char *data,
	uint64_t length,
	const Mp3XingChecksum *checksum){
	uint64_t audio_start;

	if(!checksum->present){
		return true;
	}
	audio_start = checksum->first_frame_offset + checksum->first_frame_length;
	if(checksum->audio_end < audio_start || length < checksum->audio_end){
		return false;
	}
	return mp3_audio_crc16((const unsigned char *)data + audio_start,
		checksum->audio_end - audio_start) == checksum->audio_crc;
}

// Layer III main_data_begin refers to bytes in preceding audio frames, not
// tags or padding. A nonzero value in the first frame identifies an incomplete
// beginning even when the remaining stream has compatible frame syntax.
static bool mp3_frame_has_independent_start(const char *data,
	uint64_t length,
	const FrameArgs *args) {

	if (data == NULL || args == NULL) {
		return false;
	}
	if (args->layer != 3) {
		return true;
	}
	const uint64_t side_offset = FRAME_HEADER_SIZE + (args->crc ? 2 : 0);
	const uint64_t field_bytes = args->mpegVersion == 1 ? 2 : 1;
	if (length < side_offset + field_bytes) {
		return false;
	}
	const unsigned char *side = (const unsigned char *)data + side_offset;
	const uint16_t prior_bytes = args->mpegVersion == 1
		? ((uint16_t)side[0] << 1) | (side[1] >> 7) : side[0];
	return prior_bytes == 0;
}

// Block state records plausible MPEG fragments with too little audio for a
// conclusive local decoding check.

static inline bool mp3_serialize_block_state(void **state, FILE *fp,
											StateSerialization mode){
	Mp3BlockState **s = (Mp3BlockState **)state;
	size_t (*fb)(void *ptr, size_t size, size_t nitems, FILE *stream) =
		mode == SERIALIZE ?
		(size_t (*)(void *, size_t, size_t, FILE *))fwrite :
		(size_t (*)(void *, size_t, size_t, FILE *))fread;

		if(mode == DESERIALIZE){
			*s = (Mp3BlockState *)malloc(sizeof(Mp3BlockState));
			check_memory_allocation(*s, __LINE__, __FILE__, "Mp3BlockState");
		}

		if(fb(&((*s)->maybe), sizeof(bool), 1, fp) != 1){
			perror("mp3_serialize_block_state: value");
			handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
		}

		return true;
}
static inline void *mp3_clone_block_state(const void *srcstate){
	Mp3BlockState *s = (Mp3BlockState *)srcstate;
	Mp3BlockState *d = (Mp3BlockState*) malloc(sizeof(Mp3BlockState));
	check_memory_allocation(d, __LINE__, __FILE__, "Mp3BlockState clone");
	d->maybe = s->maybe;
	return d;
}
static inline void mp3_free_block_state(void **state){
	Mp3BlockState **s = (Mp3BlockState **)state;
	if(*s){
		free(*s);
		*s = NULL;
	}
}
static inline bool mp3_compare_block_state(const void *state1, const void *state2){
	const Mp3BlockState *s1 = (const Mp3BlockState *)state1;
	const Mp3BlockState *s2 = (const Mp3BlockState *)state2;
	return (s1->maybe == s2->maybe);
}
static inline void mp3_print_block_state(const void *state) {
	const Mp3BlockState *s = (const Mp3BlockState *)state;
	if(!s){
		fprintf(stdout, "NULL");
	} else{
		fprintf(stdout, "maybe: %s", s->maybe ? "true" : "false");
	}
}

//Carve state API functions:

// All arrays have an extra entry for the cursor beyond the deepest fragment.
static void mp3_checksum_state_allocate(Mp3ChecksumState *state){
	if(state->count == 0){
		return;
	}
#define MP3_SEARCH_ALLOCATE(field) \
	state->field = calloc((size_t)state->count + 1, sizeof(*state->field)); \
	check_memory_allocation(state->field, __LINE__, __FILE__, "MP3 " #field)
	MP3_SEARCH_ALLOCATE(path);
	MP3_SEARCH_ALLOCATE(best_path);
	MP3_SEARCH_ALLOCATE(next_choice);
	MP3_SEARCH_ALLOCATE(blocks_at_depth);
	MP3_SEARCH_ALLOCATE(crc_at_depth);
	MP3_SEARCH_ALLOCATE(transform_flags);
	MP3_SEARCH_ALLOCATE(full_transforms);
	MP3_SEARCH_ALLOCATE(tail_transforms);
#undef MP3_SEARCH_ALLOCATE
}

static void mp3_checksum_state_free(Mp3ChecksumState *state){
	free(state->path);
	free(state->best_path);
	free(state->next_choice);
	free(state->blocks_at_depth);
	free(state->crc_at_depth);
	free(state->transform_flags);
	free(state->full_transforms);
	free(state->tail_transforms);
	memset(state, 0, sizeof(*state));
}

static void mp3_checksum_state_clone(Mp3ChecksumState *target,
	const Mp3ChecksumState *source){
	*target = *source;
	mp3_checksum_state_allocate(target);
	if(source->count == 0){
		return;
	}
#define MP3_SEARCH_COPY(field) \
	memcpy(target->field, source->field, \
		((size_t)source->count + 1) * sizeof(*source->field))
	MP3_SEARCH_COPY(path);
	MP3_SEARCH_COPY(best_path);
	MP3_SEARCH_COPY(next_choice);
	MP3_SEARCH_COPY(blocks_at_depth);
	MP3_SEARCH_COPY(crc_at_depth);
	MP3_SEARCH_COPY(transform_flags);
	MP3_SEARCH_COPY(full_transforms);
	MP3_SEARCH_COPY(tail_transforms);
#undef MP3_SEARCH_COPY
}

static bool mp3_checksum_states_equal(const Mp3ChecksumState *left,
	const Mp3ChecksumState *right){
	if(left->signature != right->signature || left->count != right->count
		|| left->phase != right->phase || left->depth != right->depth
		|| left->best_depth != right->best_depth
		|| left->prepare_next != right->prepare_next
		|| left->search_limit != right->search_limit
		|| left->rank_all_matches != right->rank_all_matches
		|| left->examined != right->examined
		|| left->checksum_matches != right->checksum_matches
		|| left->validated_matches != right->validated_matches
		|| left->best_score != right->best_score){
		return false;
	}
	if(left->count == 0){
		return true;
	}
#define MP3_SEARCH_COMPARE(field) \
	if(memcmp(left->field, right->field, \
		((size_t)left->count + 1) * sizeof(*left->field)) != 0){ \
		return false; \
	}
	MP3_SEARCH_COMPARE(path);
	MP3_SEARCH_COMPARE(best_path);
	MP3_SEARCH_COMPARE(next_choice);
	MP3_SEARCH_COMPARE(blocks_at_depth);
	MP3_SEARCH_COMPARE(crc_at_depth);
	MP3_SEARCH_COMPARE(transform_flags);
	MP3_SEARCH_COMPARE(full_transforms);
	MP3_SEARCH_COMPARE(tail_transforms);
#undef MP3_SEARCH_COMPARE
	return true;
}

// Serialize values and arrays explicitly; pointers and structure padding are
// not checkpoint data. The enclosing carve state carries the version marker.
static void mp3_checksum_state_io(Mp3ChecksumState *state, FILE *fp,
	StateSerialization mode){
	size_t (*fb)(void *, size_t, size_t, FILE *) = mode == SERIALIZE
		? (size_t (*)(void *, size_t, size_t, FILE *))fwrite : fread;
#define MP3_SEARCH_FIELD(field) \
	if(fb(&state->field, sizeof(state->field), 1, fp) != 1){ \
		handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__); \
	}
	MP3_SEARCH_FIELD(signature);
	MP3_SEARCH_FIELD(count);
	MP3_SEARCH_FIELD(phase);
	MP3_SEARCH_FIELD(depth);
	MP3_SEARCH_FIELD(best_depth);
	MP3_SEARCH_FIELD(prepare_next);
	MP3_SEARCH_FIELD(search_limit);
	MP3_SEARCH_FIELD(rank_all_matches);
	MP3_SEARCH_FIELD(examined);
	MP3_SEARCH_FIELD(checksum_matches);
	MP3_SEARCH_FIELD(validated_matches);
	MP3_SEARCH_FIELD(best_score);
#undef MP3_SEARCH_FIELD
	if(state->depth > state->count || state->best_depth > state->count
		|| state->prepare_next > state->count
		|| state->search_limit > state->count
		|| (state->count > 0 && (state->phase < MP3_CHECKSUM_PREPARE
			|| state->phase > MP3_CHECKSUM_COMPLETE))){
		handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
	}
	if(mode == DESERIALIZE){
		mp3_checksum_state_allocate(state);
	}
	if(state->count == 0){
		return;
	}
	const size_t count = (size_t)state->count + 1;
#define MP3_SEARCH_ARRAY(field) \
	if(fb(state->field, sizeof(*state->field), count, fp) != count){ \
		handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__); \
	}
	MP3_SEARCH_ARRAY(path);
	MP3_SEARCH_ARRAY(best_path);
	MP3_SEARCH_ARRAY(next_choice);
	MP3_SEARCH_ARRAY(blocks_at_depth);
	MP3_SEARCH_ARRAY(crc_at_depth);
	MP3_SEARCH_ARRAY(transform_flags);
	MP3_SEARCH_ARRAY(full_transforms);
	MP3_SEARCH_ARRAY(tail_transforms);
#undef MP3_SEARCH_ARRAY
	if(mode == DESERIALIZE){
		for(uint32_t i = 0; i <= state->count; i++){
			if(state->path[i] >= state->count
				|| state->best_path[i] >= state->count
				|| state->next_choice[i] > state->count
				|| (state->transform_flags[i]
					& ~(MP3_CHECKSUM_FULL_TRANSFORM | MP3_CHECKSUM_TAIL_TRANSFORM))){
				handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
			}
		}
	}
}

// Encode the fallback frontier explicitly, including its current spectral winner.
static void mp3_greedy_search_io(Mp3GreedySearch *search, uint16_t count,
	FILE *fp, StateSerialization mode){
	size_t (*io)(void *, size_t, size_t, FILE *) = mode == SERIALIZE
		? (size_t (*)(void *, size_t, size_t, FILE *))fwrite : fread;
#define MP3_GREEDY_FIELD(field) \
	if(io(&search->field, sizeof(search->field), 1, fp) != 1){ \
		handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__); \
	}
	MP3_GREEDY_FIELD(signature);
	MP3_GREEDY_FIELD(phase);
	MP3_GREEDY_FIELD(next);
	MP3_GREEDY_FIELD(matches);
	MP3_GREEDY_FIELD(best_index);
	MP3_GREEDY_FIELD(best_peaks_ok);
	MP3_GREEDY_FIELD(best_stereo);
	for(size_t channel = 0; channel < 2; channel++){
		for(size_t peak = 0; peak < 6; peak++){
			MP3_GREEDY_FIELD(best_peaks[channel][peak].val);
			MP3_GREEDY_FIELD(best_peaks[channel][peak].index);
		}
	}
#undef MP3_GREEDY_FIELD
	if(search->phase > MP3_GREEDY_FINISHED || search->next > count
		|| search->matches > count || search->best_peaks_ok > 1
		|| search->best_stereo > 1
		|| (search->phase && (search->best_index < -1
			|| search->best_index >= (int32_t)count))){
		handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
	}
}

// Equality must not depend on Peak/struct padding.
static bool mp3_greedy_search_equal(const Mp3GreedySearch *a,
	const Mp3GreedySearch *b){
	if(a->signature != b->signature || a->phase != b->phase || a->next != b->next
		|| a->matches != b->matches || a->best_index != b->best_index
		|| a->best_peaks_ok != b->best_peaks_ok || a->best_stereo != b->best_stereo){
		return false;
	}
	for(size_t channel = 0; channel < 2; channel++){
		for(size_t peak = 0; peak < 6; peak++){
			if(a->best_peaks[channel][peak].val != b->best_peaks[channel][peak].val
				|| a->best_peaks[channel][peak].index != b->best_peaks[channel][peak].index){
				return false;
			}
		}
	}
	return true;
}

//serialize or deserialize carve state to a file
static inline bool mp3_serialize_carve_state(void **state, FILE *fp,
											StateSerialization mode){
	Mp3CarveState **s = (Mp3CarveState **)state;

	size_t (*fb)(void *ptr, size_t size, size_t nitems, FILE *stream) =
		mode == SERIALIZE ?
		(size_t (*)(void *ptr, size_t size, size_t nitems, FILE *stream))fwrite :
		(size_t (*)(void *ptr, size_t size, size_t nitems, FILE *stream))fread;

	if (mode == DESERIALIZE) {
		*s = calloc(1, sizeof(Mp3CarveState));
		check_memory_allocation(*s, __LINE__, __FILE__, "s");
	}

	uint32_t version = UINT32_C(0x4d503304);
	if(fb(&version, sizeof(version), 1, fp) != 1
		|| (version != UINT32_C(0x4d503304)
			&& version != UINT32_C(0x4d503303)
			&& version != UINT32_C(0x4d503302))){
		handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
	}

	// num_frags is uint16_t; sizeof(int) here (mismatched with the field's actual size)
	// used to read/write past it into whatever padding follows, making the checkpoint
	// representation depend on struct layout and platform details rather than the field's
	// real, fixed width.
	if(fb(&(*s)->num_frags, sizeof(uint16_t), 1, fp) != 1){
		perror("mp3 num_frags");
		handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
	}

	if(mode == DESERIALIZE){
		if((*s)->num_frags > 0){
			(*s)->fragments = calloc((*s)->num_frags, sizeof(Mp3Fragment));
			check_memory_allocation((*s)->fragments, __LINE__, __FILE__, "fragments");
			(*s)->indexes = calloc((*s)->num_frags, sizeof(uint16_t));
			check_memory_allocation((*s)->indexes, __LINE__, __FILE__, "indexes");
		}
		else{
			(*s)->fragments = NULL;
			(*s)->indexes = NULL;
		}
	}

	// fragments

	for(int i = 0; i < (*s)->num_frags; i++){
		Mp3Fragment *frag = &(*s)->fragments[i];

		// not peaks
		if (fb(&frag->frontOffset, sizeof(uint16_t), 1, fp) != 1 ||
            fb(&frag->rearOffset, sizeof(uint16_t), 1, fp) != 1) {
            handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
        }
		// The integrated 0x4d503302 format has neither split-byte field.
		// They are reconstructed from the physical run when old state resumes.
		if (version >= UINT32_C(0x4d503303)
			&& (fb(&frag->frontFrameHeaderBreak, sizeof(uint8_t), 1, fp) != 1
				|| fb(&frag->rearFrameHeaderBreak, sizeof(uint8_t), 1, fp) != 1)) {
			handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
		}
		if (fb(&frag->size, sizeof(size_t), 1, fp) != 1 ||
	            fb(&frag->isHeader, sizeof(bool), 1, fp) != 1 ||
	            fb(&frag->isTail, sizeof(bool), 1, fp) != 1 ||
	            fb(&frag->active, sizeof(bool), 1, fp) != 1 ||
	            fb(&frag->preserveFrontContext, sizeof(bool), 1, fp) != 1 ||
	            fb(&frag->secondToLastFramePosition, sizeof(uint64_t), 1, fp) != 1 ||
            fb(&frag->lastFramePosition, sizeof(uint64_t), 1, fp) != 1 ||
            fb(&frag->offsetFramePosition, sizeof(uint64_t), 1, fp) != 1 ||
            // firstActBlock/lastActBlock identify which actual blocks this fragment *is* --
            // used throughout resumed fragment processing -- and were previously omitted
            // here, so a checkpoint restore would silently zero them out.
            fb(&frag->firstActBlock, sizeof(int64_t), 1, fp) != 1 ||
            fb(&frag->lastActBlock, sizeof(int64_t), 1, fp) != 1) {
            perror("mp3 fragment metadata");
            handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
        }
		if(version >= UINT32_C(0x4d503303)){
			Mp3HeaderBreakContext *contexts[2] = {
				&frag->frontHeaderContext, &frag->rearHeaderContext};
			for(uint8_t side = 0; side < 2; side++){
				Mp3HeaderBreakContext *context = contexts[side];
				if(fb(&context->mpegVersion, sizeof(uint8_t), 1, fp) != 1
					|| fb(&context->layer, sizeof(uint8_t), 1, fp) != 1
					|| fb(&context->samplingrate, sizeof(uint16_t), 1, fp) != 1
					|| fb(context->bytes, sizeof(uint8_t), 3, fp) != 3){
					handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
				}
			}
			if(fb(&frag->headerContextKnown, sizeof(bool), 1, fp) != 1){
				handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
			}
		}
		// peaks (2 channels x 6 peaks, contiguous)
		if(fb(frag->peaks, sizeof(Peak), 12, fp) != 12){
			perror("mp3 fragment peaks");
			handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
		}
		if(fb(&frag->peaksStereo, sizeof(bool), 1, fp) != 1){
			perror("mp3 fragment peaksStereo");
			handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
		}
		// separate indexes array (not in frag struct)
		if (fb(&(*s)->indexes[i], sizeof(uint16_t), 1, fp) != 1){
			perror("mp3 index");
			handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
		}
	}

	// cur_index is uint16_t; same sizeof(int)-vs-actual-field-size mismatch as num_frags above.
	if (fb(&(*s)->cur_index, sizeof(uint16_t), 1, fp) != 1){
		perror("mp3 cur_index");
		handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
	}
	if(fb(&(*s)->structural_signature, sizeof(uint64_t), 1, fp) != 1
		|| fb(&(*s)->structural_next_combination, sizeof(uint64_t), 1, fp) != 1
		|| fb(&(*s)->structural_search_complete, sizeof(bool), 1, fp) != 1
		|| fb(&(*s)->direct_signature, sizeof(uint64_t), 1, fp) != 1
		|| fb(&(*s)->direct_first, sizeof(uint32_t), 1, fp) != 1
		|| fb(&(*s)->direct_second, sizeof(uint32_t), 1, fp) != 1
		|| fb(&(*s)->direct_search_complete, sizeof(bool), 1, fp) != 1
		|| fb(&(*s)->fragment_discovery_phase, sizeof(uint8_t), 1, fp) != 1
		|| fb(&(*s)->fragment_discovery_next_actual, sizeof(int64_t), 1, fp) != 1
		|| fb(&(*s)->fragment_discovery_peak_index, sizeof(uint32_t), 1, fp) != 1
		|| fb(&(*s)->fragment_discovery_open, sizeof(bool), 1, fp) != 1
		|| fb(&(*s)->fragment_discovery_apparent_blocks,
			sizeof(uint64_t), 1, fp) != 1){
		perror("mp3 structural search state");
		handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
	}
	mp3_checksum_state_io(&(*s)->checksum, fp, mode);
	if(version >= UINT32_C(0x4d503304)){
		mp3_greedy_search_io(&(*s)->greedy, (*s)->num_frags, fp, mode);
	}
	return true;
}

static inline bool mp3_states_equal(Mp3CarveState *a, Mp3CarveState *b){
	if(!mp3_greedy_search_equal(&a->greedy, &b->greedy)){
		return false;
	}
	if(!mp3_checksum_states_equal(&a->checksum, &b->checksum)){
		return false;
	}
	if(a->num_frags != b->num_frags) return false;
	if(a->cur_index != b->cur_index) return false;
	if(a->structural_signature != b->structural_signature
		|| a->structural_next_combination
			!= b->structural_next_combination
		|| a->structural_search_complete
			!= b->structural_search_complete
		|| a->direct_signature != b->direct_signature
		|| a->direct_first != b->direct_first
		|| a->direct_second != b->direct_second
		|| a->direct_search_complete != b->direct_search_complete
		|| a->fragment_discovery_phase != b->fragment_discovery_phase
		|| a->fragment_discovery_next_actual
			!= b->fragment_discovery_next_actual
		|| a->fragment_discovery_peak_index
			!= b->fragment_discovery_peak_index
		|| a->fragment_discovery_open != b->fragment_discovery_open
		|| a->fragment_discovery_apparent_blocks
			!= b->fragment_discovery_apparent_blocks){
		return false;
	}
	for(int i = 0; i < a->num_frags; i++){
		Mp3Fragment *fa = &a->fragments[i];
		Mp3Fragment *fb = &b->fragments[i];
		if(memcmp(fa, fb, sizeof(Mp3Fragment)) != 0)
			return false;
		if(a->indexes[i] != b->indexes[i])
			return false;
	}
	return true;
}

//clone mp3 carve state
static inline void *mp3_clone_carve_state(const void *srcstate){
	Mp3CarveState *s = (Mp3CarveState *)srcstate;
	Mp3CarveState *d = malloc(sizeof(Mp3CarveState));
	Mp3Fragment *src;
	Mp3Fragment *dst;
	check_memory_allocation(d, __LINE__, __FILE__, "d");
	mp3_checksum_state_clone(&d->checksum, &s->checksum);
	d->greedy = s->greedy;
	d->num_frags = s->num_frags;
	d->cur_index = s->cur_index;
	d->structural_signature = s->structural_signature;
	d->structural_next_combination = s->structural_next_combination;
	d->structural_search_complete = s->structural_search_complete;
	d->direct_signature = s->direct_signature;
	d->direct_first = s->direct_first;
	d->direct_second = s->direct_second;
	d->direct_search_complete = s->direct_search_complete;
	d->fragment_discovery_phase = s->fragment_discovery_phase;
	d->fragment_discovery_next_actual = s->fragment_discovery_next_actual;
	d->fragment_discovery_peak_index = s->fragment_discovery_peak_index;
	d->fragment_discovery_open = s->fragment_discovery_open;
	d->fragment_discovery_apparent_blocks =
		s->fragment_discovery_apparent_blocks;
	d->fragments = calloc(d->num_frags, sizeof(Mp3Fragment));
	d->indexes = calloc(d->num_frags, sizeof(uint16_t));
	check_memory_allocation(d->fragments, __LINE__, __FILE__, "d->fragments");
	check_memory_allocation(d->indexes, __LINE__, __FILE__, "d->indexes");
	for(int i = 0; i < d->num_frags; i++){
		src = &s->fragments[i];
		dst = &d->fragments[i];
		dst->frontOffset = src->frontOffset;
		dst->rearOffset = src->rearOffset;
		dst->frontFrameHeaderBreak = src->frontFrameHeaderBreak;
		dst->rearFrameHeaderBreak = src->rearFrameHeaderBreak;
		dst->frontHeaderContext = src->frontHeaderContext;
		dst->rearHeaderContext = src->rearHeaderContext;
		dst->headerContextKnown = src->headerContextKnown;
		dst->size = src->size;
		dst->isHeader = src->isHeader;
		dst->isTail = src->isTail;
		dst->active = src->active;
		dst->preserveFrontContext = src->preserveFrontContext;
		dst->secondToLastFramePosition = src->secondToLastFramePosition;
		dst->lastFramePosition = src->lastFramePosition;
		dst->offsetFramePosition = src->offsetFramePosition;
		dst->firstActBlock = src->firstActBlock;
		dst->lastActBlock = src->lastActBlock;
		dst->peaksStereo = src->peaksStereo;

		memcpy(dst->peaks, src->peaks, sizeof(Peak) * 12);
	}
	// srcstate is nominally const -- if s->indexes is NULL there's nothing to copy, and
	// d->indexes is already zero-initialized by the calloc() above, so there's no reason to
	// allocate into (and thereby mutate) the source to give it something to copy from.
	if(s->indexes != NULL){
		memcpy(d->indexes, s->indexes, d->num_frags * sizeof(uint16_t));
	}

	return d;
}

static inline void mp3_free_carve_state(void **state){
	if(*state != NULL){
		Mp3CarveState *s = (Mp3CarveState *)*state;
		mp3_checksum_state_free(&s->checksum);
		free(s->indexes);
		free(s->fragments);
		free(s);
		*state = NULL;
	}
}

//compare two states associated with mp3 carve candidates
static inline bool mp3_compare_carve_state(const void *state1, const void *state2){
	Mp3CarveState *s1 = (Mp3CarveState *)state1;
	Mp3CarveState *s2 = (Mp3CarveState *)state2;
	if(!mp3_greedy_search_equal(&s1->greedy, &s2->greedy)){
		return false;
	}
	if(!mp3_checksum_states_equal(&s1->checksum, &s2->checksum)){
		return false;
	}
	bool result = (s1->num_frags == s2->num_frags);
	if(!result) return result;
	result = s1->structural_signature == s2->structural_signature
		&& s1->structural_next_combination
			== s2->structural_next_combination
		&& s1->structural_search_complete
			== s2->structural_search_complete
		&& s1->direct_signature == s2->direct_signature
		&& s1->direct_first == s2->direct_first
		&& s1->direct_second == s2->direct_second
		&& s1->direct_search_complete == s2->direct_search_complete
		&& s1->fragment_discovery_phase == s2->fragment_discovery_phase
		&& s1->fragment_discovery_next_actual
			== s2->fragment_discovery_next_actual
		&& s1->fragment_discovery_peak_index
			== s2->fragment_discovery_peak_index
		&& s1->fragment_discovery_open == s2->fragment_discovery_open
		&& s1->fragment_discovery_apparent_blocks
			== s2->fragment_discovery_apparent_blocks;
	if(!result) return result;
	Mp3Fragment *frag1;
	Mp3Fragment *frag2;
	for(int i = 0; i < s1->num_frags; i++){
		frag1 = &s1->fragments[i];
		frag2 = &s2->fragments[i];
		result = (result &&
		frag1->frontOffset == frag2->frontOffset &&
		frag1->rearOffset == frag2->rearOffset &&
		frag1->size == frag2->size &&
			frag1->isHeader == frag2->isHeader &&
			frag1->isTail == frag2->isTail &&
			frag1->active == frag2->active &&
			frag1->preserveFrontContext == frag2->preserveFrontContext &&
		frag1->secondToLastFramePosition == frag2->secondToLastFramePosition &&
		frag1->lastFramePosition == frag2->lastFramePosition &&
		frag1->offsetFramePosition == frag2->offsetFramePosition &&
		frag1->firstActBlock == frag2->firstActBlock &&
		frag1->lastActBlock == frag2->lastActBlock);
		if(!result) return result;
		result = (result && frag1->peaksStereo == frag2->peaksStereo);
		if(!result) return result;
		for(int ch = 0; ch < 2; ch++){
			for(int j = 0; j < 6; j++){
				result = (result &&
				frag1->peaks[ch][j].val == frag2->peaks[ch][j].val &&
				frag1->peaks[ch][j].index == frag2->peaks[ch][j].index);
				if(!result) return result;
			}
		}
		result = (result &&
		s1->indexes[i] == s2->indexes[i]);
		if(!result) return result;
	}
	result = (result && s1->cur_index == s2->cur_index);
	return result;
}

//display a representation of mp3 carve state
static inline void mp3_print_carve_state(const void *state){
	Mp3CarveState *s = (Mp3CarveState *)state;
	fprintf(stdout, "cur_index: %d\n", s->cur_index);
	fprintf(stdout, "structural_signature: %"PRIu64"\n",
		s->structural_signature);
	fprintf(stdout, "structural_next_combination: %"PRIu64"\n",
		s->structural_next_combination);
	fprintf(stdout, "structural_search_complete: %s\n",
		s->structural_search_complete ? "TRUE" : "FALSE");
	fprintf(stdout, "direct_search: first=%"PRIu32" second=%"PRIu32
		" complete=%u\n", s->direct_first, s->direct_second,
		(unsigned int)s->direct_search_complete);
	fprintf(stdout, "fragment_discovery_phase: %u\n",
		(unsigned int)s->fragment_discovery_phase);
	fprintf(stdout, "fragment_discovery_next_actual: %"PRId64"\n",
		s->fragment_discovery_next_actual);
	fprintf(stdout, "fragment_discovery_peak_index: %"PRIu32"\n",
		s->fragment_discovery_peak_index);
	fprintf(stdout, "fragment_discovery_open: %s\n",
		s->fragment_discovery_open ? "TRUE" : "FALSE");
	fprintf(stdout, "fragment_discovery_apparent_blocks: %"PRIu64"\n",
		s->fragment_discovery_apparent_blocks);
	for(int i = 0; i < s->num_frags; i++){
		fprintf(stdout, "======================\n");
		fprintf(stdout, "fragment number %d\n", i);
		fprintf(stdout, "front offset: %d\n", s->fragments[i].frontOffset);
		fprintf(stdout, "rear offset: %d\n", s->fragments[i].rearOffset);
		fprintf(stdout, "size: %zu\n", s->fragments[i].size);
		fprintf(stdout, "isHeader: %s\n", (s->fragments[i].isHeader) ? "TRUE" : "FALSE");
		fprintf(stdout, "isTail: %s\n", (s->fragments[i].isTail) ? "TRUE" : "FALSE");
		fprintf(stdout, "active: %s\n", (s->fragments[i].active) ? "TRUE" : "FALSE");
		//fprintf(stdout, "secondToLastFramePosition: %"PRIu64"\n", s->fragments[i].secondToLastFramePosition);
		fprintf(stdout, "lastFramePosition: %"PRIu64"\n", s->fragments[i].lastFramePosition);
		fprintf(stdout, "offsetFramePosition: %"PRIu64"\n", s->fragments[i].offsetFramePosition);
		fprintf(stdout, "firstActBlock: %"PRIu64"\n", s->fragments[i].firstActBlock);
		fprintf(stdout, "lastActBlock: %"PRIu64"\n", s->fragments[i].lastActBlock);
		//display_blockvector(s->fragments[i].b, "blockvector");
	}
}

//Reassembly init functions:

//NOTE: does not initialize BlockVector
Mp3Fragment *init_fragments(int num_fragments){
	//lock_fprintf(stdout, "%d\n", num_fragments);
	Mp3Fragment *fragments = (Mp3Fragment *)malloc(num_fragments * sizeof(Mp3Fragment));
	if(!fragments){
		perror("Failed to allocate memory for blocks");
		exit(EXIT_FAILURE);
	}
	for(int i = 0; i < num_fragments; i++){
		memset(&fragments[i], 0, sizeof(fragments[i]));
		fragments[i].frontOffset = 0;
		fragments[i].rearOffset = 0;
		fragments[i].size = 0;
		fragments[i].isHeader = false;
		fragments[i].isTail = false;
		fragments[i].active = true;
		fragments[i].preserveFrontContext = false;
		fragments[i].secondToLastFramePosition = 0;
		fragments[i].lastFramePosition = 0;
		fragments[i].offsetFramePosition = 0;
		for(int ch = 0; ch < 2; ch++){
			for(int j = 0; j < 6; j++){
				fragments[i].peaks[ch][j].val = 0;
				fragments[i].peaks[ch][j].index = -1;
			}
		}
		fragments[i].peaksStereo = false;
		fragments[i].firstActBlock = 0;
		fragments[i].lastActBlock = 0;
	}
	return fragments;
}

// Appends one fragment slot, growing the underlying allocation geometrically (doubling)
// rather than by exactly one slot every call -- this is called once per fragment
// discovered, and a heavily fragmented candidate can have thousands of fragments, so a
// realloc-by-one-and-copy on every single call is quadratic in the fragment count.
// '*capacity' tracks how many slots are actually allocated (>= old_count) and is updated
// in place; the caller is still responsible for incrementing its own fragment count.
Mp3Fragment *add_fragment(Mp3Fragment *old_fragments, int old_count, uint16_t *capacity){
	if((uint16_t)old_count >= *capacity){
		uint16_t new_capacity = (*capacity == 0) ? 1 :
			(*capacity > UINT16_MAX / 2 ? UINT16_MAX : (uint16_t)(*capacity * 2));
		Mp3Fragment *new_fragments = realloc(old_fragments, new_capacity * sizeof(Mp3Fragment));
		if(!new_fragments){
			perror("Failed to allocate memory for new fragment");
			free(old_fragments);
			exit(EXIT_FAILURE);
		}
		old_fragments = new_fragments;
		*capacity = new_capacity;
	}
	memset(&old_fragments[old_count], 0, sizeof(old_fragments[old_count]));
	old_fragments[old_count].frontOffset = 0;
	old_fragments[old_count].rearOffset = 0;
	old_fragments[old_count].size = 0;
	old_fragments[old_count].isHeader = false;
	old_fragments[old_count].isTail = false;
	old_fragments[old_count].active = true;
	old_fragments[old_count].preserveFrontContext = false;
	old_fragments[old_count].secondToLastFramePosition = 0;
	old_fragments[old_count].lastFramePosition = 0;
	old_fragments[old_count].offsetFramePosition = 0;
	for(int ch = 0; ch < 2; ch++){
		for(int j = 0; j < 6; j++){
			old_fragments[old_count].peaks[ch][j].val = 0;
			old_fragments[old_count].peaks[ch][j].index = -1;
		}
	}
	old_fragments[old_count].peaksStereo = false;
	old_fragments[old_count].firstActBlock = 0;
	old_fragments[old_count].lastActBlock = 0;
	return old_fragments;
}

//removes fragment at index frag_index from array of fragments
Mp3Fragment *remove_fragment(Mp3Fragment *old_fragments, int old_count, int frag_index){
	int new_count = old_count - 1;
	for(int i = frag_index; i < old_count-1; i++){
		old_fragments[i] = old_fragments[i+1];
	}
	if(new_count == 0){
		// realloc(ptr, 0) is implementation-defined -- glibc frees ptr and returns NULL,
		// which the check below would otherwise mistake for allocation failure and
		// respond to by freeing old_fragments a second time (a double free). Handle the
		// "no fragments left" case directly instead of going through realloc for it.
		free(old_fragments);
		return NULL;
	}
	Mp3Fragment *new_fragments = realloc(old_fragments, new_count * sizeof(Mp3Fragment));
	if(!new_fragments){
		perror("Failed to allow memory for new fragments");
		free(old_fragments);
		exit(EXIT_FAILURE);
	}
	return new_fragments;
}

FrameArgs get_frame_args(void){
	FrameArgs fa = {
		.mpegVersion = 0,
		.layer = 0,
		.crc = false,
		.bitrate = 0,
		.samplingrate = 0,
		.channel = singleChannel,
		.padding = 0
	};
	return fa;
}

ValidationArgs get_validation_args(void){
	ValidationArgs va = {
		.validates = false,
		.promising = false,
		.validates_to = 0,
		.needleidx = 0,
		.frontOffset = 0,
		.rearOffset = 0,
		.isHeader = false,
		.isTail = false,
		.secondToLastFramePosition = 0,
		.lastFramePosition = 0,
		.offsetFramePosition = 0
	};
	return va;
}

//returns whether state existed before init
static bool mp3_reassembly_init_candidate(int id,
									CarveInfo *candidate,
									uuid_string_t uuidp,
									uuid_string_t uuidc,
									Mp3CarveState **state){
	//check candidate state, if NULL then initialize it
	if(!*state){
		*state = (Mp3CarveState *)calloc(1, sizeof **state);
		check_memory_allocation(*state, __LINE__, __FILE__, "Mp3CarveState");
		(*state)->num_frags = 1;
		(*state)->fragments = init_fragments((*state)->num_frags);
		(*state)->indexes = calloc((*state)->num_frags, sizeof(uint16_t));
		check_memory_allocation((*state)->indexes, __LINE__, __FILE__,
			"Mp3CarveState indexes");
		carve_put_state(candidate->carvehashkey, *state);
		return false;
	}
	else{
		return true;
	}
}

//Fragment Functions:

// Remove whole leading blocks that precede the first validated MPEG frame in
// ordinary fragments. Boundary variants retain bounded context that may finish
// a frame split by fragmentation, while headers retain their complete ID3 prefix.
static void mp3_reassembly_normalize_fragment(Mp3Fragment *fragment,
	uint32_t blocksize){
	uint64_t leading_blocks;
	uint64_t leading_bytes;

	if(fragment == NULL || fragment->isHeader
		|| fragment->preserveFrontContext || blocksize == 0
		|| fragment->size == 0
		|| fragment->firstActBlock < 0){
		return;
	}
	leading_blocks = fragment->frontOffset / blocksize;
	if(leading_blocks == 0 || leading_blocks >= fragment->size
		|| leading_blocks > (uint64_t)(INT64_MAX - fragment->firstActBlock)){
		return;
	}
	leading_bytes = leading_blocks * blocksize;
	if(fragment->secondToLastFramePosition < leading_bytes
		|| fragment->lastFramePosition < leading_bytes
		|| fragment->offsetFramePosition < leading_bytes){
		return;
	}

	fragment->firstActBlock += (int64_t)leading_blocks;
	fragment->size -= leading_blocks;
	fragment->frontOffset -= (uint16_t)leading_bytes;
	fragment->secondToLastFramePosition -= leading_bytes;
	fragment->lastFramePosition -= leading_bytes;
	fragment->offsetFramePosition -= leading_bytes;
	mp3_fragment_refresh_header_context(fragment);
}

// Retain the mapped header prefix of a custom reassembly candidate. Blocks after
// the first unavailable slot remain eligible for discovery through the shared
// fragment catalog.
static bool mp3_reassembly_trim_seed_candidate(BlockVector *b){
	uint64_t available = 0;
	uint64_t blocks;

	if(b == NULL){
		return false;
	}
	deflate_blockvector(b);
	blocks = blockvector_get_num_blocks(b);
	while(available < blocks){
		const int64_t actual = blockvector_get_actual_blocknumber(b, available);
		int64_t apparent;

		if(actual < 0){
			break;
		}
		apparent = filemirror_apparent_blocknumber(
			scalpel_state.filemirror, actual);
		if(apparent < 0){
			break;
		}
		blockvector_set_apparent_blocknumber(b, available, apparent);
		available++;
	}
	if(available == 0){
		return false;
	}
	if(available < blocks){
		resize_blockvector(b, available);
	}
	normalize_blockvector(b);
	blockvector_set_data_length_to_mapped_extent(b);
	return true;
}

// Synchronize the candidate blockvector with its checked header fragment before
// discovery resumes or the candidate returns to a checkpoint barrier.
static bool mp3_reassembly_rebuild_seed_candidate(CarveInfo *candidate,
	const Mp3Fragment *fragment){
	uint64_t expected_size;

	if(candidate == NULL || candidate->b == NULL || fragment == NULL
		|| fragment->firstActBlock < 0
		|| fragment->lastActBlock < fragment->firstActBlock){
		return false;
	}
	expected_size = (uint64_t)(fragment->lastActBlock
		- fragment->firstActBlock) + 1;
	if(fragment->size == 0 || fragment->size != expected_size){
		return false;
	}

	deflate_blockvector(candidate->b);
	resize_blockvector(candidate->b, fragment->size);
	for(uint64_t position = 0; position < fragment->size; position++){
		const int64_t apparent = filemirror_apparent_blocknumber(
			scalpel_state.filemirror,
			fragment->firstActBlock + (int64_t)position);
		if(apparent < 0){
			return false;
		}
		blockvector_set_apparent_blocknumber(candidate->b, position,
			apparent);
	}
	normalize_blockvector(candidate->b);
	blockvector_set_data_length_to_mapped_extent(candidate->b);
	return true;
}

// Locate a frame in the last fragment using block slots, not the byte length
// of a possibly short final block. Reads remain bounded by the mapped data.
static bool mp3_reassembly_frame_stream(BlockVector *b,
	const Mp3Fragment *fragment,
	uint32_t blocksize,
	Bitstream *stream){
	uint64_t blocks;
	uint64_t start;
	uint64_t length;

	if(b == NULL || fragment == NULL || stream == NULL || blocksize == 0){
		return false;
	}
	blocks = blockvector_get_num_blocks(b);
	length = blockvector_get_data_length(b);
	if(fragment->size == 0 || fragment->size > blocks
		|| blocks - fragment->size > UINT64_MAX / blocksize){
		return false;
	}
	start = (blocks - fragment->size) * blocksize;
	if(start > length || fragment->offsetFramePosition > length - start){
		return false;
	}
	*stream = (Bitstream){blockvector_get_data_pointer(b), 0,
		start + fragment->offsetFramePosition, length, false};
	return true;
}

// Decode only the bytes present after a frame offset in a mapped join.
static bool mp3_reassembly_boundary_peaks(BlockVector *b,
	uint64_t offset,
	Peak left[],
	Peak right[],
	bool *stereo){
	const uint64_t length = blockvector_get_data_length(b);
	uint64_t available;

	if(offset >= length){
		*stereo = false;
		for(uint8_t i = 0; i < 6; i++){
			left[i] = (Peak){0, -1};
			right[i] = (Peak){0, -1};
		}
		return false;
	}
	available = length - offset;
	if(available > INT_MAX){
		available = INT_MAX;
	}
	return getPeaks(blockvector_get_data_pointer(b) + offset,
		(int)available, left, right, stereo);
}

// Refresh frame boundaries after coverage changes a fragment's physical run.
static void mp3_reassembly_refresh_frag_data(BlockVector *b_read,
											Mp3Fragment *frag){
	uint64_t curFragLength = 0;
	bool validates = false;
	uint64_t validates_to = 0;
	uint32_t needleidx = 0;
	uint16_t frontOffset = 0;
	uint16_t rearOffset = 0;
	bool isHeader = false;
	bool isTail = false;
	uint64_t secondToLastFramePosition = 0;
	uint64_t lastFramePosition = 0;
	uint64_t offsetFramePosition = 0;
	bool maybe;
	uint64_t count;
	int64_t blk_ap;
	uint32_t blocksize;

	resize_blockvector(
		b_read,
		frag->size
	);
	count = 0;
	for(int64_t blk_act = frag->firstActBlock; blk_act <= frag->lastActBlock; blk_act++){
		blk_ap = filemirror_apparent_blocknumber(scalpel_state.filemirror, blk_act);
		blockvector_set_apparent_blocknumber(b_read, count, blk_ap);
		count++;
	}
	blockvector_set_data_length_to_mapped_extent(b_read);
	inflate_blockvector(b_read);
	blocksize = scalpel_state.blocksize;
	curFragLength = blockvector_get_data_length(b_read);
	mp3_fragment_validate(blockvector_get_data_pointer(b_read),
		curFragLength,
		&validates,
		&validates_to,
		needleidx,
		&frontOffset,
		&rearOffset,
		&isHeader,
		&isTail,
		&secondToLastFramePosition,
		&lastFramePosition,
		&offsetFramePosition,
		&maybe);
	deflate_blockvector(b_read);
	frag->frontOffset = frontOffset;
	frag->rearOffset = rearOffset;
	frag->isHeader = isHeader;
	frag->isTail = isTail;
	frag->secondToLastFramePosition = secondToLastFramePosition;
	frag->lastFramePosition = lastFramePosition;
	frag->offsetFramePosition = offsetFramePosition;
	mp3_fragment_refresh_header_context(frag);
	mp3_reassembly_normalize_fragment(frag, blocksize);
	mp3_fragment_measure_peaks(b_read, frag, blocksize);
}

// Checks a singular fragment for whether it is still valid or a block has
// been covered. It returns true if the fragment has been adequately checked
// and false if the fragment needs to be checked again. This function handles
// the invalid fragment and updates carve state accordingly.

static bool mp3_reassembly_check_fragment(BlockVector *b_read,
										Mp3CarveState *carve_state,
										Mp3Fragment *frag,
										int frag_index){
	bool updateNeeded = false;
	uint16_t cutoff_index = 0;
	uint64_t blk_pos;
	#ifdef DEBUG_REASSEMBLY_FRAG
		lock_fprintf(stdout, "mp3_reassembly_check_fragment:\n");
	#endif
	restart:
	if(!frag->headerContextKnown){
		mp3_fragment_refresh_header_context(frag);
	}
	blk_pos = 0;
	for(int64_t blk_act = frag->firstActBlock; blk_act <= frag->lastActBlock; blk_act++){
		if(filemirror_actual_block_covered(scalpel_state.filemirror, blk_act)){
			#ifdef DEBUG_REASSEMBLY_FRAG
				lock_fprintf(stdout, "fragment found to be invalid\n");
			#endif
			if(!(frag->active)){ //if invalid fragment in candidate, need to backtrack construction progress
				for(uint16_t j = 0; j < carve_state->num_frags; j++){
					if(carve_state->indexes[j] == frag_index){
						cutoff_index = j;
						break;
					}
				}
				if(cutoff_index == 0){
					if(blk_pos == 0){ //header fragment got covered, candidate must die
						return false;
					}
					carve_state->cur_index = 0;
				}
				else{
					carve_state->cur_index = cutoff_index - 1;
				}
			}
			if(frag->size == 1){ //if fragment size a single covered block, delete fragment
				carve_state->fragments = remove_fragment(carve_state->fragments, carve_state->num_frags, frag_index);
				carve_state->num_frags--;
				// remove_fragment() shifts every fragment after frag_index down one slot, but
				// carve_state->indexes[] stores fragment *array positions* -- any committed
				// index pointing past frag_index is now stale and refers to the wrong fragment
				// (whatever shifted into that slot) unless corrected here. A fragment's array
				// position has no relationship to when it was committed into indexes[], so a
				// still-valid, earlier-committed entry can easily reference a later array slot
				// than frag_index and would otherwise silently desync.
				for(uint16_t j = 0; j < carve_state->cur_index; j++){
					if(carve_state->indexes[j] > frag_index){
						carve_state->indexes[j]--;
					}
				}
				return false;
			}
			if(blk_pos == 0){ //if first block covered
				//remove first block from current frag and rerun
				frag->size--;
				frag->firstActBlock++;
				updateNeeded = true;
				goto restart;
			}
			else if(blk_pos == frag->size-1){ //if last block covered
				//remove last block
				frag->size--;
				frag->lastActBlock--;
				mp3_reassembly_refresh_frag_data(b_read, frag);
				return true;
			}
			else{ //if we end up here, uncovered blocks were cut off by a covered block, expensive to resolve but necessary
				int frag1_size = blk_pos;
				int frag2_size = frag->size - blk_pos - 1;
				if(carve_state->num_frags >= UINT16_MAX){
					// num_frags is uint16_t; adding one more here would wrap it to 0 and
					// corrupt every fragment index already recorded. This candidate has
					// already accumulated an extreme, essentially pathological number of
					// fragments -- rather than track the tail portion (new_frag) as its own
					// fragment, drop it and keep only the part before the covered block.
					lock_fprintf(stdout,
						"MP3: candidate hit the %d fragment limit while splitting a fragment;\n"
						"discarding the portion after the covered block.\n", UINT16_MAX);
					frag->lastActBlock = frag->firstActBlock + blk_pos - 1;
					frag->size = frag1_size;
					mp3_reassembly_refresh_frag_data(b_read, frag);
					return true;
				}
				{
					// This split only ever adds a single fragment per call (not a tight
					// discovery loop), so there's no persistent capacity to amortize across
					// calls -- just tell add_fragment() the array currently holds exactly
					// num_frags slots.
					uint16_t frag_capacity = carve_state->num_frags;
					uint16_t old_frag_capacity = frag_capacity;
					carve_state->fragments = add_fragment(carve_state->fragments, carve_state->num_frags, &frag_capacity);
					if(frag_capacity != old_frag_capacity){
						uint16_t *new_indexes = realloc(carve_state->indexes,
							frag_capacity * sizeof(uint16_t));
						check_memory_allocation(new_indexes, __LINE__, __FILE__,
							"carve_state->indexes");
						memset(new_indexes + old_frag_capacity, 0,
							(frag_capacity - old_frag_capacity)
								* sizeof(uint16_t));
						carve_state->indexes = new_indexes;
					}
				}
				carve_state->num_frags++;
				// add_fragment() may realloc() the fragment array, which can move it. 'frag'
				// was computed by the caller before that happened and would otherwise be a
				// dangling pointer into the old array for every read/write below.
				// frag_index is stable across the realloc (it's this fragment's array
				// position, unaffected by appending a new one at the end), so re-derive frag
				// from carve_state->fragments (the current array) through it.
				frag = &carve_state->fragments[frag_index];
				Mp3Fragment *new_frag = &carve_state->fragments[carve_state->num_frags-1];
				new_frag->firstActBlock = frag->firstActBlock + blk_pos + 1;
				new_frag->lastActBlock = frag->lastActBlock;
				frag->lastActBlock = frag->firstActBlock + blk_pos - 1;
				frag->size = frag1_size;
				new_frag->size = frag2_size;
				// Both sides have new boundaries and need new frame positions.
				mp3_reassembly_refresh_frag_data(b_read, frag);
				mp3_reassembly_refresh_frag_data(b_read, new_frag);
				return true;
			}
		}
		blk_pos++;
	}
	if(updateNeeded){
		mp3_reassembly_refresh_frag_data(b_read, frag);
	}
	#ifdef DEBUG_REASSEMBLY_FRAG
		lock_fprintf(stdout, "fragment found to be valid\n");
	#endif
	return true;
}

//false communicates for reassembly to kill the candidate
//true communicates to reassembly that fragments have been resolved
static bool mp3_reassembly_check_fragments(BlockVector *b_read,
										Mp3CarveState *carve_state){
	#ifdef DEBUG_REASSEMBLY_FRAG
		lock_fprintf(stdout, "checking fragment 0\n");
	#endif
	if(!(mp3_reassembly_check_fragment(b_read, carve_state, &carve_state->fragments[0], 0))){
		//special case, if reading first fragment results in false, kill the candidate
		return false;
	}
	for(int i = 1; i < carve_state->num_frags; i++){
		#ifdef DEBUG_REASSEMBLY_FRAG
			lock_fprintf(stdout, "checking fragment %d\n", i);
		#endif
		while(i < carve_state->num_frags && !mp3_reassembly_check_fragment(b_read, carve_state, &carve_state->fragments[i], i));
	}
	return true;
}

// Rebuilds candidate->b's block identities from scratch based on the current committed
// fragment chain (carve_state->indexes[0..cur_index-1]). mp3_reassembly_check_fragment() can
// shrink a still-committed fragment (one of its blocks became covered by another candidate
// that validated in the meantime) or backtrack cur_index entirely (a committed fragment
// became fully invalid) -- but neither of those touches candidate->b, since neither even
// takes candidate as a parameter. Left uncorrected, candidate->b would still physically
// contain the now-covered/stolen blocks (at the tail if cur_index was backtracked, or in the
// *middle* if a still-committed fragment merely shrank), and a candidate that later
// validates using it would write out blocks another candidate already owns -- silently
// reproducing cross-candidate duplication through the "resume and adapt" path specifically.
//
// This must be called once per resume, right after mp3_reassembly_check_fragments()
// succeeds, while candidate->b is still deflated: rewriting block identities on a deflated
// vector is cheap (no data to discard/reallocate), and the data is lazily re-inflated on the
// next call to blockvector_get_data_pointer()/_get_data_length() regardless of whether
// anything actually changed this resume.
static void mp3_rebuild_committed_blockvector(CarveInfo *candidate, Mp3CarveState *carve_state){

	uint64_t total_blocks = 0;
	for(uint16_t j = 0; j < carve_state->cur_index; j++){
		total_blocks += carve_state->fragments[carve_state->indexes[j]].size;
	}

	resize_blockvector(candidate->b, total_blocks);

	uint64_t position = 0;
	for(uint16_t j = 0; j < carve_state->cur_index; j++){
		Mp3Fragment *frag = &carve_state->fragments[carve_state->indexes[j]];
		for(int64_t act = frag->firstActBlock; act <= frag->lastActBlock; act++){
			blockvector_set_apparent_blocknumber(candidate->b, position, filemirror_apparent_blocknumber(scalpel_state.filemirror, act));
			position++;
		}
	}
	blockvector_set_data_length_to_mapped_extent(candidate->b);
}

static int mp3_checksum_fragment_order_compare(const void *left,
	const void *right){
	const Mp3ChecksumFragmentOrder *a = left;
	const Mp3ChecksumFragmentOrder *b = right;

	if(a->distance < b->distance){
		return -1;
	}
	if(a->distance > b->distance){
		return 1;
	}
	if(a->index < b->index){
		return -1;
	}
	if(a->index > b->index){
		return 1;
	}
	return 0;
}

// Builds a compact spectral signature for one decoded MPEG audio frame.
// Used for full-prefix extension ranking and checksum-equivalent paths; this
// transient state is deliberately not added to checkpointed fragment state.
static bool mp3_build_seam_signature(const unsigned char *pcm,
	size_t bytes,
	int channels,
	Mp3SeamSignature *signature){
	double real[MP3_SEAM_FFT_MAX];
	double imaginary[MP3_SEAM_FFT_MAX];
	size_t sample_count;
	size_t fft_size = 1;
	size_t feature_count;
	const double pi = acos(-1.0);

	if(pcm == NULL || signature == NULL || (channels != 1 && channels != 2)
		|| bytes < (size_t)channels * sizeof(int16_t)){
		return false;
	}
	memset(signature, 0, sizeof(*signature));
	sample_count = bytes / ((size_t)channels * sizeof(int16_t));
	if(MP3_PATH_SCORE_MDCT){
		float time[1152];
		float frequency[576];
		if(bytes % ((size_t)channels * sizeof(int16_t)) != 0
			|| sample_count < 32 || sample_count > 1152
			|| sample_count % 4 != 0){
			return false;
		}
		void *plan = pfft_mdctf_init((int)sample_count);
		if(plan == NULL){
			return false;
		}
		for(int channel = 0; channel < channels; channel++){
			mp3_detect_peaks_for_channel((unsigned char *)pcm, channels,
				channel, (int)sample_count, time, frequency, plan,
				signature->peaks[channel]);
		}
		pfft_mdctf_free(plan);
		signature->channels = (uint8_t)channels;
		signature->valid = true;
		return true;
	}
	feature_count = channels == 2 ? 4 : 1;
	while(fft_size < sample_count && fft_size < MP3_SEAM_FFT_MAX){
		fft_size <<= 1;
	}
	if(sample_count < 32 || fft_size < sample_count
		|| fft_size > MP3_SEAM_FFT_MAX){
		return false;
	}

	for(size_t feature = 0; feature < feature_count; feature++){
		double norm = 0.0;

		memset(real, 0, fft_size * sizeof(*real));
		memset(imaginary, 0, fft_size * sizeof(*imaginary));
		for(size_t sample = 0; sample < sample_count; sample++){
			const int16_t left =
				((const int16_t *)pcm)[sample * (size_t)channels];
			const int16_t right = channels == 2
				? ((const int16_t *)pcm)[sample * (size_t)channels + 1]
				: left;
			double value;
			if(feature == 0){
				value = left;
			}
			else if(feature == 1){
				value = right;
			}
			else if(feature == 2){
				value = ((double)left + right) / 2.0;
			}
			else{
				value = ((double)left - right) / 2.0;
			}
			const double window = sample_count == 1 ? 1.0
				: 0.5 - 0.5 * cos(2.0 * pi * sample
					/ (double)(sample_count - 1));
			// Preserve the native PCM scale before logarithmic compression. Scaling
			// first changes the spectral shape because log1p() is nonlinear.
			real[sample] = value * window;
		}

		for(size_t i = 1, j = 0; i < fft_size; i++){
			size_t bit = fft_size >> 1;
			while(j & bit){
				j ^= bit;
				bit >>= 1;
			}
			j ^= bit;
			if(i < j){
				double value = real[i];
				real[i] = real[j];
				real[j] = value;
				value = imaginary[i];
				imaginary[i] = imaginary[j];
				imaginary[j] = value;
			}
		}
		for(size_t width = 2; width <= fft_size; width <<= 1){
			const double angle = -2.0 * pi / (double)width;
			const double step_real = cos(angle);
			const double step_imaginary = sin(angle);
			for(size_t first = 0; first < fft_size; first += width){
				double weight_real = 1.0;
				double weight_imaginary = 0.0;
				for(size_t offset = 0; offset < width / 2; offset++){
					const size_t even = first + offset;
					const size_t odd = even + width / 2;
					const double odd_real = real[odd] * weight_real
						- imaginary[odd] * weight_imaginary;
					const double odd_imaginary = real[odd] * weight_imaginary
						+ imaginary[odd] * weight_real;
					const double even_real = real[even];
					const double even_imaginary = imaginary[even];
					real[even] = even_real + odd_real;
					imaginary[even] = even_imaginary + odd_imaginary;
					real[odd] = even_real - odd_real;
					imaginary[odd] = even_imaginary - odd_imaginary;
					const double next_real = weight_real * step_real
						- weight_imaginary * step_imaginary;
					weight_imaginary = weight_real * step_imaginary
						+ weight_imaginary * step_real;
					weight_real = next_real;
				}
			}
		}

		const size_t spectrum_bins = fft_size / 2 + 1;
		for(size_t bin = 0; bin < spectrum_bins; bin++){
			const size_t band = bin * MP3_SEAM_SIGNATURE_BANDS
				/ spectrum_bins;
			signature->bands[feature][band] +=
				log1p(hypot(real[bin], imaginary[bin]));
		}
		for(size_t band = 0; band < MP3_SEAM_SIGNATURE_BANDS; band++){
			norm += signature->bands[feature][band]
				* signature->bands[feature][band];
		}
		norm = sqrt(norm);
		if(norm != 0.0){
			for(size_t band = 0; band < MP3_SEAM_SIGNATURE_BANDS; band++){
				signature->bands[feature][band] /= norm;
			}
		}
	}
	signature->channels = (uint8_t)channels;
	signature->valid = true;
	return true;
}

static double mp3_seam_signature_cost(const Mp3SeamSignature *left,
	const Mp3SeamSignature *right){
	double cost = 0.0;
	double weight_sum = 0.0;
	const uint8_t channels = left->channels < right->channels
		? left->channels : right->channels;
	const uint8_t features = channels == 2 ? 4 : channels;

	if(!left->valid || !right->valid || channels == 0){
		return 1000.0;
	}
	if(MP3_PATH_SCORE_MDCT){
		const double similarity = mp3_stereo_score(left->peaks[0],
			left->peaks[1], left->channels == 2, right->peaks[0],
			right->peaks[1], right->channels == 2);
		// Put both equations on 0..1 before accumulating seam costs, keeping
		// decoder penalties and the tie tolerance identical between modes.
		const double maximum = MP3_SCORE_MODE == MP3_SCORE_MODE_INDEX_ONLY
			? 5.0 : 1.0;
		return 1.0 - similarity / maximum;
	}
	if(left->channels != right->channels){
		cost += 1.0;
	}
	for(uint8_t feature = 0; feature < features; feature++){
		double dot = 0.0;
		const double weight = feature >= 2 ? 2.0 : 1.0;
		for(size_t band = 0; band < MP3_SEAM_SIGNATURE_BANDS; band++){
			dot += left->bands[feature][band] * right->bands[feature][band];
		}
		if(dot < 0.0){
			dot = 0.0;
		}
		else if(dot > 1.0){
			dot = 1.0;
		}
		cost += weight * (1.0 - dot);
		weight_sum += weight;
	}
	return cost / weight_sum;
}

// Scores the three decoded MPEG frames surrounding each reconstructed seam.
// The stored LAME checksum and the full parser have already accepted every
// path reaching this function; this score only ranks otherwise equivalent
// checksum collisions by audio continuity.
static bool mp3_checksum_path_seam_score(const char *data,
	uint64_t length,
	const Mp3CarveState *carve_state,
	const uint16_t *path,
	uint16_t depth,
	uint32_t blocksize,
	double *score){
	mpg123_handle *decoder = NULL;
	const long *rates = NULL;
	size_t num_rates = 0;
	uint64_t *seams = NULL;
	unsigned char *frame_data[3] = {NULL, NULL, NULL};
	size_t frame_capacity[3] = {0, 0, 0};
	size_t frame_length[3] = {0, 0, 0};
	int frame_channels[3] = {0, 0, 0};
	int64_t frame_position[3] = {-1, -1, -1};
	uint64_t cumulative_blocks = 0;
	uint16_t seam_index = 0;
	uint64_t decoded_frames = 0;
	double cost = 0.0;
	bool configured = false;
	bool result = false;
	int decoder_result;

	if(data == NULL || carve_state == NULL || path == NULL || score == NULL
		|| depth < 2 || blocksize == 0 || length > SIZE_MAX){
		return false;
	}
	seams = calloc((size_t)depth - 1, sizeof(*seams));
	check_memory_allocation(seams, __LINE__, __FILE__, "MP3 seam positions");
	for(uint16_t i = 0; i + 1 < depth; i++){
		const Mp3Fragment *fragment = &carve_state->fragments[path[i]];
		if(fragment->size > UINT64_MAX - cumulative_blocks){
			goto done;
		}
		cumulative_blocks += fragment->size;
		if(cumulative_blocks > UINT64_MAX / blocksize){
			goto done;
		}
		seams[i] = cumulative_blocks * blocksize;
		if(seams[i] >= length){
			goto done;
		}
	}

	decoder = mp3_thread_handle();
	if(decoder == NULL){
		goto done;
	}
	mpg123_close(decoder);
	if(mpg123_format_none(decoder) != MPG123_OK){
		goto done;
	}
	mpg123_rates(&rates, &num_rates);
	for(size_t i = 0; i < num_rates; i++){
		if(mpg123_format(decoder, rates[i],
			MPG123_MONO | MPG123_STEREO, MPG123_ENC_SIGNED_16)
			== MPG123_OK){
			configured = true;
		}
	}
	if(!configured || mpg123_open_feed(decoder) != MPG123_OK
		|| mpg123_feed(decoder, (const unsigned char *)data, (size_t)length)
			!= MPG123_OK){
		mpg123_close(decoder);
		goto done;
	}

	while(seam_index + 1 < depth){
		int64_t frame_number = 0;
		unsigned char *audio = NULL;
		size_t bytes = 0;
		long rate = 0;
		int channels = 0;
		int encoding = 0;

		decoder_result = mpg123_decode_frame64(
			decoder, &frame_number, &audio, &bytes);
		if(decoder_result == MPG123_NEW_FORMAT){
			continue;
		}
		if(decoder_result == MPG123_DONE
			|| decoder_result == MPG123_NEED_MORE){
			break;
		}
		if(decoder_result != MPG123_OK
			|| mpg123_getformat(decoder, &rate, &channels, &encoding)
				!= MPG123_OK
			|| !(encoding & MPG123_ENC_SIGNED_16)){
			cost += 1000.0;
			break;
		}

		unsigned char *saved_data = frame_data[0];
		const size_t saved_capacity = frame_capacity[0];
		frame_data[0] = frame_data[1];
		frame_data[1] = frame_data[2];
		frame_data[2] = saved_data;
		frame_capacity[0] = frame_capacity[1];
		frame_capacity[1] = frame_capacity[2];
		frame_capacity[2] = saved_capacity;
		frame_length[0] = frame_length[1];
		frame_length[1] = frame_length[2];
		frame_channels[0] = frame_channels[1];
		frame_channels[1] = frame_channels[2];
		frame_position[0] = frame_position[1];
		frame_position[1] = frame_position[2];
		if(bytes > frame_capacity[2]){
			unsigned char *new_data = realloc(frame_data[2], bytes);
			if(new_data == NULL){
				mpg123_close(decoder);
				goto done;
			}
			frame_data[2] = new_data;
			frame_capacity[2] = bytes;
		}
		if(bytes != 0){
			memcpy(frame_data[2], audio, bytes);
		}
		frame_length[2] = bytes;
		frame_channels[2] = channels;
		frame_position[2] = mpg123_framepos64(decoder);
		decoded_frames++;
		if(decoded_frames < 3){
			continue;
		}

		while(seam_index + 1 < depth && frame_position[1] >= 0
			&& seams[seam_index] < (uint64_t)frame_position[1]){
			cost += 1000.0;
			seam_index++;
		}
		if(seam_index + 1 < depth
			&& frame_position[1] >= 0 && frame_position[2] >= 0
			&& (uint64_t)frame_position[1] <= seams[seam_index]
			&& seams[seam_index] < (uint64_t)frame_position[2]){
			Mp3SeamSignature signatures[3];
			bool signatures_valid = true;
			for(size_t i = 0; i < 3; i++){
				if(!mp3_build_seam_signature(frame_data[i], frame_length[i],
					frame_channels[i], &signatures[i])){
					signatures_valid = false;
					break;
				}
			}
			if(signatures_valid){
				const double left_cost = mp3_seam_signature_cost(
					&signatures[0], &signatures[1]);
				const double right_cost = mp3_seam_signature_cost(
					&signatures[1], &signatures[2]);
				cost += left_cost + right_cost;
				if(MP3_SCORE_TRACE){
					lock_fprintf(stdout,
						"MP3_SCORE_SEAM mode=%d path_mdct=%d left=%.17g right=%.17g\n",
						MP3_SCORE_MODE, MP3_PATH_SCORE_MDCT, left_cost, right_cost);
				}
			}
			else{
				cost += 1000.0;
			}
			seam_index++;
		}
	}
	mpg123_close(decoder);
	if(seam_index + 1 < depth){
		cost += 1000.0 * (double)(depth - 1 - seam_index);
	}
	*score = -cost;
	result = true;

	done:
	for(size_t i = 0; i < 3; i++){
		free(frame_data[i]);
	}
	free(seams);
	return result;
}

static double mp3_checksum_path_score(const char *data,
	uint64_t length,
	const Mp3CarveState *carve_state,
	const uint16_t *path,
	uint16_t depth,
	uint32_t blocksize){
	double score = 0.0;
	double seam_score;
	uint64_t fragment_start_block = 0;

	if(mp3_checksum_path_seam_score(data, length, carve_state, path, depth,
		blocksize, &seam_score)){
		return seam_score;
	}

	for(uint16_t path_index = 0; path_index + 1 < depth; path_index++){
		const Mp3Fragment *fragment =
			&carve_state->fragments[path[path_index]];
		Peak joined_left[6];
		Peak joined_right[6];
		bool joined_stereo = false;
		uint64_t frame_block;
		uint64_t frame_offset;
		uint64_t available;

		if(fragment->size == 0){
			return -INFINITY;
		}
		frame_block = fragment_start_block + fragment->size - 1;
		if(frame_block > UINT64_MAX / blocksize){
			return -INFINITY;
		}
		frame_offset = frame_block * blocksize
			+ fragment->lastFramePosition % blocksize;
		if(frame_offset >= length){
			return -INFINITY;
		}
		available = 2ULL * blocksize
			- fragment->lastFramePosition % blocksize;
		if(available > length - frame_offset){
			available = length - frame_offset;
		}
		if(available > INT_MAX){
			available = INT_MAX;
		}

		if(getPeaks((char *)data + frame_offset, (int)available,
			joined_left, joined_right, &joined_stereo)){
			score += 1.0 + mp3_stereo_score(fragment->peaks[0],
				fragment->peaks[1], fragment->peaksStereo,
				joined_left, joined_right, joined_stereo);
		}
		else{
			score -= 10.0;
		}
		fragment_start_block += fragment->size;
	}
	return score;
}

// Scores one possible extension using the complete reconstruction prefix. This gives
// mpg123 enough preceding audio to resolve the Layer III bit reservoir and lets the
// existing seam scorer evaluate every join that led to the current choice.
static bool mp3_reassembly_score_extension(CarveInfo *candidate,
	const Mp3CarveState *carve_state,
	uint16_t fragment_index,
	uint32_t blocksize,
	double *score){
	BlockVector *trial = NULL;
	uint16_t *path = NULL;
	const Mp3Fragment *fragment;
	uint64_t previous_blocks;
	bool result = false;

	if(candidate == NULL || candidate->b == NULL || carve_state == NULL
		|| score == NULL || blocksize == 0 || carve_state->cur_index == 0
		|| carve_state->cur_index == UINT16_MAX
		|| fragment_index >= carve_state->num_frags){
		return false;
	}
	fragment = &carve_state->fragments[fragment_index];
	previous_blocks = blockvector_get_num_blocks(candidate->b);
	if(fragment->size == 0 || fragment->size > UINT64_MAX - previous_blocks
		|| fragment->firstActBlock < 0
		|| fragment->size - 1 > (uint64_t)(INT64_MAX
			- fragment->firstActBlock)){
		return false;
	}

	clone_blockvector(candidate->b, &trial, false);
	resize_blockvector(trial, previous_blocks + fragment->size);
	for(uint64_t offset = 0; offset < fragment->size; offset++){
		blockvector_set_apparent_blocknumber(trial, previous_blocks + offset,
			filemirror_apparent_blocknumber(scalpel_state.filemirror,
				fragment->firstActBlock + (int64_t)offset));
	}
	blockvector_set_data_length_to_mapped_extent(trial);
	inflate_blockvector(trial);

	path = malloc(((size_t)carve_state->cur_index + 1) * sizeof(*path));
	check_memory_allocation(path, __LINE__, __FILE__, "MP3 extension path");
	memcpy(path, carve_state->indexes,
		(size_t)carve_state->cur_index * sizeof(*path));
	path[carve_state->cur_index] = fragment_index;
	*score = mp3_checksum_path_score(blockvector_get_data_pointer(trial),
		blockvector_get_data_length(trial), carve_state, path,
		carve_state->cur_index + 1, blocksize);
	result = isfinite(*score);

	free(path);
	free_blockvector(&trial);
	return result;
}

// A 16-bit MP3 music checksum can admit more than one structurally valid reconstruction.
// Preserve every such mapping when promising output is requested rather than allowing an
// audio-continuity tiebreaker to discard a potentially exact reconstruction.
static bool mp3_write_hypothesis(CarveInfo *candidate,
	BlockVector *trial,
	uint64_t length){
	if(!scalpel_state.write_promising || candidate == NULL
		|| candidate->b == NULL || trial == NULL || length == 0){
		return false;
	}

	BlockVector *parent_blockvector = candidate->b;
	BlockVector *hypothesis = NULL;
	BlockVector *padding_hypothesis = NULL;
	const uint64_t padding_length =
		mp3_build_terminal_zero_padding_hypothesis(trial, length,
			scalpel_state.blocksize, &padding_hypothesis);
	const CarveInfoFlavor parent_flavor = candidate->flavor;
	const uint64_t parent_validates_to = candidate->best_validates_to;
	const bool parent_no_initial_extension =
		candidate->no_initial_block_extension;

	clone_blockvector(trial, &hypothesis, true);
	blockvector_set_data_length(hypothesis, length);
	candidate->b = hypothesis;
	candidate->flavor = PROMISING;
	candidate->best_validates_to = length - 1;
	candidate->no_initial_block_extension = false;
	CarveInfo *preserved_candidate = candidate;
	write_candidate(&preserved_candidate, true);
	free_blockvector(&candidate->b);
	if(padding_length > length){
		clone_blockvector(padding_hypothesis, &hypothesis, true);
		blockvector_set_data_length(hypothesis, padding_length);
		candidate->b = hypothesis;
		candidate->best_validates_to = padding_length - 1;
		preserved_candidate = candidate;
		write_candidate(&preserved_candidate, true);
		free_blockvector(&candidate->b);
	}
	if(padding_hypothesis != NULL){
		free_blockvector(&padding_hypothesis);
	}
	candidate->b = parent_blockvector;
	candidate->flavor = parent_flavor;
	candidate->best_validates_to = parent_validates_to;
	candidate->no_initial_block_extension = parent_no_initial_extension;
	return true;
}

// A final MPEG frame may begin in a recognized MP3 block and continue into a
// block that has no independent frame header. Test only the physically adjacent
// block, and retain it only when strict parsing proves that it completes the
// compatible frame chain and advances the file extent into that block.
static bool mp3_reassembly_complete_terminal_frame(CarveInfo *candidate,
	uint32_t blocksize,
	ValidationArgs *validation){
	BlockVector *trial = NULL;
	ValidationArgs trial_validation = get_validation_args();
	uint64_t current_blocks;
	uint64_t current_length;
	uint64_t trial_length;
	uint64_t exact_length;
	uint64_t actual_blocks;
	uint64_t image_size;
	int64_t last_actual;
	int64_t next_actual;
	int64_t next_apparent;

	if(candidate == NULL || candidate->b == NULL || validation == NULL
		|| blocksize == 0){
		return false;
	}

	current_blocks = blockvector_get_num_blocks(candidate->b);
	current_length = blockvector_get_data_length(candidate->b);
	if(current_blocks == 0 || current_blocks > UINT64_MAX / blocksize
		|| current_length != current_blocks * blocksize){
		return false;
	}

	last_actual = blockvector_get_actual_blocknumber(candidate->b,
		current_blocks - 1);
	if(last_actual < 0 || last_actual == INT64_MAX){
		return false;
	}
	next_actual = last_actual + 1;
	image_size = filemirror_filesize(scalpel_state.filemirror);
	actual_blocks = image_size / blocksize
		+ ((image_size % blocksize) != 0);
	if((uint64_t)next_actual >= actual_blocks
		|| filemirror_actual_block_covered(scalpel_state.filemirror,
			next_actual)){
		return false;
	}
	next_apparent = filemirror_apparent_blocknumber(scalpel_state.filemirror,
		next_actual);
	if(next_apparent < 0){
		return false;
	}

	clone_blockvector(candidate->b, &trial, false);
	resize_blockvector(trial, current_blocks + 1);
	blockvector_set_apparent_blocknumber(trial, current_blocks,
		next_apparent);
	blockvector_set_data_length_to_mapped_extent(trial);
	inflate_blockvector(trial);
	trial_length = blockvector_get_data_length(trial);
	mp3_file_validate(blockvector_get_data_pointer(trial), trial_length,
		&trial_validation.validates, &trial_validation.validates_to,
		&trial_validation.promising, candidate->needleidx, blocksize, NULL);

	if((!trial_validation.validates && !trial_validation.promising)
		|| trial_validation.validates_to < current_length
		|| trial_validation.validates_to >= trial_length){
		free_blockvector(&trial);
		return false;
	}
	exact_length = trial_validation.validates_to + 1;
	if(!mp3_complete_compatible_frame_prefix(
		blockvector_get_data_pointer(trial), exact_length)){
		free_blockvector(&trial);
		return false;
	}

	blockvector_set_data_length(trial, exact_length);
	free_blockvector(&candidate->b);
	candidate->b = trial;
	candidate->best_validates_to = trial_validation.validates_to;
	*validation = trial_validation;
	return true;
}

// Preserve a physically adjacent final-frame completion without covering its
// blocks. Frame syntax alone does not prove that the adjoining payload belongs
// to this file, so retain the original prefix as well as the longer hypothesis.
static bool mp3_preserve_single_fragment_tail(CarveInfo *candidate,
	uint32_t blocksize) {
	if (!scalpel_state.write_promising || candidate == NULL
		|| candidate->b == NULL || blocksize == 0) {
		return false;
	}
	CarveInfo trial = *candidate;
	trial.b = NULL;
	clone_blockvector(candidate->b, &trial.b, false);
	ValidationArgs validation = get_validation_args();
	bool preserved = false;
	if (mp3_reassembly_complete_terminal_frame(&trial, blocksize,
		&validation)) {
		preserved = mp3_write_hypothesis(candidate, trial.b,
			blockvector_get_data_length(trial.b));
	}
	free_blockvector(&trial.b);
	return preserved;
}

// MP3 has no file-level length field, but a partial zero run at the start of
// the adjacent physical block provides a reviewable terminal-padding boundary.
// Build that alternative without treating the padding as format-validated
// content; the caller preserves both the shorter and padded hypotheses.
static uint64_t mp3_build_terminal_zero_padding_hypothesis(
	BlockVector *source,
	uint64_t prefix_length,
	uint32_t blocksize,
	BlockVector **trial){
	uint64_t prefix_blocks;
	uint64_t trial_length;
	uint64_t padding_length = 0;
	uint64_t image_blocks;
	uint64_t image_size;
	uint64_t next_block_length = 0;
	int64_t last_actual;
	int64_t next_actual;
	int64_t next_apparent;
	const uint8_t *next_block;
	if(source == NULL || trial == NULL || *trial != NULL || blocksize == 0
		|| prefix_length == 0 || prefix_length % blocksize != 0){
		return 0;
	}

	prefix_blocks = prefix_length / blocksize;
	if(prefix_blocks == 0
		|| prefix_blocks > blockvector_get_num_blocks(source)){
		return 0;
	}

	last_actual = blockvector_get_actual_blocknumber(source,
		prefix_blocks - 1);
	if(last_actual < 0 || last_actual == INT64_MAX){
		return 0;
	}
	next_actual = last_actual + 1;
	image_size = filemirror_filesize(scalpel_state.filemirror);
	image_blocks = image_size / blocksize
		+ ((image_size % blocksize) != 0);
	if((uint64_t)next_actual >= image_blocks
		|| filemirror_actual_location_covered(scalpel_state.filemirror,
			(uint64_t)next_actual * blocksize)){
		return 0;
	}
	next_apparent = filemirror_apparent_blocknumber(scalpel_state.filemirror,
		next_actual);
	if(next_apparent < 0){
		return 0;
	}
	next_block = (const uint8_t *)filemirror_actual_block_data_pointer(
		scalpel_state.filemirror, next_actual, &next_block_length);
	if(next_block == NULL || next_block_length < blocksize){
		return 0;
	}
	while(padding_length < blocksize && next_block[padding_length] == 0){
		padding_length++;
	}
	if(padding_length < MP3_MINIMUM_TERMINAL_ZERO_PADDING_BYTES
		|| padding_length == blocksize){
		return 0;
	}

	clone_blockvector(source, trial, false);
	resize_blockvector(*trial, prefix_blocks + 1);
	blockvector_set_apparent_blocknumber(*trial, prefix_blocks,
		next_apparent);
	blockvector_set_data_length_to_mapped_extent(*trial);
	inflate_blockvector(*trial);
	trial_length = blockvector_get_data_length(*trial);
	if(trial_length < prefix_length
		|| trial_length - prefix_length < blocksize){
		goto done;
	}

	return prefix_length + padding_length;

done:
	free_blockvector(trial);
	return 0;
}

static bool mp3_preserve_terminal_zero_padding_hypothesis(
	CarveInfo *candidate,
	BlockVector *source,
	uint64_t prefix_length,
	uint32_t blocksize){
	BlockVector *trial = NULL;
	const uint64_t padded_length =
		mp3_build_terminal_zero_padding_hypothesis(source, prefix_length,
			blocksize, &trial);
	if(padded_length == 0){
		return false;
	}
	const bool preserved = mp3_write_hypothesis(candidate, trial,
		padded_length);
	free_blockvector(&trial);
	return preserved;
}

static bool mp3_fragment_ranges_overlap(const Mp3Fragment *left,
	const Mp3Fragment *right){
	return left != NULL && right != NULL
		&& left->firstActBlock <= right->lastActBlock
		&& right->firstActBlock <= left->lastActBlock;
}

static uint64_t mp3_hypothesis_extent(const char *data,
	uint64_t data_length,
	const ValidationArgs *validation,
	const Mp3Fragment *last_fragment,
	uint32_t blocksize) {
	if (data == NULL || validation == NULL || blocksize == 0
		|| data_length == 0
		|| (!validation->validates && !validation->promising)) {
		return 0;
	}

	uint64_t extent = 0;
	const uint64_t validated_length = validation->validates_to < data_length
		? validation->validates_to + 1 : data_length;
	if (validation->validates) {
		extent = validated_length;
	}
	else if (last_fragment != NULL
		&& validation->validates_to < data_length
		&& (last_fragment->isTail
			|| data_length - validated_length < blocksize)
		&& mp3_complete_compatible_frame_prefix(data, validated_length)) {
		// A complete chain followed by final-sector slack is still useful
		// PROMISING output, even without proof that this fragment is a tail.
		extent = validated_length;
	}

	uint64_t tag_offset = 0;
	uint64_t tag_end = 0;
	const uint64_t tag_search_start = data_length > blocksize
		? data_length - blocksize : 0;
	const bool projected_frame_reaches_tag = validation->promising
		&& last_fragment != NULL
		&& last_fragment->rearOffset > 0;
	if (mp3_find_terminal_id3v1(data, data_length, tag_search_start,
		data_length, false, &tag_offset, &tag_end)
		&& (validation->validates || tag_offset >= validated_length
			|| (projected_frame_reaches_tag
				&& validation->validates_to >= tag_offset))
		&& data_length - tag_end < blocksize) {
		extent = tag_end;
	}
	return extent;
}

static bool mp3_preserve_direct_path(CarveInfo *candidate,
	const Mp3CarveState *carve_state,
	const uint16_t *path,
	uint16_t path_length,
	uint32_t blocksize,
	BlockVector *trial){
	uint64_t total_blocks = 0;
	uint64_t position = 0;

	if(candidate == NULL || carve_state == NULL || path == NULL
		|| path_length == 0 || blocksize == 0 || trial == NULL){
		return false;
	}
	for(uint16_t index = 0; index < path_length; index++){
		if(path[index] >= carve_state->num_frags){
			return false;
		}
		const Mp3Fragment *fragment =
			&carve_state->fragments[path[index]];
		if(index > 0 && !mp3_reassembly_fragment_boundaries_match(
			&carve_state->fragments[path[index - 1]], fragment)){
			return false;
		}
		if(fragment->size == 0 || fragment->firstActBlock < 0
			|| fragment->lastActBlock < fragment->firstActBlock
			|| fragment->size > UINT64_MAX - total_blocks){
			return false;
		}
		for(uint16_t prior = 0; prior < index; prior++){
			if(mp3_fragment_ranges_overlap(fragment,
				&carve_state->fragments[path[prior]])){
				return false;
			}
		}
		total_blocks += fragment->size;
	}
	if(total_blocks > UINT64_MAX / blocksize
		|| total_blocks * (uint64_t)blocksize
			> scalpel_state.search_specs[candidate->needleidx].MAXIMUMSIZE){
		return false;
	}

	resize_blockvector(trial, total_blocks);
	for(uint16_t index = 0; index < path_length; index++){
		const Mp3Fragment *fragment =
			&carve_state->fragments[path[index]];
		for(int64_t actual = fragment->firstActBlock;
			actual <= fragment->lastActBlock; actual++){
			if(filemirror_actual_block_covered(scalpel_state.filemirror, actual)){
				return false;
			}
			const int64_t apparent = filemirror_apparent_blocknumber(
				scalpel_state.filemirror, actual);
			if(apparent < 0){
				return false;
			}
			blockvector_set_apparent_blocknumber(trial, position++, apparent);
		}
	}

	blockvector_set_data_length_to_mapped_extent(trial);
	inflate_blockvector(trial);
	if (path_length == 1) {
		// Test the physical run's endpoint before considering uncertain joins.
		// Keep its adjacent tail as PROMISING without changing the candidate.
		CarveInfo prefix = *candidate;
		prefix.b = trial;
		const bool preserved = mp3_preserve_single_fragment_tail(&prefix,
			blocksize);
		deflate_blockvector(trial);
		return preserved;
	}
	ValidationArgs validation = get_validation_args();
	mp3_file_validate(blockvector_get_data_pointer(trial),
		blockvector_get_data_length(trial), &validation.validates,
		&validation.validates_to, &validation.promising,
		candidate->needleidx, blocksize, NULL);
	const uint64_t data_length = blockvector_get_data_length(trial);
	const Mp3Fragment *last_fragment =
		&carve_state->fragments[path[path_length - 1]];
	const uint64_t preserved_length = mp3_hypothesis_extent(
		blockvector_get_data_pointer(trial), data_length, &validation,
		last_fragment, blocksize);
	const bool preserved = preserved_length > 0
		&& mp3_write_hypothesis(candidate, trial, preserved_length);
	deflate_blockvector(trial);
	return preserved;
}

// Identify the ordered physical fragments used by a search. Coverage changes
// can trim, split, or remove fragments before reentry, invalidating its cursors.
static uint64_t mp3_fragment_search_signature(const Mp3CarveState *state,
	uint32_t blocksize){
	uint64_t signature = UINT64_C(1469598103934665603);
	signature = (signature ^ blocksize) * UINT64_C(1099511628211);
	signature = (signature ^ state->num_frags) * UINT64_C(1099511628211);
	for(uint16_t i = 0; i < state->num_frags; i++){
		const Mp3Fragment *fragment = &state->fragments[i];
		const uint64_t fields[] = {
			(uint64_t)fragment->firstActBlock,
			(uint64_t)fragment->lastActBlock, fragment->size,
			fragment->frontOffset, fragment->rearOffset,
			fragment->frontFrameHeaderBreak, fragment->rearFrameHeaderBreak,
			fragment->frontHeaderContext.mpegVersion,
			fragment->frontHeaderContext.layer,
			fragment->frontHeaderContext.samplingrate,
			fragment->rearHeaderContext.mpegVersion,
			fragment->rearHeaderContext.layer,
			fragment->rearHeaderContext.samplingrate,
			fragment->isHeader, fragment->isTail,
			fragment->preserveFrontContext,
			fragment->secondToLastFramePosition,
			fragment->lastFramePosition, fragment->offsetFramePosition
		};
		for(size_t j = 0; j < sizeof(fields) / sizeof(fields[0]); j++){
			signature = (signature ^ fields[j]) * UINT64_C(1099511628211);
		}
	}
	return signature;
}

// A greedy frontier belongs to one committed prefix and ordered available catalog.
static uint64_t mp3_greedy_search_signature(const Mp3CarveState *state,
	uint32_t blocksize){
	uint64_t signature = mp3_fragment_search_signature(state, blocksize);
	signature = (signature ^ state->cur_index) * UINT64_C(1099511628211);
	for(uint16_t i = 0; i < state->cur_index; i++){
		signature = (signature ^ state->indexes[i]) * UINT64_C(1099511628211);
	}
	for(uint16_t i = 0; i < state->num_frags; i++){
		signature = (signature ^ state->fragments[i].active) * UINT64_C(1099511628211);
	}
	return signature;
}

// Coverage changes can remove/split fragments; only the affected frontier resets.
static bool mp3_greedy_search_resume(Mp3CarveState *state, uint32_t blocksize){
	if(state->greedy.phase == MP3_GREEDY_INACTIVE){
		return false;
	}
	if(state->greedy.signature != mp3_greedy_search_signature(state, blocksize)){
		memset(&state->greedy, 0, sizeof(state->greedy));
		return false;
	}
	return true;
}

static void mp3_greedy_search_begin(Mp3CarveState *state, uint32_t blocksize,
	uint32_t phase){
	memset(&state->greedy, 0, sizeof(state->greedy));
	state->greedy.signature = mp3_greedy_search_signature(state, blocksize);
	state->greedy.phase = phase;
	state->greedy.best_index = -1;
}

// Test the initial run's endpoint, then direct one- and two-fragment continuations.
// Matching frame offsets define possible joins, and the complete file parser
// remains the acceptance gate for every preserved hypothesis.
static Mp3StructuralSearchResult mp3_reassembly_preserve_direct_paths(
	ThreadWork *work,
	CarveInfo *candidate,
	Mp3CarveState *carve_state,
	uint32_t blocksize,
	uuid_string_t uuidp,
	uuid_string_t uuidc){
	BlockVector *trial = NULL;
	uint16_t path[3] = {0, 0, 0};

	if(!scalpel_state.write_promising || work == NULL || candidate == NULL
		|| candidate->b == NULL || carve_state == NULL
		|| carve_state->fragments == NULL || carve_state->num_frags < 2
		|| blocksize == 0){
		return MP3_STRUCTURAL_SEARCH_NOT_APPLICABLE;
	}

	const uint64_t signature = mp3_fragment_search_signature(carve_state,
		blocksize);
	if(carve_state->direct_signature != signature){
		carve_state->direct_signature = signature;
		carve_state->direct_first = 0;
		carve_state->direct_second = 0;
		carve_state->direct_search_complete = false;
	}
	if(carve_state->direct_search_complete){
		return MP3_STRUCTURAL_SEARCH_COMPLETE;
	}
	init_blockvector(scalpel_state.filemirror, &trial, 1, true);
	const Mp3Fragment *header = &carve_state->fragments[0];
	while(carve_state->direct_first < carve_state->num_frags){
		if(carve_state->direct_second == 0
			&& atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)
			&& reassembly_time_to_checkpoint(work->id, candidate, uuidp, uuidc)){
			free_blockvector(&trial);
			return MP3_STRUCTURAL_SEARCH_CHECKPOINT;
		}
		if (carve_state->direct_first == 0) {
			(void)mp3_preserve_direct_path(candidate, carve_state, path, 1,
				blocksize, trial);
			carve_state->direct_first = 1;
			continue;
		}
		const uint16_t first = (uint16_t)carve_state->direct_first;
		const Mp3Fragment *first_fragment = &carve_state->fragments[first];
		if(!mp3_reassembly_fragment_boundaries_match(header, first_fragment)
			|| mp3_fragment_ranges_overlap(header, first_fragment)){
			carve_state->direct_first++;
			carve_state->direct_second = 0;
			continue;
		}
		path[1] = first;
		if(carve_state->direct_second == 0){
			(void)mp3_preserve_direct_path(candidate, carve_state, path, 2,
				blocksize, trial);
			carve_state->direct_second = 1;
		}

		while(carve_state->direct_second < carve_state->num_frags){
			if(atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)
				&& reassembly_time_to_checkpoint(work->id, candidate, uuidp, uuidc)){
				free_blockvector(&trial);
				return MP3_STRUCTURAL_SEARCH_CHECKPOINT;
			}
			const uint16_t second = (uint16_t)carve_state->direct_second++;
			const Mp3Fragment *second_fragment =
				&carve_state->fragments[second];
			if(second == first
				|| !mp3_reassembly_fragment_boundaries_match(first_fragment,
					second_fragment)
				|| mp3_fragment_ranges_overlap(header, second_fragment)
				|| mp3_fragment_ranges_overlap(first_fragment,
					second_fragment)){
				continue;
			}
			path[2] = second;
			(void)mp3_preserve_direct_path(candidate, carve_state, path, 3,
				blocksize, trial);
		}

		carve_state->direct_first++;
		carve_state->direct_second = 0;
	}
	carve_state->direct_search_complete = true;
	free_blockvector(&trial);
	return MP3_STRUCTURAL_SEARCH_COMPLETE;
}

// Preserves complete reconstructions built from the physically local run and
// one displaced fragment for each offset mismatch in that run. MP3 frame
// syntax can leave several such reconstructions indistinguishable, so every
// parser-valid result is reviewable when promising output is requested. The
// mixed-radix cursor is checkpointed in Mp3CarveState.
static Mp3StructuralSearchResult mp3_reassembly_preserve_structural_paths(
	ThreadWork *work,
	CarveInfo *candidate,
	Mp3CarveState *carve_state,
	uint32_t blocksize,
	uuid_string_t uuidp,
	uuid_string_t uuidc){
	Mp3ChecksumFragmentOrder *local_order = NULL;
	Mp3ChecksumFragmentOrder *choice_order = NULL;
	Mp3StructuralGap *gaps = NULL;
	BlockVector *trial = NULL;
	uint16_t *path = NULL;
	bool *path_used = NULL;
	uint16_t local_count = 0;
	uint16_t gap_count = 0;
	uint16_t tail_index = UINT16_MAX;
	uint64_t tail_start = UINT64_MAX;
	uint64_t combination_count = 1;
	uint64_t signature = UINT64_C(1469598103934665603);
	Mp3StructuralSearchResult result =
		MP3_STRUCTURAL_SEARCH_NOT_APPLICABLE;

	if(!scalpel_state.write_promising || work == NULL || candidate == NULL
		|| candidate->b == NULL || carve_state == NULL
		|| carve_state->fragments == NULL || carve_state->num_frags < 2
		|| blocksize == 0){
		return result;
	}

	const Mp3Fragment *header = &carve_state->fragments[0];
	if(header->firstActBlock < 0 || header->lastActBlock < header->firstActBlock){
		return result;
	}
	for(uint16_t i = 1; i < carve_state->num_frags; i++){
		const Mp3Fragment *fragment = &carve_state->fragments[i];
		if(fragment->isTail && fragment->firstActBlock > header->lastActBlock
			&& fragment->lastActBlock >= fragment->firstActBlock
			&& (uint64_t)fragment->firstActBlock < tail_start){
			tail_start = (uint64_t)fragment->firstActBlock;
			tail_index = i;
		}
	}
	if(tail_index == UINT16_MAX){
		return result;
	}

	local_order = calloc(carve_state->num_frags, sizeof(*local_order));
	check_memory_allocation(local_order, __LINE__, __FILE__,
		"MP3 structural local order");
	for(uint16_t i = 0; i < carve_state->num_frags; i++){
		const Mp3Fragment *fragment = &carve_state->fragments[i];
		const Mp3Fragment *tail = &carve_state->fragments[tail_index];
		const bool in_local_span = fragment->firstActBlock
			>= header->firstActBlock
			&& fragment->lastActBlock >= fragment->firstActBlock
			&& fragment->lastActBlock <= tail->lastActBlock;
		const bool overlaps_tail = i != tail_index
			&& fragment->firstActBlock <= tail->lastActBlock
			&& fragment->lastActBlock >= tail->firstActBlock;

		if(i == 0 || i == tail_index
			|| (in_local_span && !fragment->isHeader && !overlaps_tail)){
			local_order[local_count].index = i;
			local_order[local_count].distance =
				(uint64_t)fragment->firstActBlock;
			local_count++;
		}
	}
	qsort(local_order, local_count, sizeof(*local_order),
		mp3_checksum_fragment_order_compare);
	if(local_count < 2 || local_order[0].index != 0
		|| local_order[local_count - 1].index != tail_index){
		goto done;
	}
	for(uint16_t i = 0; i + 1 < local_count; i++){
		const Mp3Fragment *left = &carve_state->fragments[
			local_order[i].index];
		const Mp3Fragment *right = &carve_state->fragments[
			local_order[i + 1].index];
		if(left->lastActBlock >= right->firstActBlock){
			goto done;
		}
		if(!mp3_reassembly_fragment_boundaries_match(left, right)){
			gap_count++;
		}
	}

	gaps = calloc(gap_count == 0 ? 1 : gap_count, sizeof(*gaps));
	check_memory_allocation(gaps, __LINE__, __FILE__,
		"MP3 structural gaps");
	choice_order = calloc(carve_state->num_frags, sizeof(*choice_order));
	check_memory_allocation(choice_order, __LINE__, __FILE__,
		"MP3 structural choice order");

	uint16_t gap_index = 0;
	for(uint16_t local_position = 0;
		local_position + 1 < local_count; local_position++){
		const Mp3Fragment *left = &carve_state->fragments[
			local_order[local_position].index];
		const Mp3Fragment *right = &carve_state->fragments[
			local_order[local_position + 1].index];
		uint16_t choice_count = 0;

		if(mp3_reassembly_fragment_boundaries_match(left, right)){
			continue;
		}
		for(uint16_t i = 1; i < carve_state->num_frags; i++){
			const Mp3Fragment *fragment = &carve_state->fragments[i];
			const bool outside_local_span = fragment->lastActBlock
				< header->firstActBlock
				|| fragment->firstActBlock
					> carve_state->fragments[tail_index].lastActBlock;

			if(i == tail_index || !outside_local_span || fragment->isTail
				|| fragment->firstActBlock < 0
				|| fragment->lastActBlock < fragment->firstActBlock
				|| !mp3_reassembly_fragment_boundaries_match(left, fragment)
				|| !mp3_reassembly_fragment_boundaries_match(fragment, right)){
				continue;
			}
			choice_order[choice_count].index = i;
			choice_order[choice_count].distance =
				(uint64_t)fragment->firstActBlock;
			choice_count++;
		}
		if(choice_count == 0){
			goto done;
		}
		qsort(choice_order, choice_count, sizeof(*choice_order),
			mp3_checksum_fragment_order_compare);
		gaps[gap_index].local_position = local_position;
		gaps[gap_index].choice_count = choice_count;
		gaps[gap_index].choices = calloc(choice_count,
			sizeof(*gaps[gap_index].choices));
		check_memory_allocation(gaps[gap_index].choices, __LINE__, __FILE__,
			"MP3 structural gap choices");
		for(uint16_t i = 0; i < choice_count; i++){
			gaps[gap_index].choices[i] = choice_order[i].index;
		}
		if(combination_count > UINT64_MAX / choice_count){
			if(scalpel_state.mode_verbose){
				lock_fprintf(stdout,
					"MP3 structural search skipped: combination count overflow.\n");
			}
			goto done;
		}
		combination_count *= choice_count;
		gap_index++;
	}

	// Hash the ordered local skeleton and all ordered alternatives. A blockmap
	// change resets the cursor rather than applying it to a different search.
	signature ^= carve_state->num_frags;
	signature *= UINT64_C(1099511628211);
	for(uint16_t i = 0; i < local_count; i++){
		const Mp3Fragment *fragment = &carve_state->fragments[
			local_order[i].index];
		signature ^= (uint64_t)fragment->firstActBlock;
		signature *= UINT64_C(1099511628211);
		signature ^= (uint64_t)fragment->lastActBlock;
		signature *= UINT64_C(1099511628211);
		signature ^= ((uint64_t)fragment->frontOffset << 16)
			| fragment->rearOffset;
		signature *= UINT64_C(1099511628211);
	}
	for(uint16_t i = 0; i < gap_count; i++){
		signature ^= gaps[i].local_position;
		signature *= UINT64_C(1099511628211);
		for(uint16_t j = 0; j < gaps[i].choice_count; j++){
			const Mp3Fragment *fragment = &carve_state->fragments[
				gaps[i].choices[j]];
			signature ^= (uint64_t)fragment->firstActBlock;
			signature *= UINT64_C(1099511628211);
			signature ^= (uint64_t)fragment->lastActBlock;
			signature *= UINT64_C(1099511628211);
		}
	}
	if(carve_state->structural_signature != signature){
		carve_state->structural_signature = signature;
		carve_state->structural_next_combination = 0;
		carve_state->structural_search_complete = false;
	}
	if(carve_state->structural_search_complete){
		result = MP3_STRUCTURAL_SEARCH_COMPLETE;
		goto done;
	}

	path = calloc((size_t)local_count + gap_count, sizeof(*path));
	path_used = calloc(carve_state->num_frags, sizeof(*path_used));
	check_memory_allocation(path, __LINE__, __FILE__,
		"MP3 structural path");
	check_memory_allocation(path_used, __LINE__, __FILE__,
		"MP3 structural path usage");
	init_blockvector(scalpel_state.filemirror, &trial, 1, true);

	for(uint64_t combination = carve_state->structural_next_combination;
		combination < combination_count; combination++){
		uint64_t selector = combination;
		uint16_t path_depth = 0;
		uint16_t current_gap = 0;
		uint64_t total_blocks = 0;
		bool path_valid = true;

		memset(path_used, 0,
			carve_state->num_frags * sizeof(*path_used));
		for(uint16_t i = 0; i < local_count; i++){
			const uint16_t local_fragment = local_order[i].index;
			path[path_depth++] = local_fragment;
			path_used[local_fragment] = true;
			if(current_gap < gap_count
				&& gaps[current_gap].local_position == i){
				const uint16_t choice_position =
					(uint16_t)(selector % gaps[current_gap].choice_count);
				const uint16_t chosen =
					gaps[current_gap].choices[choice_position];
				selector /= gaps[current_gap].choice_count;
				if(path_used[chosen]){
					path_valid = false;
					break;
				}
				path[path_depth++] = chosen;
				path_used[chosen] = true;
				current_gap++;
			}
		}

		for(uint16_t i = 0; path_valid && i < path_depth; i++){
			const Mp3Fragment *fragment =
				&carve_state->fragments[path[i]];
			if(fragment->size == 0
				|| fragment->size > UINT64_MAX - total_blocks){
				path_valid = false;
				break;
			}
			total_blocks += fragment->size;
		}
		if(path_valid
			&& (total_blocks > UINT64_MAX / blocksize
				|| total_blocks * (uint64_t)blocksize
					> scalpel_state.search_specs[
						candidate->needleidx].MAXIMUMSIZE)){
			path_valid = false;
		}

		if(path_valid){
			uint64_t position = 0;
			resize_blockvector(trial, total_blocks);
			for(uint16_t i = 0; i < path_depth && path_valid; i++){
				const Mp3Fragment *fragment =
					&carve_state->fragments[path[i]];
				for(int64_t actual = fragment->firstActBlock;
					actual <= fragment->lastActBlock; actual++){
					if(filemirror_actual_block_covered(
						scalpel_state.filemirror, actual)){
						path_valid = false;
						break;
					}
					blockvector_set_apparent_blocknumber(trial, position++,
						filemirror_apparent_blocknumber(
							scalpel_state.filemirror, actual));
				}
			}
			if(path_valid && position == total_blocks){
				ValidationArgs validation = get_validation_args();
				blockvector_set_data_length_to_mapped_extent(trial);
				inflate_blockvector(trial);
				mp3_file_validate(blockvector_get_data_pointer(trial),
					blockvector_get_data_length(trial),
					&validation.validates, &validation.validates_to,
					&validation.promising, candidate->needleidx,
					blocksize, NULL);
				const Mp3Fragment *last_fragment = path_depth > 0
					? &carve_state->fragments[path[path_depth - 1]] : NULL;
				const uint64_t extent = mp3_hypothesis_extent(
					blockvector_get_data_pointer(trial),
					blockvector_get_data_length(trial), &validation,
					last_fragment, blocksize);
				if(extent > 0){
					(void)mp3_write_hypothesis(candidate, trial,
						extent);
				}
				deflate_blockvector(trial);
			}
		}

		carve_state->structural_next_combination = combination + 1;
		if(atomic_load_explicit(&REASS_RETURN_TO_IDLE,
			memory_order_acquire)
			&& reassembly_time_to_checkpoint(work->id, candidate,
				uuidp, uuidc)){
			result = MP3_STRUCTURAL_SEARCH_CHECKPOINT;
			goto done;
		}
	}
	carve_state->structural_search_complete = true;
	result = MP3_STRUCTURAL_SEARCH_COMPLETE;
	if(scalpel_state.mode_verbose){
		lock_fprintf(stdout,
			"MP3 structural search complete: local_fragments=%u gaps=%u "
			"combinations=%"PRIu64".\n",
			local_count, gap_count, combination_count);
	}

	done:
	if(trial != NULL){
		free_blockvector(&trial);
	}
	free(path_used);
	free(path);
	if(gaps != NULL){
		for(uint16_t i = 0; i < gap_count; i++){
			free(gaps[i].choices);
		}
	}
	free(gaps);
	free(choice_order);
	free(local_order);
	return result;
}

static Mp3ChecksumSearchResult mp3_reassembly_find_checksum_path(
	ThreadWork *work,
	CarveInfo *candidate,
	Mp3CarveState *carve_state,
	uint32_t blocksize,
	uuid_string_t uuidp,
	uuid_string_t uuidc){
	Mp3XingChecksum expected_checksum;
	BlockVector *trial = NULL;
	uint16_t *path = NULL;
	uint16_t *best_path = NULL;
	uint32_t *next_choice = NULL;
	uint64_t *blocks_at_depth = NULL;
	uint16_t *crc_at_depth = NULL;
	bool *used = NULL;
	uint8_t *transform_flags = NULL;
	Mp3ChecksumFragmentOrder *search_order = NULL;
	Mp3ChecksumCrcTransform *full_transforms = NULL;
	Mp3ChecksumCrcTransform *tail_transforms = NULL;
	uint64_t target_blocks;
	uint64_t trailing_bytes;
	uint16_t header_crc;
	bool stop_search = false;
	bool checksum_available;
	bool candidate_checksum_matches;
	Mp3ChecksumSearchResult result = MP3_CHECKSUM_SEARCH_NOT_FOUND;

	if(work == NULL || candidate == NULL || candidate->b == NULL
		|| carve_state == NULL || carve_state->num_frags < 2
		|| carve_state->fragments == NULL || carve_state->indexes == NULL
		|| blocksize == 0){
		return result;
	}
	Mp3ChecksumState *search = &carve_state->checksum;
	checksum_available = mp3_get_xing_checksum(
		blockvector_get_data_pointer(candidate->b),
		blockvector_get_data_length(candidate->b), &expected_checksum);
	candidate_checksum_matches = checksum_available
		&& expected_checksum.present
		&& mp3_xing_checksum_matches(blockvector_get_data_pointer(candidate->b),
			blockvector_get_data_length(candidate->b), &expected_checksum);
	if(!checksum_available || !expected_checksum.present
		|| candidate_checksum_matches){
		if(scalpel_state.mode_verbose){
			lock_fprintf(stdout,
				"MP3 checksum search skipped: available=%u present=%u "
				"matches=%u fragments=%u blocks=%"PRIu64".\n",
				checksum_available, expected_checksum.present,
				candidate_checksum_matches, carve_state->num_frags,
				blockvector_get_num_blocks(candidate->b));
		}
		return result;
	}
	target_blocks = expected_checksum.audio_end / blocksize;
	if(expected_checksum.audio_end % blocksize != 0){
		target_blocks++;
	}
	if(target_blocks == 0
		|| carve_state->fragments[0].size > target_blocks){
		return result;
	}
	trailing_bytes = expected_checksum.audio_end % blocksize;
	if(trailing_bytes != 0){
		trailing_bytes = blocksize - trailing_bytes;
	}

	used = calloc(carve_state->num_frags, sizeof(*used));
	search_order = calloc(carve_state->num_frags, sizeof(*search_order));
	check_memory_allocation(used, __LINE__, __FILE__, "MP3 checksum used fragments");
	check_memory_allocation(search_order, __LINE__, __FILE__, "MP3 checksum order");
	init_blockvector(scalpel_state.filemirror, &trial, target_blocks, true);

	Mp3Fragment *header = &carve_state->fragments[0];
	for(uint16_t i = 0; i < carve_state->num_frags; i++){
		Mp3Fragment *fragment = &carve_state->fragments[i];
		search_order[i].index = i;
		if(fragment->lastActBlock < header->firstActBlock){
			search_order[i].distance = (uint64_t)(header->firstActBlock
				- fragment->lastActBlock);
		}
		else if(fragment->firstActBlock > header->lastActBlock){
			search_order[i].distance = (uint64_t)(fragment->firstActBlock
				- header->lastActBlock);
		}
		else{
			search_order[i].distance = 0;
		}
	}
	qsort(search_order, carve_state->num_frags, sizeof(*search_order),
		mp3_checksum_fragment_order_compare);
	uint32_t local_search_limit = 0;
	while(local_search_limit < carve_state->num_frags
		&& search_order[local_search_limit].distance <= target_blocks){
		local_search_limit++;
	}
	if(scalpel_state.mode_verbose){
		lock_fprintf(stdout,
			"MP3 checksum search: fragments=%u eligible=%u target_blocks=%"PRIu64
			" header_blocks=%zu audio_end=%"PRIu64".\n",
			carve_state->num_frags, local_search_limit, target_blocks,
			carve_state->fragments[0].size, expected_checksum.audio_end);
	}

	uint64_t audio_start = expected_checksum.first_frame_offset
		+ expected_checksum.first_frame_length;
	uint64_t header_length = blockvector_get_data_length(candidate->b);
	uint64_t header_crc_end = header_length;
	if(header_crc_end > expected_checksum.audio_end){
		header_crc_end = expected_checksum.audio_end;
	}
	if(header_crc_end <= audio_start){
		goto done;
	}
	header_crc = mp3_audio_crc16_update(0,
		(const unsigned char *)blockvector_get_data_pointer(candidate->b)
			+ audio_start,
		header_crc_end - audio_start);

	uint64_t signature = mp3_fragment_search_signature(carve_state, blocksize);
	const uint64_t checksum_fields[] = {expected_checksum.audio_end,
		expected_checksum.first_frame_offset, expected_checksum.first_frame_length,
		expected_checksum.audio_crc, header_crc};
	for(size_t i = 0; i < sizeof(checksum_fields) / sizeof(checksum_fields[0]); i++){
		signature = (signature ^ checksum_fields[i]) * UINT64_C(1099511628211);
	}
	if(search->count == 0 || search->signature != signature){
		mp3_checksum_state_free(search);
		search->signature = signature;
		search->count = carve_state->num_frags;
		search->phase = MP3_CHECKSUM_PREPARE;
		search->search_limit = local_search_limit;
		search->rank_all_matches = true;
		search->best_score = -INFINITY;
		mp3_checksum_state_allocate(search);
	}
	path = search->path;
	best_path = search->best_path;
	next_choice = search->next_choice;
	blocks_at_depth = search->blocks_at_depth;
	crc_at_depth = search->crc_at_depth;
	transform_flags = search->transform_flags;
	full_transforms = search->full_transforms;
	tail_transforms = search->tail_transforms;
	if(search->phase == MP3_CHECKSUM_COMPLETE){
		goto checksum_search_finished;
	}

	if(search->phase == MP3_CHECKSUM_PREPARE){
		for(uint32_t order_position = search->prepare_next;
			order_position < carve_state->num_frags; order_position++){
			if(atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)
				&& reassembly_time_to_checkpoint(work->id, candidate, uuidp, uuidc)){
				result = MP3_CHECKSUM_SEARCH_CHECKPOINT;
				goto done;
			}
			search->prepare_next = order_position + 1;
			uint16_t fragment_index = search_order[order_position].index;
			Mp3Fragment *fragment = &carve_state->fragments[fragment_index];
			uint64_t fragment_length;
			bool complete = true;

			if(fragment_index == 0 || transform_flags[fragment_index]
				|| fragment->size == 0
				|| fragment->size > UINT64_MAX / blocksize){
				continue;
			}
			fragment_length = fragment->size * (uint64_t)blocksize;
			if(fragment_length < trailing_bytes){
				continue;
			}
			resize_blockvector(trial, fragment->size);
			for(uint64_t position = 0; position < fragment->size; position++){
				int64_t actual = fragment->firstActBlock + (int64_t)position;
				if(filemirror_actual_block_covered(scalpel_state.filemirror,
					actual)){
					complete = false;
					break;
				}
				blockvector_set_apparent_blocknumber(trial, position,
					filemirror_apparent_blocknumber(scalpel_state.filemirror,
						actual));
			}
			if(!complete){
				continue;
			}
			blockvector_set_data_length_to_mapped_extent(trial);
			inflate_blockvector(trial);
			const unsigned char *data =
				(const unsigned char *)blockvector_get_data_pointer(trial);
			const uint64_t tail_length = fragment_length - trailing_bytes;
			const uint64_t available_length = blockvector_get_data_length(trial);
			if(tail_length > available_length){
				deflate_blockvector(trial);
				continue;
			}
			mp3_checksum_build_crc_transform(
				data, tail_length,
				&tail_transforms[fragment_index]);
			transform_flags[fragment_index] = MP3_CHECKSUM_TAIL_TRANSFORM;
			// A short final evidence block can finish a stream, but cannot
			// supply a complete interior block in another reconstruction.
			if(fragment_length <= available_length){
				full_transforms[fragment_index] = tail_transforms[fragment_index];
				if(trailing_bytes > 0){
					full_transforms[fragment_index].zero_crc = mp3_audio_crc16_update(
						tail_transforms[fragment_index].zero_crc,
						data + tail_length, trailing_bytes);
					for(uint32_t bit = 0; bit < 16; bit++){
						full_transforms[fragment_index].shifted_basis[bit] =
							mp3_audio_crc16_advance_zeros(
								tail_transforms[fragment_index].shifted_basis[bit], trailing_bytes);
					}
				}
				transform_flags[fragment_index] |= MP3_CHECKSUM_FULL_TRANSFORM;
			}
			deflate_blockvector(trial);
		}
		search->phase = MP3_CHECKSUM_GAPS;
	}

	// Preserve the physically local runs and solve only the holes between them.
	// This models displaced runs directly instead of allowing a short checksum
	// to select an unrelated permutation of otherwise valid MP3 fragments.
	if(search->phase == MP3_CHECKSUM_GAPS){
		Mp3ChecksumFragmentOrder *local_order = calloc(
			carve_state->num_frags, sizeof(*local_order));
		uint16_t *gap_local_indexes = calloc(carve_state->num_frags,
			sizeof(*gap_local_indexes));
		uint64_t *gap_blocks_at_depth = blocks_at_depth;
		uint16_t *gap_choices = path;
		uint32_t *gap_next = next_choice;
		uint16_t *structured_path = calloc(carve_state->num_frags,
			sizeof(*structured_path));
		uint16_t local_count = 0;
		uint16_t gap_count = 0;
		uint64_t main_last = 0;
		uint64_t local_blocks = 0;
		bool skeleton_valid = false;

		check_memory_allocation(local_order, __LINE__, __FILE__,
			"MP3 local fragment order");
		check_memory_allocation(gap_local_indexes, __LINE__, __FILE__,
			"MP3 local gap indexes");
		check_memory_allocation(gap_blocks_at_depth, __LINE__, __FILE__,
			"MP3 local gap block counts");
		check_memory_allocation(gap_choices, __LINE__, __FILE__,
			"MP3 local gap choices");
		check_memory_allocation(gap_next, __LINE__, __FILE__,
			"MP3 local gap cursors");
		check_memory_allocation(structured_path, __LINE__, __FILE__,
			"MP3 local checksum path");

		if(header->firstActBlock >= 0){
			// A physical gap increases the on-disk span without adding file blocks.
			// Select the tail whose intervening local fragments account for the
			// largest feasible portion of the described stream.
			for(uint16_t tail_index = 1;
				tail_index < carve_state->num_frags; tail_index++){
				const Mp3Fragment *tail = &carve_state->fragments[tail_index];
				uint64_t candidate_blocks = header->size;

				if(!tail->isTail || tail->firstActBlock <= header->lastActBlock
					|| tail->lastActBlock < tail->firstActBlock){
					continue;
				}
				for(uint16_t i = 1; i < carve_state->num_frags; i++){
					const Mp3Fragment *fragment = &carve_state->fragments[i];
					if(!fragment->isHeader
						&& fragment->firstActBlock > header->lastActBlock
						&& fragment->lastActBlock >= fragment->firstActBlock
						&& fragment->lastActBlock <= tail->lastActBlock){
						if(fragment->size > target_blocks - candidate_blocks){
							candidate_blocks = target_blocks + 1;
							break;
						}
						candidate_blocks += fragment->size;
					}
				}
				if(candidate_blocks <= target_blocks
					&& candidate_blocks > local_blocks){
					local_blocks = candidate_blocks;
					main_last = (uint64_t)tail->lastActBlock;
				}
			}

			if(main_last != 0){
				for(uint16_t i = 0; i < carve_state->num_frags; i++){
					const Mp3Fragment *fragment = &carve_state->fragments[i];
					if((i == 0 || !fragment->isHeader)
						&& fragment->firstActBlock >= header->firstActBlock
						&& fragment->lastActBlock >= fragment->firstActBlock
						&& (uint64_t)fragment->lastActBlock <= main_last){
						local_order[local_count].index = i;
						local_order[local_count].distance =
							(uint64_t)(fragment->firstActBlock
								- header->firstActBlock);
						local_count++;
					}
				}
			}
		}
		qsort(local_order, local_count, sizeof(*local_order),
			mp3_checksum_fragment_order_compare);
		skeleton_valid = local_count >= 2 && local_order[0].index == 0
			&& (uint64_t)carve_state->fragments[
				local_order[local_count - 1].index].lastActBlock == main_last;
		if(skeleton_valid){
			for(uint16_t i = 0; i < local_count; i++){
				const Mp3Fragment *fragment =
					&carve_state->fragments[local_order[i].index];
				if(fragment->size == 0
					|| (i > 0 && fragment->firstActBlock
						<= carve_state->fragments[
							local_order[i - 1].index].lastActBlock)){
					skeleton_valid = false;
					break;
				}
				used[local_order[i].index] = true;
					if(i + 1 < local_count){
						const Mp3Fragment *next =
							&carve_state->fragments[local_order[i + 1].index];
						if(next->firstActBlock <= fragment->lastActBlock){
							skeleton_valid = false;
							break;
						}
						// Matching offsets mean the logical stream continues across
						// a physical gap. A mismatch requires a displaced run.
						if(!mp3_reassembly_fragment_boundaries_match(fragment, next)){
							gap_local_indexes[gap_count] = i;
							gap_count++;
						}
					}
			}
		}

		if(skeleton_valid && gap_count > 0){
			bool search_done = false;
			gap_blocks_at_depth[0] = 0;
			for(uint16_t prior = 0; prior < search->depth; prior++){
				used[gap_choices[prior]] = true;
			}

			while(!search_done){
				bool advanced = false;
				const uint16_t local_gap = gap_local_indexes[search->depth];
				const Mp3Fragment *left = &carve_state->fragments[
					local_order[local_gap].index];
				const Mp3Fragment *right = &carve_state->fragments[
					local_order[local_gap + 1].index];

				for(uint32_t i = gap_next[search->depth];
					i < carve_state->num_frags; i++){
					if(atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)
						&& reassembly_time_to_checkpoint(work->id, candidate, uuidp, uuidc)){
						result = MP3_CHECKSUM_SEARCH_CHECKPOINT;
						goto gap_search_finished;
					}
					Mp3Fragment *fragment = &carve_state->fragments[i];
					gap_next[search->depth] = i + 1;
					search->examined++;
					if(used[i]
						|| !(transform_flags[i] & MP3_CHECKSUM_FULL_TRANSFORM)
						|| fragment->isHeader
						|| fragment->size > target_blocks - local_blocks
							- gap_blocks_at_depth[search->depth]
						|| !mp3_reassembly_fragment_boundaries_match(left, fragment)
						|| !mp3_reassembly_fragment_boundaries_match(fragment, right)
						|| (fragment->firstActBlock <= (int64_t)main_last
							&& fragment->lastActBlock
								>= header->firstActBlock)){
						continue;
					}
					bool overlaps_choice = false;
					for (uint16_t prior = 0; prior < search->depth; prior++) {
						if (mp3_fragment_ranges_overlap(fragment,
							&carve_state->fragments[gap_choices[prior]])) {
							overlaps_choice = true;
							break;
						}
					}
					if (overlaps_choice) {
						continue;
					}
					gap_choices[search->depth] = (uint16_t)i;
					used[i] = true;
					gap_blocks_at_depth[search->depth + 1] =
						gap_blocks_at_depth[search->depth] + fragment->size;
					search->depth++;
					advanced = true;
					if(search->depth < gap_count){
						gap_next[search->depth] = 0;
					}
					break;
				}

				if(search->depth == gap_count
					&& local_blocks + gap_blocks_at_depth[search->depth]
						== target_blocks){
					uint16_t structured_depth = 1;
					uint16_t bridge_index = 0;
					uint16_t crc = header_crc;
					bool transforms_available = true;
					structured_path[0] = local_order[0].index;
					for(uint16_t i = 0; i + 1 < local_count; i++){
						if(bridge_index < gap_count
							&& gap_local_indexes[bridge_index] == i){
							structured_path[structured_depth++] =
								gap_choices[bridge_index];
							bridge_index++;
						}
						structured_path[structured_depth++] =
							local_order[i + 1].index;
					}
					for(uint16_t i = 1; i < structured_depth; i++){
						const uint16_t index = structured_path[i];
						const bool final_fragment = i + 1 == structured_depth;
						const uint8_t required_transform = final_fragment
							? MP3_CHECKSUM_TAIL_TRANSFORM : MP3_CHECKSUM_FULL_TRANSFORM;
						if(!(transform_flags[index] & required_transform)){
							transforms_available = false;
							break;
						}
						crc = mp3_checksum_apply_crc_transform(
							final_fragment ? &tail_transforms[index]
								: &full_transforms[index], crc);
					}
					if(transforms_available && crc == expected_checksum.audio_crc){
						uint64_t position = 0;
						ValidationArgs va = get_validation_args();
						search->checksum_matches++;
						resize_blockvector(trial, target_blocks);
						for(uint16_t i = 0; i < structured_depth; i++){
							const Mp3Fragment *fragment = &carve_state->fragments[
								structured_path[i]];
							for(int64_t actual = fragment->firstActBlock;
								actual <= fragment->lastActBlock; actual++){
								blockvector_set_apparent_blocknumber(trial,
									position++, filemirror_apparent_blocknumber(
										scalpel_state.filemirror, actual));
							}
						}
						if(position == target_blocks){
							blockvector_set_data_length_to_mapped_extent(trial);
							if(blockvector_get_data_length(trial) > expected_checksum.audio_end){
								blockvector_set_data_length(trial, expected_checksum.audio_end);
							}
							mp3_extend_terminal_footer_extent(trial, blocksize);
							inflate_blockvector(trial);
							mp3_file_validate(blockvector_get_data_pointer(trial),
								blockvector_get_data_length(trial), &va.validates,
								&va.validates_to, &va.promising,
								candidate->needleidx, blocksize,
								candidate->carvehashkey);
							if(va.validates){
								(void)mp3_write_hypothesis(candidate,
									trial, blockvector_get_data_length(trial));
								const double path_score = mp3_checksum_path_score(
									blockvector_get_data_pointer(trial),
									blockvector_get_data_length(trial), carve_state,
									structured_path, structured_depth, blocksize);
								search->validated_matches++;
								if(search->best_depth == 0 || path_score > search->best_score){
									memcpy(best_path, structured_path,
										structured_depth * sizeof(*best_path));
									search->best_depth = structured_depth;
									search->best_score = path_score;
								}
							}
							deflate_blockvector(trial);
						}
					}
					search->depth--;
					used[gap_choices[search->depth]] = false;
					advanced = true;
				}
				else if(search->depth == gap_count){
					search->depth--;
					used[gap_choices[search->depth]] = false;
					advanced = true;
				}

				if(!advanced){
					if(search->depth == 0){
						search_done = true;
					}
					else{
						search->depth--;
						used[gap_choices[search->depth]] = false;
					}
				}
			}
		}

		gap_search_finished:
		memset(used, 0, carve_state->num_frags * sizeof(*used));
		free(structured_path);
		free(gap_local_indexes);
		free(local_order);
		if(result == MP3_CHECKSUM_SEARCH_CHECKPOINT){
			goto done;
		}
		if(search->best_depth > 0){
			search->phase = MP3_CHECKSUM_COMPLETE;
			goto checksum_search_finished;
		}
		search->phase = MP3_CHECKSUM_PATHS_INIT;
	}

	path_search_init:
	if(search->phase == MP3_CHECKSUM_PATHS_INIT){
		memset(path, 0, carve_state->num_frags * sizeof(*path));
		memset(next_choice, 0,
			((size_t)carve_state->num_frags + 1) * sizeof(*next_choice));
		memset(blocks_at_depth, 0,
			((size_t)carve_state->num_frags + 1) * sizeof(*blocks_at_depth));
		memset(crc_at_depth, 0,
			((size_t)carve_state->num_frags + 1) * sizeof(*crc_at_depth));
		memset(used, 0, carve_state->num_frags * sizeof(*used));
		path[0] = 0;
		used[0] = true;
		search->depth = 1;
		blocks_at_depth[search->depth] = carve_state->fragments[0].size;
		crc_at_depth[search->depth] = header_crc;
		next_choice[search->depth] = 0;
		search->phase = MP3_CHECKSUM_PATHS;
	}
	// Usage is derived from the saved path; no speculative bytes are retained.
	for(uint16_t i = 0; i < search->depth; i++){
		used[path[i]] = true;
	}

	while(search->depth > 0){
		if(search->depth > 1
			&& filemirror_actual_block_covered(scalpel_state.filemirror,
				carve_state->fragments[path[search->depth - 1]].firstActBlock)){
			used[path[search->depth - 1]] = false;
			search->depth--;
			continue;
		}
		if(blocks_at_depth[search->depth] == target_blocks){
			if(atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)
				&& reassembly_time_to_checkpoint(work->id, candidate, uuidp, uuidc)){
				result = MP3_CHECKSUM_SEARCH_CHECKPOINT;
				goto done;
			}
			Mp3XingChecksum trial_checksum;
			ValidationArgs va = get_validation_args();

			if(crc_at_depth[search->depth] == expected_checksum.audio_crc){
				search->checksum_matches++;
				uint64_t position = 0;
				bool complete = true;

				resize_blockvector(trial, target_blocks);
				for(uint16_t path_index = 0;
					path_index < search->depth && complete; path_index++){
					Mp3Fragment *fragment =
						&carve_state->fragments[path[path_index]];
					for(int64_t actual = fragment->firstActBlock;
						actual <= fragment->lastActBlock; actual++){
						if(position >= target_blocks
							|| filemirror_actual_block_covered(
								scalpel_state.filemirror, actual)){
							complete = false;
							break;
						}
						blockvector_set_apparent_blocknumber(trial, position,
							filemirror_apparent_blocknumber(
								scalpel_state.filemirror, actual));
						position++;
					}
				}
				if(!complete || position != target_blocks){
					goto checksum_path_checked;
				}
				blockvector_set_data_length_to_mapped_extent(trial);
				// The declared audio extent excludes unrelated bytes in its final block.
				if(blockvector_get_data_length(trial) > expected_checksum.audio_end){
					blockvector_set_data_length(trial, expected_checksum.audio_end);
				}
				mp3_extend_terminal_footer_extent(trial, blocksize);
				inflate_blockvector(trial);
				if(mp3_get_xing_checksum(blockvector_get_data_pointer(trial),
					blockvector_get_data_length(trial), &trial_checksum)
					&& trial_checksum.present
					&& trial_checksum.audio_end == expected_checksum.audio_end
					&& trial_checksum.audio_crc == expected_checksum.audio_crc
					&& mp3_xing_checksum_matches(
						blockvector_get_data_pointer(trial),
						blockvector_get_data_length(trial), &trial_checksum)){
					mp3_file_validate(blockvector_get_data_pointer(trial),
						blockvector_get_data_length(trial), &va.validates,
						&va.validates_to, &va.promising, candidate->needleidx,
						blocksize, candidate->carvehashkey);
				}
				if(va.validates){
					search->validated_matches++;
					(void)mp3_write_hypothesis(candidate, trial,
						blockvector_get_data_length(trial));
					double path_score = mp3_checksum_path_score(
						blockvector_get_data_pointer(trial),
						blockvector_get_data_length(trial), carve_state,
						path, search->depth, blocksize);
					if(search->best_depth == 0 || path_score > search->best_score){
						memcpy(best_path, path, search->depth * sizeof(*best_path));
						search->best_depth = search->depth;
						search->best_score = path_score;
					}
					if(!search->rank_all_matches){
						stop_search = true;
					}
				}
				deflate_blockvector(trial);
			}
			if(stop_search){
				break;
			}

			checksum_path_checked:
			search->examined++;
			if(search->depth == 1){
				break;
			}
			used[path[search->depth - 1]] = false;
			search->depth--;
			continue;
		}

		bool advanced = false;
		Mp3Fragment *current = &carve_state->fragments[path[search->depth - 1]];
		for(uint32_t order_position = next_choice[search->depth];
			order_position < search->search_limit; order_position++){
			if(atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)
				&& reassembly_time_to_checkpoint(work->id, candidate, uuidp, uuidc)){
				result = MP3_CHECKSUM_SEARCH_CHECKPOINT;
				goto done;
			}
			uint16_t candidate_index = search_order[order_position].index;
			Mp3Fragment *fragment = &carve_state->fragments[candidate_index];
			const uint8_t required_transform =
				fragment->size == target_blocks - blocks_at_depth[search->depth]
					? MP3_CHECKSUM_TAIL_TRANSFORM : MP3_CHECKSUM_FULL_TRANSFORM;
			next_choice[search->depth] = order_position + 1;
			search->examined++;
			if(used[candidate_index] || fragment->isHeader
				|| fragment->size == 0
				|| !(transform_flags[candidate_index] & required_transform)
				|| filemirror_actual_block_covered(scalpel_state.filemirror,
					fragment->firstActBlock)
				|| !mp3_reassembly_fragment_boundaries_match(current, fragment)
				|| fragment->size > target_blocks - blocks_at_depth[search->depth]){
				continue;
			}
			// Catalog alternatives can overlap without sharing an index.
			// A proposed file must not reuse the same physical blocks.
			bool overlaps_path = false;
			for (uint16_t prior = 0; prior < search->depth; prior++) {
				if (mp3_fragment_ranges_overlap(fragment,
					&carve_state->fragments[path[prior]])) {
					overlaps_path = true;
					break;
				}
			}
			if (overlaps_path) {
				continue;
			}
			path[search->depth] = candidate_index;
			used[candidate_index] = true;
			blocks_at_depth[search->depth + 1] = blocks_at_depth[search->depth]
				+ fragment->size;
			if(blocks_at_depth[search->depth + 1] == target_blocks){
				crc_at_depth[search->depth + 1] =
					mp3_checksum_apply_crc_transform(
						&tail_transforms[candidate_index],
						crc_at_depth[search->depth]);
			}
			else{
				crc_at_depth[search->depth + 1] =
					mp3_checksum_apply_crc_transform(
						&full_transforms[candidate_index],
						crc_at_depth[search->depth]);
			}
			search->depth++;
			next_choice[search->depth] = 0;
			advanced = true;
			break;
		}

		if(!advanced){
			if(search->depth == 1){
				break;
			}
			used[path[search->depth - 1]] = false;
			search->depth--;
		}
	}
	if(result != MP3_CHECKSUM_SEARCH_CHECKPOINT && search->best_depth == 0
		&& search->search_limit < carve_state->num_frags){
		search->search_limit = carve_state->num_frags;
		search->rank_all_matches = false;
		search->phase = MP3_CHECKSUM_PATHS_INIT;
		goto path_search_init;
	}
	search->phase = MP3_CHECKSUM_COMPLETE;

	checksum_search_finished:
	if(result != MP3_CHECKSUM_SEARCH_CHECKPOINT && search->best_depth > 0){
		for(uint16_t i = 0; i < carve_state->num_frags; i++){
			carve_state->fragments[i].active =
				!carve_state->fragments[i].isHeader;
		}
		memset(carve_state->indexes, 0,
			carve_state->num_frags * sizeof(*carve_state->indexes));
		for(uint16_t i = 0; i < search->best_depth; i++){
			carve_state->indexes[i] = best_path[i];
			carve_state->fragments[best_path[i]].active = false;
		}
		carve_state->cur_index = search->best_depth;
		deflate_blockvector(candidate->b);
		mp3_rebuild_committed_blockvector(candidate, carve_state);
		blockvector_set_data_length(candidate->b,
			expected_checksum.audio_end);
		mp3_extend_terminal_footer_extent(candidate->b, blocksize);
		inflate_blockvector(candidate->b);
		result = MP3_CHECKSUM_SEARCH_FOUND;
	}
	if(scalpel_state.mode_verbose){
		lock_fprintf(stdout,
			"MP3 checksum search complete: result=%u examined=%"PRIu64
			" checksum_matches=%"PRIu64" validated_matches=%"PRIu64
			" best_depth=%u best_score=%.6f.\n",
			result, search->examined, search->checksum_matches, search->validated_matches,
			search->best_depth, search->best_score);
	}

	done:
	free_blockvector(&trial);
	free(used);
	free(search_order);
	return result;
}

static bool mp3_fragment_discovery_checkpoint(ThreadWork *work,
	CarveInfo *candidate,
	Mp3CarveState *carve_state,
	uuid_string_t uuidp,
	uuid_string_t uuidc){
	if(!atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)){
		return false;
	}

	carve_put_state(candidate->carvehashkey, carve_state);
	return reassembly_time_to_checkpoint(work->id, candidate, uuidp, uuidc);
}
static void mp3_fragment_reset(Mp3Fragment *fragment) {
	memset(fragment, 0, sizeof(*fragment));
	fragment->active = true;
	for (int channel = 0; channel < 2; channel++) {
		for (int peak = 0; peak < 6; peak++) {
			fragment->peaks[channel][peak].index = -1;
		}
	}
}

// Return true only when the final MPEG frame is complete and ends exactly
// at the supplied validation boundary. A frame-chain scan can otherwise
// mistake a shortened analysis range for a physical file tail.
static bool mp3_fragment_last_frame_ends_at(const char *data,
	uint64_t length, const ValidationArgs *validation) {
	if (data == NULL || validation == NULL
		|| validation->offsetFramePosition >= length) {
		return false;
	}
	FrameArgs args;
	uint16_t frame_length = 0;
	return mp3_parse_complete_frame_at(data, length,
		validation->offsetFramePosition, &args, &frame_length)
		&& validation->offsetFramePosition <= UINT64_MAX - frame_length
		&& validation->offsetFramePosition + frame_length == length;
}

// Locate a terminal metadata footer in a mapped run. The search is bounded by
// the caller because a shared image may contain another MP3 immediately after
// this run. ID3v1 is searched within the range; APEv2 is checked at each
// candidate signature and must parse as a complete tag.
static bool mp3_fragment_find_terminal_footer(const char *data,
	uint64_t length,
	uint64_t search_start,
	uint64_t search_end,
	uint64_t *footer_start,
	uint64_t *footer_end) {
	if (data == NULL || footer_start == NULL || footer_end == NULL
		|| search_start >= length || search_end <= search_start) {
		return false;
	}
	if (search_end > length) {
		search_end = length;
	}
	uint64_t id3_start = 0;
	uint64_t id3_end = 0;
	if (mp3_find_terminal_id3v1(data, length, search_start, search_end,
		false, &id3_start, &id3_end)) {
		*footer_start = id3_start;
		*footer_end = id3_end;
		return true;
	}
	for (uint64_t position = search_start;
		position + 8 <= search_end; position++) {
		if (memcmp(data + position, "APETAGEX", 8) != 0) {
			continue;
		}
		uint64_t ape_end = 0;
		if (mp3_ape_tag_extent(data, length, position, false, &ape_end) == 1
			&& ape_end <= search_end) {
			*footer_start = position;
			*footer_end = ape_end;
			return true;
		}
	}
	return false;
}

// If mapped-length trimming stopped at the last MPEG frame, expose a terminal
// block long enough to inspect a zero-tailed metadata footer. The caller keeps
// the original length when no structurally complete footer is present.
static void mp3_extend_terminal_footer_extent(BlockVector *b,
	uint32_t blocksize) {
	if (b == NULL || blocksize == 0) {
		return;
	}
	const uint64_t current_length = blockvector_get_data_length(b);
	const uint64_t blocks = blockvector_get_num_blocks(b);
	if (blocks == 0 || blocks > UINT64_MAX / blocksize) {
		return;
	}
	const uint64_t mapped_length = blocks * (uint64_t)blocksize;
	if (mapped_length <= current_length) {
		return;
	}
	blockvector_set_data_length(b, mapped_length);
	char *data = blockvector_get_data_pointer(b);
	if (data == NULL) {
		blockvector_set_data_length(b, current_length);
		return;
	}
	uint64_t footer_start = 0;
	uint64_t footer_end = 0;
	bool found = false;
	if (mp3_find_terminal_id3v1(data, mapped_length, current_length,
		mapped_length, true, &footer_start, &footer_end)) {
		found = true;
	} else {
		for (uint64_t position = current_length;
			position + 8 <= mapped_length; position++) {
			if (memcmp(data + position, "APETAGEX", 8) != 0) {
				continue;
			}
			uint64_t ape_end = 0;
			if (mp3_ape_tag_extent(data, mapped_length, position, false,
				&ape_end) == 1
				&& ape_end <= mapped_length
				&& areBytesNULL(data + ape_end, mapped_length - ape_end)) {
				footer_start = position;
				footer_end = ape_end;
				found = true;
				break;
			}
		}
	}
	if (found && footer_end > footer_start) {
		blockvector_set_data_length(b, footer_end);
	} else {
		blockvector_set_data_length(b, current_length);
	}
}

// Measure a physical run, optionally ending at a known frame-chain boundary.
// A zero maximum_length examines the entire mapped range. The mapping itself
// retains full blocks; final file validation determines the recovered length.
// search_start anchors validation to a scanner-confirmed chain without dropping
// the leading frame remainder from the physical mapping or its byte offsets.
static bool mp3_fragment_measure_range(BlockVector *b_read,
	int64_t first_actual,
	int64_t last_actual,
	uint32_t blocksize,
	uint64_t maximum_length,
	uint64_t search_start,
	Mp3Fragment *fragment,
	bool *validates,
	bool *maybe) {

	ValidationArgs va = get_validation_args();
	uint64_t blocks;
	uint64_t mapped_length;
	uint64_t validation_length;
	bool footer_present = false;

	if (b_read == NULL || fragment == NULL || validates == NULL
		|| maybe == NULL || blocksize == 0 || first_actual < 0
		|| last_actual < first_actual) {
		return false;
	}
	blocks = (uint64_t)(last_actual - first_actual) + 1;
	resize_blockvector(b_read, blocks);
	for (uint64_t position = 0; position < blocks; position++) {
		const int64_t apparent = filemirror_apparent_blocknumber(
			scalpel_state.filemirror, first_actual + (int64_t)position);
		if (apparent < 0) {
			return false;
		}
		blockvector_set_apparent_blocknumber(b_read, position, apparent);
	}

	blockvector_set_data_length_to_mapped_extent(b_read);
	mapped_length = blockvector_get_data_length(b_read);
	inflate_blockvector(b_read);
	validation_length = mapped_length;
	if (maximum_length > 0 && maximum_length < mapped_length) {
		uint64_t footer_start = 0;
		uint64_t footer_end = 0;
		if (mp3_fragment_find_terminal_footer(
			blockvector_get_data_pointer(b_read), mapped_length,
			maximum_length, mapped_length, &footer_start, &footer_end)
			&& footer_start >= maximum_length && footer_end > maximum_length) {
			validation_length = footer_end;
			footer_present = true;
		}
	}
	if (validation_length < mapped_length) {
		blockvector_set_data_length(b_read, validation_length);
	}
	mp3_fragment_validate_from(blockvector_get_data_pointer(b_read),
		blockvector_get_data_length(b_read), &va.validates,
		&va.validates_to, va.needleidx, &va.frontOffset, &va.rearOffset,
		&va.isHeader, &va.isTail, &va.secondToLastFramePosition,
		&va.lastFramePosition, &va.offsetFramePosition, &va.maybe,
		search_start);
	// Nonzero sector slack can invalidate an otherwise checked scanner chain.
	// Retain that chain's geometry, but not a synthetic tail at its analysis
	// boundary. The physical-boundary check below still governs isTail.
	if (!va.validates && !va.maybe && !footer_present
		&& maximum_length > search_start && maximum_length < mapped_length
		&& maximum_length > (blocks - 1) * (uint64_t)blocksize) {
		va = get_validation_args();
		validation_length = maximum_length;
		mp3_fragment_validate_from(blockvector_get_data_pointer(b_read),
			validation_length, &va.validates, &va.validates_to, va.needleidx,
			&va.frontOffset, &va.rearOffset, &va.isHeader, &va.isTail,
			&va.secondToLastFramePosition, &va.lastFramePosition,
			&va.offsetFramePosition, &va.maybe, search_start);
	}
	// A cataloged frame-chain endpoint is an analysis boundary, not evidence
	// that the physical run ends there. Preserve isTail for a recognized
	// metadata footer, but otherwise require the final frame itself to end at
	// the physical validation boundary. This prevents a one-byte-short chain
	// from terminating reassembly prematurely.
	if (va.isTail && !footer_present) {
		uint64_t footer_start = 0;
		uint64_t footer_end = 0;
		const uint64_t footer_search_start = va.offsetFramePosition
			< validation_length ? va.offsetFramePosition : validation_length;
		footer_present = mp3_fragment_find_terminal_footer(
			blockvector_get_data_pointer(b_read), validation_length,
			footer_search_start, validation_length, &footer_start, &footer_end);
		if (!footer_present
			&& !mp3_fragment_last_frame_ends_at(
				blockvector_get_data_pointer(b_read), mapped_length, &va)) {
			va.isTail = false;
		}
	}
	// Split-header evidence is refreshed below from the complete physical
	// fragment, independently of the validator's shortened footer extent.
	deflate_blockvector(b_read);

	mp3_fragment_reset(fragment);
	fragment->frontOffset = va.frontOffset;
	fragment->rearOffset = va.rearOffset;
	fragment->size = blocks;
	fragment->isHeader = va.isHeader;
	fragment->isTail = va.isTail;
	fragment->secondToLastFramePosition = va.secondToLastFramePosition;
	fragment->lastFramePosition = va.lastFramePosition;
	fragment->offsetFramePosition = va.offsetFramePosition;
	fragment->firstActBlock = first_actual;
	fragment->lastActBlock = last_actual;
	mp3_fragment_refresh_header_context(fragment);
	*validates = va.validates;
	*maybe = va.maybe;
	return true;
}

static void mp3_fragment_measure_peaks(BlockVector *b_read,
	Mp3Fragment *fragment,
	uint32_t blocksize) {

	uint64_t fragment_bytes;
	uint64_t first_offset;
	uint64_t last_offset;
	uint64_t blocks;

	if (b_read == NULL || fragment == NULL || blocksize == 0) {
		return;
	}
	for (int channel = 0; channel < 2; channel++) {
		for (int peak = 0; peak < 6; peak++) {
			fragment->peaks[channel][peak].val = 0;
			fragment->peaks[channel][peak].index = -1;
		}
	}
	fragment->peaksStereo = false;
	mp3_reassembly_normalize_fragment(fragment, blocksize);
	fragment_bytes = fragment->size * (uint64_t)blocksize;
	if (fragment->offsetFramePosition
		<= fragment->secondToLastFramePosition
		|| fragment->offsetFramePosition > fragment_bytes) {
		return;
	}

	first_offset = fragment->secondToLastFramePosition / blocksize;
	last_offset = (fragment->offsetFramePosition - 1) / blocksize;
	blocks = last_offset - first_offset + 1;
	resize_blockvector(b_read, blocks);
	for (uint64_t position = 0; position < blocks; position++) {
		const int64_t apparent = filemirror_apparent_blocknumber(
			scalpel_state.filemirror,
			fragment->firstActBlock + (int64_t)first_offset
				+ (int64_t)position);
		if (apparent < 0) {
			return;
		}
		blockvector_set_apparent_blocknumber(b_read, position, apparent);
	}
	blockvector_set_data_length_to_mapped_extent(b_read);
	inflate_blockvector(b_read);
	const uint64_t read_offset = fragment->secondToLastFramePosition % blocksize;
	const uint64_t read_length = fragment->offsetFramePosition
		- fragment->secondToLastFramePosition;
	const uint64_t data_length = blockvector_get_data_length(b_read);
	if(read_offset <= data_length && read_length <= data_length - read_offset
		&& read_length <= INT_MAX){
		(void)getPeaks(blockvector_get_data_pointer(b_read) + read_offset,
			(int)read_length, fragment->peaks[0], fragment->peaks[1],
			&fragment->peaksStereo);
	}
	deflate_blockvector(b_read);
}

static bool mp3_fragment_array_append(Mp3Fragment **fragments,
	uint16_t *count,
	uint16_t *capacity,
	const Mp3Fragment *fragment) {

	if (*count == UINT16_MAX) {
		return false;
	}
	if (*count == *capacity) {
		uint32_t grown = *capacity == 0 ? 64U : (uint32_t)*capacity * 2U;
		if (grown > UINT16_MAX) {
			grown = UINT16_MAX;
		}
		Mp3Fragment *resized = realloc(*fragments,
			grown * sizeof(*resized));
		check_memory_allocation(resized, __LINE__, __FILE__,
			"MP3 fragment array");
		*fragments = resized;
		*capacity = (uint16_t)grown;
	}
	(*fragments)[*count] = *fragment;
	mp3_fragment_refresh_header_context(&(*fragments)[*count]);
	(*count)++;
	return true;
}

// A syntactically plausible final run is not enough to claim a physical tail:
// random filler can contain MPEG-looking headers. Require decoder evidence
// from the final block, retaining preceding-frame reservoir context.
static bool mp3_fragment_tail_decoder_evidence(BlockVector *b_read,
	const Mp3Fragment *fragment, uint32_t blocksize) {
	if (b_read == NULL || fragment == NULL || blocksize == 0
		|| fragment->size == 0 || fragment->firstActBlock < 0
		|| fragment->lastActBlock < fragment->firstActBlock) {
		return false;
	}
	uint64_t first_block = fragment->size > 1 ? fragment->size - 2 : 0;
	// A checked trailing tag may occupy many blocks without MPEG frames.
	// Start at the preceding audio context, not at the final metadata blocks.
	const uint64_t context_block = fragment->secondToLastFramePosition / blocksize;
	if (context_block < first_block) {
		first_block = context_block;
	}
	const uint64_t blocks = fragment->size - first_block;
	resize_blockvector(b_read, blocks);
	for (uint64_t position = 0; position < blocks; position++) {
		const int64_t actual = fragment->firstActBlock
			+ (int64_t)first_block + (int64_t)position;
		const int64_t apparent = filemirror_apparent_blocknumber(
			scalpel_state.filemirror, actual);
		if (apparent < 0) { return false; }
		blockvector_set_apparent_blocknumber(b_read, position, apparent);
	}
	blockvector_set_data_length_to_mapped_extent(b_read);
	inflate_blockvector(b_read);
	const uint64_t base = first_block * (uint64_t)blocksize;
	const uint64_t data_length = blockvector_get_data_length(b_read);
	const uint64_t prime = fragment->secondToLastFramePosition >= base
		? fragment->secondToLastFramePosition - base
		: fragment->lastFramePosition >= base
			? fragment->lastFramePosition - base : 0;
	const uint64_t final_block_start = (fragment->size - 1)
		* (uint64_t)blocksize;
	const char *data = blockvector_get_data_pointer(b_read);
	FrameArgs final_args;
	uint16_t final_length = 0;
	if (fragment->offsetFramePosition < base
		|| !mp3_parse_complete_frame_at(data, data_length,
			fragment->offsetFramePosition - base, &final_args, &final_length)) {
		deflate_blockvector(b_read);
		return false;
	}
	const uint64_t audio_end = fragment->offsetFramePosition - base + final_length;
	uint64_t tail_end = audio_end;
	uint64_t ape_end = 0;
	if (mp3_ape_tag_extent(data, data_length, tail_end, false, &ape_end) == 1) {
		tail_end = ape_end;
	}
	Bitstream tags = {(char *)data, 0, tail_end, data_length, false};
	(void)skipID3v1(&tags);
	tail_end = tags.bytePos;
	// Evidence must reach the last block, not necessarily start there. A
	// crossing final frame or its directly adjacent metadata footer counts.
	// Reject an appended block containing no audio/tag endpoint. Bytes after
	// that endpoint in the final sector are unowned disk slack, not necessarily
	// zero padding. Catalog membership does not replace final file validation.
	const bool frame_reaches_tail = tail_end > final_block_start - base
		&& tail_end <= data_length;
	const uint64_t decode_length = audio_end;
	Peak peaks_l[6], peaks_r[6]; bool stereo = false;
	const bool decoded = prime < decode_length
		&& decode_length - prime <= INT_MAX
		&& getPeaks(blockvector_get_data_pointer(b_read) + prime,
			(int)(decode_length - prime), peaks_l, peaks_r, &stereo);
	deflate_blockvector(b_read);
	return decoded && frame_reaches_tail;
}

static bool mp3_fragment_catalog_append_completion(
	Mp3FragmentCatalog *catalog,
	BlockVector *b_read,
	uint64_t actual_blocks,
	uint32_t blocksize,
	const Mp3Fragment *fragment) {
	if (catalog == NULL || blocksize == 0 || fragment == NULL
		|| fragment->rearOffset == 0 || fragment->lastActBlock < 0) {
		return true;
	}

	const uint64_t completion_blocks =
		fragment->rearOffset / blocksize
			+ ((fragment->rearOffset % blocksize) != 0);
	bool available = completion_blocks > 0
		&& (uint64_t)fragment->lastActBlock <= UINT64_MAX - completion_blocks
		&& (uint64_t)fragment->lastActBlock + completion_blocks < actual_blocks;
	for (uint64_t offset = 1; available && offset <= completion_blocks;
		offset++) {
		const int64_t actual = fragment->lastActBlock + (int64_t)offset;
		if (filemirror_actual_block_covered(scalpel_state.filemirror, actual)
			|| filemirror_apparent_blocknumber(scalpel_state.filemirror,
				actual) < 0) {
			available = false;
		}
	}
	if (!available) {
		return true;
	}

	Mp3Fragment completion = *fragment;
	completion.lastActBlock += (int64_t)completion_blocks;
	completion.size += completion_blocks;
	completion.rearOffset = 0;
	completion.isTail = true;
	if (!mp3_fragment_tail_decoder_evidence(b_read, &completion, blocksize)) {
		return true;
	}
	return mp3_fragment_array_append(&catalog->fragments,
		&catalog->count, &catalog->capacity, &completion);
}

// Preserve the measured run and bounded variants that restore blocks omitted
// or absorbed by standalone classification at a physical fragment boundary.
// Final file validation, not catalog membership, decides whether a variant is
// used.
static bool mp3_fragment_catalog_append(Mp3FragmentCatalog *catalog,
	BlockVector *b_read,
	uint64_t actual_blocks,
	uint32_t blocksize,
	const Mp3Fragment *fragment) {
	if (catalog == NULL || b_read == NULL || blocksize == 0 || fragment == NULL) {
		return false;
	}
	if (fragment->isTail
		&& !mp3_fragment_tail_decoder_evidence(b_read, fragment, blocksize)) {
		return true;
	}
	if (!mp3_fragment_array_append(&catalog->fragments,
		&catalog->count, &catalog->capacity, fragment)) {
		return false;
	}
	catalog->source_runs++;
	const uint64_t maximum_boundary_blocks =
		MP3_MAXIMUM_FRAME_BYTES / blocksize
			+ ((MP3_MAXIMUM_FRAME_BYTES % blocksize) != 0);
	for (uint64_t removed = 1; removed <= maximum_boundary_blocks; removed++) {
		Mp3Fragment trimmed;
		bool validates = false;
		bool maybe = false;

		if (fragment->lastActBlock - fragment->firstActBlock
			< (int64_t)removed) {
			break;
		}
		if (mp3_fragment_measure_range(b_read, fragment->firstActBlock,
			fragment->lastActBlock - (int64_t)removed, blocksize, 0, 0, &trimmed,
			&validates, &maybe) && (validates || maybe)) {
			trimmed.preserveFrontContext = fragment->preserveFrontContext;
			if (!mp3_fragment_array_append(&catalog->fragments,
				&catalog->count, &catalog->capacity, &trimmed)) {
				return false;
			}
			break;
		}
	}
	if (!mp3_fragment_catalog_append_completion(catalog, b_read, actual_blocks,
		blocksize, fragment)) {
		return false;
	}

	for (uint64_t extra = 1; extra <= maximum_boundary_blocks; extra++) {
		Mp3Fragment variant;
		bool validates = false;
		bool maybe = false;

		if (fragment->firstActBlock < 0
			|| (uint64_t)fragment->firstActBlock < extra) {
			break;
		}
		const int64_t first_actual =
			fragment->firstActBlock - (int64_t)extra;
		if ((uint64_t)first_actual >= actual_blocks
			|| filemirror_actual_block_covered(scalpel_state.filemirror,
				first_actual)
			|| filemirror_apparent_blocknumber(scalpel_state.filemirror,
				first_actual) < 0) {
			break;
		}
		if (!mp3_fragment_measure_range(b_read, first_actual,
			fragment->lastActBlock, blocksize, 0, 0, &variant, &validates, &maybe)
			|| (!validates && !maybe)) {
			continue;
		}
		variant.preserveFrontContext = true;
		if (!mp3_fragment_array_append(&catalog->fragments,
			&catalog->count, &catalog->capacity, &variant)) {
			return false;
		}
		if (!mp3_fragment_catalog_append_completion(catalog, b_read, actual_blocks,
			blocksize, &variant)) {
			return false;
		}
	}
	return true;
}

static int mp3_fragment_physical_compare(const void *left,
	const void *right) {
	const Mp3Fragment *a = left;
	const Mp3Fragment *b = right;

	if (a->firstActBlock != b->firstActBlock) {
		return a->firstActBlock < b->firstActBlock ? -1 : 1;
	}
	if (a->lastActBlock != b->lastActBlock) {
		return a->lastActBlock < b->lastActBlock ? -1 : 1;
	}
	if (a->frontOffset != b->frontOffset) {
		return a->frontOffset < b->frontOffset ? -1 : 1;
	}
	if (a->rearOffset != b->rearOffset) {
		return a->rearOffset < b->rearOffset ? -1 : 1;
	}
	if (a->preserveFrontContext != b->preserveFrontContext) {
		return a->preserveFrontContext ? 1 : -1;
	}
	if (a->isHeader != b->isHeader) {
		return a->isHeader ? 1 : -1;
	}
	if (a->isTail != b->isTail) {
		return a->isTail ? 1 : -1;
	}
	if (a->secondToLastFramePosition != b->secondToLastFramePosition) {
		return a->secondToLastFramePosition
			< b->secondToLastFramePosition ? -1 : 1;
	}
	if (a->lastFramePosition != b->lastFramePosition) {
		return a->lastFramePosition < b->lastFramePosition ? -1 : 1;
	}
	if (a->offsetFramePosition != b->offsetFramePosition) {
		return a->offsetFramePosition < b->offsetFramePosition ? -1 : 1;
	}
	return 0;
}

static uint64_t mp3_fragment_chain_hash(int64_t end,
	uint16_t rear_offset) {
	uint64_t value = (uint64_t)end;
	value ^= value >> 30;
	value *= UINT64_C(0xbf58476d1ce4e5b9);
	value ^= value >> 27;
	value *= UINT64_C(0x94d049bb133111eb);
	value ^= value >> 31;
	return value ^ ((uint64_t)rear_offset * UINT64_C(0x9e3779b97f4a7c15));
}

static Mp3FragmentChain *mp3_fragment_chain_lookup(
	Mp3FragmentChain *table,
	size_t capacity,
	int64_t end,
	uint16_t rear_offset,
	bool match_rear_offset) {
	if (table == NULL || capacity == 0) {
		return NULL;
	}
	size_t slot = (size_t)mp3_fragment_chain_hash(end,
		match_rear_offset ? rear_offset : 0) & (capacity - 1);
	while (table[slot].occupied) {
		if (table[slot].end == end
			&& (!match_rear_offset
				|| table[slot].rear_offset == rear_offset)) {
			return &table[slot];
		}
		slot = (slot + 1) & (capacity - 1);
	}
	return NULL;
}

static void mp3_fragment_chain_store(Mp3FragmentChain *table,
	size_t capacity,
	const Mp3FragmentChain *chain,
	bool match_rear_offset,
	bool keep_earliest) {
	if (table == NULL || capacity == 0 || chain == NULL) {
		return;
	}
	size_t slot = (size_t)mp3_fragment_chain_hash(chain->end,
		match_rear_offset ? chain->rear_offset : 0) & (capacity - 1);
	while (table[slot].occupied
		&& (table[slot].end != chain->end
			|| (match_rear_offset
				&& table[slot].rear_offset != chain->rear_offset))) {
		slot = (slot + 1) & (capacity - 1);
	}
	if (!table[slot].occupied
		|| (keep_earliest && chain->first < table[slot].first)
		|| (!keep_earliest && chain->first > table[slot].first)) {
		table[slot] = *chain;
	}
}

static void mp3_fragment_chain_store_all(Mp3FragmentChainTables *tables,
	const Mp3FragmentChain *chain) {
	if (tables == NULL || chain == NULL) {
		return;
	}
	mp3_fragment_chain_store(tables->earliest, tables->capacity, chain,
		true, true);
	mp3_fragment_chain_store(tables->latest, tables->capacity, chain,
		true, false);
	mp3_fragment_chain_store(tables->boundary_earliest, tables->capacity,
		chain, false, true);
	mp3_fragment_chain_store(tables->boundary_latest, tables->capacity,
		chain, false, false);
}

static bool mp3_fragment_starts_with_id3(BlockVector *b_read,
	const Mp3Fragment *fragment,
	uint32_t blocksize) {
	if (b_read == NULL || fragment == NULL || !fragment->isHeader
		|| fragment->firstActBlock < 0 || blocksize < ID3V2_HEADER_SIZE) {
		return false;
	}
	const int64_t apparent = filemirror_apparent_blocknumber(
		scalpel_state.filemirror, fragment->firstActBlock);
	if (apparent < 0) {
		return false;
	}

	resize_blockvector(b_read, 1);
	blockvector_set_apparent_blocknumber(b_read, 0, apparent);
	blockvector_set_data_length_to_mapped_extent(b_read);
	inflate_blockvector(b_read);
	uint32_t id3_size = 0;
	const bool is_id3 = mp3_id3v2_header_size(
		(const uint8_t *)blockvector_get_data_pointer(b_read),
		blockvector_get_data_length(b_read), &id3_size);
	deflate_blockvector(b_read);
	return is_id3;
}

static void mp3_fragment_chain_from_fragment(const Mp3Fragment *fragment,
	BlockVector *b_read,
	uint32_t blocksize,
	Mp3FragmentChain *chain) {
	memset(chain, 0, sizeof(*chain));
	chain->occupied = true;
	chain->end = fragment->lastActBlock;
	chain->first = fragment->firstActBlock;
	chain->front_offset = fragment->frontOffset;
	chain->rear_offset = fragment->rearOffset;
	chain->is_header = fragment->isHeader;
	chain->is_id3_header = mp3_fragment_starts_with_id3(b_read, fragment,
		blocksize);
	chain->is_tail = fragment->isTail;
	chain->preserve_front_context = fragment->preserveFrontContext;
	chain->second_to_last_frame_position =
		fragment->secondToLastFramePosition;
	chain->last_frame_position = fragment->lastFramePosition;
	chain->offset_frame_position = fragment->offsetFramePosition;
}

static bool mp3_fragment_chain_same(const Mp3FragmentChain *left,
	const Mp3FragmentChain *right) {
	return left != NULL && right != NULL
		&& left->first == right->first
		&& left->end == right->end
		&& left->front_offset == right->front_offset
		&& left->rear_offset == right->rear_offset
		&& left->preserve_front_context == right->preserve_front_context;
}

static bool mp3_fragment_chain_combine(const Mp3FragmentChain *predecessor,
	const Mp3Fragment *fragment,
	uint32_t blocksize,
	Mp3Fragment *combined,
	Mp3FragmentChain *chain) {
	if (predecessor == NULL || fragment == NULL || combined == NULL
		|| chain == NULL || blocksize == 0
		|| predecessor->first < 0
		|| fragment->firstActBlock < predecessor->first
		|| fragment->lastActBlock <= predecessor->end) {
		return false;
	}
	const uint64_t prefix_blocks =
		(uint64_t)(fragment->firstActBlock - predecessor->first);
	if (prefix_blocks > UINT64_MAX / blocksize) {
		return false;
	}
	const uint64_t shift = prefix_blocks * blocksize;
	if (fragment->secondToLastFramePosition > UINT64_MAX - shift
		|| fragment->lastFramePosition > UINT64_MAX - shift
		|| fragment->offsetFramePosition > UINT64_MAX - shift) {
		return false;
	}

	mp3_fragment_reset(combined);
	combined->firstActBlock = predecessor->first;
	combined->lastActBlock = fragment->lastActBlock;
	combined->size = (size_t)(combined->lastActBlock
		- combined->firstActBlock + 1);
	combined->frontOffset = predecessor->front_offset;
	combined->rearOffset = fragment->rearOffset;
	combined->isHeader = predecessor->is_header;
	combined->isTail = fragment->isTail;
	combined->preserveFrontContext = predecessor->preserve_front_context
		|| fragment->preserveFrontContext;
	combined->secondToLastFramePosition = shift
		+ fragment->secondToLastFramePosition;
	combined->lastFramePosition = shift + fragment->lastFramePosition;
	combined->offsetFramePosition = shift + fragment->offsetFramePosition;

	chain->occupied = true;
	chain->end = combined->lastActBlock;
	chain->first = combined->firstActBlock;
	chain->front_offset = combined->frontOffset;
	chain->rear_offset = combined->rearOffset;
	chain->is_header = combined->isHeader;
	chain->is_id3_header = predecessor->is_id3_header;
	chain->is_tail = combined->isTail;
	chain->preserve_front_context = combined->preserveFrontContext;
	chain->second_to_last_frame_position =
		combined->secondToLastFramePosition;
	chain->last_frame_position = combined->lastFramePosition;
	chain->offset_frame_position = combined->offsetFramePosition;
	return true;
}

// Coalesce physically adjacent parser-confirmed pieces when their MPEG frame
// offsets prove continuity. A changed offset naturally ends the physical run,
// including where a logically displaced run begins in otherwise adjacent data.
static bool mp3_fragment_catalog_consolidate(Mp3FragmentCatalog *catalog,
	BlockVector *b_read,
	uint32_t blocksize,
	bool *interrupted) {
	Mp3Fragment *ordered = NULL;
	Mp3Fragment *additions = NULL;
	Mp3FragmentChainTables tables = {0};
	uint16_t addition_count = 0;
	uint16_t addition_capacity = 0;
	size_t chain_capacity = 1;
	bool success = false;

	if (interrupted != NULL) {
		*interrupted = false;
	}
	if (catalog == NULL || b_read == NULL || blocksize == 0
		|| interrupted == NULL) {
		return false;
	}
	if (catalog->count < 2) {
		return true;
	}
	qsort(catalog->fragments, catalog->count, sizeof(*catalog->fragments),
		mp3_fragment_physical_compare);
	uint16_t unique_count = 1;
	for (uint16_t index = 1; index < catalog->count; index++) {
		if (mp3_fragment_physical_compare(
			&catalog->fragments[unique_count - 1],
			&catalog->fragments[index]) != 0) {
			catalog->fragments[unique_count++] = catalog->fragments[index];
		}
	}
	catalog->count = unique_count;
	const uint16_t base_count = catalog->count;
	if (base_count < 2) {
		return true;
	}

	ordered = malloc((size_t)base_count * sizeof(*ordered));
	check_memory_allocation(ordered, __LINE__, __FILE__,
		"MP3 ordered fragment catalog");
	memcpy(ordered, catalog->fragments,
		(size_t)base_count * sizeof(*ordered));
	qsort(ordered, base_count, sizeof(*ordered),
		mp3_fragment_physical_compare);

	while (chain_capacity < (size_t)base_count * 4U) {
		chain_capacity <<= 1;
	}
	tables.capacity = chain_capacity;
	tables.earliest = calloc(chain_capacity, sizeof(*tables.earliest));
	tables.latest = calloc(chain_capacity, sizeof(*tables.latest));
	tables.boundary_earliest = calloc(chain_capacity,
		sizeof(*tables.boundary_earliest));
	tables.boundary_latest = calloc(chain_capacity,
		sizeof(*tables.boundary_latest));
	check_memory_allocation(tables.earliest, __LINE__, __FILE__,
		"MP3 earliest physical fragment chains");
	check_memory_allocation(tables.latest, __LINE__, __FILE__,
		"MP3 latest physical fragment chains");
	check_memory_allocation(tables.boundary_earliest, __LINE__, __FILE__,
		"MP3 earliest boundary fragment chains");
	check_memory_allocation(tables.boundary_latest, __LINE__, __FILE__,
		"MP3 latest boundary fragment chains");

	for (uint16_t index = 0; index < base_count; index++) {
		const Mp3Fragment *fragment = &ordered[index];
		Mp3FragmentChain chain;

		if ((index & UINT16_C(0xff)) == 0
			&& atomic_load_explicit(&REASS_RETURN_TO_IDLE,
				memory_order_acquire)) {
			*interrupted = true;
			goto done;
		}
		if (fragment->preserveFrontContext) {
			continue;
		}
		mp3_fragment_chain_from_fragment(fragment, b_read, blocksize, &chain);
		mp3_fragment_chain_store_all(&tables, &chain);

		if (fragment->firstActBlock > INT64_MIN) {
			const int64_t predecessor_end = fragment->firstActBlock - 1;
			Mp3FragmentChain *predecessors[2] = {
				mp3_fragment_chain_lookup(tables.earliest, tables.capacity,
					predecessor_end, fragment->frontOffset, true),
				mp3_fragment_chain_lookup(tables.latest, tables.capacity,
					predecessor_end, fragment->frontOffset, true)
			};
			for (size_t choice = 0; choice < 2; choice++) {
				if (predecessors[choice] == NULL
					|| (choice == 1 && mp3_fragment_chain_same(
						predecessors[0], predecessors[1]))) {
					continue;
				}
				Mp3Fragment combined;
				Mp3FragmentChain combined_chain;
				if (mp3_fragment_chain_combine(predecessors[choice], fragment,
					blocksize, &combined, &combined_chain)) {
					if (!mp3_fragment_array_append(&additions,
						&addition_count, &addition_capacity, &combined)) {
						goto done;
					}
					mp3_fragment_chain_store_all(&tables, &combined_chain);
				}
			}
		}

		const uint64_t maximum_bridge =
			MP3_HEADER_PREDECESSOR_SCAN_BYTES / blocksize
				+ ((MP3_HEADER_PREDECESSOR_SCAN_BYTES % blocksize) != 0);
		for (int direction = -1; direction <= 1; direction += 2) {
			for (uint64_t distance = direction < 0 ? 0 : 1;
				distance <= maximum_bridge; distance++) {
				if ((distance & UINT64_C(0x3f)) == 0
					&& atomic_load_explicit(&REASS_RETURN_TO_IDLE,
						memory_order_acquire)) {
					*interrupted = true;
					goto done;
				}
				int64_t predecessor_end;
				if (direction < 0) {
					if (fragment->firstActBlock <= (int64_t)distance) {
						break;
					}
					predecessor_end = fragment->firstActBlock
						- (int64_t)distance - 1;
				}
				else {
					if (fragment->firstActBlock
						> INT64_MAX - (int64_t)distance + 1) {
						break;
					}
					predecessor_end = fragment->firstActBlock
						+ (int64_t)distance - 1;
					if (predecessor_end >= fragment->lastActBlock
						|| distance > UINT64_MAX / blocksize
						|| fragment->frontOffset >= distance * blocksize) {
						continue;
					}
				}
				Mp3FragmentChain *predecessors[2] = {
					mp3_fragment_chain_lookup(tables.boundary_earliest,
						tables.capacity, predecessor_end, 0, false),
					mp3_fragment_chain_lookup(tables.boundary_latest,
						tables.capacity, predecessor_end, 0, false)
				};
				for (size_t choice = 0; choice < 2; choice++) {
					Mp3FragmentChain *predecessor = predecessors[choice];
					if (predecessor == NULL
						|| predecessor->first >= fragment->firstActBlock
						|| (choice == 1 && mp3_fragment_chain_same(
							predecessors[0], predecessors[1]))) {
						continue;
					}
					Mp3Fragment combined;
					Mp3FragmentChain combined_chain;
					bool validates = false;
					bool maybe = false;
					if (mp3_fragment_chain_combine(predecessor, fragment,
						blocksize, &combined, &combined_chain)
						&& mp3_fragment_measure_range(b_read,
							predecessor->first, fragment->lastActBlock,
							blocksize, 0, 0, &combined, &validates, &maybe)
						&& (validates || maybe)
						&& (combined.frontOffset == predecessor->front_offset
							|| (predecessor->is_id3_header && combined.isHeader))) {
						combined.preserveFrontContext =
							predecessor->preserve_front_context
							|| fragment->preserveFrontContext;
						if (!mp3_fragment_array_append(&additions,
							&addition_count, &addition_capacity, &combined)) {
							goto done;
						}
						mp3_fragment_chain_from_fragment(&combined, b_read,
							blocksize, &combined_chain);
						mp3_fragment_chain_store_all(&tables, &combined_chain);
					}
				}
			}
		}
	}

	for (uint16_t index = 0; index < addition_count; index++) {
		if (!mp3_fragment_array_append(&catalog->fragments,
			&catalog->count, &catalog->capacity, &additions[index])) {
			goto done;
		}
	}
	qsort(catalog->fragments, catalog->count, sizeof(*catalog->fragments),
		mp3_fragment_physical_compare);
	unique_count = 1;
	for (uint16_t index = 1; index < catalog->count; index++) {
		if (mp3_fragment_physical_compare(
			&catalog->fragments[unique_count - 1],
			&catalog->fragments[index]) != 0) {
			catalog->fragments[unique_count++] = catalog->fragments[index];
		}
	}
	catalog->count = unique_count;
	success = true;

done:
	free(tables.boundary_latest);
	free(tables.boundary_earliest);
	free(tables.latest);
	free(tables.earliest);
	free(additions);
	free(ordered);
	return success;
}

static void mp3_fragment_catalog_release_builder(
	Mp3FragmentCatalog *catalog) {

	MUTEX_ERROR_CHECK(pthread_mutex_lock(&catalog->mutex),
		__LINE__, __FILE__);
	if (catalog->state == MP3_FRAGMENT_CATALOG_BUILDING) {
		catalog->state = MP3_FRAGMENT_CATALOG_IDLE;
	}
	MUTEX_ERROR_CHECK(pthread_cond_broadcast(&catalog->condition),
		__LINE__, __FILE__);
	MUTEX_ERROR_CHECK(pthread_mutex_unlock(&catalog->mutex),
		__LINE__, __FILE__);
}

static Mp3FragmentDiscoveryResult mp3_fragment_catalog_get(
	ThreadWork *work,
	CarveInfo *candidate,
	Mp3CarveState *carve_state,
	BlockVector *b_read,
	uint32_t blocksize,
	uuid_string_t uuidp,
	uuid_string_t uuidc,
	const Mp3Fragment **fragments,
	uint16_t *count) {

	Mp3FragmentCatalog *catalog = &mp3_fragment_catalog;
	const uint64_t image_size = filemirror_filesize(scalpel_state.filemirror);
	const uint64_t actual_blocks = image_size / blocksize
		+ ((image_size % blocksize) != 0);
	uint64_t first_block_length = 0;
	const char *image_data = filemirror_actual_block_data_pointer(
		scalpel_state.filemirror, 0, &first_block_length);
	if (image_data == NULL || first_block_length == 0) {
		return MP3_FRAGMENT_DISCOVERY_FAILED;
	}

	for (;;) {
		MUTEX_ERROR_CHECK(pthread_mutex_lock(&catalog->mutex),
			__LINE__, __FILE__);
		if (catalog->filemirror == NULL) {
			catalog->filemirror = scalpel_state.filemirror;
			catalog->needleidx = candidate->needleidx;
			catalog->blocksize = blocksize;
			catalog->actual_blocks = actual_blocks;
		}
		else if (catalog->filemirror != scalpel_state.filemirror
			|| catalog->needleidx != candidate->needleidx
			|| catalog->blocksize != blocksize
			|| catalog->actual_blocks != actual_blocks) {
			MUTEX_ERROR_CHECK(pthread_mutex_unlock(&catalog->mutex),
				__LINE__, __FILE__);
			lock_fprintf(stderr,
				"MP3 fragment catalog does not match the active image.\n");
			return MP3_FRAGMENT_DISCOVERY_FAILED;
		}

		if (catalog->state == MP3_FRAGMENT_CATALOG_READY) {
			*fragments = catalog->fragments;
			*count = catalog->count;
			MUTEX_ERROR_CHECK(pthread_mutex_unlock(&catalog->mutex),
				__LINE__, __FILE__);
			return MP3_FRAGMENT_DISCOVERY_FINISHED;
		}
		if (catalog->state == MP3_FRAGMENT_CATALOG_FAILED) {
			MUTEX_ERROR_CHECK(pthread_mutex_unlock(&catalog->mutex),
				__LINE__, __FILE__);
			return MP3_FRAGMENT_DISCOVERY_FAILED;
		}
		if (catalog->state == MP3_FRAGMENT_CATALOG_IDLE) {
			if (atomic_load_explicit(&REASS_RETURN_TO_IDLE,
				memory_order_acquire)) {
				MUTEX_ERROR_CHECK(pthread_mutex_unlock(&catalog->mutex),
					__LINE__, __FILE__);
				if (mp3_fragment_discovery_checkpoint(work, candidate,
					carve_state, uuidp, uuidc)) {
					return MP3_FRAGMENT_DISCOVERY_CHECKPOINT;
				}
				continue;
			}
			catalog->state = MP3_FRAGMENT_CATALOG_BUILDING;
			MUTEX_ERROR_CHECK(pthread_mutex_unlock(&catalog->mutex),
				__LINE__, __FILE__);
			break;
		}

		if (atomic_load_explicit(&REASS_RETURN_TO_IDLE,
			memory_order_acquire)) {
			MUTEX_ERROR_CHECK(pthread_mutex_unlock(&catalog->mutex),
				__LINE__, __FILE__);
			if (mp3_fragment_discovery_checkpoint(work, candidate,
				carve_state, uuidp, uuidc)) {
				return MP3_FRAGMENT_DISCOVERY_CHECKPOINT;
			}
			continue;
		}
		MUTEX_ERROR_CHECK(pthread_cond_wait(&catalog->condition,
			&catalog->mutex), __LINE__, __FILE__);
		MUTEX_ERROR_CHECK(pthread_mutex_unlock(&catalog->mutex),
			__LINE__, __FILE__);
	}

	while (image_size >= FRAME_HEADER_SIZE
		&& catalog->scan_offset <= image_size - FRAME_HEADER_SIZE) {
		const uint64_t chain_start = catalog->scan_offset;
		const int64_t first_actual = (int64_t)(chain_start / blocksize);
		FrameArgs first_args;
		uint16_t first_frame_length;

		if (atomic_load_explicit(&REASS_RETURN_TO_IDLE,
			memory_order_acquire)) {
			mp3_fragment_catalog_release_builder(catalog);
			if (mp3_fragment_discovery_checkpoint(work, candidate,
				carve_state, uuidp, uuidc)) {
				return MP3_FRAGMENT_DISCOVERY_CHECKPOINT;
			}
			return mp3_fragment_catalog_get(work, candidate, carve_state,
				b_read, blocksize, uuidp, uuidc, fragments, count);
		}
		if (filemirror_actual_block_covered(scalpel_state.filemirror,
				first_actual)
			|| filemirror_apparent_blocknumber(scalpel_state.filemirror,
					first_actual) < 0) {
			catalog->scan_offset = ((uint64_t)first_actual + 1) * blocksize;
			continue;
		}
		if ((uint8_t)image_data[chain_start] != UINT8_C(0xff)
			|| ((uint8_t)image_data[chain_start + 1] & UINT8_C(0xe0))
				!= UINT8_C(0xe0)
			|| !mp3_parse_complete_frame_at(image_data, image_size,
				chain_start, &first_args, &first_frame_length)) {
			catalog->scan_offset++;
			continue;
		}

		uint32_t frame_count = 1;
		uint64_t last_frame = chain_start;
		uint64_t next_frame = chain_start + first_frame_length;
		bool interrupted = false;
		while (next_frame <= image_size - FRAME_HEADER_SIZE) {
			FrameArgs next_args;
			uint16_t next_frame_length;
			const uint64_t first_block = last_frame / blocksize;
			const uint64_t last_block =
				(next_frame + FRAME_HEADER_SIZE - 1) / blocksize;
			bool range_available = true;

			if (atomic_load_explicit(&REASS_RETURN_TO_IDLE,
				memory_order_acquire)) {
				interrupted = true;
				break;
			}
			for (uint64_t actual = first_block;
				range_available && actual <= last_block; actual++) {
				if (actual >= actual_blocks
					|| filemirror_actual_block_covered(
						scalpel_state.filemirror, (int64_t)actual)
					|| filemirror_apparent_blocknumber(
						scalpel_state.filemirror, (int64_t)actual) < 0) {
					range_available = false;
				}
			}
			if (!range_available
				|| !mp3_parse_complete_frame_at(image_data, image_size,
					next_frame, &next_args, &next_frame_length)
				|| !mp3_frame_stream_parameters_match(&first_args, &next_args)) {
				break;
			}
			frame_count++;
			last_frame = next_frame;
			if (next_frame > UINT64_MAX - next_frame_length) {
				break;
			}
			next_frame += next_frame_length;
		}
		if (interrupted) {
			mp3_fragment_catalog_release_builder(catalog);
			if (mp3_fragment_discovery_checkpoint(work, candidate,
				carve_state, uuidp, uuidc)) {
				return MP3_FRAGMENT_DISCOVERY_CHECKPOINT;
			}
			return mp3_fragment_catalog_get(work, candidate, carve_state,
				b_read, blocksize, uuidp, uuidc, fragments, count);
		}

		if (frame_count >= MP3_FRAGMENT_CATALOG_MINIMUM_COMPATIBLE_FRAMES) {
			Mp3Fragment fragment;
			bool validates = false;
			bool maybe = false;
			const int64_t last_actual = (int64_t)(last_frame / blocksize);
			int64_t fragment_last_actual = last_actual;
			uint64_t fragment_maximum_length =
				next_frame - (uint64_t)first_actual * blocksize;
			const uint64_t expected_front = chain_start % blocksize;

			// Include a terminal metadata footer in the measured run. Without
			// this extension the frame-chain endpoint is used as the validation
			// length, so the footer cannot be seen and isTail cannot be set.
			uint64_t footer_start = 0;
			uint64_t footer_end = 0;
			bool footer_available = false;
			uint64_t footer_window = blocksize;
			if (footer_window <= UINT64_MAX - ID3V1_TAG_SIZE) {
				footer_window += ID3V1_TAG_SIZE;
			}
			uint64_t footer_search_end = image_size;
			if (next_frame <= UINT64_MAX - footer_window
				&& next_frame + footer_window < image_size) {
				footer_search_end = next_frame + footer_window;
			}
			// An adjacent complete APE tag can exceed the footer search window.
			// Measure it before validating the physical run: a partial view of
			// that tag would invalidate the audio chain and omit its extension.
			uint64_t adjacent_ape_end = 0;
			bool footer_found = mp3_ape_tag_extent(image_data, image_size,
				next_frame, false, &adjacent_ape_end) == 1;
			if (footer_found) {
				Bitstream tags = {(char *)image_data, 0, adjacent_ape_end,
					image_size, false};
				(void)skipID3v1(&tags);
				footer_start = next_frame;
				footer_end = tags.bytePos;
			} else {
				footer_found = mp3_fragment_find_terminal_footer(image_data, image_size,
					next_frame, footer_search_end, &footer_start, &footer_end);
			}
			if (footer_found
				&& footer_end > next_frame) {
				const int64_t footer_last_actual =
					(int64_t)((footer_end - 1) / blocksize);
				footer_available = footer_last_actual >= first_actual
					&& (uint64_t)footer_last_actual < actual_blocks;
				for (int64_t actual = first_actual;
					footer_available && actual <= footer_last_actual; actual++) {
					if (filemirror_actual_block_covered(
						scalpel_state.filemirror, actual)
						|| filemirror_apparent_blocknumber(
							scalpel_state.filemirror, actual) < 0) {
						footer_available = false;
						break;
					}
				}
				if (footer_available) {
					fragment_last_actual = footer_last_actual;
					fragment_maximum_length = footer_end
						- (uint64_t)first_actual * blocksize;
				}
			}

			if (expected_front <= UINT16_MAX
				&& mp3_fragment_measure_range(b_read, first_actual,
					fragment_last_actual, blocksize, fragment_maximum_length,
					expected_front, &fragment, &validates, &maybe)
				&& (validates || (footer_available && maybe))
				&& fragment.frontOffset == expected_front) {
				// Validate the scanner's chain, not an incidental sync in the
				// preceding frame remainder. Keep the validator's measured frame
				// positions and footer extent together; do not patch only the front
				// offset onto metadata obtained from another chain.
				// rearOffset already measures the final frame's overrun beyond
				// the mapped physical range, not the scanner's analysis endpoint.
				if (!mp3_fragment_catalog_append(catalog, b_read,
					actual_blocks, blocksize, &fragment)) {
					lock_fprintf(stdout,
						"MP3 fragment catalog reached the %u-fragment limit; "
						"remaining frame chains will not be indexed.\n",
						UINT16_MAX);
					catalog->scan_offset = image_size;
					break;
				}
				// A terminal APE tag can span blocks without MPEG headers.
				// Keep the audio-only run as well as its structurally checked
				// metadata extension; file validation decides the final extent.
				uint64_t tag_end = 0;
				if (mp3_ape_tag_extent(image_data, image_size, next_frame,
					false, &tag_end) == 1) {
					Bitstream tags = {(char *)image_data, 0, tag_end,
						image_size, false};
					(void)skipID3v1(&tags);
					tag_end = tags.bytePos;
					const int64_t tag_last = (int64_t)((tag_end - 1) / blocksize);
					bool available = true;
					for (int64_t actual = last_actual; actual <= tag_last; actual++) {
						if (filemirror_actual_block_covered(scalpel_state.filemirror,
								actual)
							|| filemirror_apparent_blocknumber(scalpel_state.filemirror,
								actual) < 0) {
							available = false;
							break;
						}
					}
					if (available) {
						Mp3Fragment tagged = fragment;
						tagged.lastActBlock = tag_last;
						tagged.size = (uint64_t)(tag_last - first_actual) + 1;
						tagged.rearOffset = 0;
						tagged.isTail = true;
						if (!mp3_fragment_array_append(&catalog->fragments,
							&catalog->count, &catalog->capacity, &tagged)) {
							catalog->scan_offset = image_size;
							break;
						}
					}
				}
			}
			catalog->scan_offset = next_frame;
		}
		else {
			catalog->scan_offset++;
		}
	}

	if (!catalog->consolidation_complete) {
		bool interrupted = false;
		if (!mp3_fragment_catalog_consolidate(catalog, b_read, blocksize,
			&interrupted)) {
			if (interrupted) {
				mp3_fragment_catalog_release_builder(catalog);
				if (mp3_fragment_discovery_checkpoint(work, candidate,
					carve_state, uuidp, uuidc)) {
					return MP3_FRAGMENT_DISCOVERY_CHECKPOINT;
				}
				return mp3_fragment_catalog_get(work, candidate, carve_state,
					b_read, blocksize, uuidp, uuidc, fragments, count);
			}
			MUTEX_ERROR_CHECK(pthread_mutex_lock(&catalog->mutex),
				__LINE__, __FILE__);
			catalog->state = MP3_FRAGMENT_CATALOG_FAILED;
			MUTEX_ERROR_CHECK(pthread_cond_broadcast(&catalog->condition),
				__LINE__, __FILE__);
			MUTEX_ERROR_CHECK(pthread_mutex_unlock(&catalog->mutex),
				__LINE__, __FILE__);
			return MP3_FRAGMENT_DISCOVERY_FAILED;
		}
		catalog->consolidation_complete = true;
	}

	while (catalog->peak_index < catalog->count) {
		if (atomic_load_explicit(&REASS_RETURN_TO_IDLE,
			memory_order_acquire)) {
			mp3_fragment_catalog_release_builder(catalog);
			if (mp3_fragment_discovery_checkpoint(work, candidate,
				carve_state, uuidp, uuidc)) {
				return MP3_FRAGMENT_DISCOVERY_CHECKPOINT;
			}
			return mp3_fragment_catalog_get(work, candidate, carve_state,
				b_read, blocksize, uuidp, uuidc, fragments, count);
		}
		mp3_fragment_measure_peaks(b_read,
			&catalog->fragments[catalog->peak_index], blocksize);
		catalog->peak_index++;
	}

	MUTEX_ERROR_CHECK(pthread_mutex_lock(&catalog->mutex),
		__LINE__, __FILE__);
	catalog->state = MP3_FRAGMENT_CATALOG_READY;
	*fragments = catalog->fragments;
	*count = catalog->count;
	MUTEX_ERROR_CHECK(pthread_cond_broadcast(&catalog->condition),
		__LINE__, __FILE__);
	MUTEX_ERROR_CHECK(pthread_mutex_unlock(&catalog->mutex),
		__LINE__, __FILE__);
	lock_fprintf(stdout,
		"MP3 fragment catalog contains %u plausible physical runs from "
		"%"PRIu64" frame chains.\n",
		catalog->count, catalog->source_runs);
	if (scalpel_state.mode_verbose) {
		for (uint16_t index = 0; index < catalog->count; index++) {
			const Mp3Fragment *fragment = &catalog->fragments[index];

			lock_fprintf(stdout,
				"MP3 catalog run %u: actual=%"PRId64"-%"PRId64
				" blocks=%zu offsets=%u/%u header=%u tail=%u.\n",
				index, fragment->firstActBlock, fragment->lastActBlock,
				fragment->size, fragment->frontOffset,
				fragment->rearOffset, fragment->isHeader,
				fragment->isTail);
		}
	}
	return MP3_FRAGMENT_DISCOVERY_FINISHED;
}

static Mp3FragmentDiscoveryResult mp3_fragment_catalog_import(
	ThreadWork *work,
	CarveInfo *candidate,
	Mp3CarveState *carve_state,
	BlockVector *b_read,
	uint32_t blocksize,
	const Mp3Fragment *fragments,
	uint16_t count,
	uuid_string_t uuidp,
	uuid_string_t uuidc) {

	Mp3Fragment *imported = NULL;
	uint16_t imported_count = 0;
	uint16_t imported_capacity = 0;
	const uint64_t choice_slot =
		blockvector_get_num_blocks(candidate->b) - 1;

	if (! mp3_fragment_array_append(&imported, &imported_count,
		&imported_capacity, &carve_state->fragments[0])) {
		return MP3_FRAGMENT_DISCOVERY_FAILED;
	}
	imported[0].active = false;

	for (uint16_t index = 0; index < count; index++) {
		const Mp3Fragment *source = &fragments[index];
		int64_t run_start = -1;

		if (atomic_load_explicit(&REASS_RETURN_TO_IDLE,
			memory_order_acquire)) {
			free(imported);
			if (mp3_fragment_discovery_checkpoint(work, candidate,
				carve_state, uuidp, uuidc)) {
				return MP3_FRAGMENT_DISCOVERY_CHECKPOINT;
			}
			return MP3_FRAGMENT_DISCOVERY_FAILED;
		}
		for (int64_t actual = source->firstActBlock;
			actual <= source->lastActBlock + 1; actual++) {
			bool available = false;
			if (actual <= source->lastActBlock) {
				const int64_t apparent = filemirror_apparent_blocknumber(
					scalpel_state.filemirror, actual);
				available = apparent >= 0
					&& ! filemirror_actual_block_covered(
						scalpel_state.filemirror, actual)
					&& ! blockvector_choice_is_excluded(candidate->b,
						choice_slot, apparent);
			}
			if (available && run_start < 0) {
				run_start = actual;
			}
			if ((! available || actual > source->lastActBlock)
				&& run_start >= 0) {
				const int64_t run_end = actual - 1;
				Mp3Fragment fragment;
				if (run_start == source->firstActBlock
					&& run_end == source->lastActBlock) {
					fragment = *source;
				}
				else {
					bool validates = false;
					bool maybe = false;
						if (! mp3_fragment_measure_range(b_read, run_start,
							run_end, blocksize, 0, 0, &fragment, &validates, &maybe)) {
							run_start = -1;
							continue;
						}
						if (run_start == source->firstActBlock) {
							fragment.preserveFrontContext =
								source->preserveFrontContext;
						}
						mp3_fragment_measure_peaks(b_read, &fragment,
						blocksize);
				}
				fragment.active = true;
				if (! mp3_fragment_array_append(&imported,
					&imported_count, &imported_capacity, &fragment)) {
					lock_fprintf(stdout,
						"MP3 candidate reached the %u-fragment limit while "
						"importing the shared catalog.\n", UINT16_MAX);
					index = count;
					break;
				}
				run_start = -1;
			}
		}
	}

	free(carve_state->fragments);
	free(carve_state->indexes);
	carve_state->fragments = imported;
	carve_state->num_frags = imported_count;
	carve_state->indexes = calloc(imported_count, sizeof(uint16_t));
	check_memory_allocation(carve_state->indexes, __LINE__, __FILE__,
		"MP3 imported fragment indexes");
	carve_state->cur_index = 0;
	carve_state->fragment_discovery_phase = MP3_FRAGMENT_DISCOVERY_COMPLETE;
	carve_state->fragment_discovery_next_actual = -1;
	carve_state->fragment_discovery_peak_index = imported_count;
	carve_state->fragment_discovery_open = false;
	carve_state->fragment_discovery_apparent_blocks =
		filemirror_apparent_blocks(scalpel_state.filemirror);
	carve_put_state(candidate->carvehashkey, carve_state);
	return MP3_FRAGMENT_DISCOVERY_FINISHED;
}

/**
* @discussion		MP3 Fragment Generator: imports a shared catalog of physical MP3 runs
*/
static Mp3FragmentDiscoveryResult mp3_reassembly_generate_fragments(
	ThreadWork *work,
	BlockVector *b,
	BlockVector *b_read,
	CarveInfo *candidate,
	Mp3CarveState *carve_state,
	uint32_t *blocksize,
	uuid_string_t uuidp,
	uuid_string_t uuidc) {

	const Mp3Fragment *catalog_fragments = NULL;
	uint16_t catalog_count = 0;
	Mp3FragmentDiscoveryResult result;

	if (carve_state->fragment_discovery_phase
		== MP3_FRAGMENT_DISCOVERY_UNINITIALIZED
		&& ! mp3_reassembly_trim_seed_candidate(b)) {
		return MP3_FRAGMENT_DISCOVERY_FAILED;
	}
	if (blockvector_get_num_blocks(b) == 0) {
		return MP3_FRAGMENT_DISCOVERY_FAILED;
	}
	inflate_blockvector(b);
	*blocksize = scalpel_state.blocksize;
	if (*blocksize == 0) {
		return MP3_FRAGMENT_DISCOVERY_FAILED;
	}
	if (carve_state->fragment_discovery_phase
		== MP3_FRAGMENT_DISCOVERY_UNINITIALIZED) {
		ValidationArgs va = get_validation_args();
		Mp3Fragment *first = &carve_state->fragments[0];
		mp3_fragment_validate(blockvector_get_data_pointer(b),
			blockvector_get_data_length(b), &va.validates, &va.validates_to,
			va.needleidx, &va.frontOffset, &va.rearOffset, &va.isHeader,
			&va.isTail, &va.secondToLastFramePosition,
			&va.lastFramePosition, &va.offsetFramePosition, &va.maybe);
		mp3_fragment_reset(first);
		first->frontOffset = va.frontOffset;
		first->rearOffset = va.rearOffset;
		first->size = blockvector_get_num_blocks(b);
		first->isHeader = va.isHeader;
		first->isTail = va.isTail;
		first->active = false;
		first->secondToLastFramePosition = va.secondToLastFramePosition;
		first->lastFramePosition = va.lastFramePosition;
		first->offsetFramePosition = va.offsetFramePosition;
		first->firstActBlock = blockvector_get_actual_blocknumber(b, 0);
		first->lastActBlock = blockvector_get_actual_blocknumber(b,
			first->size - 1);
		mp3_fragment_refresh_header_context(first);
		mp3_fragment_measure_peaks(b_read, first, *blocksize);
		if (! mp3_reassembly_rebuild_seed_candidate(candidate, first)) {
			return MP3_FRAGMENT_DISCOVERY_FAILED;
		}
		for (uint64_t position = 0;
			position < blockvector_get_num_blocks(b); position++) {
			blockvector_remove_choice(b,
				blockvector_get_num_blocks(b) - 1,
				blockvector_get_apparent_blocknumber(b, position));
		}
		carve_state->fragment_discovery_phase =
			MP3_FRAGMENT_DISCOVERY_SCANNING;
		carve_state->fragment_discovery_apparent_blocks =
			filemirror_apparent_blocks(scalpel_state.filemirror);
	}

	result = mp3_fragment_catalog_get(work, candidate, carve_state,
		b_read, *blocksize, uuidp, uuidc, &catalog_fragments,
		&catalog_count);
	if (result != MP3_FRAGMENT_DISCOVERY_FINISHED) {
		return result;
	}
	return mp3_fragment_catalog_import(work, candidate, carve_state,
		b_read, *blocksize, catalog_fragments, catalog_count,
		uuidp, uuidc);
}

/**
* @discussion		MP3 Block Validator: Validates whether a block is a valid section of an MP3 file.
*
* Edit: 11/21/25
* What is this function?
* The classic Scalpel3 block validator. Specifically, what the Scalpel3 backend will use to validate
* whether blocks are of the MP3 file type. mp3_fragment_validate does the majority of the validation
* logic, however extra steps have to be taken due to the risk of stealing blocks from other file types.
* Execution goes as follows:
* - First, mp3_fragment_validate is ran, which simply determines whether there are enough frame headers
* 	with valid offsets to other frame headers. If a long enough chain is discovered, the
* 	first check is passed.
* - Next, each frame is opened in the MPG123 MP3 decoder and the bytes are checked. Usually if the
* 	headers are not legitimate, the decoder will fail and the output will be largely zeroes. We take
* 	advantage of this and record how many frames are unable to be recovered. The failure rate can be
*	changed with the DECODE_FAILURE_TOLERANCE parameter at the beginning of this file.
* - Various other strange edge cases are here to handle false positives previously discovered.
* Confidence that data is of the MP3 file type is largely dependent on the length of an MP3 frame chain.
* Because of this, there is only so much confidence that can be gathered on a block by block basis, thus
* necessitating that the block validator is more rigorous and meticulous when determining what blocks to
* claim, especially because other file validators may depend on them to be available.
*
* Is there a minimum block size that this validator supports?
* Anything below 1200 bytes is risky. Consider an MP3 frame that is about 600 bytes long, and the size of
* the block is 500 bytes long. A valid MP3 frame header might be detected, but without an MP3 frame header
* immediately proceeding the MP3 frame, it isn't possible to confidently verify that that MP3 frame header
* is truly an MP3 frame header and not an assortment of bytes that happen to indicate a valid MP3 frame header.
* In other words, if the frame size is smaller than the block size, there will be issues and the validation
* will be unsuccessful.
**/

// MP3 frame front/rear offsets are stored in uint16_t (Mp3Fragment.frontOffset/rearOffset,
// ValidationArgs.frontOffset/rearOffset), computed as a byte position within a single
// scalpel block's data. scalpel3's -q option allows block sizes far larger than 65,535
// bytes, which would let a legitimate offset overflow those fields. Widening them would
// ripple through every function signature that carries them and the persisted
// Mp3Fragment/carve-state layout; capping the supported block size here instead
// is the smaller, lower-risk fix seen as an acceptable alternative.

static inline uint32_t mp3_block_validate(char* data,
	uint64_t length,
	BlockValidationDecision* decision,
	uint64_t* validates_to,
	uint32_t needleidx,
	uint32_t blocksize,
	void *blockhashkey) {

	(void)blockhashkey;
	static bool warned_unsupported_blocksize = false;

	if(blocksize > MP3_MAX_SUPPORTED_BLOCKSIZE){
		if(!warned_unsupported_blocksize){
			warned_unsupported_blocksize = true;
			lock_fprintf(stdout,
				"MP3: block size %"PRIu32" exceeds the %d-byte limit MP3 frame offsets can\n"
				"represent (uint16_t); MP3 block validation is disabled for this run. Use a\n"
				"smaller -q block size to enable MP3 support.\n",
				blocksize, MP3_MAX_SUPPORTED_BLOCKSIZE);
		}
		*decision = BLOCK_CONFIDENCE_INVALID;
		return needleidx;
	}

	uint32_t id3_size;
	if (mp3_id3v2_header_size((const uint8_t *)data, length, &id3_size)) {
		*validates_to = length > 0 ? length - 1 : 0;
		*decision = BLOCK_CONFIDENCE_VALID;
		return needleidx;
	}
	uint64_t zero_prefix_offset;
	FrameArgs zero_prefix_args;
	if (mp3_zero_prefixed_frame_header(data, length,
		&zero_prefix_offset, &zero_prefix_args)) {
		*validates_to = length > 0 ? length - 1 : 0;
		*decision = BLOCK_CONFIDENCE_VALID;
		return needleidx;
	}

	ValidationArgs va = get_validation_args();
	bool maybe;

	mp3_fragment_validate(data,
		length,
		&va.validates,
		&va.validates_to,
		needleidx,
		&va.frontOffset,
		&va.rearOffset,
		&va.isHeader,
		&va.isTail,
		&va.secondToLastFramePosition,
		&va.lastFramePosition,
		&va.offsetFramePosition,
		&maybe
	);

	*validates_to = va.validates_to;

	// A complete frame at the start supplies strong block evidence. Candidate
	// acceptance still requires file validation.
	if(va.validates && va.isHeader){
		#ifdef DEBUG_BLOCK_VALIDATE 
			lock_fprintf(stdout, "block header detected\n"); 
		#endif
		*decision = BLOCK_CONFIDENCE_VALID;
		return needleidx;
	}

	if(maybe){
		goto make_maybe;
	}
	else if(va.validates){
		//final check (are we really sure it's audio?)
		mpg123_handle *mh;
		unsigned char *buffer = malloc((length - va.frontOffset) * sizeof(unsigned char));
		if(!buffer){
			lock_fprintf(stderr, "Unable to allocate memory for buffer in block validation\n");
			*decision = BLOCK_CONFIDENCE_INVALID;
			return needleidx;
		}
		//unsigned char buffer[length-va.frontOffset];
		unsigned char *audio = &buffer[0];
		memcpy(buffer, (unsigned char *)(data+va.frontOffset), length-va.frontOffset);
		size_t bytes = 0;
		off_t frame_number;
		int ret, err;
		bool errorOccurred = false; //we allow one error, due to bit reservoir
		bool invalidate = false; //if true, we invalidate

		Bitstream bs = {data, 0, va.frontOffset, length, false};
		uint8_t mpegVersion = 0;
		uint8_t layer = 0;
		bool crc;
		uint32_t bitrate = 0;
		uint16_t samplingrate = 0;
		enum _ChannelMode channel;
		uint8_t padding = 0;
		uint16_t frameLengthInBytes = 0;
		uint64_t audioPosCount = 0;
		// wide enough that a large -q block size (which can hold far more than 255
		// frames) can't wrap these counters into a misleading small value
		uint32_t frame_num;
		uint32_t failures;

		mp3_ensure_init();
		//pthread_mutex_lock(&mp3_handle_mutex);
		//mh = mpg123_new(NULL, &err);
		//pthread_mutex_unlock(&mp3_handle_mutex);
		mh = mp3_thread_handle();
		if(!mh){
			lock_fprintf(stderr, "Unable to get handle in block validation\n");
			free(buffer);
			*decision = BLOCK_CONFIDENCE_INVALID;
			return needleidx;
		}
		mpg123_param(mh, MPG123_FLAGS, MPG123_QUIET, 0.0);
		// mh is a per-thread handle reused across every block validated by this thread (see
		// mp3_thread_handle()). The allowed-format table set by mpg123_format()/_none()/_all()
		// is handle-lifetime state, NOT reset by mpg123_close()/open_feed() -- per mpg123.h's
		// own docs, it only takes effect on mpg123's next *natural* format change, so it must
		// be reset before feeding data, not after, and on every call regardless of what a
		// previous block validated by this thread left behind.
		//
		// This check only cares whether decoding succeeds and produces non-silent samples, not
		// specific PCM values, so there's no reason to force a specific rate/channel count --
		// forcing one to an arbitrary fixed choice (as this used to do) only fails whenever the
		// real file doesn't natively match it. mpg123_format_all() lets mpg123 decode using the
		// file's own real native format, which is also what the 'channel' parsed from the raw
		// bitstream just below actually reflects.
		mpg123_format_all(mh);
		if(mpg123_open_feed(mh) != MPG123_OK){
			// Decoder setup failed outright -- this isn't "the audio didn't decode well,
			// treat as maybe/invalid based on frame count," it's "no classification attempt
			// was actually made," so don't let it fall through into the decode loop below
			// and get silently reinterpreted as ordinary content classification.
			mpg123_close(mh);
			free(buffer);
			*decision = BLOCK_CONFIDENCE_INVALID;
			return needleidx;
		}
		if(mpg123_feed(mh, buffer, length-va.frontOffset) != MPG123_OK){
			mpg123_close(mh);
			free(buffer);
			*decision = BLOCK_CONFIDENCE_INVALID;
			return needleidx;
		}
		#ifdef DEBUG_BLOCK_VALIDATE 
			lock_fprintf(stdout, "Checking audio...\n");
		#endif
		frame_num = 0;
		failures = 0;
		while(1){
			if((uint64_t)(audioPosCount+va.frontOffset) >= va.offsetFramePosition){
				#ifdef DEBUG_BLOCK_VALIDATE 
					lock_fprintf(stdout, "Finished reading block\n");
				#endif
				break;
			}
			bs.bytePos = (uint64_t)(audioPosCount+va.frontOffset);
			#ifdef DEBUG_BLOCK_VALIDATE 
				lock_fprintf(stdout, "bs.bytePos = %"PRIu64"\n", bs.bytePos);
				for(int i = 0; i < 4; i++){
					lock_fprintf(stdout, "%02x ", (unsigned char)bs.data[bs.bytePos+i]);
				}
				lock_fprintf(stdout, "\n");
			#endif
			if(!getFrameData(&bs, &mpegVersion, &layer, &crc, &bitrate, &samplingrate, &padding, &channel)){
				#ifdef DEBUG_BLOCK_VALIDATE 
					lock_fprintf(stdout, "Frame not where expected\n");
				#endif
				break;
			}
			frameByteLengthCalc(mpegVersion, layer, bitrate, samplingrate,
				padding, &frameLengthInBytes);
			ret = mpg123_decode_frame(mh, &frame_number, &audio, &bytes);
			if(ret == MPG123_NEW_FORMAT){
				#ifdef DEBUG_BLOCK_VALIDATE 
					lock_fprintf(stdout, "New format detected\n");
				#endif
				long rate;
				int channels, encoding;
				mpg123_getformat(mh, &rate, &channels, &encoding);
				rewindBits(&bs, 32);
			}
			else if(ret == MPG123_DONE){
				#ifdef DEBUG_BLOCK_VALIDATE 
					lock_fprintf(stdout, "Finished reading audio\n");
				#endif
				break;
			}
			else if(ret < 0){ //if ret is some error
				if(ret == MPG123_NEED_MORE && !errorOccurred){ //specifically to do with bit reservoir
					#ifdef DEBUG_BLOCK_VALIDATE 
						lock_fprintf(stdout, "MPG123_NEED_MORE\n");
					#endif
					errorOccurred = true;
					audioPosCount += frameLengthInBytes;
				}
				else{ //generic error or double need more, invalidate
					#ifdef DEBUG_BLOCK_VALIDATE 
						lock_fprintf(stdout, "Invalid mp3 frame\n");
						lock_fprintf(stdout, "%s\n", mpg123_strerror(mh));
					#endif
					invalidate = true;
					break;
				}
			}
			else{
				#ifdef DEBUG_BLOCK_VALIDATE
					lock_fprintf(stdout, "Frame OK\n");
				#endif
				// This only needs to know whether *any* decoded sample is nonzero
				bool isNull = true;
				for(size_t i = 0; i + 1 < bytes; i += 2){
					int16_t sample;
					memcpy(&sample, &audio[i], sizeof(int16_t));
					if(sample != 0){
						isNull = false;
						break;
					}
				}
				if(isNull){
					#ifdef DEBUG_BLOCK_VALIDATE
						lock_fprintf(stdout, "Decoding error, no data recovered, not valid frame or mp3 decoding failed.\n");
					#endif
					failures++;
				}
				audioPosCount += frameLengthInBytes;
				frame_num++;
				#ifdef DEBUG_BLOCK_VALIDATE
					lock_fprintf(stdout, "---\n");
				#endif
			}
		}
		mpg123_close(mh);
		free(buffer);

		#ifdef DEBUG_BLOCK_VALIDATE
			lock_fprintf(stdout, "Failures: %"PRIu32"\n", failures);
			lock_fprintf(stdout, "frame num: %"PRIu32"\n", frame_num);
			lock_fprintf(stdout, "--------------\n");
		#endif

		if(invalidate){
			*decision = BLOCK_CONFIDENCE_INVALID;
		}
		else if(failures > DECODE_FAILURE_TOLERANCE || frame_num < MAYBE_FRAME_LIMIT){
			goto make_maybe;
		}
		else{
			*decision = BLOCK_CONFIDENCE_VALID;
		}
	}
	else{
		*decision = BLOCK_CONFIDENCE_INVALID;
	}
	return needleidx;

	make_maybe:
	#ifdef DEBUG_BLOCK_VALIDATE
		lock_fprintf(stdout, "MAYBE BLOCK DETECTED\n");
		lock_fprintf(stdout, "frontOffset = %"PRIu16", rearOffset = %"PRIu16"\n", va.frontOffset, va.rearOffset);
	#endif
	// An incomplete frame chain is uncertain, not excluded. Preserve classifier
	// confidence when present and otherwise leave the block eligible for search.
	// The former Mp3BlockState.maybe record is intentionally not persisted: the
	// current custom reassembler discovers physical frame runs directly and does
	// not consult per-block maybe state. Fragment-level maybe remains available
	// through ValidationArgs and mp3_fragment_measure_range().
	if (*decision == BLOCK_CONFIDENCE_INVALID) {
		*decision = BLOCK_CONFIDENCE_LOW;
	}
	return needleidx;
}

/**
* @discussion		MP3 Fragment Validator: Validates whether a fragment is a valid part of an MP3 file.
*
* Edit: 11/21/25
* This function validates single blocks as well as multiple block fragments. This function has many more
* parameters than the classic Scalpel3 block validator because it communicates essential information to assist
* with optimal reassembly. This function does not attempt to decode the data within, rather it searches for
* the existence of an MP3 frame and looks for a chain.
*
* How is a block/fragment determined to be part of an MP3 file?
* To be certain that a block/fragment is a portion of an MP3 file, a fully intact MP3 frame must be found
* within the block. These MP3 frames do not have a set size and are determined by aspects of the MP3
* frame contained within the header.
*
* ID3v2 headers and terminal ID3v1 tags provide additional fragment boundaries. MPEG frame chains remain
* the primary evidence for blocks without tags.
*
**/

static inline uint32_t mp3_fragment_validate(char* data,
	uint64_t length,
	bool *validates,
	uint64_t* validates_to,
	uint32_t needleidx,
	uint16_t* frontOffset,
	uint16_t* rearOffset,
	bool* isHeader,
	bool* isTail,
	uint64_t* secondToLastFramePosition,
	uint64_t* lastFramePosition,
	uint64_t* offsetFramePosition,
	bool* maybe
) {
	return mp3_fragment_validate_from(data, length, validates, validates_to,
		needleidx, frontOffset, rearOffset, isHeader, isTail,
		secondToLastFramePosition, lastFramePosition, offsetFramePosition,
		maybe, 0);
}

// Validate from a known MPEG-chain start, retaining positions relative to the
// entire physical fragment. Ordinary block/fragment callers search from zero.
static inline uint32_t mp3_fragment_validate_from(char *data,
	uint64_t length,
	bool *validates,
	uint64_t *validates_to,
	uint32_t needleidx,
	uint16_t *frontOffset,
	uint16_t *rearOffset,
	bool *isHeader,
	bool *isTail,
	uint64_t *secondToLastFramePosition,
	uint64_t *lastFramePosition,
	uint64_t *offsetFramePosition,
	bool *maybe,
	uint64_t search_start
) {

	*validates = false;
	*maybe = false;
	*validates_to = 0;
	*frontOffset = 0;
	*rearOffset = 0;
	*isHeader = false;
	*isTail = false;
	*secondToLastFramePosition = 0;
	*lastFramePosition = 0;
	*offsetFramePosition = 0;

	// is the block long enough to have a header of a MPEG frame?
	if (search_start <= length && search_start <= UINT16_MAX
		&& length - search_start >= FRAME_HEADER_SIZE) {

		// INITIALIZATION ----------------------------------------
		bool frameFound = false;
		bool first = true;
		// wide enough that a large -q block size (giving a fragment length that, divided
		// by a small frame size, can exceed 65,535) can't wrap limit/frameCounter into a
		// misleadingly small value
		uint32_t frameCounter = 0;

		uint16_t frameLengthInBytes = 0;
		uint8_t mpegVersion = 0;
		uint8_t layer = 0;
		bool crc;
		uint32_t bitrate = 0;
		uint16_t samplingrate = 0;
		enum _ChannelMode channel;
		uint8_t padding = 0;

		Bitstream bs = {data, 0, 0, length, false};

		uint32_t limit;
		uint16_t maxFrameSize = 1000;
		bool frameJump = false;

		while ((uint64_t)bs.bytePos < length) {
			uint32_t id3_size = 0;
			uint64_t tag_end = 0;
			int tag_status;
			if (mp3_id3v2_header_size((const uint8_t *)data + bs.bytePos,
				length - bs.bytePos, &id3_size)) {
				tag_status = id3_size > length - bs.bytePos ? -1 : 1;
				tag_end = (uint64_t)bs.bytePos + id3_size;
			} else {
				tag_status = mp3_ape_tag_extent(data, length, bs.bytePos,
					true, &tag_end);
			}
			if (tag_status == 0) {
				break;
			}
			*isHeader = true;
			if (tag_status < 0) {
				*maybe = true;
				*validates_to = length - 1;
				return needleidx;
			}
			bs.bytePos = tag_end;
		}
		// Anchoring skips incidental MPEG syncs, not genuine leading file
		// metadata. Header fragments still need their ID3/APE classification
		// for catalog consolidation and checksum-guided reconstruction.
		if (search_start > 0) {
			if ((uint64_t)bs.bytePos > search_start) {
				return needleidx;
			}
			bs.bytePos = search_start;
		}
		const bool metadata_header = *isHeader;
		// Metadata footers do not contribute MPEG audio bytes. Exclude a
		// terminal ID3v1/APEv2 footer from the frame quota, while retaining
		// the footer in the validation range so it can still mark isTail.
		uint64_t expected_audio_end = length;
		uint64_t footer_start = 0;
		uint64_t footer_end = 0;
		uint64_t footer_window = scalpel_state.blocksize > 0
			? scalpel_state.blocksize : ID3V1_TAG_SIZE;
		uint64_t footer_search_start = length > footer_window
			? length - footer_window : (uint64_t)bs.bytePos;
		if (footer_search_start < (uint64_t)bs.bytePos) {
			footer_search_start = (uint64_t)bs.bytePos;
		}
		if (mp3_fragment_find_terminal_footer(data, length,
			footer_search_start, length, &footer_start, &footer_end)
			&& footer_start >= (uint64_t)bs.bytePos
			&& footer_end > footer_start) {
			expected_audio_end = footer_start;
		}
		uint64_t expected_audio_bytes = expected_audio_end
			> (uint64_t)bs.bytePos
			? expected_audio_end - (uint64_t)bs.bytePos : 0;

		// Limit is used to determine how many frames should be expected
		// in the audio portion of a given MP3 block or fragment.
		if(expected_audio_bytes < 1024){
			limit = 1;
		}
		else{
			limit = expected_audio_bytes / 1024;
		}

		//--------------------------------------------------------
		// SEARCH FOR MP3 FRAME ----------------------------------
		#ifdef DEBUG_FRAGMENT_VALIDATE
			printf("Starting block validation:\n");
			printf("Search for MPEG frame 1:\n");
		#endif
		while ((uint64_t)bs.bytePos + 3 < length) {
			if(getFrameData(&bs, &mpegVersion, &layer, &crc, &bitrate, &samplingrate, &padding, &channel)){
				if (mpegVersion == 0 || layer == 0 || bitrate == 0 || samplingrate == 0) {
					// If header found to be invalid (second check)
					#ifdef DEBUG_FRAGMENT_VALIDATE
						printf("Header determined to not be valid after all\n");
						printf("Critical problem with getFrameData function.\n");
					#endif
				}
				else {
					#ifdef DEBUG_FRAGMENT_VALIDATE
						printf("MPEG frame %"PRIu32" potentially found\n", frameCounter+1);
					#endif
					if(!frameByteLengthCalc(mpegVersion, layer, bitrate, samplingrate, padding,
					&frameLengthInBytes)){
						return needleidx;
					}
					if(frameLengthInBytes > maxFrameSize){
						maxFrameSize = frameLengthInBytes;
						limit = expected_audio_bytes / frameLengthInBytes;
					}
					if(first){
						*secondToLastFramePosition = 0;
						*lastFramePosition = 0;
						*offsetFramePosition = 0;
						// A rejected tentative frame at byte zero must not make
						// a later continuation chain look like a new file header.
						*isHeader = metadata_header || (uint64_t)bs.bytePos - 4 == 0;
						*frontOffset = bs.bytePos-4;
						first = false;
					}
					#ifdef DEBUG_FRAGMENT_VALIDATE
						printf("frameLengthInBytes = %d | ",frameLengthInBytes);
						printf("Checking bytes: %02x %02x %02x %02x at position %"PRIu64" | ", data[bs.bytePos-4],data[bs.bytePos-3],data[bs.bytePos-2],data[bs.bytePos-1], bs.bytePos-4);
						printf("MPEG frame seems valid, continuing on\n");
					#endif
					*secondToLastFramePosition = *lastFramePosition;
					*lastFramePosition = *offsetFramePosition;
					*offsetFramePosition = bs.bytePos - 4;
					skipBits(&bs, frameLengthInBytes*8 - 32);
					frameCounter = frameCounter + 1;
					frameJump = true;
				}
			}
			else {
				uint64_t ape_end = 0;
				if (frameJump && mp3_ape_tag_extent(data, length, bs.bytePos,
					false, &ape_end) == 1) {
					bs.bytePos = ape_end;
					(void)skipID3v1(&bs);
					*isTail = true;
					// A structurally valid metadata footer is part of the measured
					// range. Preserve validated status when the preceding frame
					// chain meets the normal minimum quota; block-level decoding
					// still treats the metadata boundary as a conservative MAYBE.
					if (frameCounter >= limit && limit > MAYBE_FRAME_LIMIT) {
						*validates = true;
					}
					*maybe = true;
					*validates_to = bs.bytePos - 1;
					return needleidx;
				}
				bool tagSkipped = skipID3v1(&bs);
				if(frameJump && tagSkipped){
					*isTail = true;
					if (frameCounter >= limit && limit > MAYBE_FRAME_LIMIT) {
						*validates = true;
					}
					*maybe = true;
					*validates_to = (uint64_t)bs.bytePos - 1;
					return needleidx;
				}
				uint64_t terminal_tag_offset;
				uint64_t terminal_tag_end;
				const uint64_t terminal_window = scalpel_state.blocksize > 0
					? scalpel_state.blocksize : MP3_HEADER_PREDECESSOR_SCAN_BYTES;
				uint64_t tag_search_start = length > terminal_window
					? length - terminal_window : 0;
				if (*offsetFramePosition > tag_search_start) {
					tag_search_start = *offsetFramePosition;
				}
				if (frameJump && mp3_find_terminal_id3v1(data, length,
					tag_search_start, length, true,
					&terminal_tag_offset, &terminal_tag_end)) {
					*isTail = true;
					if (frameCounter >= limit && limit > MAYBE_FRAME_LIMIT) {
						*validates = true;
					}
					*maybe = true;
					*validates_to = terminal_tag_end - 1;
					return needleidx;
				}
				if(areBytesNULL(data+bs.bytePos, length - bs.bytePos)){
					#ifdef DEBUG_FRAGMENT_VALIDATE
						printf("MPEG EOF detected\n");
					#endif
					if(bs.bytePos < 1024){
						limit = 1;
					}
					else if(bs.bytePos < 20480){
						limit = bs.bytePos / 1000;
					}
					else{
						limit = 20;
					}
					if(frameCounter >= limit && limit > MAYBE_FRAME_LIMIT){
						*validates = true;
						*validates_to = length - 1;
						*isTail = true;
						//lock_fprintf(stdout, "block found to be valid\n");
						return needleidx;
					}
					else{
						if(frameCounter >= limit){
							*maybe = true;
						}
						*validates = false;
						*validates_to = 0;
						//lock_fprintf(stdout, "block found to be invalid\n");
						return needleidx;
					}
				}
				else if(frameJump){
					#ifdef DEBUG_FRAGMENT_VALIDATE
						printf("MPEG frame found to not actually be valid, rewinding bitstream\n");
					#endif
					if(tagSkipped) rewindBits(&bs, ID3V1_TAG_SIZE * 8);
					rewindBits(&bs, frameLengthInBytes*8 - 8);
					frameCounter = 0;
					frameJump = false;
					first = true;
					*secondToLastFramePosition = 0;
					*lastFramePosition = 0;
					*offsetFramePosition = 0;
				}
				else{
					if(tagSkipped) rewindBits(&bs, ID3V1_TAG_SIZE * 8);
					skipBits(&bs, 8);
					frameCounter = 0;
					first = true;
					*secondToLastFramePosition = 0;
					*lastFramePosition = 0;
					*offsetFramePosition = 0;
				}
			}
		}
		if(frameCounter >= limit){
			//printf("bs.bytePos = %d\n",bs.bytePos);
			//printf("length = %d\n",length);
			if((uint64_t)bs.bytePos == length && !bs.truncated){
				*isTail = true;
			}
			*validates = true;
			*validates_to = length - 1;
			if((uint64_t)bs.bytePos >= length){
				*rearOffset = (uint16_t)((uint64_t)bs.bytePos - length);
			}
			else{
				*rearOffset = 0;
			}
			//lock_fprintf(stdout, "block found to be valid\n");
			return needleidx;
		}
		else{
			#ifdef DEBUG_FRAGMENT_VALIDATE
				printf("Not enough MPEG frames found\n");
			#endif
			//lock_fprintf(stdout, "invalid\n");
			return needleidx;
		}
		//--------------------------------------------------------
	}
	//lock_fprintf(stdout, "invalid\n");
	return needleidx;
}

/**
* @discussion		MP3 File Validator: Most strict MP3 validator.
*
* Edit: 11/21/25
* This function has two main uses. The first is to be applied to 'headers' of MP3 data to determine if it coincides
* with a complete contiguous MP3 file. If it does, it can be removed before reassembly even begins. This is the
* original purpose of the file validator as it pertains to the scalpel3 framework. The other use of this is to be
* applied to finished candidates of reassembly after all work has been done. It determines how far it validates and
* at what point it doesn't (using validates_to), so the padding of zeroes can be cut once
* the candidate is finally written. This is so the file is recovered in the exact same condition as the input and
* hashes can be compared.
*/
static inline void mp3_file_validate(char *data,
	uint64_t length,
	bool *validates,
	uint64_t *validates_to,
	bool *promising,
	uint32_t needleidx,
	uint32_t blocksize,
	void *carvehashkey) {

	bool debug = false;
	Mp3XingChecksum xing_checksum;

	(void)mp3_get_xing_checksum(data, length, &xing_checksum);

	//lock_fprintf(stdout, "mp3_file_validate called\n");

	// is the file long enough to have a header of a MPEG frame?
	if(length >= FRAME_HEADER_SIZE) {

		// INITIALIZATION ----------------------------------------

		bool frameFound = false;
		uint32_t frameCounter = 0;
		FrameArgs firstFrameArgs = get_frame_args();
		bool haveFirstFrameArgs = false;
		bool frameParametersCompatible = true;
		bool independentStart = false;
		uint64_t lastFrameStart = 0;
		uint64_t lastCompleteFrameEnd = 0;

		uint16_t frameLengthInBytes = 0;
		uint8_t mpegVersion = 0;
		uint8_t layer = 0;
		bool crc;
		uint32_t bitrate = 0;
		uint16_t samplingrate = 0;
		enum _ChannelMode channel;
		uint8_t padding = 0;
		uint8_t protectedBytes = 0;

		Bitstream bs = {data, 0, 0, length, false};
		if(mp3_skip_leading_tags(&bs)){
			#ifdef DEBUG_FILE_VALIDATE
				printf("ID3v2 header skipped\n");
			#endif
		}
		mp3_skip_leading_zero_prefix(&bs);
		bool incomplete_start = false;
		if (bs.bytePos < length && bs.bytePos < blocksize) {
			FrameArgs args;
			uint16_t frame_length;
			uint32_t id3_size;
			uint64_t frame_offset;
			if (!mp3_parse_complete_frame_at(data, length, bs.bytePos,
					&args, &frame_length)
				&& !mp3_id3v2_header_size((const uint8_t *)data, length,
					&id3_size)
				&& mp3_find_frame_chain_start(data, length, bs.bytePos + 1,
					blocksize, &frame_offset)) {
				bs.bytePos = frame_offset;
				incomplete_start = true;
			}
		}

		//--------------------------------------------------------
		// SEARCH FOR MP3 FRAME ----------------------------------
		#ifdef DEBUG_FILE_VALIDATE
			printf("Starting file validation:\n");
			printf("Search for MPEG frame 1:\n");
		#endif
		while ((uint64_t)bs.bytePos + 3 < length) {
			if(getFrameData(&bs, &mpegVersion, &layer, &crc, &bitrate, &samplingrate, &padding, &channel)){
				uint64_t frameStart = bs.bytePos - FRAME_HEADER_SIZE;
				lastFrameStart = frameStart;
				#ifdef DEBUG_FILE_VALIDATE
					printf("MPEG frame %" PRIu32 " potentially found\n", frameCounter + 1);
				#endif
				if(!frameByteLengthCalc(mpegVersion, layer, bitrate, samplingrate, padding,
				&frameLengthInBytes)){
					#ifdef DEBUG_FILE_VALIDATE
						printf("frameByteLengthCalc failed\n");
					#endif
					return;
				}
				#ifdef DEBUG_FILE_VALIDATE
					printf("frameLengthInBytes = %d\n",frameLengthInBytes);
					printf("MPEG frame seems valid, continuing on\n");
				#endif
				if(crc){
					if(mpegVersion == 1){
						if(channel == singleChannel){
							protectedBytes = 17;
						}
						else{
							protectedBytes = 32;
						}
					}
					else{
						if(channel == singleChannel){
							protectedBytes = 9;
						}
						else{
							protectedBytes = 17;
						}
					}
					if(((uint64_t)bs.bytePos-2) % blocksize > 0 &&
					((uint64_t)bs.bytePos-2) % blocksize < (uint64_t)(3+protectedBytes)){
						if(!check_crc(&bs, protectedBytes)){
							#ifdef DEBUG_FILE_VALIDATE
								printf("CRC found to be broken on block boundary\n");
							#endif
							*validates = false;
							*promising = true;
							*validates_to = bs.bytePos-4;
							#ifdef DEBUG_FILE_VALIDATE
								printf("validates = %d, promising = %d\n", *validates, *promising);
							#endif
							return;
						}
					}
				}
				bool completeFrame = frameStart <= length
					&& frameLengthInBytes <= length - frameStart;
				if (completeFrame) {
					const uint64_t frameEnd = frameStart + frameLengthInBytes;
					uint64_t blockBoundary =
						frameStart - (frameStart % blocksize);

					if (blockBoundary > UINT64_MAX - blocksize) {
						blockBoundary = UINT64_MAX;
					}
					else {
						blockBoundary += blocksize;
					}

					while (blockBoundary < frameEnd) {
						uint32_t nestedId3Size;

						// An ID3v2 header identifies a new stream. If it appears at a
						// physical block boundary inside this frame, the frame was
						// completed with bytes from another file.
						if (mp3_id3v2_header_size(
								(const uint8_t *)data + blockBoundary,
								length - blockBoundary, &nestedId3Size)) {
							*validates = false;
							*promising = true;
							*validates_to = blockBoundary - 1;
							return;
						}
						if (blockBoundary > UINT64_MAX - blocksize) {
							break;
						}
						blockBoundary += blocksize;
					}
					FrameArgs currentFrameArgs = {
						.mpegVersion = mpegVersion,
						.layer = layer,
						.crc = crc,
						.bitrate = bitrate,
						.samplingrate = samplingrate,
						.channel = channel,
						.padding = padding
					};
					if (! haveFirstFrameArgs) {
						firstFrameArgs = currentFrameArgs;
						haveFirstFrameArgs = true;
						independentStart = mp3_frame_has_independent_start(
							data + frameStart, frameLengthInBytes, &currentFrameArgs);
					}
					else if (! mp3_frame_stream_parameters_match(&firstFrameArgs,
						&currentFrameArgs)) {
						frameParametersCompatible = false;
					}
					frameCounter++;
					lastCompleteFrameEnd = frameStart + frameLengthInBytes;
				}
				skipBits(&bs, frameLengthInBytes*8 - 32);
			}
			else {
				uint64_t block_bound = length;
				uint64_t block_start;
				bool reached_end;
				bool id3v1_tail = false;
				bool ape_tail = false;
				bool zero_block = false;
				bool zero_tail = false;

				for(uint64_t i = 0; i <= length / blocksize; i++){
					if(i*blocksize > bs.bytePos){
						block_bound = i*blocksize;
						break;
					}
				}

				reached_end = (uint64_t)bs.bytePos == length && !bs.truncated;
				if (!reached_end && lastCompleteFrameEnd == bs.bytePos) {
					uint64_t tag_end = 0;
					ape_tail = mp3_ape_tag_extent(data, length, bs.bytePos,
						false, &tag_end) == 1;
					if (ape_tail) {
						bs.bytePos = tag_end;
					}
				}
				uint64_t terminal_tag_offset;
				uint64_t terminal_tag_end;
				uint64_t tag_search_start = length > blocksize
					? length - blocksize : 0;
				if (lastFrameStart > tag_search_start) {
					tag_search_start = lastFrameStart;
				}
				// A terminal tag must begin within or immediately after the last
				// complete frame.  The candidate buffer may include unrelated files;
				// zero padding after their footer does not validate the gap to it.
				const uint64_t tag_search_end = lastCompleteFrameEnd < length
					? lastCompleteFrameEnd + 1 : length;
				if (!ape_tail && lastCompleteFrameEnd > lastFrameStart
					&& mp3_find_terminal_id3v1(data, length,
						tag_search_start, tag_search_end, true,
						&terminal_tag_offset, &terminal_tag_end)) {
					*validates_to = terminal_tag_end - 1;
					if (xing_checksum.present
						&& !mp3_xing_checksum_matches(data, length, &xing_checksum)) {
						*validates = false;
						*promising = true;
						*validates_to = xing_checksum.first_frame_offset
							+ xing_checksum.first_frame_length - 1;
						return;
					}
					if (!xing_checksum.present
						&& (frameCounter < MP3_FILE_VALIDATION_MINIMUM_COMPATIBLE_FRAMES
							|| !frameParametersCompatible)) {
						*validates = false;
						*promising = true;
						return;
					}
					*validates = independentStart && !incomplete_start;
					*promising = !*validates;
					return;
				}
				if (! reached_end) {
					id3v1_tail = skipID3v1(&bs);
				}
				if (! reached_end && ! id3v1_tail && !ape_tail) {
					zero_tail = areBytesNULL(data + bs.bytePos, block_bound - bs.bytePos);
					block_start = ((uint64_t)bs.bytePos / blocksize) * blocksize;
					zero_block = zero_tail
						&& areBytesNULL(data + block_start, block_bound - block_start);
				}

					// A full zero block may be padding or an apparent gap.  Preserve the valid MPEG prefix as
					// PROMISING so reassembly can search for a continuation without accepting the zero block.
					if ((reached_end && length % blocksize == 0)
						|| zero_block) {
						*validates = false;
						*promising = true;
						if (zero_block) {
							*validates_to = block_start > 0 ? block_start - 1 : 0;
						}
						else {
							*validates_to = bs.bytePos > 0 ? bs.bytePos - 1 : 0;
						}
						return;
					}

				if(reached_end || id3v1_tail || ape_tail || zero_tail){
					#ifdef DEBUG_FILE_VALIDATE
						printf("MPEG EOF detected\n");
					#endif
					if (xing_checksum.present
						&& ! mp3_xing_checksum_matches(data, length, &xing_checksum)) {
						*validates = false;
						*promising = true;
						*validates_to = xing_checksum.first_frame_offset
							+ xing_checksum.first_frame_length - 1;
						return;
					}
					if (id3v1_tail || ape_tail) {
						*validates_to = bs.bytePos > 0 ? bs.bytePos - 1 : 0;
					}
					else if (lastCompleteFrameEnd > 0) {
						*validates_to = lastCompleteFrameEnd - 1;
					}
					else {
						bs.bytePos = block_bound - 1;
						while (readBits(&bs, 8) == 0) {
							rewindBits(&bs, 16);
						}
						rewindBits(&bs, 8);
						*validates_to = bs.bytePos;
					}
					if (! xing_checksum.present
						&& (frameCounter < MP3_FILE_VALIDATION_MINIMUM_COMPATIBLE_FRAMES
							|| ! frameParametersCompatible)) {
						*validates = false;
						*promising = true;
						return;
					}
					*validates = independentStart && !incomplete_start;
					*promising = !*validates;
					#ifdef DEBUG_FILE_VALIDATE
						printf("validates = %d, promising = %d\n", *validates, *promising);
					#endif
					return;
				}
				else{
					*validates = false;
					*promising = true;
					*validates_to = bs.bytePos > 0 ? bs.bytePos - 1 : 0;
					#ifdef DEBUG_FILE_VALIDATE
						printf("validates = %d, promising = %d\n", *validates, *promising);
					#endif
					return;
				}
			}
		}
			if((uint64_t)bs.bytePos == length && !bs.truncated){
				// A frame sequence ending exactly at a block boundary may be a fragmented prefix.  There is
				// no format-level end marker that distinguishes it from a complete file, so allow
				// fragmented reassembly to examine it rather than publishing a truncated MP3.
				if (length % blocksize == 0) {
					*validates = false;
					*promising = true;
					*validates_to = length - 1;
					return;
				}
				#ifdef DEBUG_FILE_VALIDATE
					printf("MPEG EOF detected\n");
				#endif
			if (xing_checksum.present
				&& ! mp3_xing_checksum_matches(data, length, &xing_checksum)) {
				*validates = false;
				*promising = true;
				*validates_to = xing_checksum.first_frame_offset
					+ xing_checksum.first_frame_length - 1;
				return;
			}
			if (! xing_checksum.present
				&& (frameCounter < MP3_FILE_VALIDATION_MINIMUM_COMPATIBLE_FRAMES
					|| ! frameParametersCompatible)) {
				*validates = false;
				*promising = true;
				*validates_to = bs.bytePos > 0 ? bs.bytePos - 1 : 0;
				return;
			}
			*validates = independentStart && !incomplete_start;
			*promising = !*validates;
			*validates_to = bs.bytePos > 0 ? bs.bytePos - 1 : 0;
			#ifdef DEBUG_FILE_VALIDATE
				printf("validates = %d, promising = %d\n", *validates, *promising);
			#endif
			return;
		}
		else{
			#ifdef DEBUG_FILE_VALIDATE
				printf("MPEG file cutoff most likely\n");
			#endif
			*validates = false;
			*promising = true;
			*validates_to = bs.bytePos > 0 ? bs.bytePos - 1 : 0;
			#ifdef DEBUG_FILE_VALIDATE
				printf("validates = %d, promising = %d\n", *validates, *promising);
			#endif
			return;
		}
		//--------------------------------------------------------
	}
	*validates = false;
	*promising = false;
	#ifdef DEBUG_FILE_VALIDATE
		printf("size too small to be a valid file, smaller than header\n");
		printf("validates = %d, promising = %d\n", *validates, *promising);
	#endif
	return;
}

static inline char *mp3_header_discovery(char *data,
	uint64_t offset,
	uint64_t length,
	char **matchpos,
	uint32_t *matchlen,
	uint32_t blocksize) {

	// now works differently, first must get header position
	// then check each block in same function call for next header

	bool debug = false;
	FrameArgs fa = get_frame_args();
	uint64_t data_length = offset + length;
	Bitstream bs = {data, 0, 0, data_length, false};
	uint32_t cur_block;

	//lock_fprintf(stdout, "mp3_header_discovery: length = %d\n", length);
	if(debug) lock_fprintf(stdout, "mp3_header_discovery: initializing with offset = %"PRIu64"\n", offset);
	if(offset == 0){
		cur_block = 0;
	}
	else{
		cur_block = offset / blocksize + 1;
	}
	bs.bytePos = cur_block * blocksize;
	while((uint64_t)bs.bytePos < data_length){
		uint64_t candidate_offset = (uint64_t)cur_block * blocksize;
		uint32_t id3_size;
		bool id3_header = mp3_id3v2_header_size(
			(const uint8_t *)data + candidate_offset,
			data_length - candidate_offset, &id3_size);
		uint64_t ape_end = 0;
		bool ape_header = data_length - candidate_offset >= 32
			&& mp3_ape_tag_extent(data, data_length,
				candidate_offset, true, &ape_end) != 0;
		if(debug) lock_fprintf(stdout, "mp3_header_discovery: cur_block: %d, checking = %"PRIu64"\n", cur_block, bs.bytePos);
		if (id3_header || ape_header) {
			*matchpos = data + candidate_offset;
			*matchlen = id3_header ? ID3V2_HEADER_SIZE : 32;
			if(debug) lock_fprintf(stdout, "mp3_header_discovery: header found, returning %p\n", *matchpos);
			return NULL;
		}
		else if(getFrameData(&bs, &fa.mpegVersion, &fa.layer, &fa.crc,
			&fa.bitrate, &fa.samplingrate, &fa.padding, &fa.channel)){
			// Suppress interior starts only when two compatible predecessor
			// frames chain into this boundary. A lone header-like byte sequence
			// in another file is not evidence that this stream is a continuation.
			if(mp3_has_compatible_frame_chain(data, data_length,
					candidate_offset, MP3_FILE_VALIDATION_MINIMUM_COMPATIBLE_FRAMES)
				&& !mp3_is_interior_frame_start(data, data_length,
					candidate_offset, &fa)){
				*matchpos = data + candidate_offset;
				*matchlen = FRAME_HEADER_SIZE;
				if(debug) lock_fprintf(stdout,
					"mp3_header_discovery: header found, returning %p\n", *matchpos);
				return NULL;
			}
		}
		else {
			uint64_t block_end = blocksize > data_length - candidate_offset
				? data_length : candidate_offset + blocksize;
			uint64_t frame_offset;
			FrameArgs zero_prefix_args;
			if (mp3_zero_prefixed_frame_header(data + candidate_offset,
				block_end - candidate_offset, &frame_offset, &zero_prefix_args)
				&& mp3_has_compatible_frame_chain(data, data_length,
					candidate_offset + frame_offset,
					MP3_FILE_VALIDATION_MINIMUM_COMPATIBLE_FRAMES)
				&& ! mp3_is_interior_frame_start(data, data_length,
					candidate_offset + frame_offset, &zero_prefix_args)) {
				*matchpos = data + candidate_offset;
				*matchlen = FRAME_HEADER_SIZE;
				if(debug) lock_fprintf(stdout,
					"mp3_header_discovery: zero-padded header found, returning %p\n",
					*matchpos);
				return NULL;
			}
			if (mp3_find_frame_chain_start(data, data_length,
					candidate_offset + 1, block_end, &frame_offset)) {
				FrameArgs args;
				uint16_t frame_length;
				if (mp3_parse_complete_frame_at(data, data_length,
						frame_offset, &args, &frame_length)
					&& !mp3_is_interior_frame_start(data, data_length,
						frame_offset, &args)) {
					// Preserve the leading partial frame without manufacturing
					// a file header. File validation keeps this run PROMISING.
					*matchpos = data + candidate_offset;
					*matchlen = FRAME_HEADER_SIZE;
					return NULL;
				}
			}
		}
		cur_block++;
		bs.bytePos = cur_block * blocksize;
	}

	if(debug) lock_fprintf(stdout, "mp3_header_discovery: ceasing operation\n");
	return NULL;
}

/**
* @discussion		MP3 Custom Reassembly: Attempts to reconstruct MP3 files
*
* Edit: 11/21/25
* This reassembly effort attempts to first identify segments of MP3 blocks which
* can be reliably determined to be a valid fragment of a larger MP3 file.
*
* Why does this require so much carve state memory?
* For identification of MP3 fragments.
* This is an extremely important aspect to accurate and efficient MP3 file recovery.
* If MP3 blocks are adjacent to each other in memory and they have matching offsets,
* it is extremely likely that they are in the correct position already and form a
* cohesive fragment. If each MP3 block is recovered individually and we rely purely
* on offsets to reassemble, we essentially throw out critical information that could
* help the reassembly effort significantly. It is very common for blocks to have
* identical offsets and my implementation of CRC/frequency analysis is not reliable
* enough.
*
**/

void mp3_custom_reassembly(ThreadWork *work,
	CarveInfo **c,
	uuid_string_t uuidp,
	uuid_string_t uuidc) {

	bool debug = false;

	#ifdef DEBUG_REASSEMBLY_THREAD
		lock_fprintf(stdout,"\nReassembly thread # %1d: Created\n", work->id);
	#endif
	CarveInfo *candidate = *c;
	BlockVector *b = candidate->b;
	BlockVector *b_read;
	uint32_t blocksize = scalpel_state.blocksize;
	Mp3CarveState *carve_state;
	bool first_run;

	ValidationArgs va = get_validation_args();

	if(!REASSEMBLY_ON){
		candidate->flavor = VALIDATED;
		inflate_blockvector(b);
		mp3_file_validate(blockvector_get_data_pointer(b),
			blockvector_get_data_length(b),
			&va.validates,
			&va.validates_to,
			&va.promising,
			va.needleidx,
			blocksize,
			NULL);
		blockvector_set_data_length(b, va.validates_to + 1);
		write_candidate(c, false);
		return;
	}
	(void)mp3_preserve_terminal_zero_padding_hypothesis(candidate, b,
		blockvector_get_data_length(b), scalpel_state.blocksize);
	init_blockvector(scalpel_state.filemirror, &b_read, 1, false);
	//check if carve state data already exists
	carve_state = (Mp3CarveState *)carve_get_state(candidate->carvehashkey);
	bool state_existed = mp3_reassembly_init_candidate(work->id, *c,
		uuidp, uuidc, &carve_state);
	first_run = false;
	if(state_existed && carve_state->fragment_discovery_phase
		!= MP3_FRAGMENT_DISCOVERY_UNINITIALIZED){
		if(!mp3_reassembly_check_fragments(b_read, carve_state)){
			goto done_abandon_candidate;
		}
		if(carve_state->fragment_discovery_phase
			== MP3_FRAGMENT_DISCOVERY_COMPLETE){
			mp3_rebuild_committed_blockvector(candidate, carve_state);
		}
		else if(!mp3_reassembly_rebuild_seed_candidate(candidate,
			&carve_state->fragments[0])){
			goto done_abandon_candidate;
		}
	}
	bool resume_greedy = mp3_greedy_search_resume(carve_state, blocksize);
	if(state_existed && carve_state->fragment_discovery_phase
		== MP3_FRAGMENT_DISCOVERY_COMPLETE && !resume_greedy){
		// A completed discovery state may return here after the assembled
		// blockvector was extended. New candidates and discovery resumes have
		// not changed since contiguous carving already rejected them, so
		// repeating the full validator only delays checkpoint progress.
		inflate_blockvector(b);
		mp3_file_validate(blockvector_get_data_pointer(b),
			blockvector_get_data_length(b),
			&va.validates,
			&va.validates_to,
			&va.promising,
			va.needleidx,
			blocksize,
			NULL);
		if(va.validates){
			goto done_validate_candidate;
		}
		deflate_blockvector(b);
	}

	if(carve_state->fragment_discovery_phase
		!= MP3_FRAGMENT_DISCOVERY_COMPLETE){
		Mp3FragmentDiscoveryResult discovery_result;
		#ifdef DEBUG_REASSEMBLY_THREAD
			lock_fprintf(stdout,
				"\nReassembly thread # %1d: %s fragment discovery\n",
				work->id, state_existed ? "resuming" : "starting");
		#endif
		discovery_result = mp3_reassembly_generate_fragments(work, b,
			b_read, candidate, carve_state, &blocksize, uuidp, uuidc);
		if(discovery_result == MP3_FRAGMENT_DISCOVERY_CHECKPOINT){
			goto done_in_progress_candidate;
		}
		if(discovery_result == MP3_FRAGMENT_DISCOVERY_FAILED){
			goto done_promising_candidate;
		}

		first_run = true;
		carve_state->indexes[0] = 0;
		carve_state->fragments[carve_state->indexes[0]].active = false;
		carve_state->cur_index = 1;
		for(int i = 1; i < carve_state->num_frags; i++){
			if(carve_state->fragments[i].isHeader)
				carve_state->fragments[i].active = false;
		}
		#ifdef DEBUG_REASSEMBLY_THREAD
			lock_fprintf(stdout,
			"\nReassembly thread # %1d: Candidate with blockvector %p and UUIDs"
			"\n%s / %s\n carve_state fragments have been generated.\n",
			work->id, candidate->b, uuidp, uuidc);
			display_blockvector(b, "blockvector");
		#endif
	}
	else{
		#ifdef DEBUG_REASSEMBLY_THREAD
			lock_fprintf(stdout,"\nReassembly thread # %1d: Carve data found to exist, checking fragments\n", work->id);
		#endif
		#ifdef DEBUG_REASSEMBLY_THREAD
			lock_fprintf(stdout,
			"\nReassembly thread # %1d: Candidate with blockvector %p and UUIDs"
			"\n%s / %s\n carve_state fragments have been checked and resolved\n",
			work->id, candidate->b, uuidp, uuidc);
		#endif
	}

	#ifdef DEBUG_REASSEMBLY_FRAG
		mp3_print_carve_state(carve_state);
		lock_fprintf(stdout, "num_frags = %d\n", carve_state->num_frags);
	#endif

	if(carve_state->num_frags == 1){
		(void)mp3_preserve_single_fragment_tail(candidate, blocksize);
		goto done_promising_candidate;
	}

	if(resume_greedy){
		goto greedy_construction;
	}
	Mp3ChecksumSearchResult checksum_search =
		mp3_reassembly_find_checksum_path(work, candidate, carve_state,
			blocksize, uuidp, uuidc);
	if(checksum_search == MP3_CHECKSUM_SEARCH_FOUND){
		goto done_promising_candidate;
	}
	if(checksum_search == MP3_CHECKSUM_SEARCH_CHECKPOINT){
		goto done_in_progress_candidate;
	}

	Mp3StructuralSearchResult direct_search =
		mp3_reassembly_preserve_direct_paths(work, candidate, carve_state,
			blocksize, uuidp, uuidc);
	if(direct_search == MP3_STRUCTURAL_SEARCH_CHECKPOINT){
		goto done_in_progress_candidate;
	}

	Mp3StructuralSearchResult structural_search =
		mp3_reassembly_preserve_structural_paths(work, candidate, carve_state,
			blocksize, uuidp, uuidc);
	if(structural_search == MP3_STRUCTURAL_SEARCH_CHECKPOINT){
		goto done_in_progress_candidate;
	}

	greedy_construction:;
	//construction init
	// Holds the -1 sentinel plus every index representable by num_frags.
	int32_t bestIndex;
	uint8_t mpegVersion = 0;
	uint8_t layer = 0;
	bool crc = false;
	uint32_t bitrate = 0;
	uint16_t samplingrate = 0;
	enum _ChannelMode channel = singleChannel;
	uint8_t padding = 0;
	uint8_t protectedBytes = 0;
	uint16_t frameLengthInBytes = 0;
	bool loop;
	bool bestPeaksOk = false, compPeaksOk;
	Peak bestPeaksL[6], bestPeaksR[6];
	Peak compPeaksL[6], compPeaksR[6];
	Peak tempPeaksL[6], tempPeaksR[6];
	bool bestIsStereo = false, compIsStereo = false, tempIsStereo = false;
	uint8_t score;
	double score1, score2;
	uint16_t guessProb = 1;
	uint16_t count;
	uint64_t prev_num_blocks;
	char *frame_buf;
	char *data;
	Mp3Fragment *current_fragment, *comp_fragment, *best_comp_fragment;
	Mp3GreedySearch *greedy = &carve_state->greedy;
	if(greedy->phase == MP3_GREEDY_INACTIVE){
		mp3_greedy_search_begin(carve_state, blocksize, MP3_GREEDY_BEGIN);
	}
	if(greedy->phase == MP3_GREEDY_FINISHED){
		goto done_validate_candidate;
	}

	#ifdef DEBUG_REASSEMBLY_CONST
		lock_fprintf(stdout, "\n\nBeginning reconstruction...\n\n");
	#endif
	bestIndex = -1;
	if(first_run) carve_state->fragments[carve_state->indexes[0]].active = false;

	loop = true;
	Bitstream bs = {0};
	resize_blockvector(
		b_read,
		2
	);
	while(loop){
		loop = false;
		current_fragment = &carve_state->fragments[
			carve_state->indexes[carve_state->cur_index - 1]];
		if(!mp3_reassembly_frame_stream(b, current_fragment, blocksize, &bs)){
			greedy->phase = MP3_GREEDY_FINISHED;
			goto done_validate_candidate;
		}

		//detect if CRC boundary present and get what bytes are protected
		//display_blockvector(b, "blockvector");
		if(!getFrameData(&bs, &mpegVersion, &layer, &crc, &bitrate, &samplingrate, &padding, &channel)){
			//frame header at this boundary couldn't be parsed -- mpegVersion/layer/crc/bitrate/
			//samplingrate/padding/channel are left stale/uninitialized by getFrameData() on
			//failure, so don't trust them. Fall back to offset-based matching below rather
			//than reading garbage into the CRC/protectedBytes logic.
			crc = false;
		}
		if(crc == true){
			#ifdef DEBUG_REASSEMBLY_CONST
				lock_fprintf(stdout, "CRC detected on index %d\n", carve_state->indexes[carve_state->cur_index - 1]);
			#endif
			if(mpegVersion == 1){
				if(channel == singleChannel){
					protectedBytes = 17;
				}
				else{
					protectedBytes = 32;
				}
			}
			else{
				if(channel == singleChannel){
					protectedBytes = 9;
				}
				else{
					protectedBytes = 17;
				}
			}
			#ifdef DEBUG_REASSEMBLY_CONST
				lock_fprintf(stdout, "protectedBytes = %d\n",protectedBytes);
			#endif
		}
		current_fragment = &carve_state->fragments[carve_state->indexes[carve_state->cur_index - 1]];
		if(crc && current_fragment->size*blocksize - current_fragment->offsetFramePosition+2 <= protectedBytes){
			if(greedy->phase == MP3_GREEDY_BEGIN){
				greedy->phase = MP3_GREEDY_CRC;
			}
			//Reached if CRC is present and block boundary resides within protected bytes
			#ifdef DEBUG_REASSEMBLY_CONST
				lock_fprintf(stdout, "Fragment %d found to reside on CRC boundary\n", carve_state->indexes[carve_state->cur_index - 1]);
			#endif

			//How many possibilities? Generated for demonstration of usefulness
			#ifdef DEBUG_REASSEMBLY_CONST
				count = 0;
				for(int k = 0; k < carve_state->num_frags; k++){
					comp_fragment = &carve_state->fragments[k];
					if(k != carve_state->indexes[carve_state->cur_index - 1] &&
					mp3_reassembly_fragment_boundaries_match(current_fragment, comp_fragment)
					&& comp_fragment->active == true){
						count++;
					}
				}
				if(count >= 2){
					lock_fprintf(stdout, "Has %d solutions\n", count);
					guessProb = guessProb * count;
				}
			#endif

			frameByteLengthCalc(mpegVersion, layer, bitrate, samplingrate,
				padding, &frameLengthInBytes);
			bool found_crc = false;
			for(int k = (int)greedy->next; k < carve_state->num_frags; k++){
				greedy->next = (uint32_t)k;
				if(atomic_load_explicit(&REASS_RETURN_TO_IDLE,
					memory_order_acquire)){
					deflate_blockvector(b);
					if(reassembly_time_to_checkpoint(work->id, candidate,
						uuidp, uuidc)){
						goto done_in_progress_candidate;
					}
					inflate_blockvector(b);
				}
				comp_fragment = &carve_state->fragments[k];
				if(k != carve_state->indexes[carve_state->cur_index - 1] &&
				mp3_reassembly_fragment_boundaries_match(current_fragment, comp_fragment) &&
				comp_fragment->active == true){
					resize_blockvector(
						b_read,
						2
					);
					blockvector_set_apparent_blocknumber(b_read, 0, filemirror_apparent_blocknumber(scalpel_state.filemirror, current_fragment->lastActBlock));
					blockvector_set_apparent_blocknumber(b_read, 1, filemirror_apparent_blocknumber(scalpel_state.filemirror, comp_fragment->firstActBlock));
					blockvector_set_data_length_to_mapped_extent(b_read);
					inflate_blockvector(b_read);
					const uint64_t crc_offset = current_fragment->offsetFramePosition
						% blocksize;
					const uint64_t crc_length = blockvector_get_data_length(b_read);
					crc = false;
					if(crc_offset < crc_length){
						Bitstream crc_stream = {
							blockvector_get_data_pointer(b_read) + crc_offset,
							0, 4, crc_length - crc_offset, false};
						crc = check_crc(&crc_stream, protectedBytes);
					}
					deflate_blockvector(b_read);

					//if crc succeeds
					if(crc){
						#ifdef DEBUG_REASSEMBLY_CONST
							lock_fprintf(stdout, "CRC check succeeded on index %d\n\n",k);
						#endif
						found_crc = true;
						carve_state->indexes[carve_state->cur_index] = k;
						comp_fragment->active = false;
						carve_state->cur_index++;
						loop = true;
						if(comp_fragment->isTail == true || carve_state->cur_index == carve_state->num_frags){
							loop = false;
						}
						//gets us out of k for loop
						k = carve_state->num_frags;
					}
				}
			}
			if(!found_crc){
				greedy->phase = MP3_GREEDY_FINISHED;
				//if CRC was not found, we can be confident that the next section of the file does not exist in the blockmap
				#ifdef DEBUG_REASSEMBLY_CONST
					lock_fprintf(stdout, "CRC not found, confident next section does not exist in file, validate\n\n");
				#endif
				goto done_validate_candidate;
			}
		}
		else{
			//This is reached if CRC isn't present or applicable, in other words 'pain'
			if(greedy->phase == MP3_GREEDY_BEGIN){
				greedy->phase = MP3_GREEDY_COUNT;
			}
			bestIndex = greedy->best_index;
			best_comp_fragment = bestIndex < 0 ? NULL : &carve_state->fragments[bestIndex];
			bestPeaksOk = greedy->best_peaks_ok;
			bestIsStereo = greedy->best_stereo;
			memcpy(bestPeaksL, greedy->best_peaks[0], sizeof(bestPeaksL));
			memcpy(bestPeaksR, greedy->best_peaks[1], sizeof(bestPeaksR));
			loop = bestIndex >= 0;

			#ifdef DEBUG_REASSEMBLY_CONST
				lock_fprintf(stdout, "CRC either not present or not applicable\n");
			#endif

			//How many possibilities? Generated for demonstration of usefulness
			count = (uint16_t)greedy->matches;
			for(int k = (int)greedy->next;
				greedy->phase == MP3_GREEDY_COUNT && k < carve_state->num_frags; k++){
				greedy->next = (uint32_t)k;
				greedy->matches = count;
				if(atomic_load_explicit(&REASS_RETURN_TO_IDLE,
					memory_order_acquire)){
					deflate_blockvector(b);
					if(reassembly_time_to_checkpoint(work->id, candidate,
						uuidp, uuidc)){
						goto done_in_progress_candidate;
					}
					inflate_blockvector(b);
				}
				comp_fragment = &carve_state->fragments[k];
				if(k != carve_state->indexes[carve_state->cur_index - 1] &&
				mp3_reassembly_fragment_boundaries_match(current_fragment, comp_fragment) &&
				comp_fragment->active == true){
					count++;
				}
			}
			if(greedy->phase == MP3_GREEDY_COUNT){
				greedy->matches = count;
				greedy->next = 0;
				greedy->phase = MP3_GREEDY_SCORE;
			}
			if(count >= 2){
				#ifdef DEBUG_REASSEMBLY_CONST
					lock_fprintf(stdout, "Index %d has %d solutions, requires frequency analysis\n",carve_state->indexes[carve_state->cur_index - 1],count);
				#endif
				guessProb = guessProb * count;
			}
			// Optimization: count (computed above) already tells us whether frequency
			// analysis will be needed at all. With count <= 1 there's at most one matching
			// fragment, so it wins by default the moment it's found -- the "else" (competing)
			// branch below can never trigger. Skip the getPeaks() call for it in that case;
			// its peaks would never be compared against anything.

			for(int k = (int)greedy->next; k < carve_state->num_frags; k++){
				greedy->next = (uint32_t)k;
				greedy->best_index = bestIndex;
				greedy->best_peaks_ok = bestPeaksOk;
				greedy->best_stereo = bestIsStereo;
				memcpy(greedy->best_peaks[0], bestPeaksL, sizeof(bestPeaksL));
				memcpy(greedy->best_peaks[1], bestPeaksR, sizeof(bestPeaksR));
				if(atomic_load_explicit(&REASS_RETURN_TO_IDLE,
					memory_order_acquire)){
					deflate_blockvector(b);
					if(reassembly_time_to_checkpoint(work->id, candidate,
						uuidp, uuidc)){
						goto done_in_progress_candidate;
					}
					inflate_blockvector(b);
				}
				comp_fragment = &carve_state->fragments[k];
				if(k != carve_state->indexes[carve_state->cur_index - 1] &&
				mp3_reassembly_fragment_boundaries_match(current_fragment, comp_fragment) &&
				comp_fragment->active == true){
				//if a fragment is found that has matching offsets and is active
					if(bestIndex == -1){
						//if a fragment hasn't been found yet, save as current solution
						bestIndex = k;
						best_comp_fragment = &carve_state->fragments[bestIndex];
						loop = true;
						if(count >= 2){
							for(int i = 0; i < 6; i++){
								bestPeaksL[i].val = 0;
								bestPeaksL[i].index = -1;
								bestPeaksR[i].val = 0;
								bestPeaksR[i].index = -1;
							}
							bestIsStereo = false;
							blockvector_set_apparent_blocknumber(b_read, 0, filemirror_apparent_blocknumber(scalpel_state.filemirror, current_fragment->lastActBlock));
							blockvector_set_apparent_blocknumber(b_read, 1, filemirror_apparent_blocknumber(scalpel_state.filemirror, best_comp_fragment->firstActBlock));
							blockvector_set_data_length_to_mapped_extent(b_read);
							inflate_blockvector(b_read);
							//b_read holds exactly 2 blocks (current_fragment's last block + best_comp_fragment's
							//first block). Feed mpg123 everything remaining in that buffer rather than an
							//exact-fit length ending right at the target frame--mpg123's feed-mode decoder
							//generally won't confirm a frame as complete until it can see past its end (e.g.
							//into the next sync word), so a byte-exact length starves it and it reports
							//MPG123_NEED_MORE even when the join itself is fine.
							bestPeaksOk = mp3_reassembly_boundary_peaks(b_read,
								current_fragment->lastFramePosition % blocksize,
								bestPeaksL, bestPeaksR, &bestIsStereo);
							if(!bestPeaksOk){
								// Nothing more to do here: getPeaks() unconditionally zeroes its output
								// array (val=0, index=-1 for all 5 peaks) before attempting any real
								// work, so on failure the peaks here are already left in that safe,
								// already-invalid state. getScore() can't match an index of -1 against
								// any real bin, so a fragment/candidate whose peaks failed to gather
								// just scores 0 in any comparison that uses them -- it can only ever
								// lose a comparison this way, never masquerade as a false match.
								#ifdef DEBUG_REASSEMBLY_CONST
									lock_fprintf(stdout, "getPeaks failed\n");
								#endif
							}
							deflate_blockvector(b_read);
						}
					}
					else{ //if a fragment has already been found, they must fight to the death
						#ifdef DEBUG_REASSEMBLY_CONST
							lock_fprintf(stdout, "comparison happening: bestIndex = %d vs k = %d\n", bestIndex, k);
						#endif
						for(int i = 0; i < 6; i++){
							compPeaksL[i].val = 0;
							compPeaksL[i].index = -1;
							compPeaksR[i].val = 0;
							compPeaksR[i].index = -1;
						}
						compIsStereo = false;
						//lock_fprintf(stdout, "length: %d\n", ((blocksize - current_fragment->lastFramePosition % blocksize) + comp_fragment->frontOffset));
						//lock_fprintf(stdout, "index: %d\n", carve_state->indexes[carve_state->cur_index - 1]);
						blockvector_set_apparent_blocknumber(b_read, 0, filemirror_apparent_blocknumber(scalpel_state.filemirror, current_fragment->lastActBlock));
						blockvector_set_apparent_blocknumber(b_read, 1, filemirror_apparent_blocknumber(scalpel_state.filemirror, comp_fragment->firstActBlock));
						blockvector_set_data_length_to_mapped_extent(b_read);
						inflate_blockvector(b_read);
						//display_blockvector(b_read, "test");
						//see bestPeaks fetch above: feed the whole 2-block buffer, not an exact-fit length.
						compPeaksOk = mp3_reassembly_boundary_peaks(b_read,
							current_fragment->lastFramePosition % blocksize,
							compPeaksL, compPeaksR, &compIsStereo);
						if(!compPeaksOk){
							// Nothing more to do here: getPeaks() unconditionally zeroes its output
							// array (val=0, index=-1 for all 5 peaks) before attempting any real
							// work, so on failure the peaks here are already left in that safe,
							// already-invalid state. getScore() can't match an index of -1 against
							// any real bin, so a fragment/candidate whose peaks failed to gather
							// just scores 0 in any comparison that uses them -- it can only ever
							// lose a comparison this way, never masquerade as a false match.
							#ifdef DEBUG_REASSEMBLY_CONST
								lock_fprintf(stdout, "getPeaks failed\n");
							#endif
						}
						deflate_blockvector(b_read);

						//make decision here
						score = 0;

						//first check if peaks are identical (or near identical) -- gated on the
						//left/mono channel only; this only decides whether to refine further,
						//not the actual scoring decision, so doubling it for stereo isn't needed
						for(int peakIndex1 = 0; peakIndex1 < 5; peakIndex1++){
							for(int peakIndex2 = 0; peakIndex2 < 5; peakIndex2++){
								if(compPeaksL[peakIndex1].index < bestPeaksL[peakIndex2].index+2 &&
								compPeaksL[peakIndex1].index > bestPeaksL[peakIndex2].index-2){
									score++;
								}
							}
						}
						if(score == 5){ //means peaks are nearly identical, change frames being compared
							#ifdef DEBUG_REASSEMBLY_CONST
								lock_fprintf(stdout, "peaks found to be (near) identical, doing analysis on next frame\n");
							#endif
							for(int i = 0; i < 6; i++){
								tempPeaksL[i].val = 0;
								tempPeaksL[i].index = -1;
								tempPeaksR[i].val = 0;
								tempPeaksR[i].index = -1;
							}
							for(int i = 0; i < 5; i++){
								tempPeaksL[i].val = bestPeaksL[i].val;
								tempPeaksL[i].index = bestPeaksL[i].index;
								tempPeaksR[i].val = bestPeaksR[i].val;
								tempPeaksR[i].index = bestPeaksR[i].index;
							}
							tempIsStereo = bestIsStereo;
							resize_blockvector(
								b_read,
								2
							);
							blockvector_set_apparent_blocknumber(b_read, 0, filemirror_apparent_blocknumber(scalpel_state.filemirror, current_fragment->lastActBlock));
							blockvector_set_apparent_blocknumber(b_read, 1, filemirror_apparent_blocknumber(scalpel_state.filemirror, best_comp_fragment->firstActBlock));
							blockvector_set_data_length_to_mapped_extent(b_read);
							inflate_blockvector(b_read);
							//see bestPeaks fetch above: feed the whole 2-block buffer, not an exact-fit length.
							bestPeaksOk = mp3_reassembly_boundary_peaks(b_read,
								current_fragment->offsetFramePosition % blocksize,
								bestPeaksL, bestPeaksR, &bestIsStereo);
							if(!bestPeaksOk){
								// Nothing more to do here: getPeaks() unconditionally zeroes its output
								// array (val=0, index=-1 for all 5 peaks) before attempting any real
								// work, so on failure the peaks here are already left in that safe,
								// already-invalid state. getScore() can't match an index of -1 against
								// any real bin, so a fragment/candidate whose peaks failed to gather
								// just scores 0 in any comparison that uses them -- it can only ever
								// lose a comparison this way, never masquerade as a false match.
								#ifdef DEBUG_REASSEMBLY_CONST
									lock_fprintf(stdout, "getPeaks failed\n");
								#endif
							}
							deflate_blockvector(b_read);

							//get peaks for second (competitor) fragment
							blockvector_set_apparent_blocknumber(b_read, 0, filemirror_apparent_blocknumber(scalpel_state.filemirror, current_fragment->lastActBlock));
							blockvector_set_apparent_blocknumber(b_read, 1, filemirror_apparent_blocknumber(scalpel_state.filemirror, comp_fragment->firstActBlock));
							blockvector_set_data_length_to_mapped_extent(b_read);
							inflate_blockvector(b_read);
							//see bestPeaks fetch above: feed the whole 2-block buffer, not an exact-fit length.
							compPeaksOk = mp3_reassembly_boundary_peaks(b_read,
								current_fragment->offsetFramePosition % blocksize,
								compPeaksL, compPeaksR, &compIsStereo);
							if(!compPeaksOk){
								// Nothing more to do here: getPeaks() unconditionally zeroes its output
								// array (val=0, index=-1 for all 5 peaks) before attempting any real
								// work, so on failure the peaks here are already left in that safe,
								// already-invalid state. getScore() can't match an index of -1 against
								// any real bin, so a fragment/candidate whose peaks failed to gather
								// just scores 0 in any comparison that uses them -- it can only ever
								// lose a comparison this way, never masquerade as a false match.
								#ifdef DEBUG_REASSEMBLY_CONST
									lock_fprintf(stdout, "getPeaks failed\n");
								#endif
							}
							deflate_blockvector(b_read);

							score1 = mp3_stereo_score(tempPeaksL, tempPeaksR, tempIsStereo, bestPeaksL, bestPeaksR, bestIsStereo);
							score2 = mp3_stereo_score(tempPeaksL, tempPeaksR, tempIsStereo, compPeaksL, compPeaksR, compIsStereo);

							#ifdef DEBUG_REASSEMBLY_CONST
								lock_fprintf(stdout, "tempIsStereo = %d, bestIsStereo = %d, compIsStereo = %d\n",
									tempIsStereo, bestIsStereo, compIsStereo);
								lock_fprintf(stdout, "tempPeaks (L):\n");
								for(size_t i = 0; i < 5; i++){
									lock_fprintf(stdout, "Value: %.2f, Index: %d\n",tempPeaksL[i].val,tempPeaksL[i].index);
								}
								lock_fprintf(stdout, "tempPeaks (R):\n");
								for(size_t i = 0; i < 5; i++){
									lock_fprintf(stdout, "Value: %.2f, Index: %d\n",tempPeaksR[i].val,tempPeaksR[i].index);
								}
								printf("-----------------\nbestPeaks (L):\n");
								for(size_t i = 0; i < 5; i++){
									lock_fprintf(stdout, "Value: %.2f, Index: %d\n",bestPeaksL[i].val,bestPeaksL[i].index);
								}
								printf("bestPeaks (R):\n");
								for(size_t i = 0; i < 5; i++){
									lock_fprintf(stdout, "Value: %.2f, Index: %d\n",bestPeaksR[i].val,bestPeaksR[i].index);
								}
								printf("-----------------\ncompPeaks (L):\n");
								for(size_t i = 0; i < 5; i++){
									lock_fprintf(stdout, "Value: %.2f, Index: %d\n",compPeaksL[i].val,compPeaksL[i].index);
								}
								printf("compPeaks (R):\n");
								for(size_t i = 0; i < 5; i++){
									lock_fprintf(stdout, "Value: %.2f, Index: %d\n",compPeaksR[i].val,compPeaksR[i].index);
								}
								lock_fprintf(stdout, "-----------------\n");
							#endif

							for(int i = 0; i < 5; i++){
								bestPeaksL[i].val = tempPeaksL[i].val;
								bestPeaksL[i].index = tempPeaksL[i].index;
								bestPeaksR[i].val = tempPeaksR[i].val;
								bestPeaksR[i].index = tempPeaksR[i].index;
							}
							bestIsStereo = tempIsStereo;
						}
						else{
							score1 = mp3_stereo_score(current_fragment->peaks[0], current_fragment->peaks[1], current_fragment->peaksStereo, bestPeaksL, bestPeaksR, bestIsStereo);
							score2 = mp3_stereo_score(current_fragment->peaks[0], current_fragment->peaks[1], current_fragment->peaksStereo, compPeaksL, compPeaksR, compIsStereo);
							#ifdef DEBUG_REASSEMBLY_CONST
								lock_fprintf(stdout, "fragIsStereo = %d, bestIsStereo = %d, compIsStereo = %d\n",
									current_fragment->peaksStereo, bestIsStereo, compIsStereo);
								lock_fprintf(stdout, "peaks for index %d (L):\n",carve_state->indexes[carve_state->cur_index - 1]);
								for(size_t i = 0; i < 5; i++){
									lock_fprintf(stdout, "Value: %.2f, Index: %d\n",current_fragment->peaks[0][i].val,current_fragment->peaks[0][i].index);
								}
								lock_fprintf(stdout, "peaks for index %d (R):\n",carve_state->indexes[carve_state->cur_index - 1]);
								for(size_t i = 0; i < 5; i++){
									lock_fprintf(stdout, "Value: %.2f, Index: %d\n",current_fragment->peaks[1][i].val,current_fragment->peaks[1][i].index);
								}
								lock_fprintf(stdout, "-----------------\nbestPeaks (L):\n");
								for(size_t i = 0; i < 5; i++){
									lock_fprintf(stdout, "Value: %.2f, Index: %d\n",bestPeaksL[i].val,bestPeaksL[i].index);
								}
								lock_fprintf(stdout, "bestPeaks (R):\n");
								for(size_t i = 0; i < 5; i++){
									lock_fprintf(stdout, "Value: %.2f, Index: %d\n",bestPeaksR[i].val,bestPeaksR[i].index);
								}
								lock_fprintf(stdout, "-----------------\ncompPeaks (L):\n");
								for(size_t i = 0; i < 5; i++){
									lock_fprintf(stdout, "Value: %.2f, Index: %d\n",compPeaksL[i].val,compPeaksL[i].index);
								}
								lock_fprintf(stdout, "compPeaks (R):\n");
								for(size_t i = 0; i < 5; i++){
									lock_fprintf(stdout, "Value: %.2f, Index: %d\n",compPeaksR[i].val,compPeaksR[i].index);
								}
								lock_fprintf(stdout, "-----------------\n");
							#endif
						}
						// These are alternative extents of the same physical chain,
						// not different successors. Prefer the longer checked extent
						// before comparing audio similarity, or a trimmed prefix can
						// win solely because its boundary frame has different peaks.
						const bool same_start = comp_fragment->firstActBlock
							== best_comp_fragment->firstActBlock
							&& comp_fragment->frontOffset == best_comp_fragment->frontOffset;
						if (same_start && comp_fragment->lastActBlock
							> best_comp_fragment->lastActBlock) {
							bestIndex = k;
							best_comp_fragment = comp_fragment;
							for (size_t i = 0; i < 6; i++) {
								bestPeaksL[i] = compPeaksL[i];
								bestPeaksR[i] = compPeaksR[i];
							}
							bestIsStereo = compIsStereo;
							continue;
						}
						if (same_start && best_comp_fragment->lastActBlock
							> comp_fragment->lastActBlock) {
							continue;
						}
						double best_path_score;
						double comp_path_score;
						bool best_path_score_ok = mp3_reassembly_score_extension(
							candidate, carve_state, (uint16_t)bestIndex,
							blocksize, &best_path_score);
						bool comp_path_score_ok = mp3_reassembly_score_extension(
							candidate, carve_state, (uint16_t)k,
							blocksize, &comp_path_score);
						bool path_scoring_used = best_path_score_ok
							|| comp_path_score_ok;
						if(path_scoring_used){
							score1 = best_path_score_ok ? best_path_score : -INFINITY;
							score2 = comp_path_score_ok ? comp_path_score : -INFINITY;
						}
						#ifdef DEBUG_REASSEMBLY_CONST
							lock_fprintf(stdout,
								"score1 = %f, score2 = %f, full_path = %d\n",
								score1, score2, path_scoring_used);
						#endif
						if(!path_scoring_used && !bestPeaksOk && !compPeaksOk){
							//neither candidate's boundary peaks could be decoded, so score1 == score2 == 0.0
							//is not a real tie--there's no frequency evidence at all. bestIndex still wins
							//below purely by fragment scan order, not any actual signal -- flag this loudly
							//(not just under DEBUG_REASSEMBLY_CONST) so it's visible for manual review even
							//in a normal run, cross-referenced by this candidate's UUIDs.
							lock_fprintf(stdout,
								"*** MP3 REASSEMBLY: no frequency evidence for either candidate fragment"
								" (indexes %d vs %d) while extending candidate %s / %s -- resolving"
								" the tie by physical locality, not by audio evidence ***\n",
								bestIndex, k, uuidp, uuidc);
						}
						// Equivalent audio scores contain no basis for selecting one fragment
						// over another. Prefer the fragment closest to the established physical
						// chain; this also recognizes a return from a displaced run.
						uint64_t best_distance = UINT64_MAX;
						uint64_t comp_distance = UINT64_MAX;
						for(uint16_t path_index = 0;
							path_index < carve_state->cur_index; path_index++){
							const Mp3Fragment *committed = &carve_state->fragments[
								carve_state->indexes[path_index]];
							uint64_t distance;

							if(best_comp_fragment->firstActBlock
								> committed->lastActBlock){
								distance = (uint64_t)(best_comp_fragment->firstActBlock
									- committed->lastActBlock);
							}
							else if(committed->firstActBlock
								> best_comp_fragment->lastActBlock){
								distance = (uint64_t)(committed->firstActBlock
									- best_comp_fragment->lastActBlock);
							}
							else{
								distance = 0;
							}
							if(distance < best_distance){
								best_distance = distance;
							}

							if(comp_fragment->firstActBlock
								> committed->lastActBlock){
								distance = (uint64_t)(comp_fragment->firstActBlock
									- committed->lastActBlock);
							}
							else if(committed->firstActBlock
								> comp_fragment->lastActBlock){
								distance = (uint64_t)(committed->firstActBlock
									- comp_fragment->lastActBlock);
							}
							else{
								distance = 0;
							}
							if(distance < comp_distance){
								comp_distance = distance;
							}
						}
						const double score_epsilon = path_scoring_used
							? MP3_SEAM_SCORE_TIE_EPSILON : 0.0;
						const bool scores_equivalent =
							fabs(score2 - score1) <= score_epsilon;
						if(MP3_SCORE_TRACE){
							lock_fprintf(stdout,
								"MP3_SCORE_DECISION mode=%d path_mdct=%d full_path=%d "
								"best=%.17g competitor=%.17g tied=%d\n",
								MP3_SCORE_MODE, MP3_PATH_SCORE_MDCT, path_scoring_used,
								score1, score2, scores_equivalent);
						}
						if(score2 > score1 + score_epsilon
							|| (scores_equivalent
								&& comp_distance < best_distance)){
							#ifdef DEBUG_REASSEMBLY_CONST
								lock_fprintf(stdout, "competitor won, bestIndex updated\n");
							#endif
							bestIndex = k;
							best_comp_fragment = &carve_state->fragments[bestIndex];
							for(size_t i = 0; i < 5; i++){
								bestPeaksL[i].val = compPeaksL[i].val;
								bestPeaksL[i].index = compPeaksL[i].index;
								bestPeaksR[i].val = compPeaksR[i].val;
								bestPeaksR[i].index = compPeaksR[i].index;
							}
							bestPeaksL[5].val = 0;
							bestPeaksL[5].index = -1;
							bestPeaksR[5].val = 0;
							bestPeaksR[5].index = -1;
							bestIsStereo = compIsStereo;
						}
						else{
							#ifdef DEBUG_REASSEMBLY_CONST
								lock_fprintf(stdout, "bestIndex won, no change made\n");
							#endif
						}
						#ifdef DEBUG_REASSEMBLY_CONST
							lock_fprintf(stdout, "\n");
						#endif
					}
				}
			}
			if(bestIndex == -1){ //no fragment matched offset
				greedy->phase = MP3_GREEDY_FINISHED;
				#ifdef DEBUG_REASSEMBLY_CONST
					lock_fprintf(stdout, "Candidate could not find a fragment with matching offset, nothing left to do.\n");
				#endif
				goto done_validate_candidate;
			}
			carve_state->indexes[carve_state->cur_index] = bestIndex;
			best_comp_fragment = &carve_state->fragments[bestIndex];
			carve_state->cur_index++;
			best_comp_fragment->active = false;
			if(best_comp_fragment->isTail == true || carve_state->num_frags == carve_state->cur_index){
				loop = false;
			}
		}
		#ifdef DEBUG_REASSEMBLY_CONST
			lock_fprintf(stdout, "Combination: ");
			for(int k = 0; k < carve_state->cur_index; k++){
				lock_fprintf(stdout, "%d ",carve_state->indexes[k]);
			}
			lock_fprintf(stdout, "\n");
		#endif
		//extend candidate
		current_fragment = &(carve_state->fragments[carve_state->indexes[carve_state->cur_index - 1]]);
		prev_num_blocks = blockvector_get_num_blocks(candidate->b);
		resize_blockvector(candidate->b, blockvector_get_num_blocks(candidate->b) + current_fragment->size);
		count = 0;
		for(int64_t i = current_fragment->firstActBlock; i <= current_fragment->lastActBlock; i++){
			blockvector_set_apparent_blocknumber(candidate->b, prev_num_blocks+count, filemirror_apparent_blocknumber(scalpel_state.filemirror, i));
			count++;
		}
		blockvector_set_data_length_to_mapped_extent(candidate->b);
		mp3_greedy_search_begin(carve_state, blocksize,
			loop ? MP3_GREEDY_BEGIN : MP3_GREEDY_FINISHED);
		#ifdef DEBUG_REASSEMBLY_CONST
			//display_blockvector(b, "blockvector");
		#endif
		deflate_blockvector(b);
		//atomic_store_explicit(&TAKE_PROGRESS_CHECKPOINT, true, memory_order_release);
		if(reassembly_time_to_checkpoint(work->id, candidate, uuidp, uuidc)) {
			#ifdef DEBUG_REASSEMBLY_THREAD
				lock_fprintf(stdout,
				"\nReassembly thread # %1d: Candidate with blockvector %p and UUIDs"
				"\n%s / %s\n will cease work due to checkpoint\n",
				work->id, candidate->b, uuidp, uuidc);
			#endif
			goto done_in_progress_candidate;
		}
		inflate_blockvector(b);
	}
	#ifdef DEBUG_REASSEMBLY_CONST
		lock_fprintf(stdout, "----------------------------\n");
	#endif
	done_validate_candidate:
	if(atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)){
		deflate_blockvector(b);
		if(reassembly_time_to_checkpoint(work->id, candidate, uuidp, uuidc)){
			goto done_in_progress_candidate;
		}
		inflate_blockvector(b);
	}
	//b_read is freed here, once, regardless of which path reached this label (contiguous,
	//isTail-terminated, or a CRC/offset dead end) -- do not free it again below.
	free_blockvector(&b_read);
	inflate_blockvector(b);
	// Mapped extents may stop at the last MPEG frame because zero padding is
	// trimmed. Expose a terminal metadata footer before final validation so
	// the recovered extent includes ID3v1/APEv2 bytes.
	mp3_extend_terminal_footer_extent(b, blocksize);
	//Always run the real validation check here, regardless of contiguous/isTail, and gate
	//the outcome on its result: a CRC-boundary or offset dead end reaching this
	//label is an unresolved reconstruction, not a validated one, and must not be silently
	//finalized as VALIDATED just because some path landed here.
	mp3_file_validate(blockvector_get_data_pointer(b),
		blockvector_get_data_length(b),
		&va.validates,
		&va.validates_to,
		&va.promising,
		va.needleidx,
		blocksize,
		NULL);
	if(!va.validates && va.promising && carve_state->num_frags > 1
		&& mp3_reassembly_complete_terminal_frame(candidate, blocksize, &va)){
		b = candidate->b;
	}
	if(!va.validates || carve_state->num_frags > 1){
		// MP3 has no mandatory file-level integrity field.  Frame syntax and the optional
		// 16-bit LAME music CRC can identify useful reconstructions, but neither proves
		// fragment identity strongly enough to cover blocks after a fragmented join.
			// A validated stream has a terminal extent. PROMISING progress alone does not:
			// validates_to may only identify the prefix checked before a fragmented join.
			if(va.validates){
				blockvector_set_data_length(b, va.validates_to + 1);
			}
			else if(va.promising){
				const uint64_t data_length = blockvector_get_data_length(b);
				const uint64_t prefix_length = va.validates_to < UINT64_MAX
					? va.validates_to + 1 : 0;
				const uint64_t search_start = data_length > blocksize
					? data_length - blocksize : 0;
				uint64_t tag_offset;
				uint64_t tag_end;
				if(prefix_length > 0 && prefix_length <= data_length
					&& mp3_complete_compatible_frame_prefix(
						blockvector_get_data_pointer(b), prefix_length)) {
					blockvector_set_data_length(b, prefix_length);
				}
				else if(mp3_find_terminal_id3v1(blockvector_get_data_pointer(b),
					data_length, search_start, data_length, true,
					&tag_offset, &tag_end)){
					blockvector_set_data_length(b, tag_end);
				}
			}
		(void)mp3_preserve_terminal_zero_padding_hypothesis(candidate, b,
			blockvector_get_data_length(b), blocksize);
		carve_put_state(candidate->carvehashkey, carve_state);
		mp3_free_carve_state((void**)&carve_state);
		candidate->flavor = PROMISING;
		#ifdef DEBUG_REASSEMBLY_THREAD
			lock_fprintf(stdout,
			"\nReassembly thread # %1d: Candidate with blockvector %p and UUIDs"
			"\n%s / %s\n promising but not complete\n",
			work->id, candidate->b, uuidp, uuidc);
		#endif
		write_candidate(c, false);
		return;
	}
	// get rid of padding for completed candidate
	//lock_fprintf(stdout, "validates_to: %d\n", va.validates_to+1);
	blockvector_set_data_length(b, va.validates_to+1);
	candidate->flavor = VALIDATED;
	#ifdef DEBUG_REASSEMBLY_THREAD
		lock_fprintf(stdout,
		"\nReassembly thread # %1d: Candidate with blockvector %p and UUIDs"
		"\n%s / %s\n will be written\n",
		work->id, candidate->b, uuidp, uuidc);
	#endif
	write_candidate(c, false);
	mp3_free_carve_state((void**)&carve_state);
	return;
	done_promising_candidate:
	carve_put_state(candidate->carvehashkey, carve_state);
	mp3_free_carve_state((void**)&carve_state);
	free_blockvector(&b_read);
	candidate->flavor = PROMISING;
	#ifdef DEBUG_REASSEMBLY_THREAD
		lock_fprintf(stdout,
		"\nReassembly thread # %1d: Candidate with blockvector %p and UUIDs"
		"\n%s / %s\n promising but not complete\n",
		work->id, candidate->b, uuidp, uuidc);
	#endif
		write_candidate(c, false);
		return;
		done_abandon_candidate:
		mp3_free_carve_state((void**)&carve_state);
		free_blockvector(&b_read);
		destroy_candidate(c);
		return;
		done_in_progress_candidate:
	carve_put_state(candidate->carvehashkey, carve_state);
	mp3_free_carve_state((void**)&carve_state);
	free_blockvector(&b_read);
	candidate->flavor = INPROGRESS;
	#ifdef DEBUG_REASSEMBLY_THREAD
		lock_fprintf(stdout,
		"\nReassembly thread # %1d: Candidate with blockvector %p and UUIDs"
		"\n%s / %s\n in progress\n",
		work->id, candidate->b, uuidp, uuidc);
	#endif
}

#pragma GCC diagnostic pop
