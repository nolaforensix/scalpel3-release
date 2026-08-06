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

//reassembly
#define REASSEMBLY_ON				true

//peak scoring
#define TOLERANCE 					1			//max index difference still counted as "nearly coincident" (Steinebach et al. 2015, Handbook of Digital Forensics of Multimedia Data and Devices, pp.234-235)
#define EDGE_GUARD_BINS				4			//bins excluded from each end of the MDCT/FFT spectrum during peak detection

//file type specific
#define FRAME_HEADER_SIZE 			4
#define ID3V2_HEADER_SIZE 			10
#define FRAME_FOOTER_SIZE 			16
#define MDCT_COEFFS 				576
#define GP                      	0x18005		/* x^16 + x^15 + x^2 + 1 */
#define CRC16_CMS_POLY          	0x8005
#define CRC16_INIT					0xFFFF

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
	uint16_t frontOffset;
	uint16_t rearOffset;
	size_t size; //in blocks
	bool isHeader;
	bool isTail;
	bool active; //if true, not in candidate, if false, in candidate
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

typedef struct{
	Mp3Fragment *fragments;
	uint16_t num_frags;
	//construction record of candidate
	uint16_t *indexes; //assuming fragment count won't exceed 65535
	uint16_t cur_index;
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

static inline uint32_t bitRateIndexer(uint8_t mpegVersion,
	uint8_t layer,
	unsigned int bitrateVal);

static inline bool frameByteLengthCalc(uint8_t layer,
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
static double getScore(Peak *peaks1, Peak *peaks2);
static double mp3_stereo_score(Peak *peaksL1, Peak *peaksR1, bool isStereo1,
	Peak *peaksL2, Peak *peaksR2, bool isStereo2);

static bool getFrameData(Bitstream *bs,
	uint8_t *mpegVersion,
	uint8_t *layer,
	bool *crc,
	uint32_t *bitrate,
	uint16_t *samplerate,
	uint8_t *padding,
	enum _ChannelMode *channel);

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

static bool mp3_reassembly_check_fragment(BlockVector *b_read,
	Mp3CarveState *carve_state,
	Mp3Fragment *frag,
	int frag_index);

static bool mp3_reassembly_check_fragments(BlockVector *b_read,
	Mp3CarveState *carve_state);

static void mp3_rebuild_committed_blockvector(CarveInfo *candidate, Mp3CarveState *carve_state);

static void mp3_reassembly_generate_fragments(BlockVector *b,
	BlockVector *b_read,
	CarveInfo *candidate,
	Mp3CarveState *carve_state,
	uint32_t *blocksize);

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

bool frameByteLengthCalc(uint8_t layer, uint32_t bitrate, uint16_t samplingrate,
uint8_t padding, uint16_t *frameLengthInBytes){
	// Frame Byte Length Calculation
	bitrate = bitrate * 1000;
	if (layer == 1) {
		*frameLengthInBytes = (12 * bitrate / samplingrate + padding) * 4;
	}
	else if (layer == 2 || layer == 3) {
		*frameLengthInBytes = 144 * bitrate / samplingrate + padding;
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
	for(int i = 0; i < 5; i++){
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
	getFrameData(&bs, &fa.mpegVersion, &fa.layer, &fa.crc, &fa.bitrate, &fa.samplingrate, &fa.padding, &fa.channel);
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
		fprintf(stderr, "Error decoding second frame: %s\n", mpg123_plain_strerror(read_result));
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
double getScore(Peak *peaks1, Peak *peaks2){
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

// Combines two candidates' peak comparisons across both stereo channels. If both sides are
// stereo, each channel is a real, independent signal, so L-vs-L and R-vs-R are both genuine
// evidence -- averaging them uses both without letting either dominate. If either side isn't
// stereo (mono, or a mismatch between two candidates decoded under different channel
// counts), there's no second channel to compare, so this falls back to a single comparison
// using peaksL1/peaksL2 (which hold the sole channel's peaks when mono).
double mp3_stereo_score(Peak *peaksL1, Peak *peaksR1, bool isStereo1,
	Peak *peaksL2, Peak *peaksR2, bool isStereo2){

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

// Function should detect if ID3v1 footer is present and skip it if detected
bool skipID3v1(Bitstream *bs){
	uint8_t* bytes = (uint8_t*)(bs->data+bs->bytePos);
	uint8_t* data_end = (uint8_t*)bs->data + bs->length;
	if(bytes + 3 > data_end){
		return false;
	}
	if(bytes[0] == 0x54 && bytes[1] == 0x41 && bytes[2] == 0x47){
		#ifdef DEBUG_ID3v2
			printf("ID3v1 Footer Detected\n");
		#endif
		if(bytes + 128 > data_end){
			return false;
		}
		#ifdef DEBUG_ID3v2
			printf("Skipping 128 bytes\n");
		#endif
		skipBits(bs, 128*8);
		return true;
	}
	return false;
}

// Function detects if an ID3v2 header is present at bitstream position and skip it if detected
bool skipID3v2(Bitstream *bs){
	uint8_t* bytes = (uint8_t*)(bs->data+bs->bytePos);
	uint8_t* data_end = (uint8_t*)bs->data + bs->length;
	if (bytes + 10 > data_end) {
		return false;
	}
	if (bytes[0] == 0x49 && bytes[1] == 0x44 && bytes[2] == 0x33 &&
		bytes[3] < 0xFF && bytes[4] < 0xFF && (bytes[5] & 0x3F) == 0 &&
		bytes[6] < 0x80 && bytes[7] < 0x80 && bytes[8] < 0x80 &&
		bytes[9] < 0x80) {
		#ifdef DEBUG_ID3v2
			printf("ID3v2 Header Detected\n");
		#endif

		uint8_t id3version = bytes[3];
		uint8_t id3revision = bytes[4]; //for debug
				
		#ifdef DEBUG_ID3v2
			printf("ID3v2 Version %d.%d\n",id3version,id3revision);
		#endif

		uint32_t size = (bytes[6] << 21) | (bytes[7] << 14) | (bytes[8] << 7) | (bytes[9]); //synchsafe
		size += 10; //add header size
		if(id3version == 4 && (bytes[5] >> 4) & 1) size += 10; //footer present

		if(bytes + size > data_end){
			return false;
		}

		#ifdef DEBUG_ID3v2
			printf("Skipping %"PRIu32" bytes\n",size);
		#endif
		skipBits(bs, size*8);
		return true;
	}
	return false;
}

//Block state API functions:
//Q: Why do we need block state?
//A: Workaround so MP3 block validator does not steal blocks with a small amount of data
// This allows us to, rather than steal blocks that COULD be MP3, flag them as "maybe"

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

//serialize or deserialize carve state to a file
static inline bool mp3_serialize_carve_state(void **state, FILE *fp,
											StateSerialization mode){
	Mp3CarveState **s = (Mp3CarveState **)state;

	size_t (*fb)(void *ptr, size_t size, size_t nitems, FILE *stream) =
		mode == SERIALIZE ?
		(size_t (*)(void *ptr, size_t size, size_t nitems, FILE *stream))fwrite :
		(size_t (*)(void *ptr, size_t size, size_t nitems, FILE *stream))fread;

	if (mode == DESERIALIZE) {
		*s = malloc(sizeof(Mp3CarveState));
		check_memory_allocation(*s, __LINE__, __FILE__, "s");
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
            fb(&frag->rearOffset, sizeof(uint16_t), 1, fp) != 1 ||
            fb(&frag->size, sizeof(size_t), 1, fp) != 1 ||
            fb(&frag->isHeader, sizeof(bool), 1, fp) != 1 ||
            fb(&frag->isTail, sizeof(bool), 1, fp) != 1 ||
            fb(&frag->active, sizeof(bool), 1, fp) != 1 ||
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
	return true;
}

static inline bool mp3_states_equal(Mp3CarveState *a, Mp3CarveState *b){
	if(a->num_frags != b->num_frags) return false;
	if(a->cur_index != b->cur_index) return false;
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
	d->num_frags = s->num_frags;
	d->cur_index = s->cur_index;
	d->fragments = calloc(d->num_frags, sizeof(Mp3Fragment));
	d->indexes = calloc(d->num_frags, sizeof(uint16_t));
	check_memory_allocation(d->fragments, __LINE__, __FILE__, "d->fragments");
	check_memory_allocation(d->indexes, __LINE__, __FILE__, "d->indexes");
	for(int i = 0; i < d->num_frags; i++){
		src = &s->fragments[i];
		dst = &d->fragments[i];
		dst->frontOffset = src->frontOffset;
		dst->rearOffset = src->rearOffset;
		dst->size = src->size;
		dst->isHeader = src->isHeader;
		dst->isTail = src->isTail;
		dst->active = src->active;
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
	bool result = (s1->num_frags == s2->num_frags);
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
		fragments[i].frontOffset = 0;
		fragments[i].rearOffset = 0;
		fragments[i].size = 0;
		fragments[i].isHeader = false;
		fragments[i].isTail = false;
		fragments[i].active = true;
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
	old_fragments[old_count].frontOffset = 0;
	old_fragments[old_count].rearOffset = 0;
	old_fragments[old_count].size = 0;
	old_fragments[old_count].isHeader = false;
	old_fragments[old_count].isTail = false;
	old_fragments[old_count].active = true;
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
		carve_put_state(candidate->carvehashkey, *state);
		return false;
	}
	else{
		return true;
	}
}

//Fragment Functions:

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
	inflate_blockvector(b_read);
	blocksize = blockvector_get_data_length(b_read) / blockvector_get_num_blocks(b_read);
	curFragLength = blocksize * frag->size;
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
}

// Checks a singular fragment for whether it is still valid or a block has
// been covered. It returns true if the fragment has been adequately checked
// and false if the fragment needs to be checked again. This function handles
// the invalid fragment and updates carve state accordingly.

static bool mp3_reassembly_check_fragment(BlockVector *b_read,
										Mp3CarveState *carve_state,
										Mp3Fragment *frag,
										int frag_index){
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
	bool updateNeeded = false;
	uint16_t cutoff_index = 0;
	uint64_t blk_pos;
	int64_t blk_ap;
	#ifdef DEBUG_REASSEMBLY_FRAG
		lock_fprintf(stdout, "mp3_reassembly_check_fragment:\n");
	#endif
	restart:
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
					return true;
				}
				{
					// This split only ever adds a single fragment per call (not a tight
					// discovery loop), so there's no persistent capacity to amortize across
					// calls -- just tell add_fragment() the array currently holds exactly
					// num_frags slots.
					uint16_t frag_capacity = carve_state->num_frags;
					carve_state->fragments = add_fragment(carve_state->fragments, carve_state->num_frags, &frag_capacity);
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
				// frag1_size wasn't previously assigned back to the shortened original
				// fragment's own size field, leaving it internally inconsistent (size no
				// longer matching lastActBlock - firstActBlock + 1).
				frag->size = frag1_size;
				resize_blockvector(
					b_read,
					frag2_size
				);
				int blk_pos_2 = 0;
				for(int64_t blk_act_2 = new_frag->firstActBlock; blk_act_2 <= new_frag->lastActBlock; blk_act_2++){
					blockvector_set_apparent_blocknumber(b_read, blk_pos_2, filemirror_apparent_blocknumber(scalpel_state.filemirror, blk_act_2));
					blk_pos_2++;
				}
				inflate_blockvector(b_read);
				uint32_t blocksize = blockvector_get_data_length(b_read) / blockvector_get_num_blocks(b_read);
				// b_read holds exactly frag2_size blocks (new_frag's), not frag->size (the
				// original, pre-split fragment's size, which is always larger) -- using
				// frag->size here told mp3_fragment_validate() more bytes were available than
				// b_read actually holds, an out-of-bounds read past the inflated buffer.
				curFragLength = blocksize * frag2_size;
				// Covered blocks are still physically present in the source image -- coverage
				// is bookkeeping (filemirror_actual_block_covered()) about which blocks are
				// off-limits for future candidate construction, not something that removes or
				// hides the underlying bytes, so reading them here (to measure new_frag, whose
				// own blocks are NOT covered -- only the single block between frag and
				// new_frag is) is safe and expected.
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

				new_frag->frontOffset = frontOffset;
				new_frag->rearOffset = rearOffset;
				new_frag->isHeader = isHeader;
				new_frag->isTail = isTail;
				new_frag->secondToLastFramePosition = secondToLastFramePosition;
				new_frag->lastFramePosition = lastFramePosition;
				new_frag->offsetFramePosition = offsetFramePosition;
				new_frag->size = frag2_size;
				return true;
			}
		}
		else if(updateNeeded){
			//trying to limit amount of times fragment data is refreshed (computationally expensive)
			//fragment needs data refreshed if covered block discovered, however fragment if entirely covered could end up deleted,
			//therefore only if a block not covered is found after a covered block discovery should trigger a fragment refresh
			mp3_reassembly_refresh_frag_data(b_read, frag);
		}
		blk_pos++;
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
}

// returns true if 'actual_block' is already known to belong to the file type identified by
// 'needleidx'--either it carries a hard BLOCK_CONFIDENCE_VALID blocktype, or it has a "maybe"
// Mp3BlockState recorded under its hash key. 'hashkey' is caller-owned scratch space (at least
// BLOCK_HASH_KEY_SIZE bytes). 'label' (e.g. "first"/"next") only distinguishes debug output.
static bool mp3_reassembly_block_check(int64_t actual_block, uint32_t needleidx,
											  char *hashkey, bool debug, const char *label){

	if(filemirror_get_blocktype(scalpel_state.filemirror, actual_block, needleidx) == BLOCK_CONFIDENCE_VALID){
		if(debug) lock_fprintf(stdout, "%s block %"PRId64" found to be valid\n", label, actual_block);
		return true;
	}

	gen_block_hash_key(hashkey, needleidx, actual_block);
	Mp3BlockState *block_state = (Mp3BlockState *)block_get_state(hashkey);
	bool maybe = block_state != NULL;
	if(maybe && debug) lock_fprintf(stdout, "%s block %"PRId64" found to be maybe\n", label, actual_block);
	mp3_free_block_state((void **)&block_state);

	return maybe;
}

// returns true if 'apparent_block' is one of the blocks claimed by the header fragment (pulled out
// of candidate->b's choices and recorded in 'removed_block_numbers' before the scan begins).
static bool mp3_reassembly_block_is_removed(int64_t *removed_block_numbers, size_t removed_block_amt,
											int64_t apparent_block, bool debug, int64_t count){

	for(size_t i = 0; i < removed_block_amt; i++){
		if(removed_block_numbers[i] == apparent_block){
			if(debug) lock_fprintf(stdout, "currently checking block not in choices, count should stay %"PRId64"\n", count);
			return true;
		}
	}

	return false;
}


/**
* @discussion		MP3 Fragment Generator: Scans the entire blockmap for how potential MP3 blocks connect
*/
static void mp3_reassembly_generate_fragments(BlockVector *b,
										BlockVector *b_read,
										CarveInfo *candidate,
										Mp3CarveState *carve_state,
										uint32_t *blocksize){

	//blocks of validated contiguous files are already covered

	bool debug = false;

	//fragment discovery init
	int64_t block_choice_start = 0;
	int64_t block_choice;
	uint64_t curFragLength;
	bool validates;
	uint64_t validates_to;
	uint32_t needleidx = 0;
	uint16_t frontOffset = 0;
	uint16_t rearOffset = 0;
	bool isHeader = false;
	bool isTail = false;
	uint64_t secondToLastFramePosition = 0;
	uint64_t lastFramePosition = 0;
	uint64_t offsetFramePosition = 0;
	bool maybe;
	Mp3Fragment *first_fragment, *current_fragment;
	BlockVector *b_check_header;
	init_blockvector(scalpel_state.filemirror, &b_check_header, 1, false);

	//candidate init
	inflate_blockvector(b);
	*blocksize = blockvector_get_data_length(b) / blockvector_get_num_blocks(b);

	first_fragment = &carve_state->fragments[0];
	//make header fragment the first fragment, no need to check if it validates, it already has
	mp3_fragment_validate(blockvector_get_data_pointer(b),
		blockvector_get_data_length(b),
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

	first_fragment->frontOffset = frontOffset;
	first_fragment->rearOffset = rearOffset;
	first_fragment->isHeader = isHeader;
	first_fragment->isTail = isTail;
	first_fragment->secondToLastFramePosition = secondToLastFramePosition;
	first_fragment->lastFramePosition = lastFramePosition;
	first_fragment->offsetFramePosition = offsetFramePosition;
	first_fragment->size = blockvector_get_num_blocks(b);
	first_fragment->firstActBlock = blockvector_get_actual_blocknumber(b, 0);
	first_fragment->lastActBlock = blockvector_get_actual_blocknumber(b, first_fragment->size-1);

	//get rid of blocks currently in header fragment
	//lock_fprintf(stdout, "blockvector_get_num_blocks(b) = %d\n", blockvector_get_num_blocks(b));
	// Heap-allocated rather than a VLA: this is sized to the WHOLE candidate's block count,
	// which for a large file can be large enough to exhaust a worker thread's stack.
	int64_t *removed_block_numbers = malloc(blockvector_get_num_blocks(b) * sizeof(int64_t));
	check_memory_allocation(removed_block_numbers, __LINE__, __FILE__, "removed_block_numbers");
	size_t removed_block_amt = blockvector_get_num_blocks(b);
	for(uint64_t i = 0; i < blockvector_get_num_blocks(b); i++){
		#ifdef DEBUG_REASSEMBLY_FRAG
			lock_fprintf(stdout, "removing actual block number %"PRId64"\n", blockvector_get_actual_blocknumber(b, i));
		#endif
		blockvector_remove_choice(
			b,
			blockvector_get_num_blocks(b) - 1,
			blockvector_get_apparent_blocknumber(b, i)
		);
		removed_block_numbers[i] = blockvector_get_apparent_blocknumber(b, i);
	}
	first_fragment->active = false;

	//------------------------
	// current_block indexes blocks WITHIN a single fragment as it grows (paired with
	// b_read_size below) -- a uint16_t here would wrap silently once one fragment reached
	// 65,536 blocks, overwriting b_read's block 0 instead of extending it and corrupting
	// that fragment's data. current_frag counts fragments, which is already bounded by the
	// carve_state->num_frags >= UINT16_MAX guard below, so it can stay uint16_t.
	uint64_t current_block = 0;
	uint16_t current_frag = 0;
	// Tracks how many fragment slots are actually allocated (see add_fragment()) across the
	// whole discovery loop below, so repeated additions grow the array geometrically instead
	// of by exactly one slot (and one realloc+copy) per fragment found.
	uint16_t frag_capacity = carve_state->num_frags;
	bool check_next_block, in_frag;
	int64_t blk_ap, blk_act, f_blk_ap, f_blk_act;
	char hashkey[BLOCK_HASH_KEY_SIZE];
	uint64_t evaluated;
	uint64_t prev_validates_to = 0;
	int64_t count = 0;
	int b_read_size = 0;
	ValidationArgs va = get_validation_args();
	count = filemirror_apparent_blocks(scalpel_state.filemirror);
	blk_ap = blockvector_get_choice(candidate->b, blockvector_get_num_blocks(candidate->b)-1, 0, count, &evaluated);
	count -= evaluated;
	while(blk_ap != -1 && count >= 0){
		blk_act = filemirror_actual_blocknumber(scalpel_state.filemirror, blk_ap);
		current_block = 0;
		b_read_size = 0;
		check_next_block = false;
		in_frag = false;
		if(debug) lock_fprintf(stdout, "----------------------------------------------\n");
		if(debug) lock_fprintf(stdout, "checking apparent block %"PRId64", actual block %"PRId64"...\n", blk_ap, blk_act);
		//was the block validated (or marked "maybe") as an mp3 block?
		check_next_block = mp3_reassembly_block_check(blk_act, candidate->needleidx, hashkey, debug, "first");
		//...but not if it was already claimed by the header fragment
		if(mp3_reassembly_block_is_removed(removed_block_numbers, removed_block_amt, blk_ap, debug, count)){
			check_next_block = false;
		}
		if(check_next_block){
			if(carve_state->num_frags >= UINT16_MAX){
				// num_frags is uint16_t; adding one more here would wrap it to 0 and corrupt
				// every fragment index already recorded. An image fragmented finely enough
				// to hit 65,535 distinct fragments for one candidate is an extreme,
				// essentially pathological case -- stop discovering further fragments and
				// work with what's already been found rather than silently wrap.
				lock_fprintf(stdout,
					"MP3: candidate hit the %d fragment limit during discovery; not scanning\n"
					"for further fragments for this candidate.\n", UINT16_MAX);
				break;
			}
			in_frag = true;
			current_frag++;
			carve_state->fragments = add_fragment(carve_state->fragments, carve_state->num_frags, &frag_capacity);
			carve_state->num_frags++;
			current_fragment = &carve_state->fragments[current_frag];
			b_read_size = 1;
			resize_blockvector(
				b_read,
				b_read_size
			);
			blockvector_set_apparent_blocknumber(b_read, current_block, blk_ap);
			inflate_blockvector(b_read);
			mp3_fragment_validate(blockvector_get_data_pointer(b_read),
				*blocksize * b_read_size,
				&va.validates,
				&va.validates_to,
				va.needleidx,
				&va.frontOffset,
				&va.rearOffset,
				&va.isHeader,
				&va.isTail,
				&va.secondToLastFramePosition,
				&va.lastFramePosition,
				&va.offsetFramePosition,
				&va.maybe);
			//printf("frontOffset = %d, rearOffset = %d\n", va.frontOffset, va.rearOffset);
			deflate_blockvector(b_read);
			current_fragment->frontOffset = va.frontOffset;
			current_fragment->rearOffset = va.rearOffset;
			current_fragment->isHeader = va.isHeader;
			current_fragment->isTail = va.isTail;
			current_fragment->secondToLastFramePosition = va.secondToLastFramePosition;
			current_fragment->lastFramePosition = va.lastFramePosition;
			current_fragment->offsetFramePosition = va.offsetFramePosition;
			current_fragment->size = b_read_size;
			current_fragment->firstActBlock = blk_act;
			f_blk_ap = blk_ap;
			f_blk_act = blk_act;
			current_block++;
		}
		while(check_next_block && count >= 0){
			if(debug) lock_fprintf(stdout, "----------------------------------------------\n");
			if(debug) lock_fprintf(stdout, "checking next block...\n");
			check_next_block = false;
			//get the next available choice--this already respects the header fragment's
			//exclusions and disk coverage (candidate->b is the same blockvector 'b' was removed
			//from above)--then only continue the fragment if that choice is physically adjacent
			//to the block we just added, since a fragment must be contiguous on disk
			int64_t next_choice_ap = blockvector_get_choice(candidate->b, blockvector_get_num_blocks(candidate->b)-1, f_blk_ap+1, count, &evaluated);
			count -= evaluated;
			if(next_choice_ap == -1){
				if(debug) lock_fprintf(stdout, "no further choices available, fragment ends\n");
				//nothing left anywhere on disk--record that so the outer scan doesn't
				//re-examine this (already-consumed) fragment's last block next iteration
				f_blk_ap = -1;
				break;
			}
			int64_t next_choice_act = filemirror_actual_blocknumber(scalpel_state.filemirror, next_choice_ap);
			if(next_choice_act != f_blk_act + 1){
				if(debug) lock_fprintf(stdout, "next choice (apparent %"PRId64", actual %"PRId64") is not adjacent to actual block %"PRId64", fragment ends\n", next_choice_ap, next_choice_act, f_blk_act);
				//not contiguous, so it can't extend this fragment--but it's still where the
				//outer scan should resume, not this fragment's own last block (which the outer
				//loop would just rediscover as a "new" fragment start, forever, never advancing)
				f_blk_ap = next_choice_ap;
				break;
			}
			f_blk_act = next_choice_act;
			f_blk_ap = next_choice_ap;
			//was the block validated (or marked "maybe") as an mp3 block?
			check_next_block = mp3_reassembly_block_check(f_blk_act, candidate->needleidx, hashkey, debug, "next");
			//now we check if the offsets match (just run frag validate)
			if(check_next_block){
				blockvector_set_apparent_blocknumber(b_check_header, 0, f_blk_ap);
				inflate_blockvector(b_check_header);
				mp3_fragment_validate(blockvector_get_data_pointer(b_check_header),
					*blocksize,
					&va.validates,
					&va.validates_to,
					va.needleidx,
					&va.frontOffset,
					&va.rearOffset,
					&va.isHeader,
					&va.isTail,
					&va.secondToLastFramePosition,
					&va.lastFramePosition,
					&va.offsetFramePosition,
					&va.maybe);
					deflate_blockvector(b_check_header);
				if(va.isHeader){
					va.validates = false;
				}
				else{
					b_read_size++;
					resize_blockvector(
						b_read,
						b_read_size
					);
					if(debug) lock_fprintf(stdout, "blockvector resized to %d\n", b_read_size);
					blockvector_set_apparent_blocknumber(b_read, current_block, f_blk_ap);
					inflate_blockvector(b_read);
					mp3_fragment_validate(blockvector_get_data_pointer(b_read),
						*blocksize * b_read_size,
						&va.validates,
						&va.validates_to,
						va.needleidx,
						&va.frontOffset,
						&va.rearOffset,
						&va.isHeader,
						&va.isTail,
						&va.secondToLastFramePosition,
						&va.lastFramePosition,
						&va.offsetFramePosition,
						&va.maybe);
					deflate_blockvector(b_read);
				}
				if(debug) printf("va.validates_to = %"PRIu64"\n", va.validates_to);
				if(!va.validates){
					if(debug) lock_fprintf(stdout, "blocks connected did not validate\n");
					b_read_size--;
					resize_blockvector(
						b_read,
						b_read_size
					);
					if(debug) lock_fprintf(stdout, "blockvector reduced to %d\n", b_read_size);
					break;
				}
				else{
					if(debug) lock_fprintf(stdout, "block added to fragment %d\n", current_frag);
					current_fragment->frontOffset = va.frontOffset;
					current_fragment->rearOffset = va.rearOffset;
					current_fragment->isHeader = va.isHeader;
					current_fragment->isTail = va.isTail;
					current_fragment->secondToLastFramePosition = va.secondToLastFramePosition;
					current_fragment->lastFramePosition = va.lastFramePosition;
					current_fragment->offsetFramePosition = va.offsetFramePosition;
					current_fragment->size = b_read_size;
					current_fragment->lastActBlock = f_blk_act;
					current_block++;
				}
			}
			//if check_next_block isn't true, loop terminates
			if(debug) lock_fprintf(stdout, "count = %"PRId64"\n", count);
		}
		if(in_frag){
			if(debug) lock_fprintf(stdout, "INFRAG\n");
			if(current_fragment->size == 1){
				current_fragment->lastActBlock = current_fragment->firstActBlock;
			}
			if(debug) lock_fprintf(stdout, "apparent block: %"PRId64"->", f_blk_ap);
			blk_ap = f_blk_ap;
			if(debug) lock_fprintf(stdout, "%"PRId64"\n", blk_ap);
			if(debug) lock_fprintf(stdout, "count = %"PRId64"\n", count);
		}
		else{
			if(debug) lock_fprintf(stdout, "!INFRAG\n");
			if(debug) lock_fprintf(stdout, "apparent block: %"PRId64"->", blk_ap);
			blk_ap = blockvector_get_choice(candidate->b, blockvector_get_num_blocks(candidate->b)-1, blk_ap+1, count, &evaluated);
			if(debug) lock_fprintf(stdout, "%"PRId64"\n", blk_ap);
			count -= evaluated;
			if(debug) lock_fprintf(stdout, "count = %"PRId64"\n", count);
		}
	}
	if(debug) lock_fprintf(stdout, "----------------------------------------------\n");
	#ifdef DEBUG_REASSEMBLY_FRAG
		lock_fprintf(stdout, "Getting peaks for each fragment\n");
	#endif
	for(int i = 0; i < carve_state->num_frags; i++){
		current_fragment = &carve_state->fragments[i];
		// secondToLastFramePosition/offsetFramePosition are byte offsets from the START of the
		// fragment (as computed by mp3_fragment_validate() over the whole, potentially
		// multi-block, fragment buffer) -- NOT necessarily within the fragment's LAST block
		uint64_t peaks_start_block_off = current_fragment->secondToLastFramePosition / (uint64_t) *blocksize;
		uint64_t peaks_end_byte = current_fragment->offsetFramePosition > 0 ? current_fragment->offsetFramePosition - 1 : 0;
		uint64_t peaks_end_block_off = peaks_end_byte / (uint64_t) *blocksize;
		uint64_t peaks_blocks_needed = peaks_end_block_off - peaks_start_block_off + 1;
		resize_blockvector(
			b_read,
			peaks_blocks_needed
		);
		for(uint64_t pb = 0; pb < peaks_blocks_needed; pb++){
			blockvector_set_apparent_blocknumber(b_read, pb, filemirror_apparent_blocknumber(scalpel_state.filemirror, current_fragment->firstActBlock + peaks_start_block_off + pb));
		}
		inflate_blockvector(b_read);
		if(!getPeaks(blockvector_get_data_pointer(b_read) + (current_fragment->secondToLastFramePosition % (uint64_t) *blocksize),
			(current_fragment->offsetFramePosition - current_fragment->secondToLastFramePosition),
			current_fragment->peaks[0], current_fragment->peaks[1], &current_fragment->peaksStereo)){
			// Nothing more to do here: getPeaks() unconditionally zeroes its output array
			// (val=0, index=-1 for all 5 peaks) before attempting any real work, so on failure
			// the peaks here are already left in that safe, already-invalid state. getScore()
			// can't match an index of -1 against any real bin, so a fragment/candidate whose
			// peaks failed to gather just scores 0 in any comparison that uses them -- it can
			// only ever lose a comparison this way, never masquerade as a false match.
			#ifdef DEBUG_REASSEMBLY_FRAG
				lock_fprintf(stdout, "getPeaks failed\n");
			#endif
		}
		deflate_blockvector(b_read);
	}
	carve_state->indexes = malloc(carve_state->num_frags * sizeof(uint16_t));
	check_memory_allocation(carve_state->indexes, __LINE__, __FILE__, "carve_state->indexes");
	carve_put_state(candidate->carvehashkey, carve_state);
	free_blockvector(&b_check_header);
	free(removed_block_numbers);
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

	ValidationArgs va = get_validation_args();
	Mp3BlockState *state = NULL;
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

	//if the block looks like a header, better to assume it is a valid mp3 block
	//reason for this is because if this block is set to maybe, a candidate
	//will not be created
	//later reassembly can then double check this candidate and
	//invalidate it later if need be
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
			frameByteLengthCalc(layer, bitrate, samplingrate, padding, &frameLengthInBytes);
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
	state = (Mp3BlockState *)block_get_state(blockhashkey);
	if(!state){
		state = (Mp3BlockState *)calloc(1, sizeof *state);
		check_memory_allocation(state, __LINE__, __FILE__, "Mp3BlockState");
		state->maybe = true; //block state existing at all also an indicator
		block_put_state(blockhashkey, state);
		#ifdef DEBUG_BLOCK_VALIDATE 
			lock_fprintf(stdout, "MAYBE BLOCK DETECTED\n");
			lock_fprintf(stdout, "frontOffset = %"PRIu16", rearOffset = %"PRIu16"\n", va.frontOffset, va.rearOffset);
		#endif
	}
	mp3_free_block_state((void **)&state);
	*decision = BLOCK_CONFIDENCE_INVALID;
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
* Is it fully finished?
* Currently, the validator only looks for valid MPEG frames contained within the block/fragment. It will
* detect some ID3v2 headers, but will not detect ID3v1/APE headers/footers. That is work to be done in the future.
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

	*validates = false;
	*maybe = false;

	*validates_to = 0;
	// is the block long enough to have a header of a MPEG frame?
	if (length >= FRAME_HEADER_SIZE) {

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

		*isHeader = false;
		*isTail = false;

		// Limit is used to determine how many frames should be expected
		// in a given MP3 block/fragment
		if(length < 1024){
			limit = 1;
		}
		else{
			limit = length / 1024;
		}

		if(skipID3v2(&bs)){
			#ifdef DEBUG_FRAGMENT_VALIDATE
				printf("ID3v2 header skipped\n");
			#endif
			*isHeader = true;
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
					if(!frameByteLengthCalc(layer, bitrate, samplingrate, padding,
					&frameLengthInBytes)){
						return needleidx;
					}
					if(frameLengthInBytes > maxFrameSize){
						maxFrameSize = frameLengthInBytes;
						limit = length / frameLengthInBytes;
					}
					if(first){
						if((uint64_t)bs.bytePos-4 == 0){
							*isHeader = true;
						}
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
				bool tagSkipped = skipID3v1(&bs);
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
					if(tagSkipped) rewindBits(&bs, 128*8);
					rewindBits(&bs, frameLengthInBytes*8 - 8);
					frameJump = false;
					first = true;
				}
				else{
					if(tagSkipped) rewindBits(&bs, 128*8);
					skipBits(&bs, 8);
					frameCounter = 0;
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

	//lock_fprintf(stdout, "mp3_file_validate called\n");

	// is the file long enough to have a header of a MPEG frame?
	if(length >= FRAME_HEADER_SIZE) {

		// INITIALIZATION ----------------------------------------

		bool frameFound = false;
		int frameCounter = 0;

		uint16_t frameLengthInBytes = 0;
		uint8_t mpegVersion = 0;
		uint8_t layer = 0;
		bool crc;
		uint32_t bitrate = 0;
		uint16_t samplingrate = 0;
		enum _ChannelMode channel;
		uint8_t padding = 0;
		uint8_t protectedBytes;

		Bitstream bs = {data, 0, 0, length, false};
		if(skipID3v2(&bs)){
			#ifdef DEBUG_FILE_VALIDATE
				printf("ID3v2 header skipped\n");
			#endif
		}
		/*
		while(bs.bytePos < length && readBits(&bs, 8) == 0){
			#ifdef DEBUG_FILE_VALIDATE
				printf("Skipping NULL byte\n");
			#endif
		}
		rewindBits(&bs, 8);
		*/

		//--------------------------------------------------------
		// SEARCH FOR MP3 FRAME ----------------------------------
		#ifdef DEBUG_FILE_VALIDATE
			printf("Starting file validation:\n");
			printf("Search for MPEG frame 1:\n");
		#endif
		while ((uint64_t)bs.bytePos + 3 < length) {
			if(getFrameData(&bs, &mpegVersion, &layer, &crc, &bitrate, &samplingrate, &padding, &channel)){
				#ifdef DEBUG_FILE_VALIDATE
					printf("MPEG frame %d potentially found\n", frameCounter+1);
				#endif
				if(!frameByteLengthCalc(layer, bitrate, samplingrate, padding,
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
				skipBits(&bs, frameLengthInBytes*8 - 32);
				frameCounter = frameCounter + 1;
			}
			else {
				uint64_t block_bound = length;
				for(uint64_t i = 0; i <= length / blocksize; i++){
					if(i*blocksize > bs.bytePos){
						block_bound = i*blocksize;
						break;
					}
				}
				if(((uint64_t)bs.bytePos == length && !bs.truncated) || skipID3v1(&bs) || areBytesNULL(data+bs.bytePos, block_bound - bs.bytePos)){
					#ifdef DEBUG_FILE_VALIDATE
						printf("MPEG EOF detected\n");
					#endif
					*validates = true;
					*promising = false;
					bs.bytePos = block_bound-1;
					while(readBits(&bs, 8)==0){
						rewindBits(&bs, 16);
					}
					rewindBits(&bs, 8);
					*validates_to = bs.bytePos;
					#ifdef DEBUG_FILE_VALIDATE
						printf("validates = %d, promising = %d\n", *validates, *promising);
					#endif
					return;
				}
				else{
					*validates = false;
					*promising = true;
					*validates_to = bs.bytePos;
					#ifdef DEBUG_FILE_VALIDATE
						printf("validates = %d, promising = %d\n", *validates, *promising);
					#endif
					return;
				}
			}
		}
		if((uint64_t)bs.bytePos == length && !bs.truncated){
			#ifdef DEBUG_FILE_VALIDATE
				printf("MPEG EOF detected\n");
			#endif
			*validates = true;
			*promising = false;
			*validates_to = bs.bytePos;
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
			*validates_to = bs.bytePos;
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
	Bitstream bs = {data, 0, 0, offset + length, false};
	uint64_t block_num = 0;
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
	while((uint64_t)bs.bytePos < offset + length){
		if(debug) lock_fprintf(stdout, "mp3_header_discovery: cur_block: %d, checking = %"PRIu64"\n", cur_block, bs.bytePos);
		if(skipID3v2(&bs)){
			*matchpos = data + cur_block*blocksize;
			*matchlen = ID3V2_HEADER_SIZE;
			if(debug) lock_fprintf(stdout, "mp3_header_discovery: header found, returning %p\n", *matchpos);
			return NULL;
		}
		else if(getFrameData(&bs, &fa.mpegVersion, &fa.layer, &fa.crc, &fa.bitrate, &fa.samplingrate, &fa.padding, &fa.channel)){
			*matchpos = data + cur_block*blocksize;
			*matchlen = FRAME_HEADER_SIZE;
			if(debug) lock_fprintf(stdout, "mp3_header_discovery: header found, returning %p\n", *matchpos);
			return NULL;
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
	uint32_t blocksize = 0;
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
			blockvector_get_data_length(b) / blockvector_get_num_blocks(b),
			NULL);
		blockvector_set_data_length(b, va.validates_to + 1);
		write_candidate(c, false);
		return;
	}

	init_blockvector(scalpel_state.filemirror, &b_read, 1, false);
	//check if carve state data already exists
	carve_state = (Mp3CarveState *)carve_get_state(candidate->carvehashkey);
	if(!mp3_reassembly_init_candidate(work->id, *c, uuidp, uuidc, &carve_state)){
		//candidate is fresh, generate carve state
		first_run = true;
		inflate_blockvector(b);
		mp3_file_validate(blockvector_get_data_pointer(b),
			blockvector_get_data_length(b),
			&va.validates,
			&va.validates_to,
			&va.promising,
			va.needleidx,
			blockvector_get_data_length(b) / blockvector_get_num_blocks(b),
			NULL);
		if(va.validates){
			goto done_validate_candidate;
		}
		else{
			deflate_blockvector(b);
		}
		#ifdef DEBUG_REASSEMBLY_THREAD
			lock_fprintf(stdout,"\nReassembly thread # %1d: Carve data found to not exist, generating fragments\n", work->id);
		#endif
		mp3_reassembly_generate_fragments(b, b_read, candidate, carve_state, &blocksize);
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
		first_run = false;
		inflate_blockvector(b);
		blocksize = blockvector_get_data_length(b) / blockvector_get_num_blocks(b);
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
		else{
			deflate_blockvector(b);
		}
		#ifdef DEBUG_REASSEMBLY_THREAD
			lock_fprintf(stdout,"\nReassembly thread # %1d: Carve data found to exist, checking fragments\n", work->id);
		#endif
		//candidate already has a carve state, check if fragments are still active
		if(!(mp3_reassembly_check_fragments(b_read, carve_state))){
			goto done_promising_candidate;
		}
		mp3_rebuild_committed_blockvector(candidate, carve_state);
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
		goto done_promising_candidate;
	}

	//construction init
	int16_t bestIndex;
	uint8_t mpegVersion = 0;
	uint8_t layer = 0;
	bool crc = false;
	uint32_t bitrate = 0;
	uint16_t samplingrate = 0;
	enum _ChannelMode channel = singleChannel;
	uint8_t padding = 0;
	uint8_t protectedBytes;
	uint16_t frameLengthInBytes = 0;
	bool loop;
	bool bestPeaksOk, compPeaksOk;
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

	#ifdef DEBUG_REASSEMBLY_CONST
		lock_fprintf(stdout, "\n\nBeginning reconstruction...\n\n");
	#endif
	bestIndex = -1;
	if(first_run) carve_state->fragments[carve_state->indexes[0]].active = false;

	loop = true;
	Bitstream bs = {blockvector_get_data_pointer(b), 0, 0, blockvector_get_data_length(b), false};
	resize_blockvector(
		b_read,
		2
	);
	while(loop){
		loop = false;
		bs.data = blockvector_get_data_pointer(b);
		bs.bytePos = blockvector_get_data_length(b) - (carve_state->fragments[carve_state->indexes[carve_state->cur_index - 1]].size * blocksize) + carve_state->fragments[carve_state->indexes[carve_state->cur_index - 1]].offsetFramePosition;
		bs.bitPos = 0;

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
					comp_fragment->frontOffset == current_fragment->rearOffset
					&& comp_fragment->active == true){
						count++;
					}
				}
				if(count >= 2){
					lock_fprintf(stdout, "Has %d solutions\n", count);
					guessProb = guessProb * count;
				}
			#endif

			frameByteLengthCalc(layer, bitrate, samplingrate, padding, &frameLengthInBytes);
			bool found_crc = false;
			for(int k = 0; k < carve_state->num_frags; k++){
				comp_fragment = &carve_state->fragments[k];
				if(k != carve_state->indexes[carve_state->cur_index - 1] &&
				comp_fragment->frontOffset == current_fragment->rearOffset &&
				comp_fragment->active == true){
					resize_blockvector(
						b_read,
						2
					);
					blockvector_set_apparent_blocknumber(b_read, 0, filemirror_apparent_blocknumber(scalpel_state.filemirror, current_fragment->lastActBlock));
					blockvector_set_apparent_blocknumber(b_read, 1, filemirror_apparent_blocknumber(scalpel_state.filemirror, comp_fragment->firstActBlock));
					inflate_blockvector(b_read);
					bs.data = blockvector_get_data_pointer(b_read) + current_fragment->offsetFramePosition % blocksize;
					bs.bytePos = 4;
					bs.bitPos = 0;
					crc = check_crc(&bs, protectedBytes);
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
				//if CRC was not found, we can be confident that the next section of the file does not exist in the blockmap
				#ifdef DEBUG_REASSEMBLY_CONST
					lock_fprintf(stdout, "CRC not found, confident next section does not exist in file, validate\n\n");
				#endif
				goto done_validate_candidate;
			}
		}
		else{
			//This is reached if CRC isn't present or applicable, in other words 'pain'
			bestIndex = -1;

			#ifdef DEBUG_REASSEMBLY_CONST
				lock_fprintf(stdout, "CRC either not present or not applicable\n");
			#endif

			//How many possibilities? Generated for demonstration of usefulness
			count = 0;
			for(int k = 0; k < carve_state->num_frags; k++){
				comp_fragment = &carve_state->fragments[k];
				if(k != carve_state->indexes[carve_state->cur_index - 1] &&
				comp_fragment->frontOffset == current_fragment->rearOffset &&
				comp_fragment->active == true){
					count++;
				}
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

			for(int k = 0; k < carve_state->num_frags; k++){
				comp_fragment = &carve_state->fragments[k];
				if(k != carve_state->indexes[carve_state->cur_index - 1] &&
				comp_fragment->frontOffset == current_fragment->rearOffset &&
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
							inflate_blockvector(b_read);
							//b_read holds exactly 2 blocks (current_fragment's last block + best_comp_fragment's
							//first block). Feed mpg123 everything remaining in that buffer rather than an
							//exact-fit length ending right at the target frame--mpg123's feed-mode decoder
							//generally won't confirm a frame as complete until it can see past its end (e.g.
							//into the next sync word), so a byte-exact length starves it and it reports
							//MPG123_NEED_MORE even when the join itself is fine.
							bestPeaksOk = getPeaks(blockvector_get_data_pointer(b_read) + current_fragment->lastFramePosition % blocksize,
								(2*blocksize - current_fragment->lastFramePosition % blocksize), bestPeaksL, bestPeaksR, &bestIsStereo);
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
						inflate_blockvector(b_read);
						//display_blockvector(b_read, "test");
						//see bestPeaks fetch above: feed the whole 2-block buffer, not an exact-fit length.
						compPeaksOk = getPeaks(blockvector_get_data_pointer(b_read) + current_fragment->lastFramePosition % blocksize,
							(2*blocksize - current_fragment->lastFramePosition % blocksize), compPeaksL, compPeaksR, &compIsStereo);
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
							inflate_blockvector(b_read);
							//see bestPeaks fetch above: feed the whole 2-block buffer, not an exact-fit length.
							bestPeaksOk = getPeaks(blockvector_get_data_pointer(b_read) + current_fragment->offsetFramePosition % blocksize,
								(2*blocksize - current_fragment->offsetFramePosition % blocksize),
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
							inflate_blockvector(b_read);
							//see bestPeaks fetch above: feed the whole 2-block buffer, not an exact-fit length.
							compPeaksOk = getPeaks(blockvector_get_data_pointer(b_read) + current_fragment->offsetFramePosition % blocksize,
								(2*blocksize - current_fragment->offsetFramePosition % blocksize),
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
						#ifdef DEBUG_REASSEMBLY_CONST
							lock_fprintf(stdout, "score1 = %f, score2 = %f\n",score1,score2);
						#endif
						if(!bestPeaksOk && !compPeaksOk){
							//neither candidate's boundary peaks could be decoded, so score1 == score2 == 0.0
							//is not a real tie--there's no frequency evidence at all. bestIndex still wins
							//below purely by fragment scan order, not any actual signal -- flag this loudly
							//(not just under DEBUG_REASSEMBLY_CONST) so it's visible for manual review even
							//in a normal run, cross-referenced by this candidate's UUIDs.
							lock_fprintf(stdout,
								"*** MP3 REASSEMBLY: no frequency evidence for either candidate fragment"
								" (indexes %d vs %d) while extending candidate %s / %s -- keeping index %d"
								" by scan order only, not by audio evidence ***\n",
								bestIndex, k, uuidp, uuidc, bestIndex);
						}
						else if(score2>score1){
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
	//b_read is freed here, once, regardless of which path reached this label (contiguous,
	//isTail-terminated, or a CRC/offset dead end) -- do not free it again below.
	free_blockvector(&b_read);
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
		blockvector_get_data_length(b) / blockvector_get_num_blocks(b),
		NULL);
	if(!va.validates){
		//Reconstruction could not be confirmed as a valid file.
		//PROMISING is the closest existing state for "not confirmed, don't discard, may be revisited."
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
