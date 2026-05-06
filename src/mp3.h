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

/**
* @author George H.
* @discussion
*
* This file contains functionality for an MP3 file validator and defragmentator.
* Comments last updated: 11/21/25
*
* MP3 reassembly is togglable inside of this file under REASSEMBLY_ON
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

//TWEAKABLE PARAMETERS:
//block validation
#define DECODE_FAILURE_TOLERANCE	2			//amount of frames in a block allowed to fail to decode
#define MAYBE_FRAME_LIMIT			2
//reassembly
#define REASSEMBLY_ON				false
//peak scoring
#define TOLERANCE 					2			//max index difference allowed
#define ALPHA						5.0			//sensitivity to value differences
#define BETA						1.0			//sensitivity to index differences

//file type specific
#define FRAME_HEADER_SIZE 			4
#define FRAME_FOOTER_SIZE 			16
#define MDCT_COEFFS 				576
#define GP                      	0x18005		/* x^16 + x^15 + x^2 + 1 */
#define CRC16_CMS_POLY          	0x8005
#define CRC16_INIT					0xFFFF

//debug
//#define DEBUG_ID3v2 1
//#define DEBUG_FILE_VALIDATE 1
//#define DEBUG_REASSEMBLY_FRAG 1
//#define DEBUG_REASSEMBLY_CONST 1
//#define DEBUG_REASSEMBLY_THREAD 1

/***** TABLES *****/

static short crc16_table[256]; /* 8-bit table */
static pthread_once_t crc16_table_once = PTHREAD_ONCE_INIT;
static void crc16_init_table(void) {
  short crc2;
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
static void mp3_do_init(void) { mpg123_init(); }
static inline void mp3_ensure_init(void) { pthread_once(&mp3_init_once, mp3_do_init); }

// Mutex protecting mpg123_new/mpg123_delete — these are NOT thread-safe
// on macOS ARM64 (corrupt shared internal state when called concurrently).
static pthread_mutex_t mp3_handle_mutex = PTHREAD_MUTEX_INITIALIZER;

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

const char id3v2v2[63][4] = {
"BUF","CNT","COM","CRA","CRM","ETC","EQU","GEO",
"IPL","LNK","MCI","MLL","PIC","POP","REV","RVA",
"SLT","STC","TAL","TBP","TCM","TCO","TCR","TDA",
"TDY","TEN","TFT","TIM","TKE","TLA","TLE","TMT",
"TOA","TOF","TOL","TOR","TOT","TP1","TP2","TP3",
"TP4","TPA","TPB","TRC","TRD","TRK","TSI","TSS",
"TT1","TT2","TT3","TXT","TXX","TYE","UFI","ULT",
"WAF","WAR","WAS","WCM","WCP","WPB","WXX"};

const char id3v2v3[74][5] = {
"AENC","APIC","COMM","COMR","ENCR","EQUA","ETCO","GEOB",
"GRID","IPLS","LINK","MCDI","MLLT","OWNE","PRIV","PCNT",
"POPM","POSS","RBUF","RVAD","RVRB","SYLT","SYTC","TALB",
"TBPM","TCOM","TCON","TCOP","TDAT","TDLY","TENC","TEXT",
"TFLT","TIME","TIT1","TIT2","TIT3","TKEY","TLAN","TLEN",
"TMED","TOAL","TOFN","TOLY","TOPE","TORY","TOWN","TPE1",
"TPE2","TPE3","TPE4","TPOS","TPUB","TRCK","TRDA","TRSN",
"TRSO","TSIZ","TSRC","TSSE","TYER","TXXX","UFID","USER",
"USLT","WCOM","WCOP","WOAF","WOAR","WOAS","WORS","WPAY",
"WPUB","WXXX"};

const char id3v2v4[83][5] = {
"AENC","APIC","ASPI","COMM","COMR","ENCR","EQU2","ETCO",
"GEOB","GRID","LINK","MCDI","MLLT","OWNE","PRIV","PCNT",
"POPM","POSS","RBUF","RVA2","RVRB","SEEK","SIGN","SYLT",
"SYTC","TALB","TBPM","TCOM","TCON","TCOP","TDEN","TDLY",
"TDOR","TDRC","TDRL","TDTG","TENC","TEXT","TFLT","TIPL",
"TIT1","TIT2","TIT3","TKEY","TLAN","TLEN","TMCL","TMED",
"TMOO","TOAL","TOFN","TOLY","TOPE","TOWN","TPE1","TPE2",
"TPE3","TPE4","TPOS","TPRO","TPUB","TRCK","TRSN","TRSO",
"TSOA","TSOP","TSOT","TSRC","TSSE","TSST","TXXX","UFID",
"USER","USLT","WCOM","WCOP","WOAF","WOAR","WOAS","WORS",
"WPAY","WPUB","WXXX"};

/**** DEFINITIONS ****/

typedef struct {
    char *data;
    int bitPos;
    uint64_t bytePos;
    uint64_t length;
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
	Peak peaks[6];
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
} GetFrameArgs;

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

static void crc16(short *crc, unsigned char m);
static bool check_crc(Bitstream *bs, uint8_t protectedBytes);

static inline uint32_t bitRateIndexer(uint8_t mpegVersion,
	uint8_t layer,
	unsigned int bitrateVal);

static inline bool frameByteLengthCalc(uint8_t layer,
	uint32_t bitrate,
	uint16_t samplerate,
	uint8_t padding,
	uint16_t *frameLengthInBytes,
	bool debug);

static bool areBytesNULL(char* data, uint64_t bytesToCheck);

static int get_pcm_byte_count(int mpeg_version, int channels);

static bool getPeaks(char *file_buf, int len, Peak peaks[], bool debug);
static int comparePeaks(const void *a, const void *b);
static int filter(const struct dirent *name);
static double getScore(Peak *peaks1, Peak *peaks2);

static bool getFrameData(Bitstream *bs,
	uint8_t *mpegVersion,
	uint8_t *layer,
	bool *crc,
	uint32_t *bitrate,
	uint16_t *samplerate,
	uint8_t *padding,
	enum _ChannelMode *channel,
	bool debug);

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
static Mp3Fragment *add_fragment(Mp3Fragment *old_fragments, int old_count);
static Mp3Fragment *remove_fragment(Mp3Fragment *old_fragments, int old_count, int frag_index);
static GetFrameArgs get_frame_args(void);
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

static void mp3_reassembly_generate_fragments(BlockVector *b,
	BlockVector *b_read,
	CarveInfo *candidate,
	Mp3CarveState *carve_state,
	uint32_t *blocksize);

static void mp3_custom_reassembly(ThreadWork *work,
	CarveInfo **c,
	uuid_string_t uuidp,
	uuid_string_t uuidc);

/******* FUNCTION DEFINITIONS *******/

// Bitstream functions:
unsigned int readBits(Bitstream *bs, int n) {
    unsigned int value = 0;
    for(int i = 0; i < n; i++){
        int bit = (bs->data[bs->bytePos] >> (7 - bs->bitPos)) & 1;
        value = (value << 1) | bit;
        bs->bitPos++;
        if(bs->bitPos == 8){
            bs->bitPos = 0;
            bs->bytePos++;
        }
    }
    return value;
}

void skipBits(Bitstream *bs, int n){
	for(int i = 0; i < n; i++){
		bs->bitPos++;
		if(bs->bitPos == 8){
			bs->bitPos = 0;
			bs->bytePos++;
		}
	}
}

void rewindBits(Bitstream *bs, int n){
	if(bs->bytePos != 0){
		for(int i = 0; i < n; i++){
			bs->bitPos = bs->bitPos - 1;
			if(bs->bitPos == -1){
				bs->bitPos = 7;
				bs->bytePos = bs->bytePos - 1;
			}
		}
	}
}

//CRC related functions:
void crc16(short *crc, unsigned char m)
//for a byte array whose accumulated crc value is stored in *crc, computes
//resultant crc obtained by appending m to the byte array
{
	pthread_once(&crc16_table_once, crc16_init_table);
	*crc = crc16_table[(((*crc) >> 8) ^ m) & 0xFF] ^ (((*crc) << 8) & 0xFFFF);
}
bool check_crc(Bitstream *bs, uint8_t protectedBytes){
	//when called, the pointer will be at the crc checksum, right after the frame header
	//take this into account
	if(bs->bytePos + 1 >= bs->length) return false;
	short crc_origin = (short)((unsigned char)bs->data[bs->bytePos] << 8 | (unsigned char)bs->data[bs->bytePos+1]);
	short crc_computed;

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
uint8_t padding, uint16_t *frameLengthInBytes, bool debug){
	// Frame Byte Length Calculation
	bitrate = bitrate * 1000;
	if (layer == 1) {
		*frameLengthInBytes = (12 * bitrate / samplingrate + padding) * 4;
	}
	else if (layer == 2 || layer == 3) {
		*frameLengthInBytes = 144 * bitrate / samplingrate + padding;
	}
	else{
		if(debug){
			printf("Error: invalid layer\n");
		}
		return false;
	}
	return true;
}

bool areBytesNULL(char* data, uint64_t bytesToCheck){
	for(uint64_t i = 0; i < bytesToCheck; i++){
		/*
		if(i%16==15){
			printf("%02X\n", (unsigned char)data[i]);
		}
		else{
			printf("%02X", (unsigned char)data[i]);
		}
		*/
		if(data[i] != 0x00){
			return false;
		}
	}
	return true;
}

// function used to determine how much memory should be allocated to account for output PCM data
// assumes 16-bit samples
int get_pcm_byte_count(int mpeg_version, int channels){
    int samples_per_frame = 0;
    if(mpeg_version == 1){
        samples_per_frame = 1152;
    } else if (mpeg_version == 2 || mpeg_version == 3){
        samples_per_frame = 576;
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

// Uses MPG123 decoder with PocketFFT library, works for layers 1-3, however layer 3 is suboptimal
// *file_buf - IMPORTANT: MUST point to beginning of frame BEFORE the frame you want to read
//      - Why is it like this? To account for the bit reservoir.
//      - If a frame uses a bit reservoir, by reading the first frame, it will fail but the data will be loaded into the decoder.
//      - The second read will be able to use that data, and this method was found to be better than doing any manual alterations
//      - to the decoder library.
// len - length of file (or data being read?)
// peaks[] - where the output of peaks will be stored, currently MUST have 6 peaks
// debug - if true, print statements will print displaying important steps being taken

bool getPeaks(char *file_buf, int len, Peak peaks[], bool debug){
    mpg123_handle *mh;
    int mpeg_version, channels, encoding, pcm_byte_num, err;
    int feed_result, N, read_result;
    unsigned char *pcm_bytes, *temp;
    long rate;
    size_t done, size;
	float* time;
	float* freq;
    float* temp2;
    bool output = false;
	void* pfft_m_plan;

	if(debug) printf("getPeaks:");

    //TODO: Get the version and channels
    mpeg_version = 1;
    channels = 2;

    //TODO: This currently doesn't take into account changing formats between frames.

    //INITIALIZATION
    //Creates a handle with an optional choice of decoder and an optional retrieval of
    //an error code to feed to mpg123_plain_strerror().
    mp3_ensure_init();
    pthread_mutex_lock(&mp3_handle_mutex);
    mh = mpg123_new(NULL, &err);
    pthread_mutex_unlock(&mp3_handle_mutex);
    if(mh == NULL){
        fprintf(stderr,"Failed to create mpg123 handle: %s\n",mpg123_plain_strerror(err));
        return false;
    }
    mpg123_format(mh, 48000, MPG123_STEREO, MPG123_ENC_SIGNED_16);
    mpg123_open_feed(mh);
    //Feeds data for a stream opened with mpg123_open_feed()
    //We provide the bytestream, mpg123 gives the decoded samples.
	if(debug) printf("Trying to feed data\n");
    feed_result = mpg123_feed(mh, (unsigned char *)file_buf, len);
    //What are we expecting the result to be here? What does MPG123_NEED_MORE mean
    if(feed_result != MPG123_OK){
        if(debug) fprintf(stderr,"Failed to feed data: %s\n",mpg123_plain_strerror(feed_result));
        pthread_mutex_lock(&mp3_handle_mutex); mpg123_delete(mh); pthread_mutex_unlock(&mp3_handle_mutex);
        return false;
    }
    if(debug) printf("Data fed successfully\n");

    //Memory allocation for decoder output
    if(debug) printf("Allocating memory for pcm data\n");
    pcm_byte_num = get_pcm_byte_count(mpeg_version, channels);
    if(pcm_byte_num == -1){
        perror("Failed to calculate pcm byte size\n");
        pthread_mutex_lock(&mp3_handle_mutex); mpg123_delete(mh); pthread_mutex_unlock(&mp3_handle_mutex);
        return false;
    }
    pcm_bytes = malloc(pcm_byte_num * sizeof(unsigned char));
    if(pcm_bytes == NULL){
        perror("Failed to allocate memory\n");
        pthread_mutex_lock(&mp3_handle_mutex); mpg123_delete(mh); pthread_mutex_unlock(&mp3_handle_mutex);
        return false;
    }
    if(debug) printf("Allocating memory for pcm data success\n");
    done = 0;

    // DFFT setup
    N = pcm_byte_num / sizeof(short);
	time = (float*)malloc(sizeof(float)*N);
	freq = (float*)malloc(sizeof(float)*(N >> 1));
	pfft_m_plan = pfft_mdctf_init(N);
	if(NULL == pfft_m_plan){
		//TODO: ERROR HANDLING
		goto finish;
	}

    size = 6;

    //TODO: currently, if second frame is different format, breaks everything >:(

    read_result = mpg123_read(mh,pcm_bytes,pcm_byte_num,&done);
    if(read_result == MPG123_NEW_FORMAT){
        //huge hassle if frame is different format than expected, getting details about frame beforehand would prevent this from being called, here just in case
        mpg123_getformat(mh,&rate,&channels,&encoding);
        if(debug) printf("New format detected: rate=%ld Hz, channels=%d, encoding=%d\n",rate,channels,encoding);
        //have to get the new number of pcm bytes
        pcm_byte_num = get_pcm_byte_count(mpeg_version, channels);
        temp = realloc(pcm_bytes, pcm_byte_num * sizeof(unsigned char));
        if(temp == NULL){
            perror("Failed to allocate memory\n");
			exit(EXIT_FAILURE);
            goto finish;
        }
        pcm_bytes = temp;
        N = pcm_byte_num / sizeof(short);
		temp2 = (float*)realloc(time, sizeof(float)*N);
        if(temp2 == NULL){
            perror("Failed to allocate memory\n");
			exit(EXIT_FAILURE);
        }
        time = temp2;
        temp2 = (float*)realloc(freq, sizeof(float)*(N >> 1));
        if(temp2 == NULL){
            perror("Failed to allocate memory\n");
            exit(EXIT_FAILURE);
        }
        freq = temp2;
		pfft_mdctf_free(pfft_m_plan);
		pfft_m_plan = pfft_mdctf_init(N);

        read_result = mpg123_read(mh,pcm_bytes,pcm_byte_num,&done);
    }
    if(read_result == MPG123_OK){
        read_result = mpg123_read(mh,pcm_bytes,pcm_byte_num,&done);
        if(read_result == MPG123_NEW_FORMAT){
            //huge hassle if frame is different format than expected, getting details about frame beforehand would prevent this from being called, here just in case
            mpg123_getformat(mh,&rate,&channels,&encoding);
            if(debug) printf("New format detected: rate=%ld Hz, channels=%d, encoding=%d\n",rate,channels,encoding);
            //have to get the new number of pcm bytes
            pcm_byte_num = get_pcm_byte_count(mpeg_version, channels);
            temp = realloc(pcm_bytes, pcm_byte_num * sizeof(unsigned char));
            if(temp == NULL){
                perror("Failed to allocate memory\n");
                goto finish;
            }
            pcm_bytes = temp;
            N = pcm_byte_num / sizeof(short);
			temp2 = (float*)realloc(time, sizeof(float)*N);
			if(temp2 == NULL){
				perror("Failed to allocate memory\n");
				exit(EXIT_FAILURE);
			}
			time = temp2;
			temp2 = (float*)realloc(freq, sizeof(float)*(N >> 1));
			if(temp2 == NULL){
				perror("Failed to allocate memory\n");
				exit(EXIT_FAILURE);
			}
			freq = temp2;
			pfft_mdctf_free(pfft_m_plan);
			pfft_m_plan = pfft_mdctf_init(N);

            read_result = mpg123_read(mh,pcm_bytes,pcm_byte_num,&done);
        }
        if(read_result == MPG123_OK){
            if(debug) printf("Decoded %zu bytes of audio data\n",done);
            if(debug) printf("-------------------------------\n");

            /*
            for(int i = 0; i < pcm_byte_num; i++){
                printf("%x ",pcm_bytes[i]);
                if(i%16==15){
                    printf("\n");
                }
            }
            */

            //Normalize PCM data and copy to PFFT input

			//printf("PocketFFT MDCT input:\n");
			for(int i = 0; i < N; i++){
				time[i] = ((short *)pcm_bytes)[i] / 32768.0;
			}

			//Execute MDCT
			pfft_mdctf(freq, time, pfft_m_plan);

			for(int i = 0; i < (N >> 1); i++){
				freq[i] = fabs(freq[i]);
			}

			if(debug) printf("PocketFFT MDCT coefficients:\n");
			for(int i = 0; i < (N >> 1); i++){
                //if peak detected, compare to other peaks, if bigger then add
                if(i != 0 && i != (N/2)-1){
                    if(freq[i-1] < freq[i] && freq[i+1] < freq[i]){
                        peaks[5] = (Peak){freq[i],i};
                        qsort(peaks, size, sizeof(Peak),comparePeaks);
                    }
                }
				if(debug) printf("PFFT Coefficient %d: %f\n", i , freq[i]);
                //fprintf(output_file,"%d\t%f\n",i,out[i]);
            }

            /*
            for(size_t i = 0; i < size-1; i++){
                printf("Value: %.2f, Index: %d\n",peaks[i].val,peaks[i].index);
            }
			*/

            if(debug) printf("---------------------------------\n");
            //fprintf(output_file,"---------------------------------\n");
			pfft_mdctf_free(pfft_m_plan);
        }
        else{
            fprintf(stderr, "Error decoding: %s\n", mpg123_plain_strerror(read_result));
			//TODO: ERROR HANDLING
            goto finish;
        }
    }
    else{
        fprintf(stderr, "Error decoding: %s\n", mpg123_plain_strerror(read_result));
		//TODO: ERROR HANDLING
        goto finish;
    }
    output = true;

    finish:
	free(freq);
	free(time);
    free(pcm_bytes);
    pthread_mutex_lock(&mp3_handle_mutex); mpg123_delete(mh); pthread_mutex_unlock(&mp3_handle_mutex);
    return output;
}

int filter(const struct dirent *name){
	return 1;
}

double getScore(Peak *peaks1, Peak *peaks2){
	double output = 0.0;
	double bestScore = 0.0;
	int bestIndex = -1;
	int indexDiff;
	double indexWeight, valueSimilarity, score;
	for(int i = 0; i < 5; i++){
		bestScore = 0.0;
		bestIndex = -1;
		for(int j = 0; j < 5; j++){
			indexDiff = abs(peaks1[i].index - peaks2[j].index);
			if(indexDiff <= TOLERANCE){
				indexWeight = exp(-BETA * fabs((double)indexDiff));
				valueSimilarity = exp(-ALPHA * fabs(peaks1[i].val - peaks2[j].val));
				score = indexWeight * valueSimilarity;
				if(score > bestScore){
					bestScore = score;
					bestIndex = j;
				}
			}
		}
		if(bestIndex != -1){
			output += bestScore;
		}
	}
	return output / 5;
}

// Function that should return all frame data from a frame header
// If provided data that isn't a frame header, it should reset bitstream
// to original position.
bool getFrameData(Bitstream *bs, uint8_t *mpegVersion, uint8_t *layer, bool *crc,
	uint32_t *bitrate, uint16_t *samplerate, uint8_t *padding,
	enum _ChannelMode *channel, bool debug) {
		uint8_t bitsRead = 0;
		unsigned int bits = readBits(bs,11);
		bitsRead += 11;
		if (bits == 2047){
			if(debug) printf("Possibly valid frame\n");

			//Read MPEG version bits
			bits = readBits(bs,2);
			bitsRead += 2;
			switch(bits){
				case 0: //MPEG version 2.5
					*mpegVersion = 3;
					break;
				case 1: //Invalid
					if(debug) printf("Invalid mpegVersion\n");
					rewindBits(bs, bitsRead);
					return false;
				case 2: //MPEG version 2
					*mpegVersion = 2;
					break;
				case 3: //MPEG version 1
					*mpegVersion = 1;
					break;
				default: //Invalid
					if(debug) printf("Invalid mpegVersion\n");
					rewindBits(bs, bitsRead);
					return false;
			}

			//Read layer
			bits = readBits(bs,2);
			bitsRead += 2;
			switch(bits){
				case 0: //Invalid
					if(debug) printf("Invalid layer\n");
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
					if(debug) printf("Invalid layer\n");
					rewindBits(bs, bitsRead);
					return false;
			}

			//Read CRC
			bits = readBits(bs,1);
			bitsRead += 1;
			if(bits == 0) *crc = true;
			else *crc = false;
			if(debug && *crc) printf("CRC is present and will be skipped\n");
			else if(debug) printf("CRC is not present and will not be skipped\n");

			//Read bitrate
			bits = readBits(bs,4);
			bitsRead += 4;
			switch(bits){
				case 0:
					if(debug) printf("Bitrate unknown\n");
					rewindBits(bs, bitsRead);
					return false;
				case 15:
					if(debug) printf("Bitrate unknown\n");
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
							if(debug) printf("Sample rate unknown\n");
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
							if(debug) printf("Sample rate unknown\n");
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
							if(debug) printf("Sample rate unknown\n");
							rewindBits(bs, bitsRead);
							return false;
					}
					break;
				default: //If bits are 3
					if(debug) printf("Sample rate unknown\n");
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
					if(debug) printf("Channel mode unknown\n");
					rewindBits(bs, bitsRead);
					return false;
			}

			//Skip rest of header
			//Things being skipped: mode extension, copyright, original/home, emphasis
			skipBits(bs,6);
			bitsRead += 6;

			if(debug) printf("Yep, header seems legit.\n");
			return true;
		}
		//if(debug) printf("Invalid frame\n");
		if(debug) printf("-");
		rewindBits(bs, bitsRead);
		return false;
}

// Function should detect if ID3v2 header is present and skip it if detected
bool skipID3v2(Bitstream *bs){
	uint8_t* bytes = (uint8_t*)(bs->data+bs->bytePos);
	uint8_t* data_end = (uint8_t*)bs->data + bs->length;
	bool id3v2found = false;
	int byteCounter = 0;
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

		byteCounter += 10;
		bytes = (bytes + byteCounter);
		int found;
		uint32_t id3FrameSize = 0;
		bool readTag = true;

		//look for id3v2 frames
		while (readTag) {
			// Bounds check: need at least 10 bytes for frame ID + size + flags
			if (bytes + 10 > data_end) {
				readTag = false;
				break;
			}
			found = -1;
			id3FrameSize = 0;
			switch(id3version){
				case 2:
					for (int i = 0; i < 63; i++) {
						if (memcmp(id3v2v2[i], &bytes[0], 3) == 0) {
							found = i;
							id3v2found = true;
							break;
						}
					}
					if (found != -1) {
						//shouldn't this be 3?
						byteCounter += 4;
						bytes = (uint8_t*)(bytes + 4);
						//there's definitely a better way to do this
						id3FrameSize = id3FrameSize + bytes[0] * 16777216;
						id3FrameSize = id3FrameSize + bytes[1] * 65536;
						id3FrameSize = id3FrameSize + bytes[2] * 256;
						id3FrameSize = id3FrameSize + bytes[3];
						#ifdef DEBUG_ID3v2
							printf("Frame %c%c%c detected\n",
								id3v2v2[found][0], id3v2v2[found][1],
								id3v2v2[found][2]);
							printf("Size of frame found to be %d bytes.\n", id3FrameSize);
						#endif
						if(id3FrameSize > 16000000 || bytes + 4 + 2 + id3FrameSize > data_end){
							byteCounter -= 4;
							readTag = false;
							break;
						}
						else{
							byteCounter = byteCounter + 4 + 2 + id3FrameSize;
							bytes = (uint8_t*)(bytes + 4 + 2 + id3FrameSize);
						}
					}
					else{
						readTag = false;
					}
					break;
				case 3:
					for (int i = 0; i < 74; i++) {
						if (memcmp(id3v2v3[i], &bytes[0], 4) == 0) {
							found = i;
							id3v2found = true;
						}
					}
					if (found != -1) {
						byteCounter += 4;
						bytes = (uint8_t*)(bytes + 4);
						id3FrameSize = id3FrameSize + bytes[0] * 16777216;
						id3FrameSize = id3FrameSize + bytes[1] * 65536;
						id3FrameSize = id3FrameSize + bytes[2] * 256;
						id3FrameSize = id3FrameSize + bytes[3];
						#ifdef DEBUG_ID3v2
							printf("Frame %c%c%c%c detected\n",
								id3v2v3[found][0], id3v2v3[found][1],
								id3v2v3[found][2], id3v2v3[found][3]);
							printf("Size of frame found to be %d bytes.\n", id3FrameSize);
						#endif
						if(id3FrameSize > 16000000 || bytes + 4 + 2 + id3FrameSize > data_end){
							byteCounter -= 4;
							readTag = false;
						}
						else{
							byteCounter = byteCounter + 4 + 2 + id3FrameSize;
							bytes = (uint8_t*)(bytes + 4 + 2 + id3FrameSize);
						}
					}
					else {
						readTag = false;
					}
					break;
				case 4:
					found = -1;
					for (int i = 0; i < 83; i++) {
						if (memcmp(id3v2v4[i], &bytes[0], 4) == 0) {
							found = i;
							id3v2found = true;
							break;
						}
					}
					if (found != -1) {
						byteCounter += 4;
						bytes = (uint8_t*)(bytes + 4);
						id3FrameSize = id3FrameSize + bytes[0] * 16777216;
						id3FrameSize = id3FrameSize + bytes[1] * 65536;
						id3FrameSize = id3FrameSize + bytes[2] * 256;
						id3FrameSize = id3FrameSize + bytes[3];
						#ifdef DEBUG_ID3v2
							printf("Frame %c%c%c%c detected\n",
								id3v2v4[found][0], id3v2v4[found][1],
								id3v2v4[found][2], id3v2v4[found][3]);
							printf("Size of frame found to be %d bytes.\n", id3FrameSize);
						#endif
						if(id3FrameSize > 16000000 || bytes + 4 + 2 + id3FrameSize > data_end){
							byteCounter -= 4;
							readTag = false;
						}
						else{
							byteCounter = byteCounter + 4 + 2 + id3FrameSize;
							bytes = (uint8_t*)(bytes + 4 + 2 + id3FrameSize);
						}
					}
					else {
						readTag = false;
					}
					break;
				default:
					#ifdef DEBUG_ID3v2
						printf("Invalid ID3v2 version detected.\n");
					#endif
					byteCounter = 0;
					return id3v2found;
			}
		}
		if(id3v2found) {
			#ifdef DEBUG_ID3v2
				printf("--------------------------------------------------------------\n");
			#endif
		}
	}
	#ifdef DEBUG_ID3v2
		printf("Skipping %d bytes\n",byteCounter);
	#endif
	skipBits(bs, byteCounter*8);
	return id3v2found;
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

	if(fb(&(*s)->num_frags, sizeof(int), 1, fp) != 1){
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
            fb(&frag->offsetFramePosition, sizeof(uint64_t), 1, fp) != 1) {
            perror("mp3 fragment metadata");
            handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
        }
		// peaks
		if(fb(frag->peaks, sizeof(Peak), 6, fp) != 6){
			perror("mp3 fragment peaks");
			handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
		}
		// separate indexes array (not in frag struct)
		if (fb(&(*s)->indexes[i], sizeof(uint16_t), 1, fp) != 1){
			perror("mp3 index");
			handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
		}
	}

	// cur_index
	if (fb(&(*s)->cur_index, sizeof(int), 1, fp) != 1){
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

		memcpy(dst->peaks, src->peaks, sizeof(Peak) * 6);
	}
	if(s->indexes == NULL){
		s->indexes = calloc(d->num_frags, sizeof(uint16_t));
	}
	else{
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
		frag1->offsetFramePosition == frag2->offsetFramePosition);
		if(!result) return result;
		for(int j = 0; j < 6; j++){
			result = (result &&
			frag1->peaks[j].val == frag2->peaks[j].val &&
			frag1->peaks[j].index == frag2->peaks[j].index);
			if(!result) return result;
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
	for(int i = 0; i < s->num_frags; i++){
		fprintf(stdout, "======================\n");
		fprintf(stdout, "fragment number %d\n", i);
		fprintf(stdout, "front offset: %d\n", s->fragments[i].frontOffset);
		fprintf(stdout, "rear offset: %d\n", s->fragments[i].rearOffset);
		fprintf(stdout, "size: %zu\n", s->fragments[i].size);
		fprintf(stdout, "isHeader: %s\n", (s->fragments[i].isHeader) ? "TRUE" : "FALSE");
		fprintf(stdout, "isTail: %s\n", (s->fragments[i].isTail) ? "TRUE" : "FALSE");
		fprintf(stdout, "active: %s\n", (s->fragments[i].active) ? "TRUE" : "FALSE");
		fprintf(stdout, "secondToLastFramePosition: %"PRIu64"\n", s->fragments[i].secondToLastFramePosition);
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
		for(int j = 0; j < 6; j++){
			fragments[i].peaks[j].val = 0;
			fragments[i].peaks[j].index = -1;
		}
		fragments[i].firstActBlock = 0;
		fragments[i].lastActBlock = 0;
	}
	return fragments;
}

//initializes one fragment to end of array of fragments
Mp3Fragment *add_fragment(Mp3Fragment *old_fragments, int old_count){
	int new_count = old_count + 1;
	Mp3Fragment *new_fragments = realloc(old_fragments, new_count * sizeof(Mp3Fragment));
	if(!new_fragments){
		perror("Failed to allocate memory for new fragment");
		free(old_fragments);
		exit(EXIT_FAILURE);
	}
	new_fragments[old_count].frontOffset = 0;
	new_fragments[old_count].rearOffset = 0;
	new_fragments[old_count].size = 0;
	new_fragments[old_count].isHeader = false;
	new_fragments[old_count].isTail = false;
	new_fragments[old_count].active = true;
	new_fragments[old_count].secondToLastFramePosition = 0;
	new_fragments[old_count].lastFramePosition = 0;
	new_fragments[old_count].offsetFramePosition = 0;
	for(int j = 0; j < 6; j++){
		new_fragments[old_count].peaks[j].val = 0;
		new_fragments[old_count].peaks[j].index = -1;
	}
	new_fragments[old_count].firstActBlock = 0;
	new_fragments[old_count].lastActBlock = 0;
	return new_fragments;
}

//removes fragment at index frag_index from array of fragments
Mp3Fragment *remove_fragment(Mp3Fragment *old_fragments, int old_count, int frag_index){
	int new_count = old_count - 1;
	for(int i = frag_index; i < old_count-1; i++){
		old_fragments[i] = old_fragments[i+1];
	}
	Mp3Fragment *new_fragments = realloc(old_fragments, new_count * sizeof(Mp3Fragment));
	if(!new_fragments){
		perror("Failed to allow memory for new fragments");
		free(old_fragments);
		exit(EXIT_FAILURE);
	}
	return new_fragments;
}

GetFrameArgs get_frame_args(void){
	GetFrameArgs fa = {
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
				carve_state->fragments = add_fragment(carve_state->fragments, carve_state->num_frags);
				carve_state->num_frags++;
				Mp3Fragment *new_frag = &carve_state->fragments[carve_state->num_frags-1];
				new_frag->firstActBlock = frag->firstActBlock + blk_pos + 1;
				new_frag->lastActBlock = frag->lastActBlock;
				frag->lastActBlock = frag->firstActBlock + blk_pos - 1;
				resize_blockvector(
					b_read,
					frag2_size
				);
				int blk_pos_2 = 0;
				for(int64_t blk_act_2 = new_frag->firstActBlock; blk_act_2 <= new_frag->lastActBlock; blk_act_2++){
					blockvector_set_apparent_blocknumber(b_read, blk_pos_2, blk_act_2);
					blk_pos_2++;
				}
				inflate_blockvector(b_read);
				uint32_t blocksize = blockvector_get_data_length(b_read) / blockvector_get_num_blocks(b_read);
				curFragLength = blocksize * frag->size;
				//TODO: can blockvector access data of covered blocks? even if it has the actual block number?
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
		//TODO: if carve_state->num_frags gets changed, will for loop still work properly?
		while(!mp3_reassembly_check_fragment(b_read, carve_state, &carve_state->fragments[i], i));
	}
	return true;
}


/**
* @discussion		MP3 Fragment Generator: Scans the entire blockmap for how potential MP3 blocks connect
*
* Edit: 11/21/25
* Generates
*/
static void mp3_reassembly_generate_fragments(BlockVector *b,
										BlockVector *b_read,
										CarveInfo *candidate,
										Mp3CarveState *carve_state,
										uint32_t *blocksize){

	//blocks of validated contiguous files are already covered

	bool debug = true;

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
	for(uint64_t i = 0; i < blockvector_get_num_blocks(b); i++){
		#ifdef DEBUG_REASSEMBLY_FRAG
			lock_fprintf(stdout, "removing actual block number %d\n", blockvector_get_actual_blocknumber(b, i));
		#endif
		blockvector_remove_choice(
			b,
			blockvector_get_num_blocks(b) - 1,
			blockvector_get_apparent_blocknumber(b, i)
		);
	}
	first_fragment->active = false;

	//------------------------
	uint16_t current_block = 0;
	uint16_t current_frag = 0;
	bool check_next_block, in_frag;
	int64_t blk_ap, blk_act, f_blk_ap, f_blk_act;
	char hashkey[BLOCK_HASH_KEY_SIZE];
	Mp3BlockState *blk_state, *f_blk_state;
	uint64_t evaluated;
	uint64_t prev_validates_to = 0;
	int64_t count = 0;
	int b_read_size = 0;
	ValidationArgs va = get_validation_args();
	count = filemirror_apparent_blocks(scalpel_state.filemirror);
	blk_ap = blockvector_get_choice(candidate->b, blockvector_get_num_blocks(candidate->b)-1, 0, count, &evaluated);
	blk_act = filemirror_actual_blocknumber(scalpel_state.filemirror, blk_ap);
	count--;
	//TODO: change Mp3Fragment so that only the first and last blocks are stored
	while(count > 0){
		current_block = 0;
		b_read_size = 0;
		check_next_block = false;
		in_frag = false;
		blk_act = filemirror_actual_blocknumber(scalpel_state.filemirror, blk_ap);
		if(debug) lock_fprintf(stdout, "----------------------------------------------\n");
		if(debug) lock_fprintf(stdout, "checking apparent block %"PRId64", actual block %"PRId64"...\n", blk_ap, blk_act);
		//was the block validated as an mp3 block
		if(filemirror_get_blocktype(scalpel_state.filemirror, blk_act, candidate->needleidx) == BLOCK_CONFIDENCE_VALID){
			check_next_block = true;
			if(debug) lock_fprintf(stdout, "first block %"PRId64" found to be valid\n", blk_act);
			goto check;
		}
		gen_block_hash_key(hashkey, candidate->needleidx, blk_act);
		blk_state = (Mp3BlockState *)block_get_state(hashkey);
		//was the block given a maybe state
		if(blk_state){ //if there is a state, must be a maybe block
			check_next_block = true;
			if(debug) lock_fprintf(stdout, "first block %"PRId64" found to be maybe\n", blk_act);
		}
		mp3_free_block_state((void **)&blk_state);
		check:
		if(check_next_block){
			in_frag = true;
			current_frag++;
			carve_state->fragments = add_fragment(carve_state->fragments, carve_state->num_frags);
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
			count--;
		}
		while(check_next_block){
			if(debug) lock_fprintf(stdout, "----------------------------------------------\n");
			if(debug) lock_fprintf(stdout, "checking next block...\n");
			check_next_block = false;
			//get block state of next block
			f_blk_act++;
			f_blk_ap = filemirror_apparent_blocknumber(scalpel_state.filemirror, f_blk_act);
			if(f_blk_ap == -1){
				break; //TODO: escape while loop
			}
			//was the block validated as an mp3 block
			if(filemirror_get_blocktype(scalpel_state.filemirror, f_blk_act, candidate->needleidx) == BLOCK_CONFIDENCE_VALID){
				check_next_block = true;
				if(debug) lock_fprintf(stdout, "next block %"PRId64" found to be valid\n", f_blk_act);
			}
			gen_block_hash_key(hashkey, candidate->needleidx, f_blk_act);
			f_blk_state = (Mp3BlockState *)block_get_state(hashkey);
			//was the block given a maybe state
			if(f_blk_state){ //if there is a state, must be a maybe block
				check_next_block = true;
				if(debug) lock_fprintf(stdout, "next block %"PRId64" found to be maybe\n", f_blk_act);
			}
			mp3_free_block_state((void **)&f_blk_state);
			//now we check if the offsets match (just run frag validate)
			if(check_next_block){
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
					count--;
				}
			}
			//if check_next_block isn't true, loop terminates
		}
		if(in_frag){
			if(current_fragment->size == 1){
				current_fragment->lastActBlock = current_fragment->firstActBlock;
			}
			if(debug) lock_fprintf(stdout, "apparent block: %"PRId64"->", f_blk_ap);
			f_blk_ap = filemirror_apparent_blocknumber(scalpel_state.filemirror, f_blk_act+1);
			blk_ap = blockvector_get_choice(candidate->b, blockvector_get_num_blocks(candidate->b)-1, f_blk_ap, count, &evaluated);
			if(debug) lock_fprintf(stdout, "%"PRId64"\n", blk_ap);
			if(debug) lock_fprintf(stdout, "count = %"PRId64"\n", count);
			count -= evaluated;
		}
		else{
			if(debug) lock_fprintf(stdout, "apparent block: %"PRId64"->", blk_ap);
			blk_ap = blockvector_get_choice(candidate->b, blockvector_get_num_blocks(candidate->b)-1, blk_ap+1, count, &evaluated);
			if(debug) lock_fprintf(stdout, "%"PRId64"\n", blk_ap);
			if(debug) lock_fprintf(stdout, "count = %"PRId64"\n", count);
			count -= evaluated;
		}
	}
	if(debug) lock_fprintf(stdout, "----------------------------------------------\n");
	#ifdef DEBUG_REASSEMBLY_FRAG
		lock_fprintf(stdout, "Getting peaks for each fragment\n");
	#endif
	for(int i = 0; i < carve_state->num_frags; i++){
		current_fragment = &carve_state->fragments[i];
		resize_blockvector(
			b_read,
			1
		);
		blockvector_set_apparent_blocknumber(b_read, 0, filemirror_apparent_blocknumber(scalpel_state.filemirror, current_fragment->lastActBlock));
		inflate_blockvector(b_read);
		#ifdef DEBUG_REASSEMBLY_FRAG
			lock_fprintf(stdout, "calling getPeaks\n");
		#endif
		if(getPeaks(blockvector_get_data_pointer(b_read) + (current_fragment->secondToLastFramePosition % (uint64_t) *blocksize),
			(current_fragment->offsetFramePosition - current_fragment->secondToLastFramePosition),
			current_fragment->peaks, false)){
			#ifdef DEBUG_REASSEMBLY_FRAG
				lock_fprintf(stdout, "getPeaks success\n");
			#endif
		}
		else{
			#ifdef DEBUG_REASSEMBLY_FRAG
				lock_fprintf(stdout, "getPeaks failed\n");
			#endif
		}
		deflate_blockvector(b_read);
	}
	carve_state->indexes = malloc(carve_state->num_frags * sizeof(uint16_t));
	carve_put_state(candidate->carvehashkey, carve_state);
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

static inline uint32_t mp3_block_validate(char* data,
	uint64_t length,
	BlockValidationDecision* decision,
	uint64_t* validates_to,
	uint32_t needleidx,
	uint32_t blocksize,
	void *blockhashkey) {


	bool debug = false;

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
		if(debug) lock_fprintf(stdout, "block header detected\n");
		*decision = BLOCK_CONFIDENCE_VALID;
		return needleidx;
	}

	if(maybe){
		goto make_maybe;
	}
	else if(va.validates){
		//final check (are we really sure it's audio?)
		mpg123_handle *mh;
		unsigned char *buffer = malloc(length - va.frontOffset);
		if(!buffer){
			*decision = BLOCK_CONFIDENCE_INVALID;
			return needleidx;
		}
		//unsigned char buffer[length-va.frontOffset];
		unsigned char *audio = &buffer[0];
		unsigned char *audio_tmp;
		memcpy(buffer, (unsigned char *)(data+va.frontOffset), length-va.frontOffset);
		size_t bytes = 0;
		off_t frame_number;
		int ret, err;
		bool errorOccurred = false; //we allow one error, due to bit reservoir
		bool invalidate = false; //if true, we invalidate

		Bitstream bs = {data, 0, va.frontOffset, length};
		uint8_t mpegVersion = 0;
		uint8_t layer = 0;
		bool crc;
		uint32_t bitrate = 0;
		uint16_t samplingrate = 0;
		enum _ChannelMode channel;
		uint8_t padding = 0;
		uint16_t frameLengthInBytes = 0;
		int audioPosCount = 0;
		int minDiff, maxDiff, avgDiff, count;
		uint8_t frame_num;
		uint8_t failures;

		mp3_ensure_init();
		pthread_mutex_lock(&mp3_handle_mutex);
		mh = mpg123_new(NULL, &err);
		pthread_mutex_unlock(&mp3_handle_mutex);
		mpg123_param(mh, MPG123_FLAGS, MPG123_QUIET, 0.0);
		mpg123_open_feed(mh);
		mpg123_feed(mh, buffer, length-va.frontOffset);
		mpg123_format(mh, 48000, MPG123_STEREO, MPG123_ENC_SIGNED_16);
		if(debug) lock_fprintf(stdout, "Checking audio...\n");
		frame_num = 0;
		failures = 0;
		while(1){
			if((uint64_t)(audioPosCount+va.frontOffset) >= va.offsetFramePosition){
				if(debug) lock_fprintf(stdout, "Finished reading block\n");
				break;
			}
			if(!getFrameData(&bs, &mpegVersion, &layer, &crc, &bitrate, &samplingrate, &padding, &channel, false)){
				break;
			}
			frameByteLengthCalc(layer, bitrate, samplingrate, padding, &frameLengthInBytes, false);
			ret = mpg123_decode_frame(mh, &frame_number, &audio, &bytes);
			if(ret == MPG123_NEW_FORMAT){
				if(debug) lock_fprintf(stdout, "New format detected\n");
				long rate;
				int channels, encoding;
				mpg123_getformat(mh, &rate, &channels, &encoding);
				//audio = &buffer[audioPosCount];
			}
			else if(ret == MPG123_DONE){
				if(debug) lock_fprintf(stdout, "Finished reading audio\n");
				break;
			}
			else if(ret < 0){ //if ret is some error
				if(ret == MPG123_NEED_MORE && !errorOccurred){ //specifically to do with bit reservoir
					if(debug) lock_fprintf(stdout, "MPG123_NEED_MORE\n");
					errorOccurred = true;
					audioPosCount += frameLengthInBytes;
				}
				else{ //generic error or double need more, invalidate
					if(debug) lock_fprintf(stdout, "Invalid mp3 frame\n");
					if(debug) lock_fprintf(stdout, "%s\n", mpg123_strerror(mh));
					invalidate = true;
					break;
				}
			}
			else{
				if(debug) lock_fprintf(stdout, "Frame OK\n");
				audio_tmp = audio;
				bool isNull = true;
				uint16_t *samples = (uint16_t*)malloc(bytes/2 * sizeof(uint16_t));
				//uint64_t avgStereoDeviation = 0;
				//uint64_t avgDifference = 0;
				if(channel != singleChannel){
					//2 channel
					count = 0;
					for(size_t i = 0; i < bytes; i+=2){
						int16_t sample;
						memcpy(&sample, &audio[i], sizeof(int16_t));
						samples[count] = sample;
						count++;
					}
					for(size_t i = 0; i < bytes/2; i++){
						if((uint8_t)samples[i] != 0){
							isNull = false;
							break;
						}
					}
					if(isNull){
						if(debug) lock_fprintf(stdout, "Decoding error, no data recovered, not valid frame or mp3 decoding failed.\n");
						failures++;
					}
					/*
					else{
						for(size_t i = 0; i < bytes/2-1; i+=2){
							avgStereoDeviation += abs(samples[i]-samples[i+1]);
						}
						avgStereoDeviation /= (bytes/4);
						for(size_t i = 0; i < bytes/2-2; i++){
							avgDifference += abs(samples[i]-samples[i+2]);
						}
						avgDifference /= (bytes/2-2);
						if(debug)lock_fprintf(stdout, "Stereo Deviation: %ld\nAvg Difference: %ld\n",avgStereoDeviation, avgDifference);
					}
					*/
				}
				else{
					count = 0;
					for(size_t i = 0; i < bytes; i+=2){
						samples[count] = (int16_t)((uint8_t)audio[i]|((int8_t)audio[i+1]<<8));
						count++;
					}
					for(size_t i = 0; i < bytes/2; i++){
						if((uint8_t)samples[i] != 0){
							isNull = false;
							break;
						}
					}
					if(isNull){
						if(debug) lock_fprintf(stdout, "Decoding error, no data recovered, not valid frame or mp3 decoding failed.\n");
						failures++;
					}
				}
				free(samples);
				audioPosCount += frameLengthInBytes;
				frame_num++;
				if(debug) lock_fprintf(stdout, "---\n");
			}
		}
		mpg123_close(mh);
		pthread_mutex_lock(&mp3_handle_mutex); mpg123_delete(mh); pthread_mutex_unlock(&mp3_handle_mutex);
		free(buffer);
		//mpg123_exit();

		if(debug) lock_fprintf(stdout, "Failures: %d\n", failures);
		if(debug) lock_fprintf(stdout, "--------------\n");

		if(invalidate){
			*decision = BLOCK_CONFIDENCE_INVALID;
		}
		else if(failures > DECODE_FAILURE_TOLERANCE || frame_num < MAYBE_FRAME_LIMIT){
			goto make_maybe;
		}
		else{
			*decision = BLOCK_CONFIDENCE_VALID;
		}
		//*decision = BLOCK_CONFIDENCE_VALID;
	}
	else{
		*decision = BLOCK_CONFIDENCE_INVALID;
	}
	return needleidx;

	make_maybe:
	state = (Mp3BlockState *)block_get_state(blockhashkey);
	if(!state){
		state = (Mp3BlockState *)calloc(1, sizeof *state);
		state->maybe = true; //block state existing at all also an indicator
		block_put_state(blockhashkey, state);
		if(debug)lock_fprintf(stdout, "MAYBE BLOCK DETECTED\n");
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
* detect ID3v2 headers, but will not detect ID3v1/APE headers/footers. That is work to be done in the future.
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
	bool debug = false;

	*validates = false;
	*maybe = false;

	*validates_to = 0;
	// is the block long enough to have a header of a MPEG frame?
	if (length >= FRAME_HEADER_SIZE) {

		// INITIALIZATION ----------------------------------------
		bool frameFound = false;
		bool first = true;
		int frameCounter = 0;

		uint16_t frameLengthInBytes = 0;
		uint8_t mpegVersion = 0;
		uint8_t layer = 0;
		bool crc;
		uint32_t bitrate = 0;
		uint16_t samplingrate = 0;
		enum _ChannelMode channel;
		uint8_t padding = 0;

		Bitstream bs = {data, 0, 0, length};

		uint8_t limit;
		uint16_t maxFrameSize = 1000;
		bool frameJump = false;

		*isHeader = false;
		*isTail = false;

		// Limit is used to determine how many frames should be expected
		// in a given MP3 block/fragment
		if(length < 1024){
			limit = 1;
		}
		else if(length < 20480){
			limit = length / 1000;
		}
		else{
			limit = 20;
		}

		if(skipID3v2(&bs)){
			if(debug) printf("ID3v2 header skipped\n");
			*isHeader = true;
		}

		//--------------------------------------------------------
		// SEARCH FOR MP3 FRAME ----------------------------------
		if (debug) {
			printf("Starting block validation:\n");
			printf("Search for MPEG frame 1:\n");
		}
		while ((uint64_t)bs.bytePos + 3 < length) {
			if(getFrameData(&bs, &mpegVersion, &layer, &crc, &bitrate, &samplingrate, &padding, &channel, debug)){
				if (mpegVersion == 0 || layer == 0 || bitrate == 0 || samplingrate == 0) {
					// If header found to be invalid (second check)
					if (debug) {
						printf("Header determined to not be valid after all\n");
						printf("Critical problem with getFrameData function.\n");
					}
				}
				else {
					if(debug) printf("MPEG frame %d potentially found\n", frameCounter+1);
					if(!frameByteLengthCalc(layer, bitrate, samplingrate, padding,
					&frameLengthInBytes, debug)){
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
					if(debug) printf("frameLengthInBytes = %d\n",frameLengthInBytes);
					//if(debug) printf("Checking bytes: %02x %02x %02x %02x\n", data[bs.bytePos-4],data[bs.bytePos-3],data[bs.bytePos-2],data[bs.bytePos-1]);
					if(debug) printf("MPEG frame seems valid, continuing on\n");
					*secondToLastFramePosition = *lastFramePosition;
					*lastFramePosition = *offsetFramePosition;
					*offsetFramePosition = bs.bytePos - 4;
					skipBits(&bs, frameLengthInBytes*8 - 32);
					frameCounter = frameCounter + 1;
					frameJump = true;
				}
			}
			else {
				if(areBytesNULL(data+bs.bytePos, length - bs.bytePos)){
					if(debug) printf("MPEG EOF detected\n");
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
					if(debug) printf("MPEG frame found to not actually be valid, rewinding bitstream\n");
					rewindBits(&bs, frameLengthInBytes*8 - 32);
					frameJump = false;
					first = true;
				}
				else{
					skipBits(&bs, 8);
					frameCounter = 0;
				}
			}
		}
		if(frameCounter >= limit){
			//printf("bs.bytePos = %d\n",bs.bytePos);
			//printf("length = %d\n",length);
			if((uint64_t)bs.bytePos == length){
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
			if(debug) printf("Not enough MPEG frames found\n");
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

		Bitstream bs = {data, 0, 0, length};
		if(skipID3v2(&bs)){
			#ifdef DEBUG_FILE_VALIDATE
				printf("ID3v2 header skipped\n");
			#endif
		}
		while(readBits(&bs, 8) == 0){
			#ifdef DEBUG_FILE_VALIDATE
				printf("Skipping NULL byte\n");
			#endif
		}
		rewindBits(&bs, 8);

		//--------------------------------------------------------
		// SEARCH FOR MP3 FRAME ----------------------------------
		#ifdef DEBUG_FILE_VALIDATE
			printf("Starting file validation:\n");
			printf("Search for MPEG frame 1:\n");
		#endif
		while ((uint64_t)bs.bytePos + 3 < length) {
			if(getFrameData(&bs, &mpegVersion, &layer, &crc, &bitrate, &samplingrate, &padding, &channel, debug)){
				#ifdef DEBUG_FILE_VALIDATE
					printf("MPEG frame %d potentially found\n", frameCounter+1);
				#endif
				if(!frameByteLengthCalc(layer, bitrate, samplingrate, padding,
				&frameLengthInBytes, debug)){
					printf("frameByteLengthCalc failed\n");
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
				uint64_t block_bound = 0;
				for(uint64_t i = 0; i <= length / blocksize; i++){
					if(i*blocksize > bs.bytePos){
						block_bound = i*blocksize;
						break;
					}
				}
				if((uint64_t)bs.bytePos == length || areBytesNULL(data+bs.bytePos, block_bound - bs.bytePos)){
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
		if((uint64_t)bs.bytePos == length){
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
	GetFrameArgs fa = get_frame_args();
	Bitstream bs = {data, 0, 0, offset + length};
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
			if(debug) lock_fprintf(stdout, "mp3_header_discovery: header found, returning %p\n", *matchpos);
			return NULL;
		}
		else if(getFrameData(&bs, &fa.mpegVersion, &fa.layer, &fa.crc, &fa.bitrate, &fa.samplingrate, &fa.padding, &fa.channel, false)){
			*matchpos = data + cur_block*blocksize;
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
	bool contiguous = false;

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
		//TODO: figure out what happens if there are no fragments
		//header frag is at least guaranteed
		//resize_blockvector(b, blockvector_get_num_blocks(b)+1);
		//blockvector_set_apparent_blocknumber(b, blockvector_get_num_blocks(b)-1, blockvector_get_apparent_blocknumber(b, blockvector_get_num_blocks(b)-2)+1);
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
			contiguous = true;
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
		#ifdef DEBUG_REASSEMBLY_THREAD
			lock_fprintf(stdout,
			"\nReassembly thread # %1d: Candidate with blockvector %p and UUIDs"
			"\n%s / %s\n carve_state fragments have been generated.\n",
			work->id, candidate->b, uuidp, uuidc);
		#endif
		display_blockvector(b, "blockvector");
	}
	else{
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
			contiguous = true;
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
		#ifdef DEBUG_REASSEMBLY_THREAD
			lock_fprintf(stdout,
			"\nReassembly thread # %1d: Candidate with blockvector %p and UUIDs"
			"\n%s / %s\n carve_state fragments have been checked and resolved\n",
			work->id, candidate->b, uuidp, uuidc);
		#endif
	}

	#ifdef DEBUG_REASSEMBLY_FRAG
		mp3_print_carve_state(carve_state);
	#endif

	lock_fprintf(stdout, "num_frags = %d\n", carve_state->num_frags);
	if(carve_state->num_frags == 1){
		goto done_promising_candidate;
	}

	//construction init
	int16_t bestIndex;
	uint8_t mpegVersion = 0;
	uint8_t layer = 0;
	bool crc;
	uint32_t bitrate = 0;
	uint16_t samplingrate = 0;
	enum _ChannelMode channel;
	uint8_t padding = 0;
	uint8_t protectedBytes;
	uint16_t frameLengthInBytes = 0;
	bool loop;
	Peak bestPeaks[6];
	Peak compPeaks[6];
	Peak tempPeaks[6];
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
	carve_state->fragments[carve_state->indexes[0]].active = false;
	loop = true;
	Bitstream bs = {blockvector_get_data_pointer(b), 0, 0, blockvector_get_data_length(b)};
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
		getFrameData(&bs, &mpegVersion, &layer, &crc, &bitrate, &samplingrate, &padding, &channel, false);
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
		#ifdef DEBUG_REASSEMBLY_CONST
			lock_fprintf(stdout, "%d\n", current_fragment->size*blocksize - current_fragment->offsetFramePosition+2);
		#endif
		if(crc && current_fragment->size*blocksize - current_fragment->offsetFramePosition+2 <= protectedBytes){
			//Reached if CRC is present and block boundary resides within protected bytes
			lock_fprintf(stdout, "Fragment %d found to reside on CRC boundary\n", carve_state->indexes[carve_state->cur_index - 1]);

			//How many possibilities? Generated for demonstration of usefulness
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
			//TODO: Optimization, no need to do CRC if there's only one solution

			frameByteLengthCalc(layer, bitrate, samplingrate, padding, &frameLengthInBytes, false);
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
					bs.data = blockvector_get_data_pointer(b_read) + current_fragment->offsetFramePosition;
					bs.bytePos = 4;
					bs.bitPos = 0;
					crc = check_crc(&bs, protectedBytes);
					deflate_blockvector(b_read);

					//if crc succeeds
					if(crc){
						#ifdef DEBUG_REASSEMBLY_CONST
							lock_fprintf(stdout, "CRC check succeeded on index %d\n\n",k);
						#endif
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
			//if CRC was not found, we can be confident that the next section of the file does not exist in the blockmap
			#ifdef DEBUG_REASSEMBLY_CONST
				lock_fprintf(stdout, "CRC not found, confident next section does not exist in file, validate\n\n");
			#endif
			free_blockvector(&b_read);
			goto done_validate_candidate;
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
				lock_fprintf(stdout, "Index %d has %d solutions, requires frequency analysis\n",carve_state->indexes[carve_state->cur_index - 1],count);
				guessProb = guessProb * count;
			}
			//TODO: Optimization: no need to do frequency analysis if there's only one solution

			for(int k = 0; k < carve_state->num_frags; k++){
				comp_fragment = &carve_state->fragments[k];
				if(k != carve_state->indexes[carve_state->cur_index - 1] &&
				comp_fragment->frontOffset == current_fragment->rearOffset &&
				comp_fragment->active == true){
				//if a fragment is found that has matching offsets and is active
					if(bestIndex == -1){
						//if a fragment hasn't been found yet, save as current solution
						#ifdef DEBUG_REASSEMBLY_CONST
							lock_fprintf(stdout, "carve_state->indexes[carve_state->cur_index - 1] = %d, k = %d\n", carve_state->indexes[carve_state->cur_index - 1], k);
						#endif
						bestIndex = k;
						best_comp_fragment = &carve_state->fragments[bestIndex];
						loop = true;
						for(int i = 0; i < 6; i++){
							bestPeaks[i].val = 0;
							bestPeaks[i].index = -1;
						}
						#ifdef DEBUG_REASSEMBLY_CONST
							lock_fprintf(stdout, "length: %d\n", ((current_fragment->size*blocksize - current_fragment->lastFramePosition) + best_comp_fragment->frontOffset));
							lock_fprintf(stdout, "index: %d\n", carve_state->indexes[carve_state->cur_index - 1]);
						#endif
						blockvector_set_apparent_blocknumber(b_read, 0, filemirror_apparent_blocknumber(scalpel_state.filemirror, current_fragment->lastActBlock));
						blockvector_set_apparent_blocknumber(b_read, 1, filemirror_apparent_blocknumber(scalpel_state.filemirror, best_comp_fragment->firstActBlock));
						inflate_blockvector(b_read);
						if(getPeaks(blockvector_get_data_pointer(b_read) + current_fragment->lastFramePosition % blocksize,
							((current_fragment->size*blocksize - current_fragment->lastFramePosition) + best_comp_fragment->frontOffset), bestPeaks, false)){
							#ifdef DEBUG_REASSEMBLY_CONST
								lock_fprintf(stdout, "getPeaks success\n");
							#endif
						}
						else{
							#ifdef DEBUG_REASSEMBLY_CONST
								lock_fprintf(stdout, "getPeaks failed\n");
							#endif
						}
						deflate_blockvector(b_read);
						#ifdef DEBUG_REASSEMBLY_CONST
							lock_fprintf(stdout, "-----------------\nbestPeaks:\n");
							for(size_t i = 0; i < 5; i++){
								lock_fprintf(stdout, "Value: %.2f, Index: %d\n",bestPeaks[i].val,bestPeaks[i].index);
							}
							lock_fprintf(stdout, "-----------------\n\n");
						#endif
					}
					else{ //if a fragment has already been found, they must fight to the death
						#ifdef DEBUG_REASSEMBLY_CONST
							lock_fprintf(stdout, "comparison happening: bestIndex = %d vs k = %d\n", bestIndex, k);
						#endif
						for(int i = 0; i < 6; i++){
							compPeaks[i].val = 0;
							compPeaks[i].index = -1;
						}
						//lock_fprintf(stdout, "length: %d\n", ((current_fragment->size*blocksize - current_fragment->lastFramePosition) + comp_fragment->frontOffset));
						//lock_fprintf(stdout, "index: %d\n", carve_state->indexes[carve_state->cur_index - 1]);
						blockvector_set_apparent_blocknumber(b_read, 0, filemirror_apparent_blocknumber(scalpel_state.filemirror, current_fragment->lastActBlock));
						blockvector_set_apparent_blocknumber(b_read, 1, filemirror_apparent_blocknumber(scalpel_state.filemirror, comp_fragment->firstActBlock));
						inflate_blockvector(b_read);
						//display_blockvector(b_read, "test");
						if(getPeaks(blockvector_get_data_pointer(b_read) + current_fragment->lastFramePosition % blocksize,
							((current_fragment->size*blocksize - current_fragment->lastFramePosition) + comp_fragment->frontOffset), compPeaks, false)){
							#ifdef DEBUG_REASSEMBLY_CONST
								lock_fprintf(stdout, "getPeaks success\n");
							#endif
						}
						else{
							#ifdef DEBUG_REASSEMBLY_CONST
								lock_fprintf(stdout, "getPeaks failed\n");
							#endif
						}
						deflate_blockvector(b_read);

						//make decision here
						score = 0;

						//first check if peaks are identical (or near identical)
						for(int peakIndex1 = 0; peakIndex1 < 5; peakIndex1++){
							for(int peakIndex2 = 0; peakIndex2 < 5; peakIndex2++){
								if(compPeaks[peakIndex1].index < bestPeaks[peakIndex2].index+2 &&
								compPeaks[peakIndex1].index > bestPeaks[peakIndex2].index-2){
									score++;
								}
							}
						}
						if(score == 5){ //means peaks are nearly identical, change frames being compared
							#ifdef DEBUG_REASSEMBLY_CONST
								lock_fprintf(stdout, "peaks found to be (near) identical, doing analysis on next frame\n");
							#endif
							for(int i = 0; i < 6; i++){
								tempPeaks[i].val = 0;
								tempPeaks[i].index = -1;
							}
							for(int i = 0; i < 5; i++){
								tempPeaks[i].val = bestPeaks[i].val;
								tempPeaks[i].index = bestPeaks[i].index;
							}
							//need to get size of first frame of each fragment...
							//getting it for first fragment
							resize_blockvector(
								b_read,
								1
							);
							blockvector_set_apparent_blocknumber(b_read, 0, filemirror_apparent_blocknumber(scalpel_state.filemirror, best_comp_fragment->firstActBlock));
							inflate_blockvector(b_read);
							bs.data = blockvector_get_data_pointer(b_read);
							bs.bytePos = best_comp_fragment->frontOffset;
							bs.bitPos = 0;
							//TODO: error handling
							getFrameData(&bs, &mpegVersion, &layer, &crc, &bitrate, &samplingrate, &padding, &channel, false);
							frameByteLengthCalc(layer, bitrate, samplingrate, padding, &frameLengthInBytes, false);
							resize_blockvector(
								b_read,
								2
							);
							blockvector_set_apparent_blocknumber(b_read, 0, filemirror_apparent_blocknumber(scalpel_state.filemirror, current_fragment->lastActBlock));
							blockvector_set_apparent_blocknumber(b_read, 1, filemirror_apparent_blocknumber(scalpel_state.filemirror, best_comp_fragment->firstActBlock));
							inflate_blockvector(b_read);
							if(getPeaks(blockvector_get_data_pointer(b_read) + current_fragment->offsetFramePosition % blocksize,
								(current_fragment->size*blocksize - current_fragment->offsetFramePosition + best_comp_fragment->frontOffset + frameLengthInBytes),
								bestPeaks, false)){
								#ifdef DEBUG_REASSEMBLY_CONST
									lock_fprintf(stdout, "getPeaks success\n");
								#endif
							}
							else{
								#ifdef DEBUG_REASSEMBLY_CONST
									lock_fprintf(stdout, "getPeaks failed\n");
								#endif
							}
							deflate_blockvector(b_read);

							//get it for second fragment
							bs.bytePos = comp_fragment->frontOffset;
							bs.bitPos = 0;
							//TODO: error handling
							getFrameData(&bs, &mpegVersion, &layer, &crc, &bitrate, &samplingrate, &padding, &channel, false);
							//deflate_blockvector(carve_state->fragments[k].b);
							frameByteLengthCalc(layer, bitrate, samplingrate, padding, &frameLengthInBytes, false);
							blockvector_set_apparent_blocknumber(b_read, 0, filemirror_apparent_blocknumber(scalpel_state.filemirror, current_fragment->lastActBlock));
							blockvector_set_apparent_blocknumber(b_read, 1, filemirror_apparent_blocknumber(scalpel_state.filemirror, comp_fragment->firstActBlock));
							inflate_blockvector(b_read);
							if(getPeaks(blockvector_get_data_pointer(b_read) + current_fragment->offsetFramePosition % blocksize,
								(current_fragment->size*blocksize - current_fragment->offsetFramePosition + comp_fragment->frontOffset + frameLengthInBytes),
								compPeaks, false)){
								#ifdef DEBUG_REASSEMBLY_CONST
									lock_fprintf(stdout, "getPeaks success\n");
								#endif
							}
							else{
								#ifdef DEBUG_REASSEMBLY_CONST
									lock_fprintf(stdout, "getPeaks failed\n");
								#endif
							}
							deflate_blockvector(b_read);

							score1 = getScore(tempPeaks, bestPeaks);
							score2 = getScore(tempPeaks, compPeaks);

							#ifdef DEBUG_REASSEMBLY_CONST
								lock_fprintf(stdout, "tempPeaks:\n",carve_state->indexes[carve_state->cur_index - 1]);
								for(size_t i = 0; i < 5; i++){
									lock_fprintf(stdout, "Value: %.2f, Index: %d\n",tempPeaks[i].val,tempPeaks[i].index);
								}
								printf("-----------------\nbestPeaks:\n");
								for(size_t i = 0; i < 5; i++){
									lock_fprintf(stdout, "Value: %.2f, Index: %d\n",bestPeaks[i].val,bestPeaks[i].index);
								}
								printf("-----------------\ncompPeaks:\n");
								for(size_t i = 0; i < 5; i++){
									lock_fprintf(stdout, "Value: %.2f, Index: %d\n",compPeaks[i].val,compPeaks[i].index);
								}
								lock_fprintf(stdout, "-----------------\n");
							#endif

							for(int i = 0; i < 5; i++){
								bestPeaks[i].val = tempPeaks[i].val;
								bestPeaks[i].index = tempPeaks[i].index;
							}
						}
						else{
							score1 = getScore(current_fragment->peaks,bestPeaks);
							score2 = getScore(current_fragment->peaks,compPeaks);
							#ifdef DEBUG_REASSEMBLY_CONST
								lock_fprintf(stdout, "peaks for index %d:\n",carve_state->indexes[carve_state->cur_index - 1]);
								for(size_t i = 0; i < 5; i++){
									lock_fprintf(stdout, "Value: %.2f, Index: %d\n",current_fragment->peaks[i].val,current_fragment->peaks[i].index);
								}
								lock_fprintf(stdout, "-----------------\nbestPeaks:\n");
								for(size_t i = 0; i < 5; i++){
									lock_fprintf(stdout, "Value: %.2f, Index: %d\n",bestPeaks[i].val,bestPeaks[i].index);
								}
								lock_fprintf(stdout, "-----------------\ncompPeaks:\n");
								for(size_t i = 0; i < 5; i++){
									lock_fprintf(stdout, "Value: %.2f, Index: %d\n",compPeaks[i].val,compPeaks[i].index);
								}
								lock_fprintf(stdout, "-----------------\n");
							#endif
						}
						#ifdef DEBUG_REASSEMBLY_CONST
							lock_fprintf(stdout, "score1 = %f, score2 = %f\n",score1,score2);
						#endif
						if(score2>score1){
							#ifdef DEBUG_REASSEMBLY_CONST
								lock_fprintf(stdout, "competitor won, bestIndex updated\n");
							#endif
							bestIndex = k;
							best_comp_fragment = &carve_state->fragments[bestIndex];
							for(size_t i = 0; i < 5; i++){
								bestPeaks[i].val = compPeaks[i].val;
								bestPeaks[i].index = compPeaks[i].index;
							}
							bestPeaks[5].val = 0;
							bestPeaks[5].index = -1;
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
				free_blockvector(&b_read);
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
		lock_fprintf(stdout, "carve_state->cur_index = %d\n", carve_state->cur_index);
		current_fragment = &(carve_state->fragments[carve_state->indexes[carve_state->cur_index - 1]]);
		prev_num_blocks = blockvector_get_num_blocks(candidate->b);
		lock_fprintf(stdout,"current_fragment->size = %zu\n",current_fragment->size);
		resize_blockvector(candidate->b, blockvector_get_num_blocks(candidate->b) + current_fragment->size);
		count = 0;
		for(int64_t i = current_fragment->firstActBlock; i <= current_fragment->lastActBlock; i++){
			blockvector_set_apparent_blocknumber(candidate->b, prev_num_blocks+count, filemirror_apparent_blocknumber(scalpel_state.filemirror, i));
			count++;
		}
		display_blockvector(b, "blockvector");
		deflate_blockvector(b);
		//atomic_store_explicit(&TAKE_CHECKPOINT, true, memory_order_release);
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
	free_blockvector(&b_read);
	done_validate_candidate:
	candidate->flavor = VALIDATED;
	if(contiguous || carve_state->fragments[carve_state->indexes[carve_state->cur_index-1]].isTail){
		// get rid of padding for completed candidate
		mp3_file_validate(blockvector_get_data_pointer(b),
			blockvector_get_data_length(b),
			&va.validates,
			&va.validates_to,
			&va.promising,
			va.needleidx,
			blockvector_get_data_length(b) / blockvector_get_num_blocks(b),
			NULL);
		//lock_fprintf(stdout, "validates_to: %d\n", va.validates_to+1);
		blockvector_set_data_length(b, va.validates_to+1);
		// added +1 because for some reason in reassembly, validates_to is always off by 1
	}
	#ifdef DEBUG_REASSEMBLY_THREAD
		lock_fprintf(stdout,
		"\nReassembly thread # %1d: Candidate with blockvector %p and UUIDs"
		"\n%s / %s\n will be written\n",
		work->id, candidate->b, uuidp, uuidc);
	#endif
	/*
	for(uint64_t i = 0; i < blockvector_get_num_blocks(b); i++){
		cover_block(scalpel_state.filemirror->shadow_blockmap, blockvector_get_actual_blocknumber(b, i));
	}
	*/
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
	write_candidate(c, false);
}

#pragma GCC diagnostic pop
