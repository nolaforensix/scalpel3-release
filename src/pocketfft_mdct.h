#ifndef POCKETFFT_MDCT_H
#define POCKETFFT_MDCT_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct pfft_mdctf_plan pfft_mdctf_plan;

/* MDCT plan object (opaque to C users) */

//typedef struct {
//    int     N;          /* number of time-domain samples (must be a multiple of 4) */
//    float   *twiddle;   /* interleaved cos/sin twiddle factors */
//    void    *fft_in;    /* opaque pointer to C++ std::complex<float> buffer */
//    void    *fft_out;   /* opaque pointer to C++ std::complex<float> buffer */
//} pfft_mdctf_plan;

pfft_mdctf_plan* pfft_mdctf_init(int N);
void pfft_mdctf_free(pfft_mdctf_plan* m_plan);
void pfft_mdctf(float* mdct_line, float* time_signal, pfft_mdctf_plan* m_plan);

#ifdef __cplusplus
}
#endif

#endif