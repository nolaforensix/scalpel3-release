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
// MDCT transform logic adapted from Shuhua Zhang's
// "MDCT and IMDCT based on FFTW3" implementation:
// https://www.musicdsp.org/en/latest/Filters/270-mdct-and-imdct-based-on-fftw3.html
//
// Adapted for PocketFFT and integrated into Scalpel3 by George Hendrick.
//
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
