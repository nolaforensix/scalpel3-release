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
// MDCT transform logic adapted from Shuhua Zhang's
// "MDCT and IMDCT based on FFTW3" implementation:
// https://www.musicdsp.org/en/latest/Filters/270-mdct-and-imdct-based-on-fftw3.html
//
// Adapted for PocketFFT and integrated into Scalpel3 by George Hendrick.
//
#include "pocketfft_mdct.h"
#include "pocketfft_hdronly.h"
#include <vector>
#include <complex>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <algorithm>

extern "C"{
    // keep similar struct name and prototypes to previous mdctf_plan
    struct pfft_mdctf_plan{
        int             N;              // number of time data points
        float*          twiddle;        // twiddle factor (interleaved cos, sin)
        std::complex<float>* fft_in;    // fft workspace, input (N/4 complex)
        std::complex<float>* fft_out;   // fft workspace, output (N/4 complex)
    };
}

// Implementation
using namespace pocketfft;

pfft_mdctf_plan* pfft_mdctf_init(int N){
    if(0x00 != (N & 0x03)){
        fprintf(stderr, "pfft_mdctf_init: Expecting N a multiple of 4\n");
        return NULL;
    }
    pfft_mdctf_plan* m_plan = (pfft_mdctf_plan*) malloc(sizeof(pfft_mdctf_plan));
    if(!m_plan) return NULL;
    m_plan->N = N;

    // twiddle storage: we need 2*(N/4) floats (cos/sin per index n = 0 ... (N/4 - 1))
    size_t n_twiddle = (size_t) (N >> 1); // N/2 floats (interleaved)
    m_plan->twiddle = (float*) malloc(sizeof(float) * n_twiddle);
    if(!m_plan->twiddle) { free(m_plan); return NULL; }

    double alpha = 2.0 * M_PI / (8.0 * N);
    double omiga = 2.0 * M_PI / N;
    double scale = std::sqrt(std::sqrt(2.0f / (double)N));
    int N4 = N >> 2;
    for(int n = 0; n < N4; ++n){
        double arg = omiga * n + alpha;
        m_plan->twiddle[2*n + 0] = (float) (scale * std::cos(arg));
        m_plan->twiddle[2*n + 1] = (float) (scale * std::sin(arg));
    }

    // allocate fft buffers (N/4 complex)
    m_plan->fft_in = (std::complex<float>*) malloc(sizeof(std::complex<float>) * (N >> 2));
    m_plan->fft_out = (std::complex<float>*) malloc(sizeof(std::complex<float>) * (N >> 2));
    if(!m_plan->fft_in || !m_plan->fft_out){
        free(m_plan->twiddle);
        free(m_plan->fft_in);
        free(m_plan->fft_out);
        free(m_plan);
        return NULL;
    }

    // zero buffers to be safe
    std::memset(m_plan->fft_in, 0, sizeof(std::complex<float>) * (N >> 2));
    std::memset(m_plan->fft_out, 0, sizeof(std::complex<float>) * (N >> 2));
    return m_plan;
}

void pfft_mdctf_free(pfft_mdctf_plan* m_plan){
    if(!m_plan) return;
    free(m_plan->twiddle);
    free(m_plan->fft_in);
    free(m_plan->fft_out);
    free(m_plan);
}

void pfft_mdctf(float* mdct_line, float* time_signal, pfft_mdctf_plan* m_plan){
    if(!m_plan || !mdct_line || !time_signal) return;
    int N = m_plan->N;
    int N4 = N >> 2;
    int N2 = 2 * N4;
    int N34 = 3 * N4;
    int N54 = 5 * N4;
    float* cos_tw = m_plan->twiddle;
    float* sin_tw = cos_tw + 1;

    // filling interleaved complex input buffer
    std::complex<float>* in = m_plan->fft_in;
    std::complex<float>* out = m_plan->fft_out;

    // pre-twiddle & folding: first loop (n from 0 to N4-1 stepping by 2)
    int n = 0;
    for(; n < N4; n+=2){
        float r0 = time_signal[N34 - 1 - n] + time_signal[N34 + n];
        float i0 = time_signal[N4 + n] - time_signal[N4 - 1 - n];
        float c = cos_tw[n]; // note: n is even, cos_tw stores interleaved values
        float s = sin_tw[n];
        int idx = n / 2;
        in[idx].real(r0 * c + i0 * s);
        in[idx].imag(i0 * c - r0 * s);
    }

    // second loop range (n from previous value to N2-1 stepping by 2)
    for(; n < N2; n += 2){
        float r0 = time_signal[N34 - 1 - n] - time_signal[-N4 + n];
        float i0 = time_signal[N4 + n] + time_signal[N54 - 1 - n];
        float c = cos_tw[n];
        float s = sin_tw[n];
        int idx = n / 2;
        in[idx].real(r0 * c + i0 * s);
        in[idx].imag(i0 * c - r0 * s);
    }

    // now perform complex fft of length N/4 using PocketFFT (forward)
    std::vector<size_t> shape = {(size_t)(N >> 2)};
    // stride for complex elements in bytes (contiguous)
    std::vector<std::ptrdiff_t> stride = {(std::ptrdiff_t) sizeof(std::complex<float>)};
    std::vector<size_t> axes = { 0 };

    // call pocketfft c2c: forward transform
    pocketfft::c2c<float>(shape, stride, stride, axes, true, in, out, 1.0f, 1);

    // post-twiddle
    for(int nn = 0; nn < N2; nn += 2){
        int idx = nn / 2;
        float r0 = out[idx].real();
        float i0 = out[idx].imag();
        float c = cos_tw[nn];
        float s = sin_tw[nn];
        mdct_line[nn] = - r0 * c - i0 * s;
        mdct_line[N2 - 1 - nn] = - r0 * s + i0 * c;
    }
}
