// elf_seg_onnx.cpp
//
// C++ ONNX inference + shape-based post-processing for 4KB ELF-block segmentation.
//
// This version assumes PostProcParams is declared in elf_seg_onnx.hpp
// and provides:
//   - tuned defaults (via PostProcParams default field initializers),
//   - runtime override via ElfSegmentationModelONNX::set_postproc_params().
//
// Build (example):
//   g++ -O3 -march=native -DNDEBUG -std=c++17 elf_seg_onnx.cpp -lonnxruntime -o elf_seg_onnx_test
//

#include "elf_onnx.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <stdexcept>
#include <cstring>
#include <set>
#include <string>
#include <array>
#include <condition_variable>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <filesystem>
#include <new>
#include <system_error>

#include <onnxruntime_cxx_api.h>

#include "onnx_cuda_options.h"
#include "onnx_providers.h"


// Internal C++ declarations.  The public Scalpel-facing API is elf_onnx.h.
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

enum class DecodeMode { RAW_ARGMAX = 0, HEAVY_POSTPROCESS = 1 };

struct RegionTriplet {
  int32_t cls;
  int32_t offset;
  int32_t size;
};

struct InferMaps {
  int32_t num_classes = 0;                 // C
  std::vector<int16_t> raw_mask;           // 4096, class IDs
  std::vector<int16_t> post_mask;          // 4096, class IDs
  std::vector<RegionTriplet> triplets;     // RLE of post_mask
};

// Centralized post-processing parameters (defaults are your tuned "best" set).
// You can override these via ElfSegmentationModelONNX::set_postproc_params().
struct PostProcParams {
  // --- Grid-search tuned knobs (current best)
  double nz_thresh        = 0.425; // allow_extension gate: global_nonzero_fraction >= nz_thresh
  int    sparse_min_width = 40;    // sparse blocks: require bbox width >= this (and touch edges)
  int    edge_tolerance   = 3;     // sparse blocks: how close counts as touching edges
  double min_fill_ratio   = 0.55;  // delete regions with area/bbox_area below this
  double max_aspect_ratio = 1.3;   // delete regions with (bbox_h/bbox_w) > this
  int    ext_min_width    = 48;    // only extend regions with bbox_w >= this (in dense blocks)

  // --- Additional knobs for ablations / future tuning
  int    min_bbox_width   = 4;

  // remove_small_elf_blobs thresholds
  int    rsb_min_bbox_height = 2;
  int    rsb_max_bbox_width  = 32;
  int    rsb_narrow_width    = 15;
  int    rsb_narrow_min_h    = 2;

  // extend_section behavior
  double extend_core_row_width_ratio = 0.7;
  int    extend_min_core_rows        = 3;

  // handle_nonelf_holes thresholds
  int    holes_min_bbox_height     = 4;
  int    holes_bbox_width_thresh   = 32;

  // remove_irregular_sections thresholds
  double irregular_zero_threshold = 0.35;
  int    irregular_min_height     = 15;

  // remove_noisy_regions thresholds
  int    noisy_max_embedded_regions    = 10;
  double noisy_max_embedded_area_ratio = 0.3;

  // Minimum width (in pixels) for a 1-row stripe to be preserved in sparse mode.
  int  sparse_thin_stripe_min_width = 16;

  //helps retain tail-ends of sections (extremely important for context)
  int    tail_max_height         = 8;    
  int    tail_min_area           = 80;    // reject tiny specks
  bool   tail_require_attachment = false;  // require interior attachment
  int    tail_attach_rows        = 2;     // how far inward to probe
  int    tail_attach_min_pixels  = 12;    // minimum same-class pixels in probe rows
  int tail_min_width = 16;
  double tail_min_fill_ratio = 0.40;
  int tail_interior_min_pixels = 6; 
  int tail_interior_min_span = 8; 

  // Stage toggles (for ablations)
  bool enable_sparse_thin_stripe_keepalive = true;
  bool enable_remove_noisy_regions      = true;
  bool enable_handle_nonelf_holes       = true; // runs only when allow_extension is true
  bool enable_remove_irregular_sections = true;
  bool enable_sparse_island_killer      = true; // runs only when !allow_extension
  bool enable_extend                   = true;  // runs only when allow_extension is true
  bool enable_remove_small_elf_blobs = true;
  bool enable_min_bbox_width_check   = true;
  bool enable_fill_ratio_check       = true;
  bool enable_aspect_ratio_check     = true;
};

class ElfSegmentationModelONNX {
public:
  ElfSegmentationModelONNX(const std::string& model_path,
                           int intra_op_threads = 1,
                           int inter_op_threads = 1,
                           const std::string& input_name = "x",
                           const std::string& out_bin_name = "out_bin",
                           const std::string& out_multi_name = "out_multi",
                           const std::string& accelerator = "cpu",
                           int max_batch = 1,
                           int device_id = 0);

  // Existing API (postprocessed triplets only)
  std::vector<RegionTriplet> infer(const uint8_t* blob, size_t nbytes) noexcept;

  // Batched API: 'blobs' is n consecutive 4096-byte chunks; out[i] receives chunk i's
  // postprocessed triplets. Chunks are run through the model max_batch samples per
  // ONNX Run (a static-batch provider pads the final partial Run); argmax, postprocess,
  // and RLE happen per sample exactly as in infer(). Returns false on inference failure.
  bool infer_batch(const uint8_t* blobs, size_t n,
                   std::vector<std::vector<RegionTriplet>>& out) noexcept;

  int last_status() const noexcept;

  int max_batch() const noexcept;

  // New API for testing/visualization
  InferMaps infer_maps(const uint8_t* blob, size_t nbytes) noexcept;

  // Runtime override for ablations / integration.
  // Call once after construction (or anytime) to swap the postproc parameter set.
  void set_postproc_params(const PostProcParams& params) noexcept;

  PostProcParams get_postproc_params() const noexcept;

  void set_decode_mode(DecodeMode mode) noexcept;
  DecodeMode get_decode_mode() const noexcept;
  void set_decode_threads(int threads) noexcept;

  // request termination of any in-flight (and all future) Runs on this handle;
  // safe to call from another thread
  bool terminate_runs() noexcept;

  void reset_timing() noexcept;
  bool write_timing_report(const char* path) const noexcept;

  ~ElfSegmentationModelONNX();

private:
  struct Impl;
  Impl* pimpl_;
};
namespace {

static constexpr int EXPECTED_BYTES = 4096;
static constexpr int H = 64;
static constexpr int W = 64;
static constexpr int ELF_NUM_CLASSES = 14;

inline int idx(int r, int c, int w = W) { return r * w + c; }

// ----------------------------
// Region struct (like skimage regionprops)
// ----------------------------
struct Region {
  int minr = 0, minc = 0, maxr = 0, maxc = 0; // bbox is [minr,maxr) x [minc,maxc)
  int area = 0;
  std::vector<std::pair<int,int>> coords;     // (r,c) coords in the mask used for labeling
};

// Connected-components labeling for a boolean mask (true = foreground).
// conn8 = true -> 8-connected, else 4-connected.
// Returns regions with bbox + coords.
// Coordinates are relative to the mask coordinate system you pass in.
static std::vector<Region> label_bool_mask(const std::vector<uint8_t>& fg,
                                          int h, int w, bool conn8)
{
  std::vector<Region> regions;
  std::vector<uint8_t> visited((size_t)h*w, 0);

  const int dr4[4] = {-1, 1, 0, 0};
  const int dc4[4] = {0, 0, -1, 1};
  const int dr8[8] = {-1,-1,-1, 0, 0, 1, 1, 1};
  const int dc8[8] = {-1, 0, 1,-1, 1,-1, 0, 1};

  for (int r = 0; r < h; r++) {
    for (int c = 0; c < w; c++) {
      const int id = idx(r,c,w);
      if (!fg[id] || visited[id]) continue;

      Region reg;
      reg.minr = r; reg.maxr = r+1;
      reg.minc = c; reg.maxc = c+1;

      // simple queue (vector as FIFO)
      std::vector<std::pair<int,int>> q;
      q.reserve(256);
      q.push_back({r,c});
      visited[id] = 1;

      for (size_t qi = 0; qi < q.size(); qi++) {
        auto [cr, cc] = q[qi];
        reg.coords.push_back({cr,cc});
        reg.area++;

        reg.minr = std::min(reg.minr, cr);
        reg.minc = std::min(reg.minc, cc);
        reg.maxr = std::max(reg.maxr, cr+1);
        reg.maxc = std::max(reg.maxc, cc+1);

        if (conn8) {
          for (int k = 0; k < 8; k++) {
            int nr = cr + dr8[k], nc = cc + dc8[k];
            if ((unsigned)nr >= (unsigned)h || (unsigned)nc >= (unsigned)w) continue;
            int nid = idx(nr,nc,w);
            if (fg[nid] && !visited[nid]) {
              visited[nid] = 1;
              q.push_back({nr,nc});
            }
          }
        } else {
          for (int k = 0; k < 4; k++) {
            int nr = cr + dr4[k], nc = cc + dc4[k];
            if ((unsigned)nr >= (unsigned)h || (unsigned)nc >= (unsigned)w) continue;
            int nid = idx(nr,nc,w);
            if (fg[nid] && !visited[nid]) {
              visited[nid] = 1;
              q.push_back({nr,nc});
            }
          }
        }
      }

      regions.push_back(std::move(reg));
    }
  }
  return regions;
}

static std::vector<int16_t> unique_sorted_classes(const std::vector<int16_t>& mask)
{
  std::set<int16_t> s(mask.begin(), mask.end());
  return std::vector<int16_t>(s.begin(), s.end());
}

// ----------------------------
// Post-processing helpers
// ----------------------------

static double global_nonzero_fraction(const std::vector<int16_t>& mask)
{
  int nonzero = 0;
  for (int v : mask) {
    if (v != 0) nonzero++;
  }
  return (double)nonzero / (double)(H * W);
}

static bool remove_small_elf_blobs(std::vector<int16_t>& out_mask,
                                  const Region& region,
                                  const PostProcParams& P)
{
  const int bbox_height = region.maxr - region.minr;
  const int bbox_width  = region.maxc - region.minc;

  const bool touches_top = (region.minr <= P.edge_tolerance);
  const bool touches_bot = ((H - region.maxr) <= P.edge_tolerance);

  if (!touches_top && !touches_bot) {
    if (bbox_height >= P.rsb_min_bbox_height && bbox_width <= P.rsb_max_bbox_width) {
      std::unordered_set<int> regset;
      regset.reserve(region.coords.size() * 2);
      for (auto [r,c] : region.coords) regset.insert(idx(r,c));

      bool is_surrounded_by_nonelf = true;
      for (auto [r,c] : region.coords) {
        const int dr[4] = {-1, 1, 0, 0};
        const int dc[4] = {0, 0, -1, 1};
        for (int k = 0; k < 4; k++) {
          int nr = r + dr[k], nc = c + dc[k];
          if ((unsigned)nr >= (unsigned)H || (unsigned)nc >= (unsigned)W) continue;
          int nid = idx(nr,nc);
          if (regset.find(nid) != regset.end()) continue;
          if (out_mask[nid] != 0) {
            is_surrounded_by_nonelf = false;
            break;
          }
        }
        if (!is_surrounded_by_nonelf) break;
      }

      if (is_surrounded_by_nonelf) {
        for (auto [r,c] : region.coords) out_mask[idx(r,c)] = 0;
        return true;
      }
    }

    if (bbox_width < P.rsb_narrow_width && bbox_height >= P.rsb_narrow_min_h) {
      for (auto [r,c] : region.coords) out_mask[idx(r,c)] = 0;
      return true;
    }
  }

  return false;
}


static void extend_section(std::vector<int16_t>& out_mask,
                           const Region& region,
                           int16_t fill_class,
                           const PostProcParams& P)
{
  std::vector<std::vector<int>> row_cols(H);
  int min_row = H;
  int max_row = -1;

  for (auto [r, c] : region.coords) {
    if ((unsigned)r >= (unsigned)H || (unsigned)c >= (unsigned)W) continue;
    row_cols[r].push_back(c);
    if (r < min_row) min_row = r;
    if (r > max_row) max_row = r;
  }

  if (max_row < 0) return;
  if ((int)region.coords.size() < 2) return;

  std::vector<int> row_width(H, 0);
  int max_width = 0;
  for (int r = min_row; r <= max_row; ++r) {
    auto &cols = row_cols[r];
    if (cols.empty()) continue;
    auto mm = std::minmax_element(cols.begin(), cols.end());
    int w = (*mm.second - *mm.first) + 1;
    row_width[r] = w;
    if (w > max_width) max_width = w;
  }

  if (max_width <= 0) return;

  const int width_thresh =
    std::max(1, (int)std::floor(P.extend_core_row_width_ratio * (double)max_width));

  int core_min_row = -1;
  int core_max_row = -1;
  int core_count   = 0;
  for (int r = min_row; r <= max_row; ++r) {
    if (row_width[r] >= width_thresh) {
      if (core_min_row == -1) core_min_row = r;
      core_max_row = r;
      core_count++;
    }
  }

  if (core_count < P.extend_min_core_rows) return;

  // drop splatter rows outside core band
  for (int r = min_row; r < core_min_row; ++r) {
    for (int c : row_cols[r]) out_mask[idx(r, c)] = 0;
  }
  for (int r = core_max_row + 1; r <= max_row; ++r) {
    for (int c : row_cols[r]) out_mask[idx(r, c)] = 0;
  }

  // extend within the core band
  for (int r = core_min_row; r <= core_max_row; ++r) {
    auto &cols = row_cols[r];
    if (cols.empty()) continue;

    auto mm = std::minmax_element(cols.begin(), cols.end());
    int start_col = *mm.first;
    int end_col   = *mm.second;

    if (r == core_min_row) {
      for (int c = start_col; c < W; ++c) out_mask[idx(r, c)] = fill_class;
    } else if (r == core_max_row) {
      for (int c = 0; c <= end_col; ++c) out_mask[idx(r, c)] = fill_class;
    } else {
      for (int c = 0; c < W; ++c) out_mask[idx(r, c)] = fill_class;
    }
  }
}


static inline bool is_sparse_stripe_region(const Region& region, const PostProcParams& P)
{
  const int bh = region.maxr - region.minr;
  const int bw = region.maxc - region.minc;

  if (bh != 1) return false;  // strictly single-row
  if (bw < P.sparse_thin_stripe_min_width) return false;

  // Optional safety: require it to be fairly contiguous within its bbox
  // (for a 1-row bbox, fill_ratio == area/bw). This rejects scattered pixels.
  const double fill = (bw > 0) ? ((double)region.area / (double)bw) : 0.0;
  if (fill < 0.60) return false;

  return true;
}


static inline bool is_sparse_edge_band_region(const Region& reg, const PostProcParams& P)
{
  const int bh = reg.maxr - reg.minr;
  const int bw = reg.maxc - reg.minc;
  if (bh < 2 || bh > 3) return false;                 // target 2-3 row tails/heads
  if (bw < P.sparse_min_width) return false;          // wide enough to matter

  const bool left  = (reg.minc <= P.edge_tolerance);
  const bool right = ((W - reg.maxc) <= P.edge_tolerance);
  if (!left || !right) return false;                  // must span the block width (within tolerance)

  // must be near the top or bottom edge of the 64x64 mask
  const bool top_edge = (reg.minr <= P.edge_tolerance);
  const bool bot_edge = ((H - reg.maxr) <= P.edge_tolerance);
  if (!top_edge && !bot_edge) return false;

  // require decent contiguity/density inside its bbox (prevents speckle bands)
  const int bbox_area = bw * bh;
  const double fill = (bbox_area > 0) ? (double)reg.area / (double)bbox_area : 0.0;
  if (fill < P.min_fill_ratio) return false;

  return true;
}


static bool tail_attached_to_interior(const std::vector<int16_t>& mask,
                                      const Region& reg,
                                      int16_t cls,
                                      const PostProcParams& P)
{
  const bool top_edge = (reg.minr <= P.edge_tolerance);
  const bool bot_edge = ((H - reg.maxr) <= P.edge_tolerance);
  if (!top_edge && !bot_edge) return false;

  const int span_l = reg.minc;
  const int span_r = reg.maxc; // exclusive

  int hits = 0;

  if (top_edge) {
    const int r0 = reg.maxr;
    const int r1 = std::min(H, reg.maxr + P.tail_attach_rows);
    for (int rr = r0; rr < r1; rr++) {
      for (int cc = span_l; cc < span_r; cc++) {
        if (mask[(size_t)idx(rr,cc)] == cls) hits++;
      }
    }
  } else { // bottom edge
    const int r0 = reg.minr - 1;
    const int r1 = std::max(0, reg.minr - P.tail_attach_rows);
    for (int rr = r0; rr >= r1; rr--) {
      for (int cc = span_l; cc < span_r; cc++) {
        if (mask[(size_t)idx(rr,cc)] == cls) hits++;
      }
    }
  }

  return hits >= P.tail_attach_min_pixels;
}



static inline bool is_tail_band_region(const std::vector<int16_t>& mask,
                                       const Region& reg,
                                       int16_t cls,
                                       const PostProcParams& P)
{
  const int bh = reg.maxr - reg.minr;
  const int bw = reg.maxc - reg.minc;

  if (bh <= 0) return false;

  // cap height (your 5-8 requirement)
  if (bh > P.tail_max_height) return false;

  const bool top_edge = (reg.minr <= P.edge_tolerance);
  const bool bot_edge = ((H - reg.maxr) <= P.edge_tolerance);
  if (!top_edge && !bot_edge) return false;

  if (bw < P.tail_min_width) return false;
  if (reg.area < P.tail_min_area) return false;

  const int bbox_area = bw * bh;
  const double fill = (bbox_area > 0) ? (double)reg.area / (double)bbox_area : 0.0;
  if (fill < P.tail_min_fill_ratio) return false;

  const bool left  = (reg.minc <= P.edge_tolerance);
  const bool right = ((W - reg.maxc) <= P.edge_tolerance);
  if (!left && !right) return false;

  if (P.tail_require_attachment) {
    if (!tail_attached_to_interior(mask, reg, cls, P)) return false;
  }

  return true;
}



static bool mask_has_tail_band(const std::vector<int16_t>& mask, const PostProcParams& P)
{
  auto classes = unique_sorted_classes(mask);
  for (int16_t cls : classes) {
    if (cls == 0) continue;

    std::vector<uint8_t> fg((size_t)H * (size_t)W, 0);
    for (int i = 0; i < H * W; i++) fg[(size_t)i] = (mask[(size_t)i] == cls) ? 1 : 0;

    auto regs = label_bool_mask(fg, H, W, /*conn8*/true);
    for (const auto& reg : regs) {
      if (is_tail_band_region(mask, reg, cls, P)) return true;
    }
  }
  return false;
}



static bool mask_has_sparse_stripe(const std::vector<int16_t>& mask, const PostProcParams& P)
{
  auto classes = unique_sorted_classes(mask);
  for (int16_t cls : classes) {
    if (cls == 0) continue;

    std::vector<uint8_t> fg((size_t)H*W, 0);
    for (int i = 0; i < H*W; i++) fg[i] = (mask[i] == cls) ? 1 : 0;

    auto regs = label_bool_mask(fg, H, W, /*conn8*/true);
    for (const auto& reg : regs) {
      if (is_sparse_stripe_region(reg, P)) return true;
    }
  }
  return false;
}



static bool dominant_class_info(const std::vector<int16_t>& mask,
                                int16_t& out_cls,
                                double& out_frac)
{
  std::array<int, 256> counts{};
  counts.fill(0);

  int nz = 0;
  for (int i = 0; i < H * W; i++) {
    const int16_t v = mask[(size_t)i];
    if (v == 0) continue;
    nz++;
    const int idxc = (v >= 0 && v < (int16_t)counts.size()) ? (int)v : -1;
    if (idxc >= 0) counts[(size_t)idxc]++;
  }

  if (nz == 0) { out_cls = 0; out_frac = 0.0; return false; }

  int best_k = 0;
  int best_c = 0;
  for (int k = 1; k < (int)counts.size(); k++) {
    if (counts[(size_t)k] > best_c) { best_c = counts[(size_t)k]; best_k = k; }
  }

  out_cls = (int16_t)best_k;
  out_frac = (double)best_c / (double)(H * W);
  return (best_k != 0 && best_c > 0);
}


static void densify_dominant_class_rows(std::vector<int16_t>& mask,
                                       int16_t dom_cls,
                                       const PostProcParams& P)
{
  if (dom_cls == 0) return;

  std::vector<uint8_t> fg((size_t)H * (size_t)W, 0);
  for (int i = 0; i < H * W; i++) fg[(size_t)i] = (mask[(size_t)i] == dom_cls) ? 1 : 0;

  auto regs = label_bool_mask(fg, H, W, /*conn8*/true);

  for (const auto& reg : regs) {
    if (is_sparse_stripe_region(reg, P)) continue;
    if (is_sparse_edge_band_region(reg, P)) continue;
    if (is_tail_band_region(mask, reg, dom_cls, P)) continue;

    const int bh = reg.maxr - reg.minr;
    const int bw = reg.maxc - reg.minc;
    if (bh <= 0 || bw <= 0) continue;

    if (bw < P.ext_min_width) continue;

    std::vector<std::vector<int>> row_cols(H);
    int min_row = H, max_row = -1;
    for (auto [r,c] : reg.coords) {
      row_cols[r].push_back(c);
      min_row = std::min(min_row, r);
      max_row = std::max(max_row, r);
    }
    if (max_row < 0) continue;

    const int min_row_pixels = std::max(2, (int)std::floor(0.20 * (double)bw));

    for (int r = min_row; r <= max_row; r++) {
      auto& cols = row_cols[r];
      if ((int)cols.size() < min_row_pixels) continue;

      auto mm = std::minmax_element(cols.begin(), cols.end());
      int lo = *mm.first;
      int hi = *mm.second;

      const int span = hi - lo + 1;
      const double row_fill = (span > 0) ? ((double)cols.size() / (double)span) : 0.0;
      if (row_fill < 0.30) continue;

      for (int c = lo; c <= hi; c++) {
        const size_t id = (size_t)idx(r,c);
        if (mask[id] == 0) mask[id] = dom_cls;
      }
    }
  }
}


static std::vector<int16_t> remove_irregular_sections(const std::vector<int16_t>& mask,
                                                      const PostProcParams& P,
                                                      int16_t protected_cls)
{
  std::vector<int16_t> output_mask = mask;

  auto classes = unique_sorted_classes(mask);
  for (int16_t cls : classes) {
    if (cls == 0) continue;
    if (cls == protected_cls) continue;

    std::vector<uint8_t> class_fg((size_t)H*W, 0);
    for (int i = 0; i < H*W; i++) class_fg[i] = (mask[i] == cls) ? 1 : 0;

    auto regions = label_bool_mask(class_fg, H, W, /*conn8*/true);

    for (const auto& region : regions) {
      if (is_sparse_stripe_region(region, P)) continue;
      if (is_sparse_edge_band_region(region, P)) continue;
      if (is_tail_band_region(mask, region, cls, P)) continue;

      const int bbox_height = region.maxr - region.minr;
      if (bbox_height <= P.irregular_min_height) continue;

      const int bh = bbox_height;
      const int bw = region.maxc - region.minc;
      const int total_pixels = bh * bw;
      if (total_pixels <= 0) continue;

      int zeros = 0;
      for (int r = region.minr; r < region.maxr; r++) {
        for (int c = region.minc; c < region.maxc; c++) {
          if (output_mask[idx(r,c)] == 0) zeros++;
        }
      }

      const double proportion = (double)zeros / (double)total_pixels;
      if (proportion > P.irregular_zero_threshold) {
        for (auto [r,c] : region.coords) output_mask[idx(r,c)] = 0;
      }
    }
  }

  return output_mask;
}



struct LinearFillJob {
  int16_t cls;
  int lo;   // inclusive
  int hi;   // inclusive
  int area; // original region area (pixels)
};

static void linear_fill_components_rowmajor(std::vector<int16_t>& mask,
                                            const PostProcParams& P,
                                            bool conn8 = true,
                                            double max_growth_ratio = 12.0)
{
  const std::vector<int16_t> base = mask;

  auto classes = unique_sorted_classes(base);

  std::vector<LinearFillJob> jobs;
  jobs.reserve(128);

  for (int16_t cls : classes) {
    if (cls == 0) continue;

    std::vector<uint8_t> fg((size_t)H * (size_t)W, 0);
    for (int i = 0; i < H * W; i++) fg[(size_t)i] = (base[(size_t)i] == cls) ? 1 : 0;

    auto regions = label_bool_mask(fg, H, W, conn8);

    for (const auto& reg : regions) {

      // Critical: don't let tails or sparse edge-bands seed row-major fill
      if (is_sparse_edge_band_region(reg, P)) continue;
      if (is_tail_band_region(base, reg, cls, P)) continue;

      int lo = H * W, hi = -1;
      for (auto [r, c] : reg.coords) {
        const int lin = idx(r, c);
        lo = std::min(lo, lin);
        hi = std::max(hi, lin);
      }
      if (hi < lo) continue;

      const int span = (hi - lo + 1);
      if (reg.area > 0 && (double)span > max_growth_ratio * (double)reg.area) {
        continue;
      }

      jobs.push_back({cls, lo, hi, reg.area});
    }
  }

  std::sort(jobs.begin(), jobs.end(),
            [](const LinearFillJob& a, const LinearFillJob& b) {
              return (a.hi - a.lo) > (b.hi - b.lo);
            });

  for (const auto& job : jobs) {
    for (int i = job.lo; i <= job.hi; i++) {
      if (mask[(size_t)i] == 0) mask[(size_t)i] = job.cls;
    }
  }
}


static void densify_tail_band_rows(std::vector<int16_t>& mask,
                                  const Region& reg,
                                  int16_t cls,
                                  const PostProcParams& P)
{
  (void)P;
  const int bh = reg.maxr - reg.minr;
  const int bw = reg.maxc - reg.minc;
  if (bh <= 0 || bw <= 0) return;

  const int first_row = reg.minr;
  const int last_row  = reg.maxr - 1;

  std::vector<int> row_count(H, 0);
  std::vector<int> row_lo(H,  W), row_hi(H, -1);

  for (auto [r,c] : reg.coords) {
    if ((unsigned)r >= (unsigned)H || (unsigned)c >= (unsigned)W) continue;
    row_count[r]++;
    row_lo[r] = std::min(row_lo[r], c);
    row_hi[r] = std::max(row_hi[r], c);
  }

  auto fill_row = [&](int r, int lo, int hi) {
    lo = std::max(0, lo);
    hi = std::min(W - 1, hi);
    for (int c = lo; c <= hi; c++) {
      mask[(size_t)idx(r,c)] = cls;
    }
  };

  // --- Single-row tail: preserve its own span only.
  if (bh == 1) {
    if (row_hi[first_row] >= row_lo[first_row]) {
      fill_row(first_row, row_lo[first_row], row_hi[first_row]);
    }
    return;
  }

  // 1) First row: preserve start offset, fill rightward.
  if (row_hi[first_row] >= row_lo[first_row]) {
    fill_row(first_row, row_lo[first_row], W - 1);
  } else {
    fill_row(first_row, reg.minc, W - 1);
  }

  // 2) Last row: preserve end offset, fill leftward.
  if (row_hi[last_row] >= row_lo[last_row]) {
    fill_row(last_row, 0, row_hi[last_row]);
  } else {
    fill_row(last_row, 0, reg.maxc - 1);
  }

  // 3) Interior rows: ALWAYS fill full-width.
  for (int r = first_row + 1; r <= last_row - 1; r++) {
    if (row_count[r] > 0) {
      fill_row(r, 0, W - 1);
    }
  }
}


static void smooth_tail_bands(std::vector<int16_t>& mask, const PostProcParams& P)
{
  auto classes = unique_sorted_classes(mask);

  for (int16_t cls : classes) {
    if (cls == 0) continue;

    std::vector<uint8_t> fg((size_t)H * (size_t)W, 0);
    for (int i = 0; i < H * W; i++) fg[(size_t)i] = (mask[(size_t)i] == cls) ? 1 : 0;

    auto regs = label_bool_mask(fg, H, W, /*conn8*/true);

    for (const auto& reg : regs) {
      if (!is_tail_band_region(mask, reg, cls, P)) continue;
      densify_tail_band_rows(mask, reg, cls, P);
    }
  }
}


static std::vector<int16_t> remove_noisy_regions(const std::vector<int16_t>& mask,
                                                 const PostProcParams& P,
                                                 int16_t protected_cls)
{
  std::vector<int16_t> output_mask = mask;
  auto classes = unique_sorted_classes(mask);

  for (int16_t cls : classes) {
    if (cls == 0) continue;
    if (cls == protected_cls) continue;

    std::vector<uint8_t> class_fg((size_t)H*W, 0);
    for (int i = 0; i < H*W; i++) class_fg[i] = (mask[i] == cls) ? 1 : 0;

    auto regions = label_bool_mask(class_fg, H, W, /*conn8*/true);

    for (const auto& region : regions) {
      if (is_sparse_stripe_region(region, P)) continue;
      if (is_sparse_edge_band_region(region, P)) continue;
      if (is_tail_band_region(mask, region, cls, P)) continue;

      const int total_pixels = (int)region.coords.size();
      if (total_pixels <= 0) continue;

      const int bh = region.maxr - region.minr;
      const int bw = region.maxc - region.minc;
      if (bh <= 0 || bw <= 0) continue;

      std::vector<uint8_t> embedded_fg((size_t)bh*bw, 0);
      for (int rr = 0; rr < bh; rr++) {
        for (int cc = 0; cc < bw; cc++) {
          const int16_t v = mask[idx(region.minr + rr, region.minc + cc)];
          embedded_fg[idx(rr,cc,bw)] = (v != cls) ? 1 : 0;
        }
      }

      auto embedded_regions = label_bool_mask(embedded_fg, bh, bw, /*conn8*/true);

      int num_embedded = 0;
      int total_embedded_pixels = 0;

      for (const auto& er : embedded_regions) {
        const bool touches =
          (er.minr == 0 || er.minc == 0 || er.maxr == bh || er.maxc == bw);
        if (touches) continue;

        num_embedded++;
        total_embedded_pixels += er.area;
      }

      const double ratio = (double)total_embedded_pixels / (double)total_pixels;
      if (num_embedded > P.noisy_max_embedded_regions || ratio > P.noisy_max_embedded_area_ratio) {
        for (auto [r,c] : region.coords) output_mask[idx(r,c)] = 0;
      }
    }
  }

  return output_mask;
}


static bool mask_has_stripe_like_region(const std::vector<int16_t>& mask,
                                        const PostProcParams& P,
                                        int min_width,
                                        int min_height_rows)
{
  auto classes = unique_sorted_classes(mask);
  for (int16_t cls : classes) {
    if (cls == 0) continue;

    std::vector<uint8_t> fg((size_t)H*W, 0);
    for (int i = 0; i < H*W; i++) fg[i] = (mask[i] == cls);

    auto regs = label_bool_mask(fg, H, W, /*conn8*/true);
    for (const auto& reg : regs) {
      const int bw = reg.maxc - reg.minc;
      const int bh = reg.maxr - reg.minr;
      if (bw < min_width) continue;
      if (bh < min_height_rows) continue;

      const int bbox_area = bw * bh;
      const double fill = (bbox_area > 0) ? (double)reg.area / (double)bbox_area : 0.0;

      const bool left  = (reg.minc <= P.edge_tolerance);
      const bool right = ((W - reg.maxc) <= P.edge_tolerance);

      if (left && right && fill >= P.min_fill_ratio) return true;
    }
  }
  return false;
}

static bool is_pathological_speckle_map(const std::vector<int16_t>& mask,
                                        const PostProcParams& P)
{
  int nz = 0;
  std::set<int16_t> cls_set;
  for (int i = 0; i < H*W; i++) {
    if (mask[i] != 0) { nz++; cls_set.insert(mask[i]); }
  }
  const double nz_frac = (double)nz / (double)(H*W);
  const int num_cls = (int)cls_set.size();
  if (nz == 0) return false;

  if (nz_frac < 0.20) return false;
  if (num_cls < 3) return false;

  int total_components = 0;
  for (int16_t cls : cls_set) {
    std::vector<uint8_t> fg((size_t)H*W, 0);
    for (int i = 0; i < H*W; i++) fg[i] = (mask[i] == cls);
    auto regs = label_bool_mask(fg, H, W, /*conn8*/true);
    total_components += (int)regs.size();
  }

  int disagree = 0, edges = 0;
  for (int r = 0; r < H; r++) for (int c = 0; c < W; c++) {
    const int16_t v = mask[idx(r,c)];
    if (c+1 < W) { edges++; if (v != mask[idx(r,c+1)]) disagree++; }
    if (r+1 < H) { edges++; if (v != mask[idx(r+1,c)]) disagree++; }
  }
  const double boundary = (edges > 0) ? (double)disagree / (double)edges : 0.0;

  const bool has_stripe = mask_has_stripe_like_region(mask, P, P.ext_min_width, 4);

  if (!has_stripe && (total_components >= 20) && (boundary >= 0.10)) {
    return true;
  }
  return false;
}

static std::vector<int16_t> handle_nonelf_holes(const std::vector<int16_t>& in_mask,
                                                const PostProcParams& P)
{
  std::vector<int16_t> output_mask = in_mask;
  auto classes = unique_sorted_classes(output_mask);

  for (int16_t cls : classes) {
    if (cls == 0) continue;

    std::vector<uint8_t> class_fg((size_t)H*W, 0);
    for (int i = 0; i < H*W; i++) class_fg[i] = (output_mask[i] == cls) ? 1 : 0;

    auto regions = label_bool_mask(class_fg, H, W, /*conn8*/false);

    for (const auto& region : regions) {
      const int bh = region.maxr - region.minr;
      const int bw = region.maxc - region.minc;
      if (bh <= 0 || bw <= 0) continue;

      std::vector<int16_t> section_bbox((size_t)bh*bw, 0);
      for (int rr = 0; rr < bh; rr++) {
        for (int cc = 0; cc < bw; cc++) {
          section_bbox[idx(rr,cc,bw)] = output_mask[idx(region.minr + rr, region.minc + cc)];
        }
      }

      std::vector<uint8_t> nonelf_fg((size_t)bh*bw, 0);
      for (int i = 0; i < bh*bw; i++) nonelf_fg[i] = (section_bbox[i] == 0) ? 1 : 0;

      auto holes = label_bool_mask(nonelf_fg, bh, bw, /*conn8*/false);

      int max_hole_w = 0;
      for (const auto& hole : holes) {
        const bool touches =
          (hole.minr == 0 || hole.minc == 0 || hole.maxr == bh || hole.maxc == bw);
        if (touches) continue;
        const int hole_w = hole.maxc - hole.minc;
        max_hole_w = std::max(max_hole_w, hole_w);
      }

      if (max_hole_w > P.holes_bbox_width_thresh) {
        for (auto [r,c] : region.coords) output_mask[idx(r,c)] = 0;
        continue;
      }

      for (const auto& hole : holes) {
        const int hole_h = hole.maxr - hole.minr;
        const int hole_w = hole.maxc - hole.minc;
        if (hole_h >= P.holes_min_bbox_height && hole_w <= P.holes_bbox_width_thresh) {
          std::set<int16_t> neighbors;

          for (auto [rr,cc] : hole.coords) {
            const int dr[4] = {-1, 1, 0, 0};
            const int dc[4] = {0, 0, -1, 1};
            for (int k = 0; k < 4; k++) {
              int nr = rr + dr[k], nc = cc + dc[k];
              if ((unsigned)nr >= (unsigned)bh || (unsigned)nc >= (unsigned)bw) continue;
              neighbors.insert(section_bbox[idx(nr,nc,bw)]);
            }
          }

          neighbors.erase(0);
          if (neighbors.size() == 1) {
            const int16_t fill = *neighbors.begin();
            for (auto [rr,cc] : hole.coords) {
              output_mask[idx(region.minr + rr, region.minc + cc)] = fill;
            }
          }
        }
      }
    }
  }

  return output_mask;
}

static std::vector<int16_t> shape_based_postprocess(const std::vector<int16_t>& pred_mask,
                                                    const PostProcParams& P)
{
  std::vector<int16_t> out_mask = pred_mask;

  const double global_nz = global_nonzero_fraction(pred_mask);
  const bool allow_extension = (global_nz >= P.nz_thresh);

  int16_t dom_cls = 0;
  double dom_frac = 0.0;
  const bool have_dom = allow_extension && dominant_class_info(out_mask, dom_cls, dom_frac);
  const bool protect_dom = have_dom && (dom_frac >= 0.45);

  if (P.enable_remove_noisy_regions) {
    out_mask = remove_noisy_regions(out_mask, P, protect_dom ? dom_cls : (int16_t)0);
  } else {
    (void)dom_cls;
  }

  if (is_pathological_speckle_map(out_mask, P)) {
    std::fill(out_mask.begin(), out_mask.end(), (int16_t)0);
    return out_mask;
  }

  auto classes = unique_sorted_classes(pred_mask);

  for (int16_t cls : classes) {
    if (cls == 0) continue;

    std::vector<uint8_t> class_fg((size_t)H*W, 0);
    for (int i = 0; i < H*W; i++) class_fg[i] = (out_mask[i] == cls) ? 1 : 0;

    auto regions = label_bool_mask(class_fg, H, W, /*conn8*/true);

    for (const auto& region : regions) {
      const int bbox_h = region.maxr - region.minr;
      const int bbox_w = region.maxc - region.minc;
      const int bbox_area = bbox_h * bbox_w;
      const int area = region.area;

      const bool keep_sparse_stripe = is_sparse_stripe_region(region, P);
      const bool keep_edge_band = (!allow_extension) && is_sparse_edge_band_region(region, P);
      const bool keep_tail_band = is_tail_band_region(out_mask, region, cls, P);

      if (P.enable_remove_small_elf_blobs) {
        if (!keep_sparse_stripe && !keep_edge_band && !keep_tail_band) {
          if (remove_small_elf_blobs(out_mask, region, P)) continue;
        }
      }

      if (P.enable_sparse_island_killer && !allow_extension) {
        if (!keep_sparse_stripe && !keep_edge_band && !keep_tail_band) {
          const bool touches_left_edge  = (region.minc <= P.edge_tolerance);
          const bool touches_right_edge = ((W - region.maxc) <= P.edge_tolerance);

          if (bbox_w < P.sparse_min_width || !touches_left_edge || !touches_right_edge) {
            for (auto [r,c] : region.coords) out_mask[idx(r,c)] = 0;
            continue;
          }
        }
      }

      if (keep_edge_band || keep_tail_band) {
        continue;
      }

      if (protect_dom && cls == dom_cls) {
        continue;
      }

      if (P.enable_min_bbox_width_check) {
        if (bbox_w < P.min_bbox_width) {
          for (auto [r,c] : region.coords) out_mask[idx(r,c)] = 0;
          continue;
        }
      }

      const double fill_ratio = (bbox_area > 0) ? ((double)area / (double)bbox_area) : 0.0;
      if (P.enable_fill_ratio_check) {
        if (fill_ratio < P.min_fill_ratio) {
          for (auto [r,c] : region.coords) out_mask[idx(r,c)] = 0;
          continue;
        }
      }

      const double ar = (bbox_w > 0) ? ((double)bbox_h / (double)bbox_w) : 1e9;
      if (P.enable_aspect_ratio_check) {
        if (ar > P.max_aspect_ratio) {
          for (auto [r,c] : region.coords) out_mask[idx(r,c)] = 0;
          continue;
        }
      }

      if (P.enable_extend && allow_extension && bbox_w >= P.ext_min_width) {
        extend_section(out_mask, region, cls, P);
      }
    }

    if (P.enable_extend && allow_extension) {
      std::vector<uint8_t> class_fg2((size_t)H*W, 0);
      for (int i = 0; i < H*W; i++) class_fg2[i] = (out_mask[i] == cls) ? 1 : 0;

      auto merged = label_bool_mask(class_fg2, H, W, /*conn8*/true);
      for (const auto& mreg : merged) {
        const int bbox_w = mreg.maxc - mreg.minc;
        if (bbox_w >= P.ext_min_width) {
          extend_section(out_mask, mreg, cls, P);
        }
      }
    }
  }

  if (protect_dom) {
    densify_dominant_class_rows(out_mask, dom_cls, P);
  }

  if (P.enable_handle_nonelf_holes && allow_extension) {
    out_mask = handle_nonelf_holes(out_mask, P);
  }

  if (P.enable_remove_irregular_sections) {
    out_mask = remove_irregular_sections(out_mask, P, protect_dom ? dom_cls : (int16_t)0);
  }

  const int band_min_h = allow_extension ? 4 : 2;
  const int band_min_w = allow_extension ? P.ext_min_width : P.sparse_min_width;

  smooth_tail_bands(out_mask, P);

  const bool has_real_band = mask_has_stripe_like_region(out_mask, P, band_min_w, band_min_h);
  const bool has_sparse_stripe = mask_has_sparse_stripe(out_mask, P);
  const bool has_tail_band = mask_has_tail_band(out_mask, P);

  if (!has_real_band && !has_sparse_stripe && !has_tail_band) {
    std::fill(out_mask.begin(), out_mask.end(), (int16_t)0);
    return out_mask;
  }

  linear_fill_components_rowmajor(out_mask, P, true, 12.0);

  return out_mask;
}


// Extract run-length triplets over 4096 pixels (row-major).
static std::vector<RegionTriplet> extract_regions_triplets(const std::vector<int16_t>& class_map)
{
  std::vector<RegionTriplet> res;
  if (class_map.empty()) return res;

  int start = 0;
  int cur = (int)class_map[0];

  for (int i = 1; i < (int)class_map.size(); i++) {
    int v = (int)class_map[i];
    if (v != cur) {
      res.push_back({cur, start, i - start});
      start = i;
      cur = v;
    }
  }
  res.push_back({cur, start, (int)class_map.size() - start});
  return res;
}

} // namespace

// ----------------------------
// ONNX model wrapper
// ----------------------------
// process-global inference timing, aggregated across every handle. Inference runs on per-thread
// handles, not the singleton the global report is written from, so per-handle counters read zero;
// file-scope counters make a run's real totals show up. Survives the move to batched workers.
static std::atomic<unsigned long long> g_elf_timing_calls{0};
static std::atomic<unsigned long long> g_elf_timing_input_ns{0};
static std::atomic<unsigned long long> g_elf_timing_run_ns{0};
static std::atomic<unsigned long long> g_elf_timing_argmax_ns{0};
static std::atomic<unsigned long long> g_elf_timing_post_ns{0};
static std::atomic<unsigned long long> g_elf_timing_rle_ns{0};
static std::atomic<unsigned long long> g_elf_timing_total_ns{0};

class ElfDecodePool {
public:
  static ElfDecodePool& instance()
  {
    static ElfDecodePool pool;
    return pool;
  }

  void ensure_workers(size_t count)
  {
    std::lock_guard<std::mutex> guard(lock_);

    while (workers_.size() < count) {
      workers_.emplace_back([this]() {
        worker();
      });
    }
  }

  void submit(std::function<void()> task)
  {
    {
      std::lock_guard<std::mutex> guard(lock_);
      tasks_.push_back(std::move(task));
    }
    ready_.notify_one();
  }

  ~ElfDecodePool()
  {
    {
      std::lock_guard<std::mutex> guard(lock_);
      stopping_ = true;
    }
    ready_.notify_all();
    for (std::thread& worker_thread : workers_) {
      if (worker_thread.joinable()) {
        worker_thread.join();
      }
    }
  }

private:
  ElfDecodePool() = default;
  ElfDecodePool(const ElfDecodePool&) = delete;
  ElfDecodePool& operator=(const ElfDecodePool&) = delete;

  void worker()
  {
    for (;;) {
      std::function<void()> task;

      {
        std::unique_lock<std::mutex> guard(lock_);
        ready_.wait(guard, [this]() {
          return stopping_ || ! tasks_.empty();
        });
        if (stopping_ && tasks_.empty()) {
          return;
        }
        task = std::move(tasks_.front());
        tasks_.pop_front();
      }
      task();
    }
  }

  std::mutex lock_;
  std::condition_variable ready_;
  std::deque<std::function<void()>> tasks_;
  std::vector<std::thread> workers_;
  bool stopping_ = false;
};

struct ElfDecodeJob {
  std::vector<uint8_t> labels;
  std::vector<std::vector<RegionTriplet>> *out = nullptr;
  PostProcParams postproc;
  DecodeMode decode_mode = DecodeMode::HEAVY_POSTPROCESS;
  size_t output_base = 0;
  size_t samples = 0;
  std::atomic<size_t> next_sample{0};
  std::atomic<size_t> workers_left{0};
  std::atomic<int> status{ELF_ONNX_OK};
  std::mutex done_lock;
  std::condition_variable done;

  void set_failure(int failure)
  {
    int expected = ELF_ONNX_OK;
    status.compare_exchange_strong(expected, failure);
  }

  void decode()
  {
    using Clock = std::chrono::steady_clock;
    auto ns_between = [](Clock::time_point a,
                         Clock::time_point b) -> unsigned long long {
      return (unsigned long long)
          std::chrono::duration_cast<std::chrono::nanoseconds>(b - a).count();
    };

    while (status.load(std::memory_order_acquire) == ELF_ONNX_OK) {
      size_t sample = next_sample.fetch_add(1, std::memory_order_acq_rel);

      if (sample >= samples) {
        break;
      }

      try {
        const auto post_start = Clock::now();
        const uint8_t *source = labels.data() + sample * (size_t)H * (size_t)W;
        bool all_zero = true;

        for (size_t i = 0; i < (size_t)H * (size_t)W; i++) {
          if (source[i] != 0) {
            all_zero = false;
            break;
          }
        }
        if (all_zero) {
          const auto post_end = Clock::now();

          (*out)[output_base + sample] = {{0, 0, H * W}};
          const auto rle_end = Clock::now();
          g_elf_timing_post_ns.fetch_add(ns_between(post_start, post_end));
          g_elf_timing_rle_ns.fetch_add(ns_between(post_end, rle_end));
          continue;
        }

        std::vector<int16_t> raw_mask((size_t)H * (size_t)W);

        for (size_t i = 0; i < raw_mask.size(); i++) {
          raw_mask[i] = (int16_t)source[i];
        }

        std::vector<int16_t> post_mask;
        if (decode_mode == DecodeMode::HEAVY_POSTPROCESS) {
          post_mask = shape_based_postprocess(raw_mask, postproc);
        }
        else {
          post_mask = std::move(raw_mask);
        }
        const auto post_end = Clock::now();
        g_elf_timing_post_ns.fetch_add(ns_between(post_start, post_end));

        (*out)[output_base + sample] = extract_regions_triplets(post_mask);
        const auto rle_end = Clock::now();
        g_elf_timing_rle_ns.fetch_add(ns_between(post_end, rle_end));
      }
      catch (const std::bad_alloc&) {
        set_failure(ELF_ONNX_RETRYABLE);
      }
      catch (const std::exception& e) {
        std::fprintf(stderr, "[elf onnx] output decoding failed: %s\n", e.what());
        set_failure(ELF_ONNX_FATAL);
      }
      catch (...) {
        set_failure(ELF_ONNX_FATAL);
      }
    }

    if (workers_left.fetch_sub(1, std::memory_order_acq_rel) == 1) {
      std::lock_guard<std::mutex> guard(done_lock);
      done.notify_all();
    }
  }

  int wait()
  {
    std::unique_lock<std::mutex> guard(done_lock);
    done.wait(guard, [this]() {
      return workers_left.load(std::memory_order_acquire) == 0;
    });
    return status.load(std::memory_order_acquire);
  }
};

struct ElfSegmentationModelONNX::Impl {
  Ort::Env env;
  Ort::Session session;
  Ort::AllocatorWithDefaultOptions allocator;

  std::string model_file;
  std::string accelerator_name;
  std::string input_name;
  std::string output_name;
  std::string tensorrt_cache;
  int intra_threads = 1;
  int inter_threads = 1;
  int accelerator_device = 0;
  bool compact_label_output = false;
  bool using_tensorrt = false;
  bool reported_cuda_policy = false;
  std::atomic<bool> terminate_requested{false};

  // Runtime-tunable post-processing parameters (defaults are in the struct).
  PostProcParams postproc;
  DecodeMode decode_mode = DecodeMode::HEAVY_POSTPROCESS;

  // shared by every Run so a terminate request (from another thread) can stop an
  // in-flight Run promptly; once set it latches and subsequent Runs fail fast
  Ort::RunOptions run_options;

  // Per-Run sample ceiling. Providers with fixed_run_batch execute every Run at
  // this size; the batch driver zero-pads the final partial Run.
  int  run_max_batch = 1;
  bool fixed_run_batch = false;
  int  inference_status = ELF_ONNX_OK;
  int  decode_threads = 1;

  // Return the persistent TensorRT engine-cache directory for this device.
  std::string tensorrt_cache_directory()
  {
    const char *configured = std::getenv("SCALPEL3_ELF_TENSORRT_CACHE");
    const char *xdg = std::getenv("XDG_CACHE_HOME");
    const char *home = std::getenv("HOME");
    std::filesystem::path path;
    std::error_code error;

    if (configured && configured[0]) {
      path = configured;
    }
    else if (xdg && xdg[0]) {
      path = std::filesystem::path(xdg) / "scalpel3" / "elf-tensorrt";
    }
    else if (home && home[0]) {
      path = std::filesystem::path(home) / ".cache" / "scalpel3"
             / "elf-tensorrt";
    }
    else {
      return std::string();
    }
    path /= "device-" + std::to_string(accelerator_device);
    std::filesystem::create_directories(path, error);
    if (error) {
      std::fprintf(stderr,
                   "[elf onnx] TensorRT cache directory %s is unavailable: %s\n",
                   path.string().c_str(), error.message().c_str());
      return std::string();
    }
    return path.string();
  }

  // Build a session with the selected provider. CUDA always follows TensorRT
  // in the provider list so unsupported graph nodes execute correctly.
  void create_session(bool enable_tensorrt)
  {
    Ort::SessionOptions options;
    bool configured_tensorrt = false;

    options.SetIntraOpNumThreads(intra_threads);
    options.SetInterOpNumThreads(inter_threads);
    options.SetExecutionMode(ORT_SEQUENTIAL);
    options.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_ALL);

    if (accelerator_name == "cuda") {
      OrtCUDAProviderOptions cuda_options{};
      OnnxCudaProviderPolicy policy{};

      if (! onnx_cuda_provider_options(accelerator_device, &cuda_options,
                                       &policy)) {
        throw std::runtime_error(
            "CUDA memory policy could not query the selected device");
      }
      if (! reported_cuda_policy) {
        std::fprintf(stderr,
                     "[elf onnx] CUDA device %d (physical %d): %.1f MiB free, "
                     "%.1f MiB arena limit (%.0f%%).\n",
                     accelerator_device, policy.physical_device_id,
                     policy.free_bytes / 1048576.0,
                     policy.arena_limit / 1048576.0,
                     policy.memory_fraction * 100.0);
        reported_cuda_policy = true;
      }

      if (enable_tensorrt) {
        const char *fp16 = std::getenv("SCALPEL3_ELF_TENSORRT_FP16");
        const bool use_fp16 = ! fp16 || std::strcmp(fp16, "false");
        Ort::TensorRTProviderOptions tensorrt_options;
        std::unordered_map<std::string, std::string> values = {
          {"device_id", std::to_string(accelerator_device)},
          {"trt_fp16_enable", use_fp16 ? "1" : "0"},
          {"trt_engine_cache_enable", tensorrt_cache.empty() ? "0" : "1"}
        };

        if (! tensorrt_cache.empty()) {
          values["trt_engine_cache_path"] = tensorrt_cache;
          values["trt_engine_cache_prefix"] =
              "scalpel3_elf_device_" + std::to_string(accelerator_device)
              + (use_fp16 ? "_fp16" : "_fp32");
        }
        tensorrt_options.Update(values);
        options.AppendExecutionProvider_TensorRT_V2(*tensorrt_options);
        configured_tensorrt = true;
      }
      options.AppendExecutionProvider_CUDA(cuda_options);
    }
    else if (accelerator_name == "coreml") {
      const char* keys[] = {"ModelFormat", "RequireStaticInputShapes"};
      const char* values[] = {"MLProgram", "1"};

      Ort::ThrowOnError(Ort::GetApi().AddFreeDimensionOverrideByName(
          options, "batch", run_max_batch));
      Ort::ThrowOnError(Ort::GetApi().SessionOptionsAppendExecutionProvider(
          options, "CoreML", keys, values, 2));
    }

    Ort::Session replacement(env, model_file.c_str(), options);

    session = std::move(replacement);
    using_tensorrt = configured_tensorrt;
  }

  Impl(const std::string& model_path,
       int intra_op_threads,
       int inter_op_threads,
       const std::string& in_name,
       const std::string& ob,
       const std::string& om,
       const std::string& accelerator,
       int max_batch,
       int device_id)
    : env(ORT_LOGGING_LEVEL_ERROR, "elf_seg"),
      session(nullptr),
      allocator(),
      model_file(model_path),
      accelerator_name(accelerator),
      input_name(),
      output_name(),
      postproc(),
      run_options()
  {
    (void)in_name;
    (void)ob;
    (void)om;

    if (max_batch < 1) {
      max_batch = 1;
    }
    if (max_batch > 4096) {
      max_batch = 4096;
    }
    run_max_batch = max_batch;
    decode_threads = 1;
    intra_threads = intra_op_threads > 0
                        ? intra_op_threads
                        : (accelerator_name == "cpu" ? 0 : 1);
    inter_threads = inter_op_threads > 0 ? inter_op_threads : 1;
    accelerator_device = device_id >= 0 ? device_id : 0;
    fixed_run_batch =
        accelerator_name == "cuda" || accelerator_name == "coreml";

    bool try_tensorrt = false;
    const char *tensorrt_setting = std::getenv("SCALPEL3_ELF_TENSORRT");
    const bool tensorrt_disabled =
        tensorrt_setting && ! std::strcmp(tensorrt_setting, "false");

    if (accelerator_name == "cuda" && ! tensorrt_disabled) {
      char reason[320] = {0};

      try_tensorrt = onnx_tensorrt_available(reason, sizeof(reason));
      if (try_tensorrt) {
        tensorrt_cache = tensorrt_cache_directory();
      }
      else if (tensorrt_setting && ! std::strcmp(tensorrt_setting, "true")) {
        std::fprintf(stderr,
                     "[elf onnx] TensorRT is unavailable; using CUDA: %s\n",
                     reason[0] ? reason : "no compatible runtime");
      }
    }

    try {
      create_session(try_tensorrt);
    }
    catch (const std::exception& error) {
      if (! try_tensorrt) {
        throw;
      }
      std::fprintf(stderr,
                   "[elf onnx] TensorRT session creation failed; using CUDA: %s\n",
                   error.what());
      create_session(false);
    }
    if (using_tensorrt) {
      std::fprintf(stderr,
                   "[elf onnx] TensorRT enabled%s%s.\n",
                   tensorrt_cache.empty() ? "" : ", engine cache ",
                   tensorrt_cache.empty() ? "" : tensorrt_cache.c_str());
    }

    // Auto-discover IO names from the model.
    size_t n_in = session.GetInputCount();
    size_t n_out = session.GetOutputCount();
    if (n_in < 1 || n_out < 1) {
      throw std::runtime_error("Unexpected ONNX model IO count");
    }

    auto in0 = session.GetInputNameAllocated(0, allocator);
    input_name = in0.get();
    std::string output_description;

    for (size_t i = 0; i < n_out; i++) {
      auto name = session.GetOutputNameAllocated(i, allocator);
      auto output_type = session.GetOutputTypeInfo(i);
      auto tensor = output_type.GetTensorTypeAndShapeInfo();
      auto shape = tensor.GetShape();
      ONNXTensorElementDataType element_type = tensor.GetElementType();
      const std::string candidate_name = name.get();

      if (! output_description.empty()) {
        output_description += ", ";
      }
      output_description += candidate_name + " type="
                            + std::to_string((int)element_type)
                            + " rank=" + std::to_string(shape.size());

      if (element_type == ONNX_TENSOR_ELEMENT_DATA_TYPE_UINT8
          && shape.size() == 3
          && (shape[1] <= 0 || shape[1] == H)
          && (shape[2] <= 0 || shape[2] == W)) {
        output_name = name.get();
        compact_label_output = true;
        break;
      }
      if (element_type == ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT
          && (candidate_name == "out_multi"
              || (shape.size() == 4
                  && (shape[1] <= 0 || shape[1] == ELF_NUM_CLASSES)
                  && (shape[2] <= 0 || shape[2] == H)
                  && (shape[3] <= 0 || shape[3] == W)))) {
        output_name = name.get();
      }
    }
    if (output_name.empty()) {
      throw std::runtime_error(
          "ELF ONNX model has no supported class output (" + output_description + ")");
    }
  }

  void set_postproc_params(const PostProcParams& P) noexcept {
    postproc = P;
  }

  const PostProcParams& get_postproc_params() const noexcept {
    return postproc;
  }

  void reset_timing() noexcept {
    g_elf_timing_calls.store(0);
    g_elf_timing_input_ns.store(0);
    g_elf_timing_run_ns.store(0);
    g_elf_timing_argmax_ns.store(0);
    g_elf_timing_post_ns.store(0);
    g_elf_timing_rle_ns.store(0);
    g_elf_timing_total_ns.store(0);
  }

  bool write_timing_report(const char* path) const noexcept {
    if (!path || !path[0]) return false;
    try {
      std::ofstream f(path);
      if (!f) return false;
      const unsigned long long calls = g_elf_timing_calls.load();
      auto ms = [](unsigned long long ns) { return (double)ns / 1000000.0; };
      auto avg_us = [calls](unsigned long long ns) { return calls ? ((double)ns / 1000.0 / (double)calls) : 0.0; };
      f << "decode_mode," << (decode_mode == DecodeMode::HEAVY_POSTPROCESS ? "heavy_postprocess" : "raw_argmax") << "\n";
      f << "calls," << calls << "\n";
      f << "stage,total_ms,avg_us_per_call\n";
      f << "input," << ms(g_elf_timing_input_ns.load()) << "," << avg_us(g_elf_timing_input_ns.load()) << "\n";
      f << "onnx_run," << ms(g_elf_timing_run_ns.load()) << "," << avg_us(g_elf_timing_run_ns.load()) << "\n";
      f << "argmax," << ms(g_elf_timing_argmax_ns.load()) << "," << avg_us(g_elf_timing_argmax_ns.load()) << "\n";
      f << "postprocess_or_copy," << ms(g_elf_timing_post_ns.load()) << "," << avg_us(g_elf_timing_post_ns.load()) << "\n";
      f << "rle," << ms(g_elf_timing_rle_ns.load()) << "," << avg_us(g_elf_timing_rle_ns.load()) << "\n";
      f << "total," << ms(g_elf_timing_total_ns.load()) << "," << avg_us(g_elf_timing_total_ns.load()) << "\n";
      return true;
    } catch (...) {
      return false;
    }
  }

  // Run one input batch and return one class byte per pixel. Current models perform
  // argmax on the execution provider. The legacy logits output remains supported so an
  // existing installation fails neither silently nor abruptly during an upgrade.
  bool run_labels_batch(const float* input,
                        int b,
                        std::vector<uint8_t>& labels) noexcept
  {
    inference_status = ELF_ONNX_OK;
    try {
      Ort::MemoryInfo meminfo = Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);

      std::vector<int64_t> in_shape = {(int64_t)b, 1, 64, 64};
      Ort::Value in_tensor = Ort::Value::CreateTensor<float>(
        meminfo, const_cast<float*>(input),
        (size_t)b * (size_t)EXPECTED_BYTES,
        in_shape.data(), in_shape.size()
      );

      const char* input_names[] = { input_name.c_str() };
      const char* output_names[] = { output_name.c_str() };

      auto outputs = session.Run(run_options,
                                 input_names, &in_tensor, 1,
                                 output_names, 1);

      Ort::Value& output = outputs[0];
      auto type_info = output.GetTensorTypeAndShapeInfo();
      auto shape = type_info.GetShape();

      if (compact_label_output) {
        if (type_info.GetElementType() != ONNX_TENSOR_ELEMENT_DATA_TYPE_UINT8
            || shape.size() != 3 || shape[0] != (int64_t)b
            || shape[1] != H || shape[2] != W) {
          inference_status = ELF_ONNX_FATAL;
          return false;
        }

        const uint8_t *p = output.GetTensorData<uint8_t>();
        labels.assign(p, p + (size_t)b * (size_t)H * (size_t)W);
        return true;
      }

      if (type_info.GetElementType() != ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT
          || shape.size() != 4 || shape[0] != (int64_t)b
          || shape[1] != ELF_NUM_CLASSES || shape[2] != H || shape[3] != W) {
        inference_status = ELF_ONNX_FATAL;
        return false;
      }

      const auto argmax_start = std::chrono::steady_clock::now();
      const float *logits = output.GetTensorData<float>();
      labels.resize((size_t)b * (size_t)H * (size_t)W);
      for (int sample = 0; sample < b; sample++) {
        const float *sample_logits =
            logits + (size_t)sample * (size_t)ELF_NUM_CLASSES
                     * (size_t)H * (size_t)W;
        uint8_t *sample_labels =
            labels.data() + (size_t)sample * (size_t)H * (size_t)W;

        for (int pixel = 0; pixel < H * W; pixel++) {
          int best_class = 0;
          float best_value = sample_logits[pixel];

          for (int cls = 1; cls < ELF_NUM_CLASSES; cls++) {
            float value =
                sample_logits[(size_t)cls * (size_t)H * (size_t)W
                              + (size_t)pixel];
            if (value > best_value) {
              best_value = value;
              best_class = cls;
            }
          }
          sample_labels[pixel] = (uint8_t)best_class;
        }
      }
      const auto argmax_end = std::chrono::steady_clock::now();
      g_elf_timing_argmax_ns.fetch_add(
          (unsigned long long)
              std::chrono::duration_cast<std::chrono::nanoseconds>(
                  argmax_end - argmax_start).count());
      return true;
    } catch (const Ort::Exception& e) {
      std::string message = e.what() ? e.what() : "unknown ONNX Runtime error";

      if (using_tensorrt
          && ! terminate_requested.load(std::memory_order_acquire)) {
        try {
          std::fprintf(stderr,
                       "[elf onnx] TensorRT inference failed; rebuilding the "
                       "session on CUDA: %s\n", message.c_str());
          create_session(false);
          return run_labels_batch(input, b, labels);
        }
        catch (const std::exception& fallback_error) {
          std::fprintf(stderr,
                       "[elf onnx] CUDA session rebuild failed: %s\n",
                       fallback_error.what());
        }
      }
      std::fprintf(stderr, "[elf onnx] ORT Run failed: %s\n", message.c_str());
      if (message.find("terminate") != std::string::npos
          || message.find("Terminate") != std::string::npos) {
        inference_status = ELF_ONNX_TERMINATED;
      }
      else if (message.find("out of memory") != std::string::npos
               || message.find("Out of memory") != std::string::npos
               || message.find("memory allocation") != std::string::npos
               || message.find("cudaErrorMemoryAllocation") != std::string::npos
               || message.find("CUDNN_STATUS_ALLOC_FAILED") != std::string::npos
               || (message.find("Available memory") != std::string::npos
                   && message.find("smaller than requested") != std::string::npos)) {
        inference_status = ELF_ONNX_RETRYABLE;
      }
      else {
        inference_status = ELF_ONNX_FATAL;
      }
      return false;
    } catch (const std::bad_alloc&) {
      inference_status = ELF_ONNX_RETRYABLE;
      return false;
    } catch (const std::exception& e) {
      std::fprintf(stderr, "[elf onnx] inference failed: %s\n", e.what());
      inference_status = ELF_ONNX_FATAL;
      return false;
    } catch (...) {
      inference_status = ELF_ONNX_FATAL;
      return false;
    }
  }

  bool run_labels(const float* input_1x1x64x64,
                  size_t input_count,
                  std::vector<uint8_t>& labels) noexcept
  {
    (void)input_count;
    return run_labels_batch(input_1x1x64x64, 1, labels);
  }
};

ElfSegmentationModelONNX::ElfSegmentationModelONNX(const std::string& model_path,
                                                   int intra_op_threads,
                                                   int inter_op_threads,
                                                   const std::string& input_name,
                                                   const std::string& out_bin_name,
                                                   const std::string& out_multi_name,
                                                   const std::string& accelerator,
                                                   int max_batch,
                                                   int device_id)
{
  pimpl_ = new Impl(model_path, intra_op_threads, inter_op_threads,
                    input_name, out_bin_name, out_multi_name, accelerator,
                    max_batch, device_id);
}

ElfSegmentationModelONNX::~ElfSegmentationModelONNX()
{
  delete pimpl_;
  pimpl_ = nullptr;
}

void ElfSegmentationModelONNX::set_postproc_params(const PostProcParams& params) noexcept
{
  if (pimpl_) pimpl_->set_postproc_params(params);
}

PostProcParams ElfSegmentationModelONNX::get_postproc_params() const noexcept {
  if (!pimpl_) return PostProcParams{};
  return pimpl_->get_postproc_params(); // returns a copy
}

void ElfSegmentationModelONNX::set_decode_mode(DecodeMode mode) noexcept {
  if (pimpl_) pimpl_->decode_mode = mode;
}

DecodeMode ElfSegmentationModelONNX::get_decode_mode() const noexcept {
  if (!pimpl_) return DecodeMode::HEAVY_POSTPROCESS;
  return pimpl_->decode_mode;
}

void ElfSegmentationModelONNX::set_decode_threads(int threads) noexcept
{
  if (!pimpl_) {
    return;
  }
  if (threads < 1) {
    threads = 1;
  }
  if (threads > pimpl_->run_max_batch) {
    threads = pimpl_->run_max_batch;
  }
  pimpl_->decode_threads = threads;
}

bool ElfSegmentationModelONNX::terminate_runs() noexcept {
  if (!pimpl_) {
    return false;
  }
  try {
    pimpl_->terminate_requested.store(true, std::memory_order_release);
    pimpl_->run_options.SetTerminate();
    return true;
  } catch (...) {
    return false;
  }
}

void ElfSegmentationModelONNX::reset_timing() noexcept {
  if (pimpl_) pimpl_->reset_timing();
}

bool ElfSegmentationModelONNX::write_timing_report(const char* path) const noexcept {
  if (!pimpl_) return false;
  return pimpl_->write_timing_report(path);
}

InferMaps ElfSegmentationModelONNX::infer_maps(const uint8_t* blob, size_t nbytes) noexcept
{
  InferMaps out;
  if (!pimpl_ || !blob) return out;

  using Clock = std::chrono::steady_clock;
  auto ns_between = [](Clock::time_point a, Clock::time_point b) -> unsigned long long {
    return (unsigned long long)std::chrono::duration_cast<std::chrono::nanoseconds>(b - a).count();
  };
  const auto t_total0 = Clock::now();
  auto t_stage0 = t_total0;

  // ---- Thread-local scratch (one instance per worker thread; reused across calls)
  thread_local std::array<uint8_t, EXPECTED_BYTES> tmp_buf;
  thread_local std::vector<float> input_f;
  thread_local std::vector<uint8_t> labels;

  // 1) pad/truncate to 4096
  if (nbytes >= EXPECTED_BYTES) {
    std::memcpy(tmp_buf.data(), blob, EXPECTED_BYTES);
  } else {
    std::memcpy(tmp_buf.data(), blob, nbytes);
    std::memset(tmp_buf.data() + nbytes, 0, EXPECTED_BYTES - nbytes);
  }

  // 2) bytes -> floats in [0,1]
  try {
    input_f.resize(EXPECTED_BYTES);
  } catch (...) {
    return out;
  }

  const uint8_t* tmp = tmp_buf.data();
  for (int i = 0; i < EXPECTED_BYTES; i++) {
    input_f[(size_t)i] = (float)tmp[(size_t)i] / 255.0f;
  }
  auto t_stage1 = Clock::now();
  g_elf_timing_input_ns.fetch_add(ns_between(t_stage0, t_stage1));
  t_stage0 = t_stage1;

  // 3) run model -> one class label per pixel
  if (!pimpl_->run_labels(input_f.data(), input_f.size(), labels)) {
    return out;
  }
  t_stage1 = Clock::now();
  g_elf_timing_run_ns.fetch_add(ns_between(t_stage0, t_stage1));
  t_stage0 = t_stage1;

  out.num_classes = ELF_NUM_CLASSES;

  // 4) convert the compact class labels to the postprocessor's mask type
  out.raw_mask.assign((size_t)H * (size_t)W, 0);
  for (size_t i = 0; i < out.raw_mask.size(); i++) {
    out.raw_mask[i] = (int16_t)labels[i];
  }

  // 5) decode mode: either current heavy shape post-processing, or raw argmax for timing/ablation.
  if (pimpl_->decode_mode == DecodeMode::HEAVY_POSTPROCESS) {
    out.post_mask = shape_based_postprocess(out.raw_mask, pimpl_->get_postproc_params());
  } else {
    out.post_mask = out.raw_mask;
  }
  t_stage1 = Clock::now();
  g_elf_timing_post_ns.fetch_add(ns_between(t_stage0, t_stage1));
  t_stage0 = t_stage1;

  // 6) RLE triplets of decoded mask
  out.triplets = extract_regions_triplets(out.post_mask);
  t_stage1 = Clock::now();
  g_elf_timing_rle_ns.fetch_add(ns_between(t_stage0, t_stage1));
  g_elf_timing_total_ns.fetch_add(ns_between(t_total0, t_stage1));
  g_elf_timing_calls.fetch_add(1);
  return out;
}


std::vector<RegionTriplet> ElfSegmentationModelONNX::infer(const uint8_t* blob, size_t nbytes) noexcept
{
  InferMaps maps = infer_maps(blob, nbytes);
  return std::move(maps.triplets);
}

int ElfSegmentationModelONNX::max_batch() const noexcept
{
  return pimpl_ ? pimpl_->run_max_batch : 1;
}

int ElfSegmentationModelONNX::last_status() const noexcept
{
  return pimpl_ ? pimpl_->inference_status : ELF_ONNX_FATAL;
}

bool ElfSegmentationModelONNX::infer_batch(const uint8_t* blobs, size_t n,
                                           std::vector<std::vector<RegionTriplet>>& out) noexcept
{
  out.clear();
  if (!pimpl_) {
    return false;
  }
  pimpl_->inference_status = ELF_ONNX_OK;
  if (n == 0) {
    return true;
  }
  if (!blobs) {
    pimpl_->inference_status = ELF_ONNX_FATAL;
    return false;
  }

  try {
    out.resize(n);
  } catch (const std::bad_alloc&) {
    pimpl_->inference_status = ELF_ONNX_RETRYABLE;
    return false;
  } catch (const std::exception& e) {
    std::fprintf(stderr, "[elf onnx] output allocation failed: %s\n", e.what());
    pimpl_->inference_status = ELF_ONNX_FATAL;
    return false;
  } catch (...) {
    pimpl_->inference_status = ELF_ONNX_FATAL;
    return false;
  }

  using Clock = std::chrono::steady_clock;
  auto ns_between = [](Clock::time_point a, Clock::time_point b) -> unsigned long long {
    return (unsigned long long)std::chrono::duration_cast<std::chrono::nanoseconds>(b - a).count();
  };

  const int max_b = pimpl_->run_max_batch;
  const auto total_start = Clock::now();

  // ---- Thread-local scratch (reused across sub-batches and calls)
  thread_local std::vector<float> input_f;
  std::deque<std::shared_ptr<ElfDecodeJob>> pending;

  for (size_t base = 0; base < n; base += (size_t)max_b) {
    auto t_stage0 = Clock::now();

    // Keep one decoded batch in flight while the next accelerator Run executes.
    if (pending.size() == 2) {
      int decode_status = pending.front()->wait();
      pending.pop_front();
      if (decode_status != ELF_ONNX_OK) {
        pimpl_->inference_status = decode_status;
        for (const auto& job : pending) {
          job->wait();
        }
        return false;
      }
    }

    const int b = (int)((n - base < (size_t)max_b) ? (n - base) : (size_t)max_b);
    // Fixed-shape execution prevents provider workspaces from multiplying when a pass
    // ends with a partial batch. Padding lanes are decoded but their outputs are ignored.
    const int run_b = pimpl_->fixed_run_batch ? max_b : b;

    // bytes -> floats in [0,1]; padding lanes stay 0
    try {
      input_f.assign((size_t)run_b * (size_t)EXPECTED_BYTES, 0.0f);
    } catch (const std::bad_alloc&) {
      pimpl_->inference_status = ELF_ONNX_RETRYABLE;
      return false;
    } catch (const std::exception& e) {
      std::fprintf(stderr, "[elf onnx] input allocation failed: %s\n", e.what());
      pimpl_->inference_status = ELF_ONNX_FATAL;
      return false;
    } catch (...) {
      pimpl_->inference_status = ELF_ONNX_FATAL;
      return false;
    }

    const uint8_t* src = blobs + base * (size_t)EXPECTED_BYTES;
    const size_t live = (size_t)b * (size_t)EXPECTED_BYTES;
    for (size_t i = 0; i < live; i++) {
      input_f[i] = (float)src[i] / 255.0f;
    }
    auto t_stage1 = Clock::now();
    g_elf_timing_input_ns.fetch_add(ns_between(t_stage0, t_stage1));
    t_stage0 = t_stage1;

    // One Run for the whole sub-batch. Only compact class labels cross the
    // provider boundary in the current model.
    std::shared_ptr<ElfDecodeJob> job = std::make_shared<ElfDecodeJob>();
    if (!pimpl_->run_labels_batch(input_f.data(), run_b, job->labels)) {
      for (const auto& pending_job : pending) {
        pending_job->wait();
      }
      return false;
    }
    t_stage1 = Clock::now();
    g_elf_timing_run_ns.fetch_add(ns_between(t_stage0, t_stage1));

    job->labels.resize((size_t)b * (size_t)H * (size_t)W);
    job->out = &out;
    job->postproc = pimpl_->get_postproc_params();
    job->decode_mode = pimpl_->decode_mode;
    job->output_base = base;
    job->samples = (size_t)b;

    size_t workers = std::min((size_t)pimpl_->decode_threads, (size_t)b);
    job->workers_left.store(workers, std::memory_order_release);
    ElfDecodePool& pool = ElfDecodePool::instance();
    pool.ensure_workers(workers);
    for (size_t worker = 0; worker < workers; worker++) {
      pool.submit([job]() {
        job->decode();
      });
    }
    pending.push_back(std::move(job));
  }

  for (const auto& job : pending) {
    int decode_status = job->wait();
    if (decode_status != ELF_ONNX_OK) {
      pimpl_->inference_status = decode_status;
      return false;
    }
  }

  // 'calls' counts chunks so reports remain comparable with the batch-one path.
  g_elf_timing_total_ns.fetch_add(ns_between(total_start, Clock::now()));
  g_elf_timing_calls.fetch_add((unsigned long long)n);
  return true;
}

// ----------------------------
// C ABI for Scalpel C code
// ----------------------------
struct ElfOnnxHandle {
  ElfSegmentationModelONNX model;

  ElfOnnxHandle(const char* path, const char* accelerator, int max_batch,
                int device_id, int intra_op_threads)
    : model(std::string(path),
            /*intra=*/intra_op_threads,
            /*inter=*/1,
            /*input_name=*/"",
            /*out_bin_name=*/"",
            /*out_multi_name=*/"",
            /*accelerator=*/std::string(accelerator ? accelerator : "cpu"),
            /*max_batch=*/max_batch,
            /*device_id=*/device_id)
  {}
};

extern "C" elf_onnx_handle_t elf_onnx_create_batch_device_threads(
    const char* model_path, const char* accelerator, int max_batch,
    int device_id, int intra_op_threads)
{
  if (!model_path || !model_path[0]) {
    return nullptr;
  }
  try {
    ElfOnnxHandle* h = new (std::nothrow) ElfOnnxHandle(model_path, accelerator,
                                                        max_batch, device_id,
                                                        intra_op_threads);
    return reinterpret_cast<elf_onnx_handle_t>(h);
  } catch (const Ort::Exception& e) {
    std::fprintf(stderr, "[elf onnx] session creation failed: %s\n", e.what());
    return nullptr;
  } catch (const std::exception& e) {
    std::fprintf(stderr, "[elf onnx] session creation failed: %s\n", e.what());
    return nullptr;
  } catch (...) {
    std::fprintf(stderr, "[elf onnx] session creation failed with an unknown error.\n");
    return nullptr;
  }
}

extern "C" elf_onnx_handle_t elf_onnx_create_batch_device(
    const char* model_path, const char* accelerator, int max_batch,
    int device_id)
{
  return elf_onnx_create_batch_device_threads(
      model_path, accelerator, max_batch, device_id, 0);
}

extern "C" elf_onnx_handle_t elf_onnx_create_batch(const char* model_path,
                                                   const char* accelerator,
                                                   int max_batch)
{
  return elf_onnx_create_batch_device(model_path, accelerator, max_batch, 0);
}

extern "C" elf_onnx_handle_t elf_onnx_create(const char* model_path, const char* accelerator)
{
  return elf_onnx_create_batch(model_path, accelerator, 1);
}

extern "C" int elf_onnx_max_batch(elf_onnx_handle_t h)
{
  if (!h) {
    return 0;
  }
  return reinterpret_cast<ElfOnnxHandle*>(h)->model.max_batch();
}

extern "C" void elf_onnx_destroy(elf_onnx_handle_t h)
{
  if (!h) {
    return;
  }
  ElfOnnxHandle* hh = reinterpret_cast<ElfOnnxHandle*>(h);
  delete hh;
}

extern "C" int elf_onnx_set_decode_mode(elf_onnx_handle_t h, int mode)
{
  if (!h) {
    return ELF_ONNX_BADARG;
  }
  ElfOnnxHandle* hh = reinterpret_cast<ElfOnnxHandle*>(h);
  if (mode == ELF_ONNX_DECODE_RAW_ARGMAX) {
    hh->model.set_decode_mode(DecodeMode::RAW_ARGMAX);
    return ELF_ONNX_OK;
  }
  if (mode == ELF_ONNX_DECODE_HEAVY_POSTPROCESS) {
    hh->model.set_decode_mode(DecodeMode::HEAVY_POSTPROCESS);
    return ELF_ONNX_OK;
  }
  return ELF_ONNX_BADARG;
}

extern "C" int elf_onnx_set_decode_threads(elf_onnx_handle_t h, int threads)
{
  if (!h || threads < 1) {
    return ELF_ONNX_BADARG;
  }
  ElfOnnxHandle* hh = reinterpret_cast<ElfOnnxHandle*>(h);
  hh->model.set_decode_threads(threads);
  return ELF_ONNX_OK;
}

extern "C" int elf_onnx_terminate(elf_onnx_handle_t h)
{
  if (!h) {
    return ELF_ONNX_BADARG;
  }
  return reinterpret_cast<ElfOnnxHandle*>(h)->model.terminate_runs()
           ? ELF_ONNX_OK : ELF_ONNX_ERR;
}

extern "C" void elf_onnx_reset_timing(elf_onnx_handle_t h)
{
  if (!h) {
    return;
  }
  reinterpret_cast<ElfOnnxHandle*>(h)->model.reset_timing();
}

extern "C" int elf_onnx_write_timing_report(elf_onnx_handle_t h, const char* path)
{
  if (!h || !path || !path[0]) {
    return ELF_ONNX_BADARG;
  }
  return reinterpret_cast<ElfOnnxHandle*>(h)->model.write_timing_report(path)
           ? ELF_ONNX_OK : ELF_ONNX_ERR;
}

extern "C" int elf_onnx_infer(elf_onnx_handle_t h,
                              const uint8_t* blob, size_t nbytes,
                              RegionTripletC* out, size_t out_cap,
                              size_t* out_count_needed)
{
  if (out_count_needed) {
    *out_count_needed = 0;
  }
  if (!h) {
    return ELF_ONNX_BADARG;
  }
  if (!blob || nbytes == 0) {
    return ELF_ONNX_BADARG;
  }

  ElfOnnxHandle* hh = reinterpret_cast<ElfOnnxHandle*>(h);

  try {
    std::vector<RegionTriplet> v = hh->model.infer(blob, nbytes);

    if (out_count_needed) {
      *out_count_needed = v.size();
    }

    if (!out && out_cap == 0) {
      return ELF_ONNX_OK; // query mode
    }
    if (!out) {
      return ELF_ONNX_BADARG;
    }
    if (v.size() > out_cap) {
      return ELF_ONNX_BUF_TOO_SMALL;
    }

    for (size_t i = 0; i < v.size(); i++) {
      out[i].cls    = v[i].cls;
      out[i].offset = v[i].offset;
      out[i].size   = v[i].size;
    }

    return ELF_ONNX_OK;
  } catch (const std::bad_alloc&) {
    return ELF_ONNX_NOMEM;
  } catch (...) {
    return ELF_ONNX_ERR;
  }
}

extern "C" int elf_onnx_infer_batch(elf_onnx_handle_t h,
                                    const uint8_t* blobs, size_t n,
                                    RegionTripletC** out_triplets,
                                    size_t* out_counts)
{
  if (!h || !out_triplets || !out_counts) {
    return ELF_ONNX_BADARG;
  }
  if (n == 0) {
    return ELF_ONNX_OK;
  }
  if (!blobs) {
    return ELF_ONNX_BADARG;
  }

  ElfOnnxHandle* hh = reinterpret_cast<ElfOnnxHandle*>(h);

  for (size_t i = 0; i < n; i++) {
    out_triplets[i] = NULL;
    out_counts[i] = 0;
  }

  try {
    std::vector<std::vector<RegionTriplet>> res;
    if (!hh->model.infer_batch(blobs, n, res)) {
      return hh->model.last_status();
    }

    for (size_t i = 0; i < n; i++) {
      const std::vector<RegionTriplet>& v = res[i];
      out_counts[i] = v.size();
      if (v.empty()) {
        continue;
      }
      RegionTripletC* arr = (RegionTripletC*)std::malloc(v.size() * sizeof(RegionTripletC));
      if (!arr) {
        for (size_t j = 0; j < i; j++) {
          std::free(out_triplets[j]);
          out_triplets[j] = NULL;
          out_counts[j] = 0;
        }
        out_counts[i] = 0;
        return ELF_ONNX_NOMEM;
      }
      for (size_t t = 0; t < v.size(); t++) {
        arr[t].cls    = v[t].cls;
        arr[t].offset = v[t].offset;
        arr[t].size   = v[t].size;
      }
      out_triplets[i] = arr;
    }

    return ELF_ONNX_OK;
  } catch (const std::bad_alloc&) {
    return ELF_ONNX_NOMEM;
  } catch (...) {
    return ELF_ONNX_ERR;
  }
}
