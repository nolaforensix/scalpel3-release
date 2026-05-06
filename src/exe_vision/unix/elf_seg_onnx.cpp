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

#include "elf_seg_onnx.hpp"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <cstring>
#include <set>
#include <string>
#include <array>
#include <unordered_set>
#include <utility>
#include <vector>

#include <onnxruntime_cxx_api.h>

namespace {

static constexpr int EXPECTED_BYTES = 4096;
static constexpr int H = 64;
static constexpr int W = 64;

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
struct ElfSegmentationModelONNX::Impl {
  Ort::Env env;
  Ort::SessionOptions sess_opts;
  Ort::Session session;
  Ort::AllocatorWithDefaultOptions allocator;

  std::string input_name;
  std::string out_bin_name;
  std::string out_multi_name;

  // Runtime-tunable post-processing parameters (defaults are in the struct).
  PostProcParams postproc;

  Impl(const std::string& model_path,
       int intra_op_threads,
       int inter_op_threads,
       const std::string& in_name,
       const std::string& ob,
       const std::string& om,
       const std::string& accelerator)
    : env(ORT_LOGGING_LEVEL_WARNING, "elf_seg"),
      sess_opts(),
      session(nullptr),
      allocator(),
      input_name(),
      out_bin_name(),
      out_multi_name(),
      postproc()
  {
    (void)intra_op_threads;
    (void)inter_op_threads;
    (void)in_name;
    (void)ob;
    (void)om;
    sess_opts.SetIntraOpNumThreads(1);
    sess_opts.SetInterOpNumThreads(1);
    sess_opts.SetExecutionMode(ORT_SEQUENTIAL);
    sess_opts.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_ALL);

    // Append CUDA execution provider if requested.
    // Falls back to CPU automatically if CUDA is unavailable.
    if (accelerator == "cuda") {
      OrtCUDAProviderOptions cuda_opts{};
      cuda_opts.device_id = 0;
      sess_opts.AppendExecutionProvider_CUDA(cuda_opts);
    }

    session = Ort::Session(env, model_path.c_str(), sess_opts);

    // Auto-discover IO names from the model.
    size_t n_in  = session.GetInputCount();
    size_t n_out = session.GetOutputCount();
    if (n_in < 1 || n_out < 2) {
      throw std::runtime_error("Unexpected ONNX model IO count");
    }

    auto in0  = session.GetInputNameAllocated(0, allocator);
    auto out0 = session.GetOutputNameAllocated(0, allocator);
    auto out1 = session.GetOutputNameAllocated(1, allocator);

    input_name     = in0.get();
    out_bin_name   = out0.get();
    out_multi_name = out1.get();
  }

  void set_postproc_params(const PostProcParams& P) noexcept {
    postproc = P;
  }

  const PostProcParams& get_postproc_params() const noexcept {
    return postproc;
  }

  bool run_logits(const float* input_1x1x64x64,
                  size_t input_count,
                  std::vector<float>& out_multi,
                  int& C) noexcept
  {
    try {
      Ort::MemoryInfo meminfo = Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);

      std::vector<int64_t> in_shape = {1, 1, 64, 64};
      Ort::Value in_tensor = Ort::Value::CreateTensor<float>(
        meminfo, const_cast<float*>(input_1x1x64x64),
        input_count,
        in_shape.data(), in_shape.size()
      );

      const char* input_names[] = { input_name.c_str() };
      const char* output_names[] = { out_bin_name.c_str(), out_multi_name.c_str() };

      auto outputs = session.Run(Ort::RunOptions{nullptr},
                                 input_names, &in_tensor, 1,
                                 output_names, 2);

      // outputs[1] = out_multi logits (1,C,64,64)
      Ort::Value& logits_v = outputs[1];
      auto type_info = logits_v.GetTensorTypeAndShapeInfo();
      auto shape = type_info.GetShape();
      if (shape.size() != 4 || shape[0] != 1 || shape[2] != 64 || shape[3] != 64) {
        return false;
      }
      C = (int)shape[1];

      const float* p = logits_v.GetTensorData<float>();
      size_t count = (size_t)C * 64u * 64u;
      out_multi.assign(p, p + count);
      return true;
    } catch (...) {
      return false;
    }
  }
};

ElfSegmentationModelONNX::ElfSegmentationModelONNX(const std::string& model_path,
                                                   int intra_op_threads,
                                                   int inter_op_threads,
                                                   const std::string& input_name,
                                                   const std::string& out_bin_name,
                                                   const std::string& out_multi_name,
                                                   const std::string& accelerator)
{
  pimpl_ = new Impl(model_path, intra_op_threads, inter_op_threads,
                    input_name, out_bin_name, out_multi_name, accelerator);
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

InferMaps ElfSegmentationModelONNX::infer_maps(const uint8_t* blob, size_t nbytes) noexcept
{
  InferMaps out;
  if (!pimpl_ || !blob) return out;

  // ---- Thread-local scratch (one instance per worker thread; reused across calls)
  thread_local std::array<uint8_t, EXPECTED_BYTES> tmp_buf;
  thread_local std::vector<float> input_f;
  thread_local std::vector<float> logits;

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

  // 3) run model -> logits
  int C = 0;
  if (!pimpl_->run_logits(input_f.data(), input_f.size(), logits, C)) return out;
  if (C <= 0) return out;

  out.num_classes = C;

  // 4) argmax logits -> raw_mask
  out.raw_mask.assign((size_t)H * (size_t)W, 0);

  for (int r = 0; r < H; r++) {
    for (int c = 0; c < W; c++) {
      int best_k = 0;
      float best_v =
        logits[(size_t)0 * (size_t)H * (size_t)W + (size_t)r * (size_t)W + (size_t)c];

      for (int k = 1; k < C; k++) {
        float v =
          logits[(size_t)k * (size_t)H * (size_t)W + (size_t)r * (size_t)W + (size_t)c];
        if (v > best_v) { best_v = v; best_k = k; }
      }

      out.raw_mask[(size_t)idx(r, c)] = (int16_t)best_k;
    }
  }

  // 5) postprocess (driven by params)
  out.post_mask = shape_based_postprocess(out.raw_mask, pimpl_->get_postproc_params());

  // 6) RLE triplets of post
  out.triplets = extract_regions_triplets(out.post_mask);
  return out;
}


std::vector<RegionTriplet> ElfSegmentationModelONNX::infer(const uint8_t* blob, size_t nbytes) noexcept
{
  InferMaps maps = infer_maps(blob, nbytes);
  return std::move(maps.triplets);
}