// elf_seg_onnx.hpp
#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

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
                           const std::string& accelerator = "cpu");

  // Existing API (postprocessed triplets only)
  std::vector<RegionTriplet> infer(const uint8_t* blob, size_t nbytes) noexcept;

  // New API for testing/visualization
  InferMaps infer_maps(const uint8_t* blob, size_t nbytes) noexcept;

  // Runtime override for ablations / integration.
  // Call once after construction (or anytime) to swap the postproc parameter set.
  void set_postproc_params(const PostProcParams& params) noexcept;

  PostProcParams get_postproc_params() const noexcept;

  ~ElfSegmentationModelONNX();

private:
  struct Impl;
  Impl* pimpl_;
};