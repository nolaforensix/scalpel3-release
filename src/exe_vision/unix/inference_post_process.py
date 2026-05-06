"""
This script contains a collection of functions and data structures for:
[*] Loading ELF data and preparing it for a model trained to classify ELF data within
    hard drive blocks.
[*] Performing inference on the model with the data.
[*] Post-processing the output from the model to eliminate as many false positives
    and false negatives as possible.
[*] Converting a 64x64 class map into [section, offset, size] triplets for Scalpel.

Author: Karley W.  (robustified)
"""

from __future__ import annotations

import sys
import os
from typing import List, Sequence

import faulthandler, sys
faulthandler.enable()

import numpy as np
import torch
try:
    torch.set_num_threads(1)
except Exception:
    pass
try:
    torch.set_num_interop_threads(1)
except Exception:
    pass
torch.set_grad_enabled(False)
import torch.nn as nn
from skimage.measure import label, regionprops  # requires scikit-image
# Note: keep dependencies minimal; plotting libs etc. removed

# ----------------------------
# Constants / label mappings
# ----------------------------

EXPECTED_BYTES = 4096
H = W = 64

multiclass_section_encoding = {
    "non-elf": 0,
    "pointer": 1,
    "symbol": 2,
    "plt": 3,
    "string": 4,
    "dynamic": 5,
    "eh-frame": 6,
    "eh-frame-hdr": 7,
    "text": 8,
    "relocation": 9,
}
index_to_section_mapping = {v: k for k, v in multiclass_section_encoding.items()}

# ----------------------------
# Model
# ----------------------------

class UNet(nn.Module):
    def __init__(self, in_channels: int, binary_out_channels: int, multi_out_channels: int, dropout: float = 0.4):
        super().__init__()

        self.init_conv1 = self.conv_block(in_channels, 64, kernel_size=3, padding=1, dropout=dropout)
        self.init_conv2 = self.conv_block(64, 64, kernel_size=3, padding=1, dropout=dropout)

        # Encoder
        self.enc1 = self.conv_block(64, 128, kernel_size=9, padding=4, dropout=dropout)
        self.enc2 = self.conv_block(128, 256, kernel_size=4, padding=1, stride=2, dropout=dropout)
        self.enc3 = self.conv_block(256, 256, kernel_size=4, padding=1, stride=2, dropout=dropout)

        # Bottleneck
        self.bottleneck = self.conv_block(256, 256, kernel_size=4, padding=1, stride=2, dropout=dropout)

        # Decoder
        self.dec3 = nn.ConvTranspose2d(256, 256, kernel_size=2, stride=2)
        self.dec2 = nn.ConvTranspose2d(512, 256, kernel_size=2, stride=2)
        self.dec1 = nn.ConvTranspose2d(512, 128, kernel_size=2, stride=2)

        # Heads
        self.final_conv_bin = nn.Conv2d(256, binary_out_channels, kernel_size=1)
        self.final_conv_multi = nn.Conv2d(256, multi_out_channels, kernel_size=1)

    def conv_block(self, in_channels, out_channels, kernel_size=3, padding=1, dropout=0.1, stride=1, dilation=1):
        return nn.Sequential(
            nn.Conv2d(in_channels, out_channels, kernel_size=kernel_size, padding=padding, stride=stride, dilation=dilation),
            nn.ReLU(inplace=True),
            nn.Dropout(dropout),
        )

    def forward(self, x: torch.Tensor):
        # Encoder
        x = self.init_conv1(x)
        x = self.init_conv2(x)

        enc1 = self.enc1(x)
        enc2 = self.enc2(enc1)
        enc3 = self.enc3(enc2)

        # Bottleneck
        bottleneck = self.bottleneck(enc3)

        # Decoder with skip connections
        dec3 = self.dec3(bottleneck)
        dec3 = torch.cat((dec3, enc3), dim=1)

        dec2 = self.dec2(dec3)
        dec2 = torch.cat((dec2, enc2), dim=1)

        dec1 = self.dec1(dec2)
        dec1 = torch.cat((dec1, enc1), dim=1)

        out_bin = self.final_conv_bin(dec1)       # (N, 1, 64, 64)
        out_multi = self.final_conv_multi(dec1)   # (N, C, 64, 64)
        return out_bin, out_multi


# ----------------------------
# Checkpoint Loading (robust)
# ----------------------------

def _load_checkpoint_into_model(model: nn.Module, checkpoint_path: str, device: torch.device) -> None:
    """
    Accepts:
      - {'state_dict': ...}
      - plain state_dict
      - whole nn.Module (extract state_dict)
    """
    obj = torch.load(checkpoint_path, map_location=device)
    if isinstance(obj, dict) and "state_dict" in obj:
        model.load_state_dict(obj["state_dict"])
    elif isinstance(obj, dict) and all(isinstance(k, str) for k in obj.keys()):
        model.load_state_dict(obj)
    elif isinstance(obj, nn.Module):
        model.load_state_dict(obj.state_dict())
    else:
        raise RuntimeError(f"Unrecognized checkpoint format at {checkpoint_path!r}")


# ----------------------------
# Post-processing helpers
# ----------------------------

def remove_small_elf_blobs(out_mask: np.ndarray, region, min_bbox_height=2, max_bbox_width=32, verbose=False) -> bool:
    minr, minc, maxr, maxc = region.bbox
    bbox_height = maxr - minr
    bbox_width = maxc - minc

    if bbox_height >= min_bbox_height and bbox_width <= max_bbox_width:
        is_surrounded_by_nonelf = True
        region_coords_set = set(map(tuple, region.coords))
        for r, c in region.coords:
            for dr, dc in [(-1, 0), (1, 0), (0, -1), (0, 1)]:
                nr, nc = r + dr, c + dc
                if not (0 <= nr < out_mask.shape[0] and 0 <= nc < out_mask.shape[1]):
                    continue
                if (nr, nc) in region_coords_set:
                    continue
                if out_mask[nr, nc] != 0:
                    is_surrounded_by_nonelf = False
                    break
            if not is_surrounded_by_nonelf:
                break

        if is_surrounded_by_nonelf:
            for (r, c) in region.coords:
                out_mask[r, c] = 0
            return True

    if bbox_width < 15 and bbox_height >= 2:
        for (r, c) in region.coords:
            out_mask[r, c] = 0
        return True

    return False


def extend_section(out_mask: np.ndarray, region, fill_class: int) -> None:
    """
    Extends a region horizontally to cover the full width for all rows in the region.
    First/last rows preserve initial/terminal columns.
    """
    H_, W_ = out_mask.shape
    coords = region.coords
    if len(coords) < 2:
        return

    row_dict = {}
    for r, c in coords:
        row_dict.setdefault(r, []).append(c)

    min_row = min(row_dict.keys())
    max_row = max(row_dict.keys())

    for r, cols in row_dict.items():
        if not cols:
            continue
        if r == min_row:
            start_col = min(cols)
            out_mask[r, start_col:] = fill_class
        elif r == max_row:
            end_col = max(cols)
            out_mask[r, :end_col + 1] = fill_class
        else:
            out_mask[r, :] = fill_class


def remove_irregular_sections(mask: np.ndarray, threshold=0.25, min_height=15, verbose=False) -> np.ndarray:
    output_mask = mask.copy()
    classes = np.unique(mask)
    non_zero = classes[classes != 0]

    for cls in non_zero:
        class_mask = (mask == cls)
        labeled = label(class_mask, connectivity=2)
        regions = regionprops(labeled)

        for region in regions:
            minr, minc, maxr, maxc = region.bbox
            bbox_height = maxr - minr
            if bbox_height <= min_height:
                continue

            bbox = output_mask[minr:maxr, minc:maxc]
            total_pixels = bbox.size
            class_0_pixels = np.sum(bbox == 0)
            proportion = class_0_pixels / total_pixels if total_pixels > 0 else 0.0

            if proportion > threshold:
                for (r, c) in region.coords:
                    output_mask[r, c] = 0
    return output_mask


def remove_noisy_regions(mask: np.ndarray, max_embedded_regions=10, max_embedded_area_ratio=0.3, verbose=False) -> np.ndarray:
    output_mask = mask.copy()
    classes = np.unique(mask)

    for cls in classes:
        if cls == 0:
            continue
        class_mask = (mask == cls)
        labeled = label(class_mask, connectivity=2)
        regions = regionprops(labeled)

        for region in regions:
            region_coords = region.coords
            total_pixels = len(region_coords)

            minr, minc, maxr, maxc = region.bbox
            region_bbox = mask[minr:maxr, minc:maxc]

            embedded_mask = region_bbox != cls
            embedded_labeled = label(embedded_mask, connectivity=2)
            embedded_regions = regionprops(embedded_labeled)

            num_embedded = 0
            total_embedded_pixels = 0

            for er in embedded_regions:
                er_minr, er_minc, er_maxr, er_maxc = er.bbox
                touches_boundary = (
                    er_minr == 0 or er_minc == 0 or
                    er_maxr == region_bbox.shape[0] or er_maxc == region_bbox.shape[1]
                )
                if touches_boundary:
                    continue
                num_embedded += 1
                total_embedded_pixels += er.area

            ratio = (total_embedded_pixels / total_pixels) if total_pixels > 0 else 0.0
            if num_embedded > max_embedded_regions or ratio > max_embedded_area_ratio:
                for (r, c) in region_coords:
                    output_mask[r, c] = 0
    return output_mask


def handle_nonelf_holes(out_mask: np.ndarray, min_bbox_height=4, bbox_width_threshold=32, verbose=False) -> np.ndarray:
    output_mask = out_mask.copy()
    classes = np.unique(output_mask)
    elf_classes = classes[classes != 0]

    for cls in elf_classes:
        class_mask = (output_mask == cls)
        labeled_class = label(class_mask, connectivity=1)
        regions = regionprops(labeled_class)

        for region in regions:
            minr, minc, maxr, maxc = region.bbox
            section_bbox = output_mask[minr:maxr, minc:maxc]

            nonelf_labeled = label(section_bbox == 0, connectivity=1)
            nonelf_regions = regionprops(nonelf_labeled)

            max_hole_w = 0
            for ner in nonelf_regions:
                r0, c0, r1, c1 = ner.bbox
                bbox_h = r1 - r0
                bbox_w = c1 - c0
                touches_boundary = (
                    r0 == 0 or c0 == 0 or r1 == section_bbox.shape[0] or c1 == section_bbox.shape[1]
                )
                if not touches_boundary:
                    max_hole_w = max(max_hole_w, bbox_w)

            if max_hole_w > bbox_width_threshold:
                for (r, c) in region.coords:
                    output_mask[r, c] = 0
                continue

            for ner in nonelf_regions:
                r0, c0, r1, c1 = ner.bbox
                bbox_h = r1 - r0
                bbox_w = c1 - c0
                if bbox_h >= min_bbox_height and bbox_w <= bbox_width_threshold:
                    neighbors = set()
                    for (rr, cc) in ner.coords:
                        for dr, dc in [(-1, 0), (1, 0), (0, -1), (0, 1)]:
                            nr, nc = rr + dr, cc + dc
                            if 0 <= nr < section_bbox.shape[0] and 0 <= nc < section_bbox.shape[1]:
                                neighbors.add(section_bbox[nr, nc])
                    neighbors.discard(0)
                    if len(neighbors) == 1:
                        fill_class = next(iter(neighbors))
                        for (rr, cc) in ner.coords:
                            output_mask[minr + rr, minc + cc] = fill_class

    return output_mask


def shape_based_postprocess(pred_mask: np.ndarray,
                            min_fill_ratio=0.25,
                            max_aspect_ratio=1.3,
                            min_bbox_width=4,
                            verbose=False) -> np.ndarray:
    out_mask = pred_mask.copy()
    out_mask = remove_noisy_regions(out_mask, verbose=verbose)

    classes = np.unique(pred_mask)
    elf_classes = classes[classes != 0]

    for cls in elf_classes:
        class_mask = (out_mask == cls)
        labeled = label(class_mask, connectivity=2)
        regions = regionprops(labeled)

        for region in regions:
            minr, minc, maxr, maxc = region.bbox
            bbox_h = maxr - minr
            bbox_w = maxc - minc
            bbox_area = bbox_h * bbox_w
            area = region.area

            if remove_small_elf_blobs(out_mask, region, verbose=verbose):
                continue

            if bbox_w < min_bbox_width:
                for (r, c) in region.coords:
                    out_mask[r, c] = 0
                continue

            fill_ratio = (area / bbox_area) if bbox_area > 0 else 0.0
            if fill_ratio < min_fill_ratio:
                for (r, c) in region.coords:
                    out_mask[r, c] = 0
                continue

            ar = (bbox_h / bbox_w) if bbox_w > 0 else float("inf")
            if ar > max_aspect_ratio:
                for (r, c) in region.coords:
                    out_mask[r, c] = 0
                continue

            extend_section(out_mask, region, cls)

        # second pass after extend
        class_mask = (out_mask == cls)
        relabeled = label(class_mask, connectivity=2)
        merged_regions = regionprops(relabeled)
        for mreg in merged_regions:
            extend_section(out_mask, mreg, cls)

    out_mask = handle_nonelf_holes(out_mask, verbose=verbose)
    out_mask = remove_irregular_sections(out_mask, verbose=verbose)
    return out_mask


# ----------------------------
# Inference utilities
# ----------------------------

def prepare_blob_for_model(blob_bytes: bytes, device: torch.device) -> torch.Tensor:
    """
    Coerce to exactly 4096 bytes (pad/truncate) and produce (1,1,64,64) float32 tensor in [0,1].
    """
    if not isinstance(blob_bytes, (bytes, bytearray, memoryview)):
        blob_bytes = bytes(blob_bytes)

    n = len(blob_bytes)
    if n < EXPECTED_BYTES:
        blob_bytes = blob_bytes + b"\x00" * (EXPECTED_BYTES - n)
    elif n > EXPECTED_BYTES:
        blob_bytes = blob_bytes[:EXPECTED_BYTES]

    arr = np.frombuffer(blob_bytes, dtype=np.uint8).reshape((H, W))
    arr = arr.astype(np.float32) / 255.0
    tensor = torch.from_numpy(arr).unsqueeze(0).unsqueeze(0).to(device)  # (1,1,64,64)
    return tensor


def process_bytes_blob(blob_bytes: bytes, model: nn.Module, device: torch.device) -> np.ndarray:
    """
    Runs model inference + simple numeric stabilization + post-processing.
    Returns a (64,64) int map of predicted classes.
    """
    x = prepare_blob_for_model(blob_bytes, device)
    with torch.no_grad():
        out_bin, logits = model(x)  # logits: (1, C, 64, 64)
        # numeric stabilization for softmax
        m = logits.amax(dim=1, keepdim=True)
        probs = torch.softmax(logits - m, dim=1)
        pred = torch.argmax(probs, dim=1).squeeze(0).to("cpu").numpy().astype(np.int16)
    post = shape_based_postprocess(pred, verbose=False)
    return post


def extract_regions(class_map: np.ndarray) -> List[List[int]]:
    """
    Flatten row-major and emit [class, offset, size] runs over 4096 elements.
    """
    flat = class_map.reshape(-1)
    res: List[List[int]] = []

    start = 0
    cur = int(flat[0])
    for i in range(1, flat.size):
        v = int(flat[i])
        if v != cur:
            res.append([int(cur), int(start), int(i - start)])
            start, cur = i, v

    res.append([int(cur), int(start), int(flat.size - start)])
    return res


def infer_regions_from_data(blob_bytes: bytes, model: nn.Module, device: torch.device) -> List[List[int]]:
    class_map = process_bytes_blob(blob_bytes, model, device)
    return extract_regions(class_map)


# ----------------------------
# Public wrapper used by C
# ----------------------------

class ElfSegmentationModel:
    def __init__(self, model_path: str, device_str: str):
        self.device = torch.device(device_str)
        self.model = UNet(in_channels=1, binary_out_channels=1, multi_out_channels=10).to(self.device)
        _load_checkpoint_into_model(self.model, model_path, self.device)
        self.model.eval()
        torch.set_grad_enabled(False)

    def infer(self, blob_bytes: bytes) -> List[List[int]]:
        """
        Returns a Python list of [int, int, int] triplets.
        Never raises; on error returns [].
        """
        try:
            class_map = process_bytes_blob(blob_bytes, self.model, self.device)
            triplets = extract_regions(class_map)
            # Ensure pure Python ints (not numpy types)
            return [[int(a), int(b), int(c)] for (a, b, c) in triplets]
        except Exception as e:
            import traceback
            print("infer() exception:", e, file=sys.stderr)
            traceback.print_exc()
            return []


# ----------------------------
# Optional module self-test
# ----------------------------

# if __name__ == "__main__":
#     # Quick sanity test (requires an existing checkpoint path)
#     ckpt = os.environ.get("ELF_SEGMENT_CKPT", "exe_vision/unix/segmentation_model-state.pth")
#     device = "cuda" if torch.cuda.is_available() else "cpu"
#     try:
#         model = ElfSegmentationModel(ckpt, device)
#         fake = os.urandom(4096)
#         out = model.infer(fake)
#         print(f"Triplets returned: {len(out)}; head={out[:5]}")
#     except Exception as e:
#         print("Self-test failed:", e)
#         raise