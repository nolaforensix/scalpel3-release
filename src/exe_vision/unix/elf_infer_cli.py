#!/usr/bin/env python3
import argparse
import os
import sys
import json

import numpy as np
import torch
torch.set_num_threads(1)
torch.set_num_interop_threads(1)
torch.set_grad_enabled(False)

from inference_post_process import ElfSegmentationModel, prepare_blob_for_model, process_bytes_blob, extract_regions


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--model", required=True)
    p.add_argument("--device", default="cpu")
    p.add_argument("--input", required=True, help="Path to 4096-byte blob file")
    args = p.parse_args()

    try:
        with open(args.input, "rb") as f:
            blob = f.read()
    except Exception as e:
        print(f"error: failed to read input: {e}", file=sys.stderr)
        return 2

    try:
        model = ElfSegmentationModel(args.model, args.device)
        class_map = process_bytes_blob(blob, model.model, model.device)
        trips = extract_regions(class_map)
        # Print as lines: "a b c"
        for a, b, c in trips:
            print(f"{int(a)} {int(b)} {int(c)}")
        return 0
    except Exception as e:
        print(f"error: inference failed: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())


