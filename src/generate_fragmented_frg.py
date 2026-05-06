import sys
import random
import re
import math
import os

# --- Configuration ---
FRAG_DIRECTIVES = ["OUTOFORDER", "MISSING", "GUARANTEED_GAP"]
FRAG_DIRECTIVES_NON_MISSING = ["OUTOFORDER", "GUARANTEED_GAP"]
FRAG_DIRECTIVE_MISSING = "MISSING"

# --- Set BASE_DATA_PATH to current directory for relative paths ---
BASE_DATA_PATH = ""

def get_file_block_count(file_path, blocksize):
    """
    Determines the total number of blocks in a file by reading its actual size.
    """
    full_path = os.path.join(BASE_DATA_PATH, file_path)

    try:
        size = os.path.getsize(full_path)

        if size == 0:
            print(f"CRITICAL WARNING: File size for {full_path} is 0 bytes. Assuming 0 blocks.")
            return 0

        numblocks = math.ceil(size / blocksize)

        return int(max(1, numblocks))
    except FileNotFoundError:
        # File not found at the specified path. This results in 0 blocks.
        return 0
    except Exception as e:
        print(f"Error reading file size for {file_path}: {e}")
        return 0

def parse_global_config(lines):
    """Parses BLOCKSIZE and HEADERBLOCKS from the global configuration section."""
    config = {'BLOCKSIZE': 512, 'HEADERBLOCKS': 2}

    for line in lines:
        stripped = line.strip().upper()
        if stripped.startswith('BLOCKSIZE:'):
            match = re.search(r'BLOCKSIZE:\s*(\d+)', line, re.IGNORECASE)
            if match:
                config['BLOCKSIZE'] = int(match.group(1))
        elif stripped.startswith('HEADERBLOCKS:'):
            match = re.search(r'HEADERBLOCKS:\s*(\d+)', line, re.IGNORECASE)
            if match:
                config['HEADERBLOCKS'] = int(match.group(1))
        elif stripped.startswith('FILE:'):
            break

    return config

def get_safe_single_block(numblocks, headerblocks, frag_type):
    """
    Guarantees a valid single block number.
    """
    min_block = headerblocks
    if frag_type == "GAP" or frag_type == "GUARANTEED_GAP":
        max_block = numblocks - 2
    else:
        max_block = numblocks - 1

    if max_block < min_block:
        return None

    safe_block = random.randint(min_block, min(max_block, min_block + 10))
    return str(safe_block)

def get_valid_block_span_for_frag(file_def, headerblocks, frag_type, potential_gap_targets):
    """
    Calculates a valid block span (start-end) for fragmentation, including fallbacks.
    """
    numblocks = file_def['numblocks']
    min_block = headerblocks

    if frag_type == "GAP" or frag_type == "GUARANTEED_GAP":
        max_end_block = numblocks - 2
    else:
        max_end_block = numblocks - 1

    if max_end_block < min_block:
        return None

    if frag_type == "GUARANTEED_GAP":

        if not potential_gap_targets:
            return get_safe_single_block(numblocks, headerblocks, frag_type)

        target_file_def = random.choice(potential_gap_targets)
        gap_size = target_file_def['numblocks']

        if gap_size == 0:
            return get_safe_single_block(numblocks, headerblocks, frag_type)

        max_start_block = max_end_block - gap_size + 1

        if max_start_block < min_block:
            return get_safe_single_block(numblocks, headerblocks, frag_type)

        start_block = random.randint(min_block, max_start_block)
        end_block = start_block + gap_size - 1

        file_def['gap_target'] = target_file_def['path']
        return f"{start_block}-{end_block}"

    elif frag_type in ["OUTOFORDER", "MISSING"]:
        max_span_size = 5

        start_block = random.randint(min_block, max_end_block)
        max_possible_end = min(max_end_block, start_block + max_span_size - 1)

        if max_possible_end >= start_block:
            end_block = random.randint(start_block, max_possible_end)
            return f"{start_block}-{end_block}"
        else:
            return get_safe_single_block(numblocks, headerblocks, frag_type)

    return get_safe_single_block(numblocks, headerblocks, frag_type)

def process_frg_file(input_path, output_path, frag_types_str, frag_percent, missing_percent):
    """
    Main logic to parse, process, and reassemble the FRAG file.
    """
    try:
        with open(input_path, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"Error: Input file not found at {input_path}")
        return

    # 1. Parse Global Configuration
    global_config = parse_global_config(lines)
    headerblocks = global_config['HEADERBLOCKS']
    blocksize = global_config['BLOCKSIZE']

    print(f"Detected HEADERBLOCKS: {headerblocks}")
    print(f"Detected BLOCKSIZE: {blocksize}")

    # 2. Setup Trackers
    files_to_process = []
    total_files = 0
    total_fragmentable_candidates = 0
    files_with_missing_blocks = 0
    files_fragmented = 0
    files_unfragmentable_size = 0 # Tracks files with numblocks <= HEADERBLOCKS

    frag_types = set(s.strip().upper() for s in frag_types_str.split(','))
    frag_prob = max(0.0, min(100.0, frag_percent)) / 100.0
    missing_prob = max(0.0, min(100.0, missing_percent)) / 100.0
    current_type = None

    # 3. First Pass: Identify all FILE: definitions, determine block count
    for line in lines:
        stripped_line = line.strip()

        if stripped_line.startswith('#') and len(stripped_line.split()) >= 2:
            current_type = stripped_line.split()[1].upper()

        elif stripped_line.upper().startswith('FILE:'):
            total_files += 1
            match = re.search(r'FILE:\s*(.+)', line, re.IGNORECASE)
            file_path_arg = match.group(1).strip()

            if file_path_arg.startswith('"') and file_path_arg.endswith('"'):
                file_path = file_path_arg[1:-1]
            else:
                file_path = file_path_arg

            numblocks = get_file_block_count(file_path, blocksize)

            files_to_process.append({
                'file_line': line,
                'path': file_path,
                'type': current_type,
                'numblocks': numblocks,
                'directives': [],
                'original_directives': []
            })

        elif files_to_process and stripped_line.upper().startswith(('MISSING:', 'OUTOFORDER:', 'GAP:', 'DUPLICATE:', 'FRAGMENTED:')):
            files_to_process[-1]['original_directives'].append(stripped_line)

    # --- FATAL ERROR CHECK ---
    # The number of files too small (<= HEADERBLOCKS) includes files that were not found (numblocks=0).
    # If every file is deemed too small, the data access has fundamentally failed.
    files_unfragmentable_size_check = sum(1 for f in files_to_process if f['numblocks'] <= headerblocks)

    if files_unfragmentable_size_check == total_files and total_files > 0:
        print("\n❌ FATAL ERROR: Data Access Failure")
        print("The script failed to find any files large enough to fragment (numblocks > HEADERBLOCKS).")
        print("This typically means the file paths in the .frg file are incorrect relative to your current directory.")
        print(f"Total files processed: {total_files}")
        sys.exit(1)
    # -------------------------

    # 4. Second Pass: Decide fragmentation and generate directives

    potential_gap_targets = [
        f for f in files_to_process
        if f['numblocks'] > headerblocks and
           f['numblocks'] <= 50 and
           not any('FRAGMENTED: TRUE' in d.upper() for d in f['original_directives']) and
           not any(any(d.upper().startswith(f'{frag}:') for frag in ["OUTOFORDER", "GAP", "MISSING"]) for d in f['original_directives'])
    ]

    for file_def in files_to_process:
        is_target_type = file_def['type'] in frag_types

        # Check for existing, conflicting fragmentation
        has_fragmented_true = any('FRAGMENTED: TRUE' in d.upper() for d in file_def['original_directives'])
        has_custom_frag = any(any(d.upper().startswith(f'{f}:') for f in ["OUTOFORDER", "GAP", "MISSING"])
                              for d in file_def['original_directives'])

        # --- Handle Existing Fragmentation (and count) ---
        if has_fragmented_true or has_custom_frag:
            file_def['directives'].extend(file_def['original_directives'])
            files_fragmented += 1
            if any('MISSING:' in d.upper() for d in file_def['directives']):
                files_with_missing_blocks += 1
            continue

        # --- Check if the file is a candidate for NEW fragmentation ---

        if file_def['numblocks'] <= headerblocks:
            # Not eligible: Too small or file not found (numblocks=0)
            file_def['directives'].append("# File too small for fragmentation after HEADERBLOCKS")
            files_unfragmentable_size += 1

        elif not is_target_type:
            # Not eligible: Not a target type
            pass

        else:
            total_fragmentable_candidates += 1

            # --- Targeted Random Chance Check (Only run for viable candidates) ---
            if random.random() < frag_prob:

                # 4d. Determine Directive Type (MISSING vs. non-MISSING)
                if random.random() < missing_prob:
                    frag_type = FRAG_DIRECTIVE_MISSING
                else:
                    frag_type = random.choice(FRAG_DIRECTIVES_NON_MISSING)

                block_span = get_valid_block_span_for_frag(file_def, headerblocks, frag_type, potential_gap_targets)

                if block_span:
                    output_frag_type = "GAP" if frag_type == "GUARANTEED_GAP" else frag_type

                    file_def['directives'].append(f"{output_frag_type}: {block_span}")

                    if frag_type == "GUARANTEED_GAP" and 'gap_target' in file_def:
                        file_def['directives'].append(f"# GAP size guarantees space for: {file_def['gap_target']}")

                    files_fragmented += 1
                    if frag_type == "MISSING":
                        files_with_missing_blocks += 1

                else:
                    file_def['directives'].append("# Fragmentation attempt failed (internal constraint failure).")

        # Add explicit FRAGMENTED:FALSE only if not fragmented
        if not any(d.upper().startswith(('MISSING:', 'OUTOFORDER:', 'GAP:', 'FRAGMENTED:TRUE')) for d in file_def['directives']):
             file_def['directives'].append("FRAGMENTED: FALSE")

        # Cleanup directives
        file_def['directives'].extend([d for d in file_def['original_directives']
                                       if not (d.upper().startswith('FRAGMENTED:') or any(d.upper().startswith(f'{f}:') for f in ["OUTOForder", "GAP", "MISSING"]))])

        file_def['directives'] = list(dict.fromkeys(file_def['directives']))


    # 5. Third Pass: Reassemble the file content

    header_end_index = -1
    for i, line in enumerate(lines):
        if line.strip().upper().startswith('FILE:'):
            header_end_index = i
            break

    if header_end_index == -1 and files_to_process:
        print("Error: Could not determine the separation point between global config and FILE: definitions.")
        return

    if header_end_index == -1:
        new_lines = lines
    else:
        new_lines = lines[:header_end_index]

    file_idx = 0
    skip_original_directive = False

    if header_end_index != -1:
        for i in range(header_end_index, len(lines)):
            line = lines[i]
            stripped_line = line.strip()

            if stripped_line.upper().startswith('FILE:'):
                if file_idx < len(files_to_process):
                    file_def = files_to_process[file_idx]

                    new_lines.append(file_def['file_line'])

                    for directive in file_def['directives']:
                        new_lines.append(f"    {directive}\n")

                    file_idx += 1
                    skip_original_directive = True
                else:
                    new_lines.append(line)

            elif skip_original_directive and stripped_line.upper().startswith(('MISSING:', 'OUTOFORDER:', 'GAP:', 'DUPLICATE:', 'FRAGMENTED:')):
                continue

            elif skip_original_directive and not stripped_line:
                skip_original_directive = False
                new_lines.append(line)

            elif skip_original_directive and stripped_line.startswith('#'):
                new_lines.append(line)

            else:
                skip_original_directive = False
                new_lines.append(line)

    # Write the new file
    try:
        with open(output_path, 'w') as f:
            f.writelines(new_lines)

        # --- Output Statistics ---
        total_unfragmented = total_files - files_fragmented

        print("\n--- Fragmentation Statistics ---")
        print(f"Total files processed: {total_files}")
        print(f"Files deemed too small/not found (numblocks <= HEADERBLOCKS): {files_unfragmentable_size}")
        print(f"Files eligible for new fragmentation (Target type, large enough, non-conflicting): {total_fragmentable_candidates}")
        print("-" * 40)
        print(f"Files Fragmented (custom directives or existing FRAGMENTED:TRUE): {files_fragmented}")
        print(f"Files Unfragmented (contiguous): {total_unfragmented}")
        print(f"Files with MISSING blocks (incomplete recovery targets): {files_with_missing_blocks}")

        overall_frag_rate = (files_fragmented / total_files) * 100 if total_files > 0 else 0
        targeted_frag_rate = (files_fragmented / total_fragmentable_candidates) * 100 if total_fragmentable_candidates > 0 else 0

        print(f"\nTargeted fragmentation success rate (against viable pool): {targeted_frag_rate:.2f}%")
        print(f"Overall fragmentation percentage (Fragmented / Total Files): {overall_frag_rate:.2f}%")
        print(f"\n✅ Successfully generated configuration file at: {output_path}")

    except Exception as e:
        print(f"Error writing output file: {e}")

# --- Command Line Interface ---

if __name__ == "__main__":

    BASE_DATA_PATH = ""

    if len(sys.argv) != 6:
        print(f"Usage: python {sys.argv[0]} <input.frg> <output.frg> <frag_types_list> <frag_percent> <missing_percent>")
        print("\nArguments:")
        print("  <frag_types_list>: Comma-separated file type names (e.g., GIF,JPG)")
        print("  <frag_percent>:    Overall percentage of eligible files to fragment (0-100)")
        print("  <missing_percent>: Percentage of *fragmented* files that will specifically use MISSING blocks (0-100)")
        print("\nExample: python script.py in.frg out.frg GIF,JPG 40 10")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    frag_types_csv = sys.argv[3]
    frag_percent_str = sys.argv[4]
    missing_percent_str = sys.argv[5]

    try:
        frag_percent = float(frag_percent_str)
        missing_percent = float(missing_percent_str)
    except ValueError:
        print("Error: Fragmentation and Missing percentages must be numbers.")
        sys.exit(1)

    process_frg_file(input_file, output_file, frag_types_csv, frag_percent, missing_percent)
