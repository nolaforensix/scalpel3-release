#!/bin/bash
#
# Script to apply any postprocessing necessary to carved files in /scalpel-output/{timestamp}/VALIDATED/
# Add to this as needed for different types.
#
# Initial version for ZIP files written by Tyler S.
#

# loop through appropriate file-type dirs
change_names () {
    #TODO: add more types (apk, JAR, ODF, XPI, etc.)
    find $1 -type f -name "*.zip" | 
    while read -r zip_file; do
        # check if file contains docx string
        if strings "$zip_file" | grep -q "word/document"; then
            # if found, rename the file with correct extension
            new_file="${zip_file%.zip}.docx"
            echo "Renaming $zip_file to $new_file"
            mv "$zip_file" "$new_file"
        # pptx
        elif strings "$zip_file" | grep -q "ppt/slides"; then
            new_file="${zip_file%.zip}.pptx"
            echo "Renaming $zip_file to $new_file"
            mv "$zip_file" "$new_file"
        # xlsx
        elif strings "$zip_file" | grep -q "xl/workbook"; then
            new_file="${zip_file%.zip}.xlsx"
            echo "Renaming $zip_file to $new_file"
            mv "$zip_file" "$new_file"
        #else
            #echo "$zip_file is not DOCX, PPTX, or XLSX"
        fi
    done
}


# get most recent output
target_dir=$(find ./scalpel-output -mindepth 1 -maxdepth 1 -type d -exec stat -f "%m %N" {} + | sort -n | tail -1 | cut -d' ' -f2-)
# error check
if [[ -z $target_dir ]]; then
    echo "No output directories found"
    exit 0
fi

# find out how many dirs for filetype
num_dirs=$(find "$target_dir/VALIDATED" -maxdepth 1 -type d | grep zip | wc -l)
# iterate through targeted filetype dirs
for (( i=0; i<num_dirs; i++ )); do
    change_names "$target_dir/VALIDATED/zip-$i"
done