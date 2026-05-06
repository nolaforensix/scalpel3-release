#!/bin/bash

# Initialize counters
ok=0
bad=0
total=0

echo "🔍 Starting recursive ELF file validation..."
echo "------------------------------------------------"

# Use find to locate all .elf files recursively.
while IFS= read -r f; do
    if [ -f "$f" ]; then
        ((total++))

        # Run the linter, capturing all output to 'out' (stdout and stderr)
        out=$(eu-elflint --gnu-ld "$f" 2>&1)

        # Check the exit status ($?) of the last command (eu-elflint)
        if [ $? -ne 0 ]; then
            # eu-elflint exited with a non-zero status (failure/error)
            ((bad++))
            echo "❌ ERROR: $f"
            # Show the first line of the error output for diagnosis
            echo "   Reason: $(echo "$out" | head -n 1)"
        else
            # eu-elflint exited with status 0 (success/no errors)
            ((ok++))
        fi
    fi
done < <(find . -type f -name "*.elf")

echo "------------------------------------------------"
echo "✨ Test Complete."
echo "Checked $total files."
echo "✅ Valid/OK: $ok"
echo "❌ Invalid/Bad: $bad"
