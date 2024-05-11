# !/bin/bash

chmod 777 "$1"

if [ "$#" -lt 3 ]; then
    echo "Usage: $0 <file_path> <isolated_dir> <keyword1> [<keyword2> ...]"
    exit 1
fi


file_path=$1
isolated_dir=$2
shift 2

if [ ! -f "$file_path" ]; then
    echo "Error: File '$file_path' does not exist."
    exit 1
fi

# Initialize a flag indicating whether any warnings are found
is_warning_found=0

# Count the number of lines, words, and characters in the file
line_count=$(wc -l < "$file_path") 
word_count=$(wc -w < "$file_path")
char_count=$(wc -m < "$file_path")

if [ $line_count -lt 3 ]; then
    echo "Warning: File '$file_path' has less than 3 lines."
    is_warning_found=1
fi

if [ $word_count -gt 1000 ]; then
    echo "Warning: File '$file_path' has more than 1000 words."
    is_warning_found=1
fi

if [ $char_count -gt 2000 ]; then
    echo "Warning: File '$file_path' has more than 2000 characters."
    is_warning_found=1
fi

if grep -qP '[^\x00-\x7F]' "$file_path"; then
    echo "Warning: File '$file_path' has non-Ascii characters"
    is_warning_found=1
fi


for keyword in "$@"; do
    if grep -q "$keyword" "$file_path"; then
        echo "Warning: File '$file_path' may be potentially malicious (contains keyword: $keyword)."
        is_warning_found=1
        break
    fi
done

if [ $is_warning_found -eq 1 ]; then
    chmod 000 "$file_path"
    mv "$file_path" "$isolated_dir"
    echo "File '$file_path' moved to isolated directory: $isolated_dir"
# else 
#     echo "SAFE"
fi

# Exit with status 0 to indicate successful execution
exit 0


