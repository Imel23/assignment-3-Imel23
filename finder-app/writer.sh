#!/bin/bash
write_file=$1
write_str=$2

if [ -z "$write_file" ] || [ -z "$write_str" ]; then
    exit 1
fi

mkdir -p "$(dirname "$write_file")"

echo "$write_str" > "$write_file"

if [ $? -ne 0 ]; then
    echo "Error: Could not write to file '$write_file'."
    exit 1
fi