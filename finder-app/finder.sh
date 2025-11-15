#!/bin/sh
filesdir=$1
searchstr=$2

if [ -z "$filesdir" ] || [ -z "$searchstr" ]; then
    exit 1
fi

if [ ! -d "$filesdir" ]; then
    exit 1
fi

num_files=$(grep -rl "$searchstr" "$filesdir" | wc -l)
num_lines=$(grep -ro "$searchstr" "$filesdir" | wc -l)
echo "The number of files are $num_files and the number of matching lines are $num_lines"