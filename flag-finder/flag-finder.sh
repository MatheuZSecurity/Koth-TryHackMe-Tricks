#!/bin/bash

## https://www.youtube.com/MatheuZSecurity

echo "Finding flags... Please leave this script running in a terminal as this will take a long time."

find / -type f -name "*flag.txt" -o -name ".flag*" -o -name "user.txt" -exec cat {} \; 2>/dev/null > temp_flags.txt

grep -r "THM{" / >> temp_flags.txt 2>/dev/null

if [[ -s temp_flags.txt ]]; then
    echo "All flags found"
else
    echo "No flags found"
fi

sleep 2

clear

echo "Here are your flags."

cat temp_flags.txt
