#!/bin/bash
# Usage: ./get_byte.sh <index>

hex="87-81-91-01-42-7F-79-46-99-B5-9C-48-63-CF-54-04-C2-6E-A0-7A-F6-CE-47-F2-0C-4F-04-A8-8B-B1-7F-62-CE-D0-61-CE-51-7B-66-05-61-98-0A-74-49-79-14-7F-4E-89-81-73-26-34-96-8E-D4-67-6D-2C-90-0D-32-FB-04-F5-FB-DF-3D-55-2C-F1-04-58-8D-42-44-A0-08-79-00-CA-1B-4E-01-A3-C2-49-6D-10-F5-D0-2E-03-94-7C-F1-99-E6-D0-78-00-01-7D-76-3C-66-CC-37-F1-BF-B9-57-21-97-1A-C3-A3-6A-A5-60-19-DF-3E-26-3D-E2-B3-0D-12-94-6A-57-A4-21-09-80-A2-AA-7A-1F-91-95-EC-85-54-1E-E6-99-02-90-00-8E-08-13-28-30-75-7B-8C-C1-74-90-00"

index=$1

# clean sequence (remove dashes)
hex_clean=$(echo "$hex" | tr -d '-')

# calculate start position in characters (2 chars per byte)
start=$(( (index - 1) * 2 ))

# extract the byte
byte=${hex_clean:$start:2}

echo "$byte"
