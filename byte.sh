#!/bin/bash
# Usage: ./get_byte.sh <index>

hex="87-81-91-01-C9-A2-EE-96-13-CD-D0-FE-36-B7-E5-7D-2B-77-BF-5C-99-10-60-A6-E9-61-17-FA-AD-42-EB-8D-C0-36-99-07-23-47-58-06-21-BC-F4-E9-A6-0C-10-D1-BD-B5-3E-EF-F0-64-93-8C-2E-5F-86-5C-B7-0C-00-BF-4B-82-AF-DC-A2-09-2C-E0-D0-45-12-99-7D-E7-FC-28-E4-B1-B6-5C-D2-D4-D6-15-F5-29-5A-FB-F3-FA-B1-83-35-16-4C-01-9A-51-B1-2F-70-11-69-5C-7F-0E-5F-92-38-58-92-11-EE-F3-D4-E1-11-58-C8-5E-15-33-E7-EC-C5-BA-A6-81-9F-E3-1D-63-7A-91-8D-83-22-CC-87-AF-0D-7D-F7-31-99-02-90-00-8E-08-C5-4F-3D-72-91-81-D7-6F"

index=$1

# clean sequence (remove dashes)
hex_clean=$(echo "$hex" | tr -d '-')

# calculate start position in characters (2 chars per byte)
start=$(( (index - 1) * 2 ))

# extract the byte
byte=${hex_clean:$start:2}

echo "$byte"
