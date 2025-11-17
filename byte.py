#!/usr/bin/env python3
import sys

# Usage: python get_byte.py <index>

hex_str = "6F-81-E2-30-81-DF-30-0D-06-09-2A-86-48-86-F7-0D-01-01-01-05-00-03-81-CD-00-30-81-C9-02-81-C1-00-D9-7E-BC-62-55-06-98-18-16-40-D3-C0-BF-A6-50-56-9F-81-21-A1-CE-2E-E0-0B-3B-C0-6C-96-2D-E6-70-3A-33-E3-A9-CB-CC-8C-AD-95-7B-20-DF-99-3A-9C-2C-0A-42-42-72-6F-8D-65-F9-C5-19-2A-B5-B7-BD-9F-F4-97-71-75-51-C7-95-AC-38-DF-27-FA-06-18-41-89-26-66-D4-F0-0F-26-A8-9B-C7-5D-7E-60-31-24-B1-BB-F3-04-B4-15-E7-5D-99-28-4A-17-7B-FE-44-61-E9-00-0C-0C-39-BF-88-01-1F-B8-19-BF-5E-3E-AF-6C-5C-13-44-80-EF-7C-AD-79-B9-55-26-A9-94-97-0D-72-DD-0F-54-8D-E1-DB-89-1C-25-68-0D-6E-A0-89-77-FF-8F-83-43-43-A3-D3-A9-BC-46-E3-5F-7C-FA-7F-DB-DB-62-A0-35-0E-6C-46-3C-26-BA-17-F8-9E-EE-4F-E8-3E-0D-D6-14-A3-02-03-01-00-01"
if len(sys.argv) != 2:
    print("Usage: python get_byte.py <index>")
    sys.exit(1)

index = int(sys.argv[1])
hex_clean = hex_str.replace("-", "")
start = (index - 1) * 2
byte = hex_clean[start:start + 2]

print(byte)
