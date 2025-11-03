using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

// --- 1. Säkrad TagReader (Dina Klasser + Säkerhetsfixar) ---

public static class TagReader
{
    // SÄKERHETSFIX 3: Definiera ett maximalt djup för rekursion
    private const int MAX_RECURSION_DEPTH = 32;

    public class Length
    {
        public byte[] GetHeaderFormat()
        {
            return lengthHeader;
        }

        public int ParseLength(byte[] data, ref int i, bool allowInvalidLen)
        {
            lengthHeader = [data[i]];
            int length = data[i];
            int oldI = i;
            i++;


            if ((length & 0x80) == 0x80) // longform
            {
                int byteCount = length & ~0x80;
                length = 0;

                // SÄKERHETSFIX 4: Förhindra Integer Overflow
                // En längd som beskrivs av mer än 4 bytes passar inte i en 32-bitars int.
                if (byteCount > 4)
                {
                    return -1; // Ogiltig, för stor längd-av-längd
                }

                if ((byteCount + i) > data.Length)
                {
                    return -1;
                }
                
                // SÄKERHETSFIX 4 (Del 2): Förhindra overflow till negativt tal
                // Om 4 bytes används, får den första byten inte vara > 0x7F
                if (byteCount == 4 && data[i] > 0x7F)
                {
                    return -1; // Längden kommer att överstiga int.MaxValue (2GB)
                }

                for (int ii = 0; ii < byteCount; ii++)
                {
                    length = (length << 8) | data[i];
                    i++;
                }

                lengthHeader = data[oldI..i];
            }

            return length;
        }
        byte[] lengthHeader = [];
    }
    public class TagEntry
    {
        public int Tag { get; set; }
        public byte[] Data { get; set; } = [];
        public Length _length = new();
        public List<TagEntry> Children { get; set; } = [];

        public byte[] GetHeaderFormat()
        {
            byte[] tagBytes = Tag > 0xFF ? new[] { (byte)(Tag >> 8), (byte)Tag } : new[] { (byte)Tag };
            return [.. tagBytes, .. _length.GetHeaderFormat(), .. Data];
        }
    }

    // Uppdaterad signatur för att hantera rekursionsdjup
    public static List<TagEntry> ReadTagData(byte[] buffer, HashSet<int>? sequenceTags = null, int currentDepth = 0)
    {
        var list = new List<TagEntry>();
        int i = 0;

        // SÄKERHETSFIX 3: Kontrollera rekursionsdjup
        if (currentDepth > MAX_RECURSION_DEPTH)
        {
            throw new InvalidDataException($"Maximalt kapslingsdjup ({MAX_RECURSION_DEPTH}) överskridet. Trolig skadlig fil.");
        }

        while (i < buffer.Length)
        {
            if (i + 2 > buffer.Length) break; // Behöver minst 1 tag + 1 längd-byte

            int tag = buffer[i];
            i += 1;

            Length len = new();
            int length = len.ParseLength(buffer, ref i, false);

            if (length == -1)
            {
                throw new InvalidDataException("Ogiltigt längdfält (antingen -1 eller overflow).");
            }
            
            // SÄKERHETSFIX 1 & 2: Kontrollera längd mot buffertstorlek
            // Detta förhindrar BÅDE DoS (OutOfMemoryException) och Buffer Over-read (ArgumentOutOfRangeException).
            if (i + length > buffer.Length)
            {
                throw new InvalidDataException($"Tag 0x{tag:X2} angav en längd ({length}) som överskrider buffertens slut.");
            }

            byte[] data = new byte[length];
            Array.Copy(buffer, i, data, 0, length);
            i += length;

            var entry = new TagEntry { Tag = tag, Data = data, _length = len };

            if (sequenceTags != null && sequenceTags.Contains(tag))
            {
                // Skicka med det ökade djupet i det rekursiva anropet
                entry.Children = ReadTagData(entry.Data, sequenceTags, currentDepth + 1);
            }
            list.Add(entry);
        }

        return list;
    }
}

// --- (Dina övriga klasser förblir oförändrade) ---
public static class TagReaderExtensions
{
    public static List<TagReader.TagEntry> FilterByTag(this List<TagReader.TagEntry> entries, byte tag)
    {
        return entries.Where(e => e.Tag == tag).ToList();
    }

    public static void PrintAll(this List<TagReader.TagEntry> tags, int indent = 0)
    {
        string indentStr = new string(' ', indent * 2);
        foreach (var tag in tags)
        {
            Console.Write($"{indentStr}Tag: 0x{tag.Tag:X2} ");
            if (tag.Children != null && tag.Children.Count > 0)
            {
                Console.WriteLine($" (Children: {tag.Children.Count})");
                tag.Children.PrintAll(indent + 1);
            }
            else
            {
                string hex = BitConverter.ToString(tag.Data);
                int maxLineLength = 64;
                Console.Write($" (Length: {tag.Data.Length})\n{indentStr} Data:\n");
                for (int j = 0; j < hex.Length; j += maxLineLength)
                {
                    if (j > 0) Console.WriteLine();
                    Console.Write($"{indentStr}      {hex.Substring(j, Math.Min(maxLineLength, hex.Length - j))}");
                }
                Console.WriteLine();
            }
        }
    }
}

