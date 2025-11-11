using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Helper;


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

        if (currentDepth > MAX_RECURSION_DEPTH)
        {
            throw new InvalidDataException($"Maximalt kapslingsdjup ({MAX_RECURSION_DEPTH}) överskridet.");
        }

        while (i < buffer.Length)
        {
            if (i + 2 > buffer.Length) break;

            // Denna kod hanterar nu korrekt 1-bytes och 2-bytes taggar 
            // (som 0x5F30), vilket är vanligt i DG-filer.
            int tag = buffer[i++];
            if ((tag & 0x1F) == 0x1F) // Multi-byte tag (första byten)
            {
                int nextByte = buffer[i++];
                tag = (tag << 8) | nextByte;

                // Fortsätt om det är en sällsynt 3+ bytes tagg
                while ((nextByte & 0x80) == 0x80 && i < buffer.Length)
                {
                    nextByte = buffer[i++];
                    tag = (tag << 8) | nextByte;
                }
            }
            // --- KORRIGERAD TAGG-LÄSNING SLUT ---

            Length len = new();
            int length = len.ParseLength(buffer, ref i, false);

            if (length == -1) throw new InvalidDataException("Ogiltigt längdfält.");
            if (i + length > buffer.Length) throw new InvalidDataException($"Tag 0x{tag:X} angav en längd ({length}) som överskrider buffertens slut.");

            byte[] data = new byte[length];
            Array.Copy(buffer, i, data, 0, length);
            i += length;

            var entry = new TagEntry { Tag = tag, Data = data, _length = len };

            // Uppdatera sequenceTags för att inkludera multi-byte taggar om det behövs
            bool isSequence = sequenceTags != null &&
                              (sequenceTags.Contains(tag) ||
                               (tag >= 0x60 && (tag & 0x20) == 0x20)); // Generell regel: 'constructed' bit

            if (isSequence && tag != 0x00) // Undvik oändlig loop på 0x00-padding
            {
                entry.Children = ReadTagData(entry.Data, sequenceTags, currentDepth + 1);
            }
            list.Add(entry);
        }
        return list;
    }
}



public static class TagReaderExtensions
{
    public static List<TagReader.TagEntry> FilterByTag(this List<TagReader.TagEntry> entries, byte tag)
    {
        return entries.Where(e => e.Tag == tag).ToList();
    }

    /// <summary>
    /// Hittar den första noden i en lista som matchar den angivna taggen.
    /// Returnerar null om den inte hittas, för att undvika krascher.
    /// </summary>
    public static TagReader.TagEntry? Find(this List<TagReader.TagEntry> entries, int tag)
    {
        return entries.FirstOrDefault(e => e.Tag == tag);
    }

    /// <summary>
    /// Hittar det första barnet till en nod som matchar den angivna taggen.
    /// Returnerar null om noden är null eller om barnet inte hittas.
    /// </summary>
    public static TagReader.TagEntry? FindChild(this TagReader.TagEntry? entry, int tag)
    {
        if (entry == null) return null;
        return entry.Children.FirstOrDefault(c => c.Tag == tag);
    }


    public static string ToStringFormat(this List<TagReader.TagEntry> tags)
    {
        StringBuilder sb = new();
        ToStringBuilder(tags, sb, 0);
        return sb.ToString();
    }

    public static string ToStringFormat(this TagReader.TagEntry tag)
    {
        StringBuilder sb = new();
        ToStringBuilder([tag], sb, 0);
        return sb.ToString();
    }
    private static void ToStringBuilder(List<TagReader.TagEntry> tags, StringBuilder sb, int indent)
    {
        string indentStr = new(' ', indent * 2);
        foreach (var tag in tags)
        {
            sb.Append($"{indentStr}Tag: 0x{tag.Tag:X2} ");
            if (tag.Children != null && tag.Children.Count > 0)
            {
                sb.AppendLine($" (Children: {tag.Children.Count})");
                // Recursive call
                ToStringBuilder(tag.Children, sb, indent + 1);
            }
            else
            {
                string hex = BitConverter.ToString(tag.Data);
                if (tag.Tag == 0x06) // object identifier
                {
                    hex = tag.Data.ToOidStr();
                }
                int maxLineLength = 64;
                sb.Append($" (Length: {tag.Data.Length})\n{indentStr} Data:\n");
                for (int j = 0; j < hex.Length; j += maxLineLength)
                {
                    if (j > 0) sb.AppendLine();


                    sb.Append($"{indentStr}      {hex.Substring(j, Math.Min(maxLineLength, hex.Length - j))}");
                }
                sb.AppendLine();
            }
        }
    }
}

