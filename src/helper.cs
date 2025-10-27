using Encryption;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Logging.Console;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Utilities;
using Serilog;
using Serilog.Sinks.SystemConsole.Themes;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Text.Json;
using Type;
namespace Helper;



public static class MrzUtils
{

    internal class PassportData
    {
        public string document_number { get; set; }
        public string birth_date { get; set; }
        public string expiry_date { get; set; }
    }
    public static byte[] GetMrz(string docNr, string birth, string dateExpire)
    {
        if (File.Exists("mrz.json"))
        {
            string json = File.ReadAllText("mrz.json");

            PassportData data = JsonSerializer.Deserialize<PassportData>(json)!;
            docNr = data.document_number;
            birth = data.birth_date;
            dateExpire = data.expiry_date;
        }

        Log.Info("mrz: " + docNr + " " + birth + " " + dateExpire);

        while (docNr.Length < 9)
            docNr += "<";

        string fullStr = "";
        fullStr += docNr + GetCheckDigit(docNr);
        fullStr += birth + GetCheckDigit(birth);
        fullStr += dateExpire + GetCheckDigit(dateExpire);

        return Encoding.ASCII.GetBytes(fullStr);
    }

    internal static string GetCheckDigit(string s)
    {
        int[] lookupWeight = [7, 3, 1];
        int lookupIndex = 0;
        int sum = 0;

        foreach (char c in s.ToLowerInvariant())
        {
            int asciiCode = (int)c;

            if (asciiCode >= 48 && asciiCode <= 57) // 0-9
            {
                sum += (c - '0') * lookupWeight[lookupIndex];
            }
            else if (asciiCode >= 97 && asciiCode <= 122) // a-z
            {
                sum += (asciiCode - 87) * lookupWeight[lookupIndex]; // 'a' -> 10
            }
            else if (c != '<')
            {
                throw new Exception("Illegal character for check digit");
            }

            lookupIndex = (lookupIndex + 1) % 3;
        }

        return (sum % 10).ToString();
    }

    public static void PrintByteArray(byte[] bytes)
    {
        string hexString = BitConverter.ToString(bytes).Replace("-", " ");
        Console.WriteLine(hexString);
    }

    public static string DecodeOid(byte[] bytes)
    {
        if (bytes.Length == 0) return string.Empty;

        StringBuilder buffer = new();
        int first = bytes[0] / 40;
        int second = bytes[0] % 40;
        buffer.Append($"{first}.{second}");

        int value = 0;
        for (int i = 1; i < bytes.Length; i++)
        {
            int b = bytes[i];
            value = (value << 7) | (b & 0x7F);
            if ((b & 0x80) == 0) // end of subidentifier
            {
                buffer.Append($".{value}");
                value = 0;
            }
        }

        return buffer.ToString();
    }
}

public class AsnInfo(byte tag, byte[] data)
{
    public byte Tag { get; } = tag;
    public byte[] Data { get; } = data;
}

public class ByteReader(byte[] data)
{
    private readonly byte[] _data = data;
    private int _position = 0;

    public int Offset => _position;

    public byte[] ReadBytes(int len)
    {
        var sub = _data[_position..(_position + len)];
        _position += len;
        return sub;
    }

    public int ReadInt(int len)
    {
        byte[] list = ReadBytes(len);
        int ret = 0;
        for (int i = 0; i < list.Length; i++)
        {
            ret |= list[i] << ((list.Length - i - 1) * 8);
        }
        return ret;
    }

    public string ReadString(int len)
    {
        string s = Encoding.ASCII.GetString(_data, _position, len);
        _position += len;
        return s;
    }

    public void PaddingNext(int len) => _position += len;

    public bool HasRemaining() => _position < _data.Length;

    public int ReadLength()
    {
        int first = ReadInt(1);
        if (first < 0x80) return first;

        int numBytes = first & 0x7F;


        // if (numBytes > 4)
        //     throw new InvalidOperationException("Unsupported ASN.1 lenght (to big)");

        // byte[] lengthBytes = ReadBytes(numBytes);
        // int length = 0;
        // foreach (byte b in lengthBytes)
        //     length = (length << 8) | b;
        // return length;
        return ReadInt(numBytes);
    }

    public AsnInfo ReadASN1()
    {
        byte tag = (byte)ReadInt(1);
        int len = ReadLength();
        byte[] data = ReadBytes(len);
        return new AsnInfo(tag, data);
    }
}

public static class HexUtils
{
    public static string HexEncode(byte[] bytes) => BitConverter.ToString(bytes).Replace("-", "");

    public static byte[] HexDecode(string hexString)
    {
        if (hexString.Length % 2 != 0)
            throw new FormatException("Hex string must have an even number of characters.");

        byte[] result = new byte[hexString.Length / 2];
        for (int i = 0; i < hexString.Length; i += 2)
        {
            string hexPair = hexString.Substring(i, 2);
            result[i / 2] = Convert.ToByte(hexPair, 16);
        }
        return result;
    }
}



public static class Log
{

    private enum LogType
    {
        Info,
        Warning,
        Error,
    }

    public static void Info(string message, [CallerFilePath] string file = "",
        [CallerLineNumber] int line = 0,
        [CallerMemberName] string member = "")
    {  // Color the file/line/member prefix
        InternalLog(message, LogType.Info, file, line, member);
    }
    public static void Warn(string message, [CallerFilePath] string file = "",
        [CallerLineNumber] int line = 0,
        [CallerMemberName] string member = "")
    {
        InternalLog(message, LogType.Warning, file, line, member);
    }
    public static void Error(string message,
        [CallerFilePath] string file = "",
        [CallerLineNumber] int line = 0,
        [CallerMemberName] string member = "")
    {
        InternalLog(message, LogType.Error, file, line, member);
    }

    private static void InternalLog(string message, LogType logType,
        [CallerFilePath] string file = "",
        [CallerLineNumber] int line = 0,
        [CallerMemberName] string member = "")

    {
        var logMeta = logType switch
        {
            LogType.Info => (ConsoleColor.Green, "Info"),
            LogType.Warning => (ConsoleColor.Yellow, "Warning"),
            LogType.Error => (ConsoleColor.Red, "Error"),
            _ => throw new Exception("Undefined LogType: " + logType),
        };
        Console.Write($"{file}({line})\n");
        Console.ResetColor();
        Console.ForegroundColor = logMeta.Item1;
        Console.Write(logMeta.Item2 + ": ");

        Console.ResetColor();

        // Log the actual message normally
        Console.WriteLine(message + "\n");
    }
}
public class RandomNumberProvider
{
    private readonly RandomNumberGenerator _generator = RandomNumberGenerator.Create();
    public byte[] GetNextBytes(int count)
    {
        byte[] bytes = new byte[count];
        _generator.GetBytes(bytes);
        return bytes;
    }
}

public class ParameterUtil
{
    public static DomainParameter getParameterById(int id)
    {
        return id switch
        {
            16 => DomainParameter.BrainpoolP384r1,
            _ => throw new NotImplementedException("Parameter ID not implemented"),
        };

    }
}

public static class Util
{
    public static byte[] AlignData(byte[] input, int aligment)
    {
        var diffLen = aligment - ((input.Length + 1) % aligment);
        byte padTag = 0x80;
        byte[] padding = [padTag, .. new byte[diffLen]];
        return [.. input, .. padding];
    }
}

public static class BIgIntegerExtension
{
    public static byte[] ToPaddedLength(this BigInteger value, int length)
    {

        var sscBA = value.ToByteArray(isUnsigned: true);
        var remainder = length - sscBA.Length;
        return new byte[remainder].Concat(sscBA).ToArray();
    }
}



public static class TagReader
{
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

                // how many bytes 
                int byteCount = length & ~0x80;
                length = 0;

                // INVALID TAG
                if ((byteCount + i) > data.Length)
                {
                    return -1;
                }


                for (int ii = 0; ii < byteCount; ii++)
                {
                    length = (length << 8) | data[i];
                    i++;
                }




                lengthHeader = data[oldI..i];
                // for now
            }
            // the length is too big, so must be wrong tag

            return length;
        }
        byte[] lengthHeader = [];
    }
    public class TagEntry
    {
        public int Tag { get; set; }           // 1- or 2-byte tags
        public byte[] Data { get; set; } = [];

        public Length _length = new();
        public List<TagEntry> Children { get; set; } = [];

        public byte[] GetHeaderFormat()
        {
            byte[] tagBytes = Tag > 0xFF ? new[] { (byte)(Tag >> 8), (byte)Tag } : new[] { (byte)Tag };
            return [.. tagBytes, .. _length.GetHeaderFormat(), .. Data];
        }
    }

    public static List<TagEntry> ReadTagData(byte[] buffer, HashSet<int>? sequenceTags = null)
    {
        var list = new List<TagEntry>();
        int i = 0;


        while (i < buffer.Length)
        {
            if (i + 2 > buffer.Length) break;


            // Read Tag
            int tag = buffer[i];
            i += 1;


            Length len = new();
            int length = len.ParseLength(buffer, ref i, false);

            if (length == -1)
                return [];





            // shortform

            // longform




            // Read Value

            //int length = buffer[i];
            // if (i + length > buffer.Length) break;
            // i++;

            byte[] data = new byte[length];
            Array.Copy(buffer, i, data, 0, length);
            i += length;

            var entry = new TagEntry { Tag = tag, Data = data, _length = len };

            // parse children if this is a user-specified sequence tag
            if (sequenceTags != null && sequenceTags.Contains(tag))
            {
                entry.Children = ReadTagData(entry.Data, sequenceTags);
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

    public static void PrintAll(this List<TagReader.TagEntry> tags, int indent = 0)
    {
        string indentStr = new string(' ', indent * 2);

        foreach (var tag in tags)
        {

            Console.Write($"{indentStr}Tag: 0x{tag.Tag:X4} ");
            if (tag.Children != null && tag.Children.Count > 0)
            {
                Console.WriteLine();
                tag.Children.PrintAll(indent + 1);
            }
            else
            {

                string hex = BitConverter.ToString(tag.Data);
                int maxLineLength = 64;

                Console.Write($"\n{indentStr}Data:\n");
                for (int i = 0; i < hex.Length; i += maxLineLength)
                {
                    if (i > 0)
                        Console.WriteLine();
                    Console.Write($"{indentStr}       {hex.Substring(i, Math.Min(maxLineLength, hex.Length - i))}");
                }
                Console.WriteLine();
            }
        }
    }
}

public static class IntExtensions
{
    public static string ToHex(this int value, int digits = 2)
    {
        return value.ToString($"X{digits}");
    }

    public static byte[] IntoLeExtended(this int value)
    {
        return [(byte)((value >> 8) & 0xFF), (byte)(value & 0xFF)];
    }
}

public static class BytesExtensions
{
    public static byte[] TruncateData(this byte[] data)
    {
        if (data == null || data.Length == 0)
            return data;

        for (int i = data.Length - 1; i >= 0; i--)
        {
            if (data[i] == 0x80)
            {
                var truncated = new byte[i];
                Buffer.BlockCopy(data, 0, truncated, 0, i);
                return truncated;
            }
        }

        return data;
    }
}

public static class SodHelper
{
    public static void ReadSodData(byte[] sodBytes)
    {
        try
        {
            var cms = new CmsSignedData(sodBytes);
            var certStore = cms.GetCertificates();
            var signers = cms.GetSignerInfos().GetSigners();

            foreach (SignerInformation signer in signers)
            {
                var allCerts = certStore.EnumerateMatches(null);

                foreach (Org.BouncyCastle.X509.X509Certificate cert in allCerts)
                {
                    if (signer.SignerID.Match(cert))
                    {
                        Log.Info($"Signer cert: {cert.SubjectDN}");
                        Log.Info($"Utfärdat av: {cert.IssuerDN}");
                        Log.Info($"Giltigt: {cert.NotBefore} - {cert.NotAfter}");
                        Log.Info($"Signature info: {cert.SigAlgName}");

                        // Do we need Key info???

                        bool verified = signer.Verify(cert.GetPublicKey());
                        Log.Info($"Digital signatur inuti EF.SOD: {(verified ? "✅ OK" : "❌ FEL")}");
                        Log.Info($"Version??: {cert.Version}");

                        Log.Info($"Certificate Serial Number: {cert.SerialNumber}");





                        if (cms.SignedContent != null)
                        {
                            using (var ms = new System.IO.MemoryStream())
                            {
                                cms.SignedContent.Write(ms);
                                var contentBytes = ms.ToArray();
                                Log.Info($"Singed content: {contentBytes.Length} bytes");
                            }

                        }
                        break;
                    }

                }
            }
        }
        catch (Exception ex)
        {
            Log.Error($"Not read :(: {ex.Message} ");
        }

    }
}

