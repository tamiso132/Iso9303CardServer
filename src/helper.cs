using Encryption;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Logging.Console;
using Serilog;
using Serilog.Sinks.SystemConsole.Themes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using Type;
namespace Helper;

public static class MrzUtils
{
    public static byte[] GetMrz(string docNr, string birth, string dateExpire)
    {
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
