using Microsoft.Extensions.Logging;
using Serilog;
using Serilog.Sinks.SystemConsole.Themes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Type;
namespace Helper;

public static class MrzUtils
{
    public static string GetMrz(string docNr, string birth, string dateExpire)
    {
        while (docNr.Length < 9)
            docNr += "<";

        string fullStr = "";
        fullStr += docNr + GetCheckDigit(docNr);
        fullStr += GetCheckDigit(docNr);
        fullStr += birth + GetCheckDigit(birth);
        fullStr += dateExpire + GetCheckDigit(dateExpire);

        return fullStr;
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

public class AsnInfo(TagID tag, byte[] data)
{
    public TagID Tag { get; } = tag;
    public byte[] Data { get; } = data;
}

public class ByteReader(byte[] data)
{
    private readonly byte[] _data = data;
    private int _offset = 0;

    public byte[] ReadBytes(int len)
    {
        var sub = _data[_offset..(_offset + len)];
        _offset += len;
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
        string s = Encoding.ASCII.GetString(_data, _offset, len);
        _offset += len;
        return s;
    }

    public void PaddingNext(int len) => _offset += len;

    public bool HasRemaining() => _offset < _data.Length;

    public int ReadLength()
    {
        int first = ReadInt(1);
        if (first < 0x80) return first;

        int numBytes = first & 0x7F;
        return ReadInt(numBytes);
    }

    public AsnInfo ReadASN1()
    {
        TagID tag = TagID.FromInt(ReadInt(1));
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
    static Log()
    {

        // Configure Serilog once
        Serilog.Log.Logger = new LoggerConfiguration()
        .WriteTo.Console(
            outputTemplate: "{Timestamp:HH:mm:ss} {Message:lj}{NewLine}", // remove {Level}
            theme: AnsiConsoleTheme.Code)
        .MinimumLevel.Information()
        .CreateLogger();
    }
    public static void Info(string message) => Serilog.Log.Information("[INF] {Message}", message);
    public static void Warn(string message) => Serilog.Log.Warning("[WRN] {Message}", message);
    public static void Error(string message) => Serilog.Log.Error("[ERR] {Message}", message);

}

