using Encryption;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Logging.Console;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509.Extension;
using Serilog;
using Serilog.Sinks.SystemConsole.Themes;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Formats.Asn1;
using System.Linq;
using System.Linq.Expressions;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
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




public static class ByteArrayExtension
{
    public static void PrintByteComparison(this byte[] correct, byte[] b)
    {
        int length = Math.Max(b.Length, correct.Length);

        // First line: compared array, red for mismatches
        for (int i = 0; i < length; i++)
        {
            byte bVal = i < b.Length ? b[i] : (byte)0;
            byte cVal = i < correct.Length ? correct[i] : (byte)0;

            if (i >= correct.Length || bVal != cVal)
                Console.ForegroundColor = ConsoleColor.Red;
            Console.Write($"{bVal:X2} ");
            Console.ResetColor();
        }
        Console.WriteLine();

        // Second line: correct array
        for (int i = 0; i < length; i++)
        {
            byte cVal = i < correct.Length ? correct[i] : (byte)0;
            Console.Write($"{cVal:X2} ");
        }
        Console.WriteLine();
    }

    public static string ToOidStr(this byte[] oid)
    {
        StringBuilder retVal = new StringBuilder();

        for (int i = 0; i < oid.Length; i++)
        {
            if (i == 0)
            {
                int b = oid[0] % 40;
                int a = (oid[0] - b) / 40;
                retVal.AppendFormat("{0}.{1}", a, b);
            }
            else
            {
                if (oid[i] < 128)
                    retVal.AppendFormat(".{0}", oid[i]);
                else
                {
                    retVal.AppendFormat(".{0}",
                       ((oid[i] - 128) * 128) + oid[i + 1]);
                    i++;
                }
            }
        }

        return retVal.ToString();
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

    public static EfIdAppSpecific IntoDgFileID(this int value)
    {
        switch (value)
        {
            case 1: return EfIdAppSpecific.Dg1;

            case 2: return EfIdAppSpecific.Dg2;

            case 3: return EfIdAppSpecific.Dg3;

            case 4: return EfIdAppSpecific.Dg4;

            case 5: return EfIdAppSpecific.Dg5;

            case 6: return EfIdAppSpecific.Dg6;

            case 7: return EfIdAppSpecific.Dg7;

            case 8: return EfIdAppSpecific.Dg8;

            case 9: return EfIdAppSpecific.Dg9;

            case 10: return EfIdAppSpecific.Dg10;

            case 11: return EfIdAppSpecific.Dg11;

            case 12: return EfIdAppSpecific.Dg12;

            case 13: return EfIdAppSpecific.Dg13;

            case 14: return EfIdAppSpecific.Dg14;

            case 15: return EfIdAppSpecific.Dg15;

            case 16: return EfIdAppSpecific.Dg16;

            default:
                throw new Exception("Invalid Value: " + value);
        }
    }
}

public static class BytesExtensions
{
    public static byte[] TruncateData(this byte[] data)
    {
        if (data == null || data.Length == 0)
            return data!;

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

public static class StringExtension
{
    // A dictionary mapping the OID *byte strings* (as our parser outputs them)
    // to the names .NET's crypto library understands.
    private static readonly Dictionary<string, string> _oidToNameMap = new()
    {
        // OID for SHA-256
        { "60.86.48.01.65.03.04.02.01", "SHA256" },
        
        // OID for SHA-1
        { "2B.0E.03.02.1A", "SHA1" },
        
        // OID for SHA-512
        { "60.86.48.01.65.03.04.02.03", "SHA512" },
        
        // OID for SHA-384
        { "60.86.48.01.65.03.04.02.02", "SHA384" }
        
        // --- Add other common OIDs here as needed ---
        // e.g., RSA, ECDSA, etc.
    };

    /// <summary>
    /// Converts a DER-byte-string-style OID into a .NET algorithm name.
    /// </summary>
    /// <param name="oidString">The 'this' string, e.g., "60.86.48.01.65.03.04.02.01"</param>
    /// <returns>The .NET algorithm name, e.g., "SHA256"</returns>
    /// <exception cref="NotSupportedException">Thrown if the OID is not in the map.</exception>
    public static string GetAlgorithmName(this string oidString)
    {
        if (_oidToNameMap.TryGetValue(oidString, out string algName))
        {
            return algName;
        }

        // This is a critical error. We can't validate the signature
        // if we don't recognize the hash algorithm.
        throw new NotSupportedException($"The OID {oidString} is not a supported hash algorithm.");
    }
}


public static class HashCalculator
{
    /// <summary>
    /// Computes the hash of the input data using the specified algorithm name.
    /// </summary>
    /// <param name="algorithmName">The .NET name of the hash algorithm (e.g., "SHA256", "SHA512", "MD5").</param>
    /// <param name="inputData">The data to be hashed (as a byte array).</param>
    /// <returns>The computed hash as a byte array.</returns>
    /// <exception cref="NotSupportedException">Thrown if the algorithm name is not supported by .NET.</exception>
    public static byte[] CalculateSHAHash(string algorithmName, byte[] inputData)
    {
        // 1. Create the HashAlgorithm instance dynamically
        // The .NET framework can create the correct class (e.g., SHA256, MD5) 
        // using the string name returned from your OID switch/dictionary.
        switch (algorithmName)
        {
            case "SHA256":
                return SHA256.HashData(inputData);

            case "SHA512":
                return SHA512.HashData(inputData);
        }

        throw new Exception("NOT IMPLEMENTED HASH");
    }

}

public static class SodHelper
{
    public static Org.BouncyCastle.X509.X509Certificate? ReadSodData(byte[] sodBytes)
    {
        Org.BouncyCastle.X509.X509Certificate? verifiedDsc = null; // För att spara det verifierade DSC
        try
        {
            Log.Info("Found EF.SOD! in: EFSodDumpcsmtag.bin file");
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

                        Log.Info($"Signer certificate (DSC): {cert.SubjectDN}");
                        Log.Info($"Utfärdat av: {cert.IssuerDN}");
                        Log.Info($"Giltigt: {cert.NotBefore} - {cert.NotAfter}");
                        Log.Info($"Signature info: {cert.SigAlgName}");

                        // Do we need Key info???

                        bool verified = signer.Verify(cert.GetPublicKey());
                        Log.Info($"Internal signature in EF.SOD: {(verified ? "✅ OK" : "❌ FEL")}");

                        if (verified)
                        {
                            verifiedDsc = cert;
                        }
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
        return verifiedDsc;
    }


    public static Dictionary<int, byte[]> ParseAndVerifySod(byte[] sodBytes)
    {
        // Försök att dekoda CMS/PKCS#7 med standardklassen. Detta är det korrekta sättet.
        try
        {
            var signedCms = new SignedCms();
            signedCms.Decode(sodBytes);

            if (signedCms.Certificates.Count == 0)
            {
                Console.WriteLine("Varning: Hittade inget Document Signer Certificate (DSC) i SOD-filen.");
            }

            // Detta verifierar att SOD-signaturen är giltig mot det inbäddade DSC.
            signedCms.CheckSignature(verifySignatureOnly: true);
            Console.WriteLine("SOD Signatur verifierad framgångsrikt mot det inbäddade DSC.");

            // 3. Extrahera det inre innehållet (ContentInfo).
            // Detta innehåll är själva ICAO-strukturen som innehåller DG Hashes.
            byte[] innerContent = signedCms.ContentInfo.Content;

            // 4. Parsa Data Group Hashes
            return ExtractHashesFromContent(innerContent);
        }
        catch (CryptographicException ex) when (ex.Message.Contains("ASN1 corrupted data"))
        {
            Console.WriteLine($"KRYPTOGRAFISKT FEL (ASN.1 corrupted data): Standard-dekodning misslyckades. Försöker manuell ICAO-parsing...");

            // Åtgärd: Om standarddekodning misslyckas (p.g.a. icke-standard CMS-struktur), 
            // försöker vi manuellt hitta det inre ICAO-innehållet för att komma åt DG-hasharna.

            // EF.SOD (CMS) är en SEQUENCE av SEQUENCE. Det inre innehållet
            // (som är ICAO LDS Security Object) är kapslat i ett OCTET STRING.
            return ExtractHashesManually(sodBytes);
        }
        catch (CryptographicException ex)
        {
            Console.WriteLine($"Kryptografiskt fel vid verifiering: {ex.Message}");
            return null;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Allmänt fel: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    /// Fallback-funktion: Försöker hitta det inre ICAO LDS Security Object-innehållet 
    /// genom att manuellt parsa de yttre CMS-lagren som omsluter det.
    /// Detta ignorerar CMS-signaturvalideringen.
    /// </summary>
    /// <param name="sodBytes">De råa bytena för EF.SOD.</param>
    /// <returns>Dictionary med Data Group Hashes, eller null vid fel.</returns>
    private static Dictionary<int, byte[]>? ExtractHashesManually(byte[] sodBytes)
    {
        try
        {
            var reader = new AsnReader(sodBytes, AsnEncodingRules.DER);

            // 1. SEQUENCE (Det yttersta lagret för CMS/SignedData)
            var outerSequence = reader.ReadSequence();

            // 2. OID för Content Type (should be pkcs7-signedData)
            outerSequence.ReadObjectIdentifier();

            // 3. SEQUENCE [0] (Kontext-specifik tagg)
            var contentSequence = outerSequence.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));

            // KORRIGERING: Istället för att förvänta sig en Universal SEQUENCE (Tag 16),
            // letar vi nu explicit efter Application-specifik Tag 23 (APPLICATION [23])
            // som ICAO ofta använder för att definiera SignedData-strukturen.

            // 4. SEQUENCE (SignedData) - Med ICAO:s Application Tag 23
            var signedDataSequence = contentSequence.ReadSequence(new Asn1Tag(TagClass.Application, 23));

            // --- Hoppa över Version, DigestAlgorithms, EncapsulatedContentInfo ---
            // Hoppa över Version (INTEGER)
            signedDataSequence.ReadInteger();

            // Hoppa över DigestAlgorithms (SET OF SEQUENCE)
            signedDataSequence.ReadSetOf();

            // 5. EncapsulatedContentInfo (SEQUENCE)
            var encapsulatedContentInfo = signedDataSequence.ReadSequence();

            // 6. ContentType (OID)
            encapsulatedContentInfo.ReadObjectIdentifier();

            // 7. Content (OCTET STRING) - Detta är det inre ICAO-innehållet vi vill ha!
            // Det är kapslat i en kontext-specifik tagg [0]
            if (encapsulatedContentInfo.HasData)
            {
                var innerContent = encapsulatedContentInfo.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 0));

                // 8. Skicka det råa ICAO-innehållet till den ursprungliga parsaren
                return ExtractHashesFromContent(innerContent);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"FATALT FEL vid manuell parsing: {ex.Message}");
            return null;
        }

        Console.WriteLine("Manuellt försök misslyckades: Kunde inte hitta det inre innehållet.");
        return null;
    }


    /// <summary>
    /// Avkodar ICAO LDS Security Object (DG Hashes) från den råa ASN.1-byteströmmen.
    /// Denna ASN.1-sekvens är det signerade innehållet i EF.SOD.
    /// </summary>
    /// <param name="content">Det inre ASN.1-råa innehållet från SignedCms.</param>
    /// <returns>En Dictionary med Data Group ID som nyckel och Hash som värde.</returns>
    private static Dictionary<int, byte[]>? ExtractHashesFromContent(byte[] content)
    {
        Console.WriteLine($"\n--- Parsar ICAO-innehåll ({content.Length} bytes) ---");
        var hashes = new Dictionary<int, byte[]>();

        try
        {
            var reader = new AsnReader(content, AsnEncodingRules.DER);

            // 1. SEQUENCE (huvudstrukturen för LDS Security Object)
            var securityObject = reader.ReadSequence();

            // 2. Version (INTEGER) - Bör vara 1
            if (!securityObject.TryReadInt32(out int version) || version != 1)
            {
                Console.WriteLine("Varning: SOD Version är inte 1.");
            }

            // 3. Hash Algorithm Identifier (SEQUENCE) - Innehåller OID för hash-algoritmen
            securityObject.ReadSequence(); // Bara läser OID Sequence, ignorerar värdet för enkelhet

            // 4. Encapsulated Content (SEQUENCE) - Innehåller OID och det faktiska DG-hashet
            securityObject.ReadSequence(); // Läs ContentInfo Sequence

            // 5. DataGroupHash-listan (SET OF SEQUENCE)
            // OBS: Detta SET-objekt innehåller de faktiska hashar du letar efter.
            var dataGroupHashesSet = securityObject.ReadSetOf();

            // Loopa igenom varje DataGroupHash-post
            while (dataGroupHashesSet.HasData)
            {
                // Varje post är en SEQUENCE: { Data Group ID (INTEGER), Hash (OCTET STRING) }
                var dgHashSequence = dataGroupHashesSet.ReadSequence();

                // Hämta Data Group ID (INTEGER)
                if (!dgHashSequence.TryReadInt32(out int dgId))
                {
                    Console.WriteLine("Fel vid läsning av Data Group ID.");
                    continue;
                }

                // Hämta Hash-värdet (OCTET STRING)
                byte[] hashValue = dgHashSequence.ReadOctetString();

                hashes.Add(dgId, hashValue);
                Console.WriteLine($"Extraherade hash: DG{dgId}, längd: {hashValue.Length} bytes.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"FATALT FEL vid ASN.1-parsing av SOD-innehåll: {ex.Message}");
            return null;
        }

        return hashes;
    }

    private static bool VerifyDscTrustChainWithPem(
Org.BouncyCastle.X509.X509Certificate dscCertBC,
string masterListDirectoryPath)
    {
        Log.Info("Step 2 Pa start");


        string issuerDN = dscCertBC.IssuerDN.ToString();
        Org.BouncyCastle.X509.X509Certificate? matchingCscaCertBC = null;
        X509Certificate2? dscCertDotNet = null;
        X509Certificate2? matchingCscaCertDotNet = null;
        List<IDisposable> disposables = new List<IDisposable>();

        try
        {
            //Fetch AKI from DSC
            var akidExtension = dscCertBC.GetExtensionValue(X509Extensions.AuthorityKeyIdentifier);
            if (akidExtension == null)
            {
                Log.Warn("DSC saknar AKI, letar efter csca baserat på namn (less secure)");
            }
            AuthorityKeyIdentifier? authorityKeyIdentifier = null; //Parse AKI extension
            if (akidExtension != null)
            {
                authorityKeyIdentifier = AuthorityKeyIdentifier.GetInstance(X509ExtensionUtilities.FromExtensionValue(akidExtension));
            }
            byte[]? keyIdToMatch = authorityKeyIdentifier?.GetKeyIdentifier();

            if (!Directory.Exists(masterListDirectoryPath)) throw new DirectoryNotFoundException();

            Log.Info($"Searching for CSCA for '{issuerDN}'{(keyIdToMatch != null ? "with keyID: " + HexUtils.HexEncode(keyIdToMatch) : "")} in: {masterListDirectoryPath}");

            foreach (string pemFile in Directory.EnumerateFiles(masterListDirectoryPath, "*.pem", SearchOption.AllDirectories))
            {
                try
                {
                    using (var reader = File.OpenText(pemFile))
                    {
                        var pemReader = new PemReader(reader);
                        object? pemObject;
                        while ((pemObject = pemReader.ReadObject()) != null)
                        {
                            if (pemObject is Org.BouncyCastle.X509.X509Certificate cscaCertBC)
                            { // Name check
                                if (cscaCertBC.SubjectDN.Equivalent(dscCertBC.IssuerDN, true))
                                { // Check AKI against SKI
                                    bool keyIdMatches = false;
                                    if (keyIdToMatch == null)
                                    {
                                        keyIdMatches = true;
                                        Log.Warn($"Using CSCA '{cscaCertBC.SubjectDN}' only using name match");
                                    }
                                    else
                                    { // Get SKI from CSCA and compare to AKI
                                        var skidExtension = cscaCertBC.GetExtensionValue(X509Extensions.SubjectKeyIdentifier);
                                        if (skidExtension != null)
                                        {
                                            var subjectKeyIdentifier = SubjectKeyIdentifier.GetInstance(X509ExtensionUtilities.FromExtensionValue(skidExtension));
                                            byte[] cscaSki = subjectKeyIdentifier.GetKeyIdentifier();
                                            if (keyIdToMatch.SequenceEqual(cscaSki))
                                            {
                                                keyIdMatches = true; // Name and KeyId matches :)))))))
                                            }
                                        }
                                    } // if both matches
                                    if (keyIdMatches)
                                    {
                                        if (matchingCscaCertBC != null)
                                        {
                                            Log.Error($"Found multiple valid CSCA (name and keyID) for {issuerDN}");
                                        }
                                        else
                                        {
                                            matchingCscaCertBC = cscaCertBC;
                                            Log.Info($"Found correct CSCA PEM (matching name {(keyIdToMatch != null ? " & keyID" : "")}): {Path.GetFileName(pemFile)} ({matchingCscaCertBC.SubjectDN})");
                                            goto FoundCorrectCsca;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                catch (Exception readEx) { Log.Warn($"Cant read/parse PEM {pemFile}: {readEx.Message}"); }
            } // Foreach stop

        FoundCorrectCsca:
            if (matchingCscaCertBC == null)
            {
                throw new Exception($"No CSCA .pem cerificate found in '{masterListDirectoryPath}' that matches issuer: '{issuerDN}'{(keyIdToMatch != null ? "and keyId" : "")}");
            }
            //Convert to .Net object
            dscCertDotNet = new X509Certificate2(dscCertBC.GetEncoded());
            matchingCscaCertDotNet = new X509Certificate2(matchingCscaCertBC.GetEncoded());
            disposables.Add(dscCertDotNet);
            disposables.Add(matchingCscaCertDotNet);

            //Very chain
            var chain = new X509Chain();
            disposables.Add(chain);
            try
            {
                // Big money check
                chain.ChainPolicy.ExtraStore.Add(matchingCscaCertDotNet); // Trust Anchor
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck; // No revocation for now
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority; // Not in windows?

                if (!chain.Build(dscCertDotNet))
                {
                    Log.Error("DSC -> CSCA not validated Status:");
                    foreach (var status in chain.ChainStatus)
                    {
                        Log.Error($"{status.Status}: {status.StatusInformation}");
                    }
                    throw new Exception("Cert chain DSC -> CSCA no valid");
                }


                Log.Info("Step 2 pa OK");
                return true;
            }
            finally { }
        }

        catch (Exception ex)
        {
            return false;
        }
        finally
        {

        }
    }
    public static bool PerformPassiveAuthStep2(Org.BouncyCastle.X509.X509Certificate verifiedDscCertBC, string masterListDirectoryPath)
    {
        return VerifyDscTrustChainWithPem(verifiedDscCertBC, masterListDirectoryPath);
    }
}
