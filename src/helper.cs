using Encryption;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Logging.Console;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
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
        int padLength = aligment - (input.Length % aligment);
        byte[] padding = new byte[padLength];
        padding[0] = 0x80;
        return [.. input, .. padding];
    }
}

//TODO Remove??
public static class BIgIntegerExtension
{
    public static byte[] ToPaddedLength(this BigInteger value, int length)
    {
        // 1. Get the bytes (These are Little Endian in .NET!)
        byte[] bytes = value.ToByteArray(isUnsigned: true);

        // 2. CRITICAL: Reverse them to get Big Endian
        Array.Reverse(bytes);

        // 3. Right-Align in the target buffer
        if (bytes.Length < length)
        {
            byte[] padded = new byte[length];
            // Copy bytes to the END of the padded array
            Buffer.BlockCopy(bytes, 0, padded, length - bytes.Length, bytes.Length);
            return padded;
        }
        else if (bytes.Length > length)
        {
            // Safety: If number is too big, take the last 'length' bytes
            return bytes[^length..];
        }

        return bytes;
    }
}



// TODO Remove??
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

//TODO Remove??
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

// TODO Remove??
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
public enum HashAlgoType
{
    Sha1,
    Sha224, // Requires Bouncy Castle
    Sha256,
    Sha384,
    Sha512
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
    /// 
    /// 
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

    public static byte[] ComputeHash(HashAlgoType algo, byte[] data)
    {
        if (data == null || data.Length == 0)
            throw new ArgumentException("Data cannot be empty");

        return algo switch
        {
            // Standard .NET (Fast & Native)
            HashAlgoType.Sha1 => SHA1.HashData(data),
            HashAlgoType.Sha256 => SHA256.HashData(data),
            HashAlgoType.Sha384 => SHA384.HashData(data),
            HashAlgoType.Sha512 => SHA512.HashData(data),

            // Non-Standard (Use Bouncy Castle)
            HashAlgoType.Sha224 => ComputeSHA224(data),


            _ => throw new NotSupportedException($"Algorithm {algo} is not implemented.")
        };
    }

    private static byte[] ComputeSHA224(byte[] data)
    {
        var digest = new Sha224Digest();
        byte[] result = new byte[digest.GetDigestSize()];

        digest.BlockUpdate(data, 0, data.Length);
        digest.DoFinal(result, 0);

        return result;
    }

}

public static class SodHelper
{
    // Verifierar EF.SOD interna signatur
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

                        // Manipulerade hash-lista och intern signatur går inte genom detta steg, manipulerad data går igenom men hanteras i steg 3.
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

    // TODO Remove?
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

    // Function that creates chain between chip (DSC) and master list CSCA
    public static bool PerformPassiveAuthStep2(byte[] dscRawBytes, string masterListDirectoryPath)
    {
        Log.Info("Step 2 Pa start (Bouncy Castle Correct Usage)");

        try
        {
            // 1. PARSE: Use X509CertificateParser
            // This returns 'Org.BouncyCastle.X509.X509Certificate' (The "Smart" object)
            // NOT 'Org.BouncyCastle.Asn1.X509.Certificate' (The "Dumb" data structure)
            var parser = new Org.BouncyCastle.X509.X509CertificateParser();
            Org.BouncyCastle.X509.X509Certificate dscCert = parser.ReadCertificate(dscRawBytes);

            // 2. FIND CSCA
            var cscaCert = FindCscaCertificate(dscCert, masterListDirectoryPath);

            if (cscaCert == null)
            {
                Log.Error($"Step 2 FAILED: No CSCA found for issuer '{dscCert.IssuerDN}'.");
                return false;
            }

            // 3. VERIFY
            // The 'Smart' object has a .Verify() method that handles the OID/Name mapping 
            // and Signer initialization internally.
            try
            {
                // Get the Public Key (AsymmetricKeyParameter implements ICipherParameters)
                AsymmetricKeyParameter cscaPublicKey = cscaCert.GetPublicKey();

                // Verify checks if dscCert was signed by cscaPublicKey
                dscCert.Verify(cscaPublicKey);

                Log.Info($"Step 2 Pa OK. Signature Verified against: {cscaCert.SubjectDN}");
            }
            catch (InvalidKeyException)
            {
                Log.Error("Step 2 FAILED: Signature verification failed (Invalid Key).");
                return false;
            }
            catch (Exception sigEx)
            {
                // This catches signature mismatch errors
                Log.Error($"Step 2 FAILED: Signature verification failed: {sigEx.Message}");
                return false;
            }

            // 4. VALIDITY (Warning only for Passports)
            try
            {
                dscCert.CheckValidity();
            }
            catch (Exception)
            {
                Log.Warn("DSC is expired or not yet valid (Standard for Passive Auth).");
            }

            return true; // TODO Change to true if we want to check AA/CA is working
        }
        catch (Exception ex)
        {
            Log.Error($"Step 2 Critical Error: {ex.Message}");
            return false;
        }
    }

    private static Org.BouncyCastle.X509.X509Certificate? FindCscaCertificate(
        Org.BouncyCastle.X509.X509Certificate dscCert,
        string masterListPath)
    {
        // Use the Logic Class property 'IssuerDN'
        var issuerDN = dscCert.IssuerDN;

        byte[]? keyIdToMatch = null;

        // Correct way to extract Extension Value using OID
        var akidOid = X509Extensions.AuthorityKeyIdentifier; // This is the OID Object
        var akidExt = dscCert.GetExtensionValue(akidOid);

        if (akidExt != null)
        {
            // Parse the ASN.1 Octet String
            var akidStruct = AuthorityKeyIdentifier.GetInstance(X509ExtensionUtilities.FromExtensionValue(akidExt));
            keyIdToMatch = akidStruct.GetKeyIdentifier();
        }

        if (!Directory.Exists(masterListPath)) return null;

        var files = Directory.EnumerateFiles(masterListPath, "*.*", SearchOption.AllDirectories)
                             .Where(s => s.EndsWith(".pem") || s.EndsWith(".crt") || s.EndsWith(".cer"));

        foreach (string pemFile in files)
        {
            try
            {
                using var reader = File.OpenText(pemFile);
                var pemReader = new PemReader(reader);
                object? pemObject;

                while ((pemObject = pemReader.ReadObject()) != null)
                {
                    // Ensure we cast to the Logic Class
                    if (pemObject is Org.BouncyCastle.X509.X509Certificate cscaCert)
                    {
                        if (!cscaCert.SubjectDN.Equivalent(issuerDN, true)) continue;

                        if (keyIdToMatch == null)
                        {
                            // Weak match (Name only)
                            return cscaCert;
                        }

                        // Extract SKI
                        var skiOid = X509Extensions.SubjectKeyIdentifier;
                        var skiExt = cscaCert.GetExtensionValue(skiOid);
                        if (skiExt != null)
                        {
                            var skiStruct = SubjectKeyIdentifier.GetInstance(X509ExtensionUtilities.FromExtensionValue(skiExt));
                            if (keyIdToMatch.SequenceEqual(skiStruct.GetKeyIdentifier()))
                            {
                                return cscaCert;
                            }
                        }
                    }
                }
            }
            catch { }
        }
        return null;
    }

}
