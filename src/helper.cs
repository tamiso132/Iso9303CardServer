using App;
using Command;
using Encryption;
using Interfaces;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Logging.Console;
using Org.BouncyCastle.Asn1;
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
    /// <summary>
    /// Verifierar förtroendekedjan (Chain of Trust) genom att kontrollera att DSC är signerat av en betrodd CSCA.
    /// </summary>
    /// <returns>
    /// TRUE innebär:
    /// 1. DSC-certifikatet är äkta och matchar ett CSCA-certifikat i Master List.
    /// 2. Vi kan nu lita på att detta DSC är utfärdat/signerat av staten, och inte av en hackare.
    /// </returns>
    public static bool VerifyChipSignature(byte[] dscRawBytes, string masterListDirectoryPath)
    {
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
                dscCert.CheckValidity(); // Check valid date
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

    /// <summary>
    /// Verifierar SOD-filens äkthet (Passive Authentication) genom integritets- och signaturkontroll.
    /// </summary>
    /// <remarks>
    /// 1. Integritet: Säkerställer att innehållet (DG-hashlistan) matchar de signerade attributen.
    /// 2. Autenticitet: Verifierar att signaturen är giltig och skapad av utfärdaren (DSC).
    /// </remarks>
    /// <returns>
    /// TRUE innebär:
    /// 1. Vi har ett "äkta facit": Listan med hashar (DataGroupHashes) är garanterat 
    ///    utfärdad av passmyndigheten och har inte manipulerats.
    /// 2. Vi kan nu lita på hasharna: Det är nu säkert att läsa DG1, DG2 etc. från 
    ///    chippet och jämföra dem mot denna lista.
    /// </returns>

    public static bool CheckSodIntegrity(SodContent sodFile)
    {
        var parser = new Org.BouncyCastle.X509.X509CertificateParser();
        Org.BouncyCastle.X509.X509Certificate dscCert = parser.ReadCertificate(sodFile.DocumentSignerCertificate);


        // 2. Hitta den lagrade hashen i SignedAttributes (OID 1.2.840.113549.1.9.4)
        byte[] storedHash = [];
        bool foundHashAttribute = false;

        AsymmetricKeyParameter publicKey = dscCert.GetPublicKey();
        byte[] tbsData = sodFile.SignedAttributesBytes;
        tbsData[0] = 0x31;


        string hashPart = "SHA256"; // hårdkodat
        if (publicKey is Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters)
        {
            // BouncyCastle-namn för PSS: "SHA256withRSAandMGF1"
            string pssAlgo = $"{hashPart}withRSAandMGF1";

            ISigner pssSigner = SignerUtilities.GetSigner(pssAlgo);
            pssSigner.Init(false, publicKey);
            pssSigner.BlockUpdate(tbsData, 0, tbsData.Length);

            if (!pssSigner.VerifySignature(sodFile.Signature))
                throw new Exception("Failed to verify Signature with DSC public key");
        }

        // Din TagReader-logik för att hitta attributet
        // Vi filtrerar fram 0xA0 (SignedAttributes)
        var signedAttrSeq = TagReader.ReadTagData(sodFile.SignedAttributesBytes, [0x30, 0x31, 0xA0])[0];
        if (signedAttrSeq != null)
        {
            foreach (var child in signedAttrSeq.Children)
            {
                // OID ligger i 0x06. Vi kollar de sista 3 bytesen för 1.9.4
                var oidTag = child.FindChild(0x06);
                if (oidTag != null && oidTag.Data.Length >= 3)
                {
                    byte[] oidSuffix = oidTag.Data[^3..];
                    if (oidSuffix.SequenceEqual([(byte)1, (byte)9, (byte)4]))
                    {
                        // Hittade MessageDigest! Värdet ligger i SET(0x31) -> OCTET STRING eller liknande
                        // Din kod skippade 2 header bytes, vi antar att det stämmer för din parser
                        var valueTag = child.FindChild(0x31);
                        if (valueTag != null)
                        {
                            storedHash = valueTag.Data[2..];
                            foundHashAttribute = true;
                            break;
                        }
                    }
                }
            }
        }

        if (!foundHashAttribute)
        {
            Log.Error("Could not find MessageDigest attribute in SOD.");
            return true;
        }

        var calculatedHash = SHA256.HashData(sodFile.EncapsulatedContentBytes);


        if (!calculatedHash.SequenceEqual(storedHash))
        {
            Log.Error("en del av signaturen stämmer inte överens med beräknade värdet av dg listan.");
            TestClass.PrintByteComparison(storedHash, calculatedHash);
            return false;
        }

        return true;
    }
    /// <summary>
    /// Verifierar integriteten hos passets datagrupper (DG1-DG16) genom att jämföra dem mot SOD-filens hash-lista.
    /// </summary>
    /// <remarks>
    /// Denna funktion utför det sista steget i Passive Authentication:
    /// 1. Den läser faktiska filer från chippet.
    /// 2. Den beräknar hashen på dessa filer.
    /// 3. Den jämför hashen mot "facit" i SOD-filen.
    /// 
    /// Dessutom scannar den efter DG14 (Chip Auth) och DG15 (Active Auth) för nästa steg.
    /// </remarks>
    /// <returns>
    /// (success, foundDg14, foundDg15)
    /// 
    /// SUCCESS = TRUE innebär:
    /// Datan i passet (namn, bild, etc.) är exakt den som utfärdaren signerade. 
    /// Ingen har manipulerat informationen på chippet.
    /// </returns>
    public static async Task<(bool success, bool foundDg14, bool foundDg15)> VerifyDataGroups(Command<ServerEncryption> _cmd, SodContent sodFile)
    {
        bool dg14Find = false;
        bool dg15Find = false;
        string algoName = sodFile.HashAlgorithmOid.GetAlgorithmName();

        var parser = new Org.BouncyCastle.X509.X509CertificateParser();
        Org.BouncyCastle.X509.X509Certificate dscCert = parser.ReadCertificate(sodFile.DocumentSignerCertificate);

        foreach (var dg in sodFile.DataGroupHashes)
        {
            // 1. Filter: Hoppa över känsliga DGs eftersom vi ej har behörighet
            if (dg.DataGroupNumber == 3 || dg.DataGroupNumber == 4) 
            {
                Log.Warn($"Skipping verification of DG{dg.DataGroupNumber} (Requires EAC/Terminal Auth).");
                continue;
            }
            if (dg.DataGroupNumber == 2)
            {
                Log.Warn($"Skipping verification of DG{dg.DataGroupNumber} (Very big file that holds the image of the person)");
                continue;
            }

            // 2. Flaggor för nästa steg
            if (dg.DataGroupNumber == 15) dg15Find = true;
            if (dg.DataGroupNumber == 14) dg14Find = true;

            EfIdAppSpecific dgID = dg.DataGroupNumber.IntoDgFileID();
            var responseResult = await _cmd.ReadBinary(MessageType.SecureMessage, dgID);

            if (!responseResult.IsSuccess)
            {
                Log.Error($"Failed to read DG{dg.DataGroupNumber} from chip.");
                return (false, dg14Find, dg15Find);
            }

            byte[] dgData = responseResult.Unwrap().data;


            byte[] calculatedHashData = HashCalculator.CalculateSHAHash(algoName, dgData);

            if (!calculatedHashData.SequenceEqual(dg.Hash))
            {
                Log.Error($"Hash mismatch for DG{dg.DataGroupNumber}!");
                TestClass.PrintByteComparison(calculatedHashData, dg.Hash);
                return (false, dg14Find, dg15Find); // Fail immediately
            }
        }

        return (true, dg14Find, dg15Find);
    }
    private static string GetSignatureAlgorithmName(AsymmetricKeyParameter pubKey, string hashOid)
    {
        // 1. Bestäm Hash-del
        string hashPart = "SHA256"; // Default
        if (hashOid.Contains("1.101.3.4.2.2")) hashPart = "SHA384";
        else if (hashOid.Contains("1.101.3.4.2.3")) hashPart = "SHA512";
        else if (hashOid == "1.3.14.3.2.26") hashPart = "SHA1"; // Gamla pass

        // 2. Bestäm Krypterings-del
        if (pubKey is Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters)
        {
            return $"{hashPart}withRSA";
        }
        else if (pubKey is Org.BouncyCastle.Crypto.Parameters.ECPublicKeyParameters)
        {
            // För ECDSA heter det ofta "SHA256withECDSA" i BouncyCastle
            return $"{hashPart}withECDSA";
        }

        // Fallback
        return $"{hashPart}withRSA";
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
