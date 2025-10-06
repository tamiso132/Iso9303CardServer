using System.Formats.Asn1;
using System.Runtime.Intrinsics.Arm;
using System.Security.Cryptography;
using System.Text;
using Asn1;
using Command;
using ErrorHandling;
using Helper;
using Interfaces;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;


namespace Encryption;

public class TestClass
{
    static bool IsEqual(byte[] a, byte[] b)
    {
        if (a.Length != b.Length)
        {
            return false;
        }

        for (int i = 0; i < a.Length; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }
        return true;


    }
    static int? IsEqualByteNr(byte[] a, byte[] b)
    {
        if (a.Length != b.Length)
        {
            return a.Length + 10;
        }

        for (int i = 0; i < a.Length; i++)
        {
            if (a[i] != b[i])
            {
                return i;
            }
        }
        return null;
    }
    static void PrintByteComparison(byte[] correct, byte[] b)
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

    static bool TestingECDH()
    {
        byte[] privateKey =
        [
            0x7F, 0x4E, 0xF0, 0x7B,
            0x9E, 0xA8, 0x2F, 0xD7,
            0x8A, 0xD6, 0x89, 0xB3,
            0x8D, 0x0B, 0xC7, 0x8C,
            0xF2, 0x1F, 0x24, 0x9D,
            0x95, 0x3B, 0xC4, 0x6F,
            0x4C, 0x6E, 0x19, 0x25,
            0x9C, 0x01, 0x0F, 0x99
        ];

        byte[] sharedSecret =
        [
            0x04, 0x60, 0x33, 0x2E, 0xF2,
            0x45, 0x0B, 0x5D, 0x24,
            0x7E, 0xF6, 0xD3, 0x86,
            0x83, 0x97, 0xD3, 0x98,
            0x85, 0x2E, 0xD6, 0xE8,
            0xCA, 0xF6, 0xFF, 0xEE,
            0xF6, 0xBF, 0x85, 0xCA,
            0x57, 0x05, 0x7F, 0xD5,
            0x08, 0x40, 0xCA, 0x74,
            0x15, 0xBA, 0xF3, 0xE4,
            0x3B, 0xD4, 0x14, 0xD3,
            0x5A, 0xA4, 0x60, 0x8B,
            0x93, 0xA2, 0xCA, 0xF3,
            0xA4, 0xE3, 0xEA, 0x4E,
            0x82, 0xC9, 0xC1, 0x3D,
            0x03, 0xEB, 0x71, 0x81
        ];

        byte[] chipPublicKey =
        [
            0x04, 0x82, 0x4F, 0xBA, 0x91,
            0xC9, 0xCB, 0xE2, 0x6B,
            0xEF, 0x53, 0xA0, 0xEB,
            0xE7, 0x34, 0x2A, 0x3B,
            0xF1, 0x78, 0xCE, 0xA9,
            0xF4, 0x5D, 0xE0, 0xB7,
            0x0A, 0xA6, 0x01, 0x65,
            0x1F, 0xBA, 0x3F, 0x57,
            0x30, 0xD8, 0xC8, 0x79,
            0xAA, 0xA9, 0xC9, 0xF7,
            0x39, 0x91, 0xE6, 0x1B,
            0x58, 0xF4, 0xD5, 0x2E,
            0xB8, 0x7A, 0x0A, 0x0C,
            0x70, 0x9A, 0x49, 0xDC,
            0x63, 0x71, 0x93, 0x63,
            0xCC, 0xD1, 0x3C, 0x54
        ];

        byte[] nonceDecrypted =
       [
            0x3F, 0x00, 0xC4, 0xD3,
            0x9D, 0x15, 0x3F, 0x2B,
            0x2A, 0x21, 0x4A, 0x07,
            0x8D, 0x89, 0x9B, 0x22
       ];


        byte[] mappedGenerator =
        [
            0x04, 0x8C, 0xED, 0x63, 0xC9,
            0x14, 0x26, 0xD4, 0xF0,
            0xEB, 0x14, 0x35, 0xE7,
            0xCB, 0x1D, 0x74, 0xA4,
            0x67, 0x23, 0xA0, 0xAF,
            0x21, 0xC8, 0x96, 0x34,
            0xF6, 0x5A, 0x9A, 0xE8,
            0x7A, 0x92, 0x65, 0xE2,
            0x8C, 0x87, 0x95, 0x06,
            0x74, 0x3F, 0x86, 0x11,
            0xAC, 0x33, 0x64, 0x5C,
            0x5B, 0x98, 0x5C, 0x80,
            0xB5, 0xF0, 0x9A, 0x0B,
            0x83, 0x40, 0x7C, 0x1B,
            0x6A, 0x4D, 0x85, 0x7A,
            0xE7, 0x6F, 0xE5, 0x22
        ];

        ECDH ecdh = new ECDH(DomainParameter.BrainpoolP256r1, privateKey);
        ecdh.CalculateSharedSecret(chipPublicKey);
        var secretCalculated = ecdh._secret.Normalize().GetEncoded();

        if (!IsEqual(sharedSecret, secretCalculated))
        {
            Log.Info("Shared Secret wrong computation");
            PrintByteComparison(sharedSecret, secretCalculated);
            return false;
        }

        ecdh.MapGenerator(nonceDecrypted);
        var generator = ecdh._generator.Normalize().GetEncoded();

        if (!IsEqual(generator, mappedGenerator))
        {
            PrintByteComparison(generator, mappedGenerator);
            return false;
        }



        return true;
    }

    private static bool EncryptionTesting()
    {

        byte[] nonceDecrypted =
        [
            0x3F, 0x00, 0xC4, 0xD3,
            0x9D, 0x15, 0x3F, 0x2B,
            0x2A, 0x21, 0x4A, 0x07,
            0x8D, 0x89, 0x9B, 0x22
        ];

        // Encrypted Nonce z
        byte[] nonceEncrypted =
        [
            0x95, 0xA3, 0xA0, 0x16,
            0x52, 0x2E, 0xE9, 0x8D,
            0x01, 0xE7, 0x6C, 0xB6,
            0xB9, 0x8B, 0x42, 0xC3
        ];


        byte[] password =
        [
            0x89, 0xDE, 0xD1, 0xB2,
            0x66, 0x24, 0xEC, 0x1E,
            0x63, 0x4C, 0x19, 0x89,
            0x30, 0x28, 0x49, 0xDD
        ];

        using var aes = System.Security.Cryptography.Aes.Create();
        aes.KeySize = 128;
        aes.BlockSize = 128;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.None;
        aes.Key = password;
        aes.IV = new byte[16];


        using var dectryptor = aes.CreateDecryptor();
        byte[] dectryptedNonce = dectryptor.TransformFinalBlock(nonceEncrypted, 0, nonceEncrypted.Length);

        if (!IsEqual(dectryptedNonce, nonceDecrypted))
        {
            PrintByteComparison(dectryptedNonce, nonceDecrypted);
            return false;
        }

        return true;

    }
    private static bool MrzTest()
    {

        //! CHECK DIGIT TESTING
        byte[] mrzTest = MrzUtils.GetMrz("L898902C<", "690806", "940623");

        byte[] val = SHA1.HashData(mrzTest);

        byte[] testVal =
        [
            0x23, 0x9A, 0xB9, 0xCB, 0x28, 0x2D, 0xAF, 0x66,
            0x23, 0x1D, 0xC5, 0xA4, 0xDF, 0x6B, 0xFB, 0xAE,
            0xDF, 0x47, 0x75, 0x65
        ];

        if (!IsEqual(val, testVal))
        {
            Log.Error("Fail: 1");

            return false;
        }



        byte[] RealK =
        [
            0x7E, 0x2D, 0x2A, 0x41,
            0xC7, 0x4E, 0xA0, 0xB3,
            0x8C, 0xD3, 0x6F, 0x86,
            0x39, 0x39, 0xBF, 0xA8,
            0xE9, 0x03, 0x2A, 0xAD
        ];

        // Derived AES-128 key Kπ
        byte[] RealKpi =
        [
            0x89, 0xDE, 0xD1, 0xB2,
            0x66, 0x24, 0xEC, 0x1E,
            0x63, 0x4C, 0x19, 0x89,
            0x30, 0x28, 0x49, 0xDD
        ];

        // MRZ fields
        string documentNumber = "T22000129";
        string dateOfBirth = "640812";
        string dateOfExpiry = "101031";

        byte[] mrzBytes = MrzUtils.GetMrz(documentNumber, dateOfBirth, dateOfExpiry);

        // Concatenate MRZ info (as bytes, typically ASCII)
        //    string mrzString = documentNumber + dateOfBirth + dateOfExpiry;

        // Compute SHA-1 hash to derive Kπ
        using var sha1 = SHA1.Create();
        byte[] kMrz = sha1.ComputeHash(mrzBytes);

        byte[] PACEMODE = [0x00, 0x00, 0x00, 0x03];

        byte[] data = [.. kMrz, .. PACEMODE];
        byte[] key = [];

        // TODO, implement for DESEDE2, cause it works different when creating key.

        key = SHA1.HashData(data);

        if (!IsEqual(RealK, kMrz))
            return false;

        if (!IsEqual(RealKpi, key[0..16]))
        {
            PrintByteComparison(RealKpi, key[0..16]);
            return false;
        }



        return true;

    }
    public static bool Testing()
    {


        // Print Kπ in hex
        if (!MrzTest())
            return false;

        if (!EncryptionTesting())
            return false;

        if (!TestingECDH())
            return false;

        byte[] mrz =
        [
            0x89, 0xDE, 0xD1, 0xB2,
            0x66, 0x24, 0xEC, 0x1E,
            0x63, 0x4C, 0x19, 0x89,
            0x30, 0x28, 0x49, 0xDD
        ];

        byte[] sharedSecret = [

            0x28, 0x76, 0x8D, 0x20,
                0x70, 0x12, 0x47, 0xDA,
                0xE8, 0x18, 0x04, 0xC9,
                0xE7, 0x80, 0xED, 0xE5,
                0x82, 0xA9, 0x99, 0x6D,
                0xB4, 0xA3, 0x15, 0x02,
                0x0B, 0x27, 0x33, 0x19,
                0x7D, 0xB8, 0x49, 0x25
        ];





        byte[] concatenatedMac = [.. sharedSecret, .. new byte[3], 2];
        byte[] concatenatedEnc = [.. sharedSecret, .. new byte[3], 1];

        byte[] KSEnc =
        [
            0xF5, 0xF0, 0xE3, 0x5C,
            0x0D, 0x71, 0x61, 0xEE,
            0x67, 0x24, 0xEE, 0x51,
            0x3A, 0x0D, 0x9A, 0x7F
        ];

        byte[] KSMAC =
        [
            0xFE, 0x25, 0x1C, 0x78,
            0x58, 0xB3, 0x56, 0xB2,
            0x45, 0x14, 0xB3, 0xBD,
            0x5F, 0x42, 0x97, 0xD1
        ];
        byte[] macKey = SHA1.HashData(concatenatedMac).Take(16).ToArray();
        byte[] encKey = SHA1.HashData(concatenatedEnc).Take(16).ToArray();

        if (!IsEqual(macKey, KSMAC))
            return false;

        if (!IsEqual(encKey, KSEnc))
            return false;

        byte[] terminalPublicKey =
        [
            0x2D, 0xB7, 0xA6, 0x4C,
            0x03, 0x55, 0x04, 0x4E,
            0xC9, 0xDF, 0x19, 0x05,
            0x14, 0xC6, 0x25, 0xCB,
            0xA2, 0xCE, 0xA4, 0x87,
            0x54, 0x88, 0x71, 0x22,
            0xF3, 0xA5, 0xEF, 0x0D,
            0x5E, 0xDD, 0x30, 0x1C,
            0x35, 0x56, 0xF3, 0xB3,
            0xB1, 0x86, 0xDF, 0x10,
            0xB8, 0x57, 0xB5, 0x8F,
            0x6A, 0x7E, 0xB8, 0x0F,
            0x20, 0xBA, 0x5D, 0xC7,
            0xBE, 0x1D, 0x43, 0xD9,
            0xBF, 0x85, 0x01, 0x49,
            0xFB, 0xB3, 0x64, 0x62
        ];

        byte[] chipPublicKey =
        [
            0x04, 0x9E, 0x88, 0x0F, 0x84,
            0x29, 0x05, 0xB8, 0xB3,
            0x18, 0x1F, 0x7A, 0xF7,
            0xCA, 0xA9, 0xF0, 0xEF,
            0xB7, 0x43, 0x84, 0x7F,
            0x44, 0xA3, 0x06, 0xD2,
            0xD2, 0x8C, 0x1D, 0x9E,
            0xC6, 0x5D, 0xF6, 0xDB,
            0x77, 0x64, 0xB2, 0x22,
            0x77, 0xA2, 0xED, 0xDC,
            0x3C, 0x26, 0x5A, 0x9F,
            0x01, 0x8F, 0x9C, 0xB8,
            0x52, 0xE1, 0x11, 0xB7,
            0x68, 0xB3, 0x26, 0x90,
            0x4B, 0x59, 0xA0, 0x19,
            0x37, 0x76, 0xF0, 0x94
        ];

        byte[] inputDataForTIFD =
        [
            0x7F, 0x49, 0x4F, 0x06,
            0x0A, 0x04, 0x00, 0x7F,
            0x00, 0x07, 0x02, 0x02,
            0x04, 0x02, 0x02, 0x86,
            0x41, 0x04, 0x9E, 0x88,
            0x0F, 0x84, 0x29, 0x05,
            0xB8, 0xB3, 0x18, 0x1F,
            0x7A, 0xF7, 0xCA, 0xA9,
            0xF0, 0xEF, 0xB7, 0x43,
            0x84, 0x7F, 0x44, 0xA3,
            0x06, 0xD2, 0xD2, 0x8C,
            0x1D, 0x9E, 0xC6, 0x5D,
            0xF6, 0xDB, 0x77, 0x64,
            0xB2, 0x22, 0x77, 0xA2,
            0xED, 0xDC, 0x3C, 0x26,
            0x5A, 0x9F, 0x01, 0x8F,
            0x9C, 0xB8, 0x52, 0xE1,
            0x11, 0xB7, 0x68, 0xB3,
            0x26, 0x90, 0x4B, 0x59,
            0xA0, 0x19, 0x37, 0x76,
            0xF0, 0x94
        ];

        byte[] oid =
        [
            0x04, 0x00, 0x7F, 0x00,
            0x07, 0x02, 0x02, 0x04,
            0x02, 0x02
        ];

        var token = Command.Command<IServerFormat>.TestGeneralToken(chipPublicKey, oid, macKey);

        byte[] tokenCmd2 =
        [
            0x00, 0x86, 0x00, 0x00,
            0x0C, 0x7C, 0x0A, 0x85,
            0x08, 0xC2, 0xB0, 0xBD,
            0x78, 0xD9, 0x4B, 0xA8,
            0x66, 0x00
        ];

        var byteProblem = IsEqualByteNr(tokenCmd2, token);

        if (byteProblem != null)
        {
            byte[] inputTIFD = Command.Command<IServerFormat>.TestGeneralInput(chipPublicKey, oid, macKey);
            var r = IsEqualByteNr(inputTIFD, inputDataForTIFD);
            if (r != null)
            {
                Log.Info("Problem with inputTIFD");
                PrintByteComparison(inputDataForTIFD, inputTIFD);
            }
            return false;
        }



        // using var aes = Aes.Create();
        // aes.KeySize = 128;
        // aes.BlockSize = 128;
        // aes.Mode = CipherMode.CBC;
        // aes.Padding = PaddingMode.None;
        // aes.Key = password;
        // aes.IV = new byte[16];


        // using var dectryptor = aes.CreateDecryptor();
        // var dectryptedNonce = dectryptor.TransformFinalBlock(encrypted_nounce, 0, encrypted_nounce.Length);

        // Log.Info("Dectrypted Nonce: " + BitConverter.ToString(dectryptedNonce));

        // return Result<byte[]>.Success(dectryptedNonce);


        return true;
    }

    // TODO, read more. so I can support stuff
    public static byte[] DerivePaceKey(EncryptionInfo info)
    {

        // MRZ fields

        byte[] mrzBytes = MrzUtils.GetMrz("XA0000002", "820821", "270101");

        // Concatenate MRZ info (as bytes, typically ASCII)
        //    string mrzString = documentNumber + dateOfBirth + dateOfExpiry;

        // Compute SHA-1 hash to derive Kπ
        using var sha1 = SHA1.Create();
        byte[] kMrz = sha1.ComputeHash(mrzBytes);

        byte[] PACEMODE = [0x00, 0x00, 0x00, 0x03];

        byte[] data = [.. kMrz, .. PACEMODE];
        byte[] key = [];

        key = SHA1.HashData(data);

        if (info.KeySize <= 128 / 8)
        {
            key = SHA1.HashData(data);
        }
        else
        {
            key = SHA256.HashData(data);
        }





        return key;




        // the counter is 4 bytes long and ends in either of these
        // case ENC_MODE = 0x01
        //case MAC_MODE = 0x02
        //case PACE_MODE = 0x03 

        // the data for the command is prepared by 
        // keyseed -> data counter

        // then that data is getting another encryption depending on 
        // key derivation is SHA1 if .AES128  or DES and DESEDE2
        // AES more then 128 bits is SHA256

        /* Then this and u get the key
         let key: [UInt8] = switch securityConfig.encryption {
        case .DESEDE2:
            
            // Actually DES-EDE2 is used, so it requires 3 DES keys k1, k2, k3 where k1 = k3.
            // For this reason, the key length is 192 bit (or 156 bit without parity bits) but
            // the actual length is 128 bit (or 112 bit without parity bits): 64 (or 56) bit for each key.
            //
            // NOTE: DES-EDE is a 3DES where the encryption is performed as ENC(k1, DEC(k2, ENC(k3, M))).
            // Each operation (ENC/DEC) is a DES operation and this 3DES version is used to make interoperability
            // with DES smarter.
            //
            // Here, the first and the second  octects are used as k1 (for ENC operation) and k2 (for DEC operation).
            // Then, the first octect is extracted again for k3, known k3 has to be equal to k1 for ENC operation.
            
            [UInt8].init(
                digest[0..<securityConfig.encryption.params.keySize * 8 / 12]
                + digest[0..<securityConfig.encryption.params.keySize * 8 / 24])
        default:
            [UInt8](digest[0..<securityConfig.encryption.params.keySize * 8 / 8])
        }
        
        return key
        */
    }

    public static Tuple<byte[], byte[]> DeriveSessionKeys(EncryptionInfo info, byte[] sharedSecretX)
    {
        byte[] concatenatedMac = [.. sharedSecretX, .. new byte[3], 2];
        byte[] concatenatedEnc = [.. sharedSecretX, .. new byte[3], 1];

        var hasher = SHA256.Create();




        //         To derive 192-bit and 256-bit AES [FIPS 197] keys SHA-256 [FIPS 180-4] SHALL be used. For 192-bit AES keys the
        // following additional step MUST be performed:
        // • Use octets 1 to 24 of keydata; additional octets are not used.


        byte[] macKey = hasher.ComputeHash(concatenatedMac);
        byte[] encKey = hasher.ComputeHash(concatenatedEnc);

        if (macKey.Length != 32 && encKey.Length != 32)
        {
            Log.Error("Incorrect length from hash");
        }


        return new Tuple<byte[], byte[]>(macKey, encKey);

    }

    public enum PasswordType : byte
    {
        Undefined = 0,
        MRZ = 1,
        CAN = 2,
    }

    public static async Task<Result<byte[]>> ComputeDecryptedNounce<T>(Command<T> command, EncryptionInfo info, byte[] password, PasswordType passwordType)
    where T : IServerFormat
    {
        var response = await command.GeneralAuthenticate(new GenAuthType.EncryptedNounce());
        if (!response.IsSuccess)
        {
            Log.Error("Encrypted nounce command fails");
            return Result<byte[]>.Fail(response.Error);
        }




        var allNodes = AsnNode.Parse(new AsnReader(response.Value.data, AsnEncodingRules.DER));



        var encrypted_nounce = allNodes.GetAllNodes()[0].Children[0].GetValueAsBytes();





        // -- Decrypt-- 

        using var aes = System.Security.Cryptography.Aes.Create();
        aes.KeySize = info.KeySize * 8;
        aes.BlockSize = 128;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.None;
        aes.Key = password;
        aes.IV = new byte[16];


        using var dectryptor = aes.CreateDecryptor();
        var dectryptedNonce = dectryptor.TransformFinalBlock(encrypted_nounce, 0, encrypted_nounce.Length);

        Log.Info("Dectrypted Nonce: " + BitConverter.ToString(dectryptedNonce));

        return Result<byte[]>.Success(dectryptedNonce);






    }

    static void PerformKeyAgreement()
    {
        // Compute decrypted Nounce By 
        //Send general Authenticate,  with tag 0x7C and no data
        // Parse the response and get the nounce from it
        // decrypt it, using the paceKey with the encryption algoritm



        // Compute EphermeralParams
        //Perform Key agreement
    }
}

public class AlgorithmIdentifier(AlgorithmType type, int bitLength, int? modPrimeOrder = null)
{
    public AlgorithmType Type { get; } = type;
    public int BitLength { get; } = bitLength;
    public int? ModPrimeOrder { get; } = modPrimeOrder;
}

public class EncryptionInfo
{
    private static readonly Dictionary<int, (KeyAgreement, Mapping)> paceMap = new()
    {
        {1, (KeyAgreement.Dh, Mapping.Gm)},
        {2, (KeyAgreement.EcDh, Mapping.Gm)},
        {3, (KeyAgreement.Dh, Mapping.Im)},
        {4, (KeyAgreement.EcDh, Mapping.Im)},
        {6, (KeyAgreement.EcDh, Mapping.Cam)}
    };

    private static readonly Dictionary<int, (CipherEncryption, MacType, int)> cryptoMap = new()
    {
        {1, (CipherEncryption.E3Des, MacType.Cbc, 0)},
        {2, (CipherEncryption.Aes, MacType.CMAC, 128)},
        {3, (CipherEncryption.Aes, MacType.CMAC, 192)},
        {4, (CipherEncryption.Aes, MacType.CMAC, 256)}
    };



    public EncryptionInfo(byte[] oid, int parameterId)
    {
        int lastID = oid[^1];
        int paceID = oid[^2];

        this.OrgOid = oid;
        this.OrgParameterID = parameterId;


        var pace = paceMap[paceID];
        this.AgreementType = pace.Item1;
        this.MappingType = pace.Item2;

        var crypto = cryptoMap[lastID];
        this.EncryptType = crypto.Item1;
        this.MacType = crypto.Item2;
        this._keybits = crypto.Item3;

        if (this.AgreementType == KeyAgreement.Unknown) throw new Exception("Invalid KeyAgreement");
        if (this.EncryptType == CipherEncryption.Unknown) throw new Exception("Invalid CipherEncryption");
        if (this.MappingType == Mapping.Unknown) throw new Exception("Invalid Mapping");
        if (this.MacType == MacType.Unknown) throw new Exception("Invalid MacType");

    }

    public void PrintInfo()
    {
        Log.Info($"{AgreementType} {EncryptType}{_keybits} {MappingType} {MacType}, {OrgParameterID}");
    }

    public KeyAgreement AgreementType { get; set; } = KeyAgreement.Unknown;
    public CipherEncryption EncryptType { get; set; } = CipherEncryption.Unknown;
    public Mapping MappingType { get; set; } = Mapping.Unknown;
    public MacType MacType { get; set; } = MacType.Unknown;
    public AlgorithmIdentifier AlgoIdent { get; set; } = null!;
    public byte[] OrgOid { get; } = [];
    public int OrgParameterID { get; }
    private int _keybits { get; }
    public int KeySize => _keybits / 8;

}


public enum Mapping
{
    Im,
    Gm,
    Cam,
    Unknown
}

public enum KeyAgreement
{
    Dh,
    EcDh,
    Unknown
}

public enum CipherEncryption
{
    Aes,
    E3Des,
    Unknown
}

public enum MacType
{
    Cbc,
    CMAC,
    Unknown
}

public enum AlgorithmType
{
    BrainPool,
    Nist,
    ModPrime
}



public static class AesHelper
{
    public static byte[] EncryptAesCbc(byte[] plainText, byte[] key, byte[] iv)
    {
        var cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()), new Pkcs7Padding());
        cipher.Init(true, new ParametersWithIV(new KeyParameter(key), iv)); // true = encryption

        byte[] output = new byte[cipher.GetOutputSize(plainText.Length)];
        int len = cipher.ProcessBytes(plainText, 0, plainText.Length, output, 0);
        len += cipher.DoFinal(output, len);

        return output[..len];
    }

    public static byte[] DecryptAesCbc(byte[] cipherText, byte[] key, byte[] iv)
    {
        var cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()), new Pkcs7Padding());
        cipher.Init(false, new ParametersWithIV(new KeyParameter(key), iv)); // false = decryption

        byte[] output = new byte[cipher.GetOutputSize(cipherText.Length)];
        int len = cipher.ProcessBytes(cipherText, 0, cipherText.Length, output, 0);
        len += cipher.DoFinal(output, len);

        return output[..len];
    }

    public static byte[] ComputeCmac(byte[] key, byte[] message)
    {
        var mac = new CMac(new AesEngine());
        mac.Init(new KeyParameter(key));
        mac.BlockUpdate(message, 0, message.Length);

        byte[] output = new byte[mac.GetMacSize()];
        mac.DoFinal(output, 0);
        return output;
    }

    public static byte[] Process(byte[] data, byte[] key, byte[] iv, MacType macType, bool encrypt = true)
    {
        return macType switch
        {
            MacType.Cbc => encrypt ? EncryptAesCbc(data, key, iv) : DecryptAesCbc(data, key, iv),
            MacType.CMAC => ComputeCmac(key, data),
            _ => throw new NotImplementedException()
        };
    }
}



public sealed record DomainParameter(X9ECParameters param)
{
    public readonly X9ECParameters param = param;

    internal static DomainParameter BrainpoolP384r1 = new(ECNamedCurveTable.GetByName("BRAINPOOLP384R1"));
    internal static DomainParameter BrainpoolP256r1 = new(ECNamedCurveTable.GetByName("BRAINPOOLP256R1"));
}

public sealed record ECDH
{

    public ECDH(DomainParameter param, byte[] privateKey, byte[]? generator = null)
    {
        PrivateKey = new BigInteger(1, privateKey);
        this.param = param;
        _secret = this.param.param.G;
        if (generator == null)
            _generator = this.param.param.G;
        else
            _generator = this.param.param.Curve.DecodePoint(generator).Normalize();

    }

    // Using nounce, create new generator
    public void MapGenerator(byte[] nonce)
    {
        Log.Info("Calculate new generator, using the nounce, current generator and secret");
        var iNonce = new BigInteger(1, nonce);
        _generator = _generator.Multiply(iNonce).Add(_secret).Normalize();

    }

    public void CalculateSharedSecret(byte[] encodedChipPublic)
    {
        Log.Info("Calculate Shared Secret");
        var publicKeyIC = param.param.Curve.DecodePoint(encodedChipPublic).Normalize();
        _secret = publicKeyIC.Multiply(PrivateKey).Normalize();
    }

    // Update Private key
    public void GenerateEphemeralKeys(RandomNumberProvider RandomNumberProvider)
    {
        PrivateKey = new BigInteger(1, RandomNumberProvider.GetNextBytes(32));
    }

    public byte[] PublicKey
    {
        get
        {
            return _generator.Multiply(PrivateKey).Normalize().GetEncoded();
        }
    }

    public byte[] SharedSecret
    {
        get
        {
            return _secret.Normalize().XCoord.GetEncoded();
        }
    }

    DomainParameter param;
    public Org.BouncyCastle.Math.EC.ECPoint _generator;
    public Org.BouncyCastle.Math.EC.ECPoint _secret;

    BigInteger PrivateKey;
}


/*
Data Object Notation      Tag   Type
Object Identifier         0x06  Object Identifier
Prime modulus p           0x81  Unsigned Integer
First coefficient a       0x82  Unsigned Integer
Second coefficient b      0x83  Unsigned Integer
Base point G              0x84  Elliptic Curve Point
Order of the base point r 0x85  Unsigned Integer
Public point Y            0x86  Elliptic Curve Point
Cofactor f                0x87  Unsigned Integer

*/

