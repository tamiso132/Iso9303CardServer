using System.Numerics;
using System.Security.Cryptography;
using Encryption;
using Helper;
using Interfaces;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

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
    public static void PrintByteComparison(byte[] correct, byte[] b)
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

    public static bool TestLengthThing()
    {
        int first = 0xFF01;
        byte[] hey = first.IntoLeExtended();
        Log.Info(hey[1].ToString());

        return hey[0] == 0xFF && hey[1] == 0x01;
    }
    static void TestEncryptionMessage()
    {
        byte[] KSEnc = new byte[]
              {
            0x97, 0x9E, 0xC1, 0x3B, 0x1C, 0xBF, 0xE9, 0xDC,
            0xD0, 0x1A, 0xB0, 0xFE, 0xD3, 0x07, 0xEA, 0xE5
              };

        byte[] KSMAC = new byte[]
        {
            0xF1, 0xCB, 0x1F, 0x1F, 0xB5, 0xAD, 0xF2, 0x08,
            0x80, 0x6B, 0x89, 0xDC, 0x57, 0x9D, 0xC1, 0xF8
        };

        // SSC as BigInteger (big-endian)
        byte[] sscBytes = new byte[]
        {
            0x88, 0x70, 0x22, 0x12, 0x0C, 0x06, 0xC2, 0x26
        };

        byte[] EncryptedDataTest = new byte[]
        {
            0x63, 0x75, 0x43, 0x29, 0x08, 0xC0, 0x44, 0xF6
        };

        byte[] PaddedDataTest = new byte[]
        {
            0x01, 0x1E, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00
        };

        byte[] UnEncrypteddata = [0x01, 0x1E];
        byte[] cmdHeader = [0x0C, 0xA4, 0x02, 0x0C];
        BigInteger SSC = new BigInteger(sscBytes.ToArray(), true);


        var paddedData = Util.AlignData(UnEncrypteddata, 16);

        if (!IsEqual(paddedData, PaddedDataTest))
        {
            PrintByteComparison(PaddedDataTest, paddedData);
            return;
        }





        SSC += 1;
        var cipher = CipherUtilities.GetCipher($"AES/CBC/NOPADDING");
        var iv1 = new byte[16];
        var ivParameter = new ParametersWithIV(new KeyParameter(KSEnc), iv1);
        cipher.Init(true, ivParameter);

        var paddedSSCBA = SSC.ToPaddedLength(16);
        var iv2 = cipher.DoFinal(paddedSSCBA);


        var ivParameter2 = new ParametersWithIV(new KeyParameter(KSEnc), iv2);
        cipher.Init(true, ivParameter2);
        var calculatedEncryptedData = cipher.DoFinal(paddedData);

        if (!IsEqual(EncryptedDataTest, calculatedEncryptedData))
        {
            PrintByteComparison(EncryptedDataTest, calculatedEncryptedData);
            return;
        }




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

        if (!TestLengthThing())
            return false;

        TestEncryptionMessage();

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

        return true;
    }
}