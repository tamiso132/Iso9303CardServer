using System.Diagnostics;
using System.Formats.Asn1;
using System.Numerics;
using System.Runtime.Intrinsics.Arm;
using System.Security.Cryptography;
using System.Text;
using Asn1;
using Command;
using ErrorHandling;
using Helper;
using Interfaces;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;


namespace Encryption;



public static class PassHelper
{

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

    }

    public static Tuple<byte[], byte[]> DeriveSessionKeys(EncryptionInfo info, byte[] sharedSecretX)
    {
        byte[] concatenatedMac = [.. sharedSecretX, .. new byte[3], 2];
        byte[] concatenatedEnc = [.. sharedSecretX, .. new byte[3], 1];

        var hasher = SHA256.Create();




        // To derive 192-bit and 256-bit AES [FIPS 197] keys SHA-256 [FIPS 180-4] SHALL be used. For 192-bit AES keys the
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

}

public class OidInfo
{
    Mapping? mapping;
    KeyAgreement agreement;
    CipherEncryption cipher;
}

public static class ParseOid
{
    public static OidInfo FromChipAuth(byte[] oid)
    {
        throw new Exception("TODO");
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


public sealed record DomainParameter(X9ECParameters param)
{
    public readonly X9ECParameters param = param;

    internal static DomainParameter BrainpoolP384r1 = new(ECNamedCurveTable.GetByName("BRAINPOOLP384R1"));
    internal static DomainParameter BrainpoolP256r1 = new(ECNamedCurveTable.GetByName("BRAINPOOLP256R1"));
    internal static DomainParameter NistP192r1 = new(ECNamedCurveTable.GetByName("secp192r1"));
    internal static DomainParameter NistP256r1 = new(ECNamedCurveTable.GetByName("secp256r1"));
    internal static DomainParameter NistP384r1 = new(ECNamedCurveTable.GetByName("secp384r1"));
    internal static DomainParameter NistP521r1 = new(ECNamedCurveTable.GetByName("secp521r1"));

    public static DomainParameter GetFromDerEncoded(byte[] derEncodedExplicit)
    {
        return new DomainParameter(X9ECParameters.GetInstance(derEncodedExplicit));
    }
    public static DomainParameter GetFromId(int parameterId)
    {
        // --- Replaced with a switch statement ---
        switch (parameterId)
        {
            // NIST Curves
            case 8:
                return NistP192r1;
            case 12:
                return NistP256r1;
            case 15:
                return NistP384r1;
            case 18:
                return NistP521r1;

            // Brainpool Curves
            case 13:
                return BrainpoolP256r1;
            case 16:
                return BrainpoolP384r1;

            default:
                throw new NotSupportedException($"Unknown Domain Parameter ID: {parameterId}");
        }
    }
}

public sealed record ECDH
{

    public ECDH(DomainParameter param, byte[]? generator = null)
    {

        var rnd = new RandomNumberProvider();
        PrivateKey = new Org.BouncyCastle.Math.BigInteger(1, rnd.GetNextBytes(32));
        this.param = param;
        _secret = this.param.param.G;
        if (generator == null)
            _generator = this.param.param.G;
        else
            _generator = this.param.param.Curve.DecodePoint(generator).Normalize();

    }

    public void PrintECParameters()
    {
        StringBuilder sb = new StringBuilder();
        sb.AppendLine("--- Elliptic Curve Parameters (Bouncy Castle) ---");

        // 1. Prime (p)
        sb.Append("Prime (p):   ").AppendLine(BitConverter.ToString(param.param.Curve.Field.Characteristic.ToByteArrayUnsigned()));

        // 2. Coeff (a)
        sb.Append("Coeff (a):   ").AppendLine(BitConverter.ToString(param.param.Curve.A.ToBigInteger().ToByteArrayUnsigned()));

        // 3. Coeff (b)
        sb.Append("Coeff (b):   ").AppendLine(BitConverter.ToString(param.param.Curve.B.ToBigInteger().ToByteArrayUnsigned()));

        // 4. Base (G)
        // GetEncoded() or GetEncoded(false) returns the uncompressed point
        sb.Append("Base (G):    ").AppendLine(BitConverter.ToString(param.param.G.GetEncoded()));

        // 5. Order (n)
        sb.Append("Order (n):   ").AppendLine(BitConverter.ToString(param.param.N.ToByteArrayUnsigned()));

        // 6. Cofactor (h)
        sb.Append("Cofactor (h):").AppendLine(BitConverter.ToString(param.param.H.ToByteArrayUnsigned()));

        Log.Info(sb.ToString());
    }

    // Using nounce, create new generator
    public void MapGenerator(byte[] nonce)
    {
        Log.Info("Calculate new generator, using the nounce, current generator and secret");
        var iNonce = new Org.BouncyCastle.Math.BigInteger(1, nonce);
        _generator = _generator.Multiply(iNonce).Add(_secret).Normalize();

    }

    public byte[] ParseCalculateSharedSecret(byte[] responseData)
    {
        using var stream = new Asn1InputStream(responseData);
        Asn1Object obj = stream.ReadObject();  // top-level object
        byte[] encodedChipPublic = obj.GetDerEncoded()[4..];

        var publicKeyIC = param.param.Curve.DecodePoint(encodedChipPublic).Normalize();
        _secret = publicKeyIC.Multiply(PrivateKey).Normalize();

        return encodedChipPublic;

    }

    public byte[] CalculateSharedSecret(byte[] icPub)
    {
        Log.Info("Calculate Shared Secret");
        byte[] encodedChipPublic = icPub[1..]; // skip the 00

        var publicKeyIC = param.param.Curve.DecodePoint(encodedChipPublic).Normalize();
        _secret = publicKeyIC.Multiply(PrivateKey).Normalize();

        return encodedChipPublic;
    }

    // Update Private key
    public void GenerateEphemeralKeys(RandomNumberProvider RandomNumberProvider)
    {
        PrivateKey = new Org.BouncyCastle.Math.BigInteger(1, RandomNumberProvider.GetNextBytes(32));
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

    Org.BouncyCastle.Math.BigInteger PrivateKey;
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

