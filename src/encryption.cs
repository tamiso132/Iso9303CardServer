using System.Security.Cryptography;
using System.Text;
using Asn1;
using Command;
using ErrorHandling;
using Helper;
using Interfaces;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;


namespace Encryption;

public class TestClass
{
    static public byte[] MappingGm(EncryptionInfo info)
    {
        var bytes = Encoding.ASCII.GetBytes(MrzUtils.GetMrz("35172541", "010813", "250820"));
        return SHA1.Create().ComputeHash(bytes);
    }
    // TODO, read more. so I can support stuff
    public static byte[] DerivePaceKey(EncryptionInfo info)
    {
        // get mrz
        // SHA1 the mrz
        var mrz = MrzUtils.GetMrz("35172541", "010813", "250820");
        byte[] shaMrz = SHA1.HashData(Encoding.UTF8.GetBytes(mrz));

        byte[] PACEMODE = [0x00, 0x00, 0x00, 0x03];

        byte[] data = [.. shaMrz, .. PACEMODE];
        byte[] key = [];

        // TODO, implement for DESEDE2, cause it works different when creating key.

        if (info.KeySize <= 128 / 8)
        {
            key = SHA1.HashData(data);
        }
        else
        {
            key = SHA256.HashData(data);
        }

        return key[0..info.KeySize];


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


    public static async Task<Result<RVoid>> ComputeDecryptedNounce<T>(Command<T> command, EncryptionInfo info)
    where T : IServerFormat
    {
        var response = await command.GeneralAuthenticate();
        if (!response.IsSuccess)
        {
            Log.Error(response.Error.ErrorMessage());
            return RVoid.Fail(response.Error);
        }

        Log.Info("Does it come here?");

        var tree = AsnNode.Parse(new ByteReader(response.Value.data));

        var nodes = tree.GetAllNodes();
        nodes[0].PrintBare();
        // TODO, check length

        // ERROR
        if (nodes[0].Id != 0x7C)
        { }

        if (nodes[0].Children[0].Id != 0x80)
        {
            // error
        }

        var encrypted_nounce = nodes[0].Children[0].GetValueAsOID();

        var aes = Aes.Create();
        aes.KeySize = info.KeySize * 8;
        aes.BlockSize = 128; // TODO, support other
        byte[] iv = [.. Enumerable.Repeat<byte>(0x00, 16)];

        // byte[] actualCmac = AesHelper.ComputeCmac(key, encrypted_nounce);

        // byte[] cipherTxt = AesHelper.Process(encrypted_nounce, key, iv, info.MacType, false);


        return RVoid.Success();


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
        Log.Info($"{AgreementType} {EncryptType}{_keybits} {MappingType} {MacType}");
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