using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Runtime.Intrinsics.Arm;
using System.Security.Cryptography;
using System.Text;
using System.Text.Unicode;
using System.Threading.Tasks;
using Helper;
using Interfaces;


namespace Encryption;

public class TestClass
{
    static public byte[] MappingGm(EncryptionInfo info)
    {
        var bytes = Encoding.ASCII.GetBytes(MrzUtils.GetMrz("35172541", "010813", "250820"));
        return SHA1.Create().ComputeHash(bytes);
    }

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

        if (info.KeySize > 128)
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

    private static readonly Dictionary<int, (CipherEncryption, MacType, uint)> cryptoMap = new()
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
        this.KeySize = crypto.Item3;

        if (this.AgreementType == KeyAgreement.Unknown) throw new Exception("Invalid KeyAgreement");
        if (this.EncryptType == CipherEncryption.Unknown) throw new Exception("Invalid CipherEncryption");
        if (this.MappingType == Mapping.Unknown) throw new Exception("Invalid Mapping");
        if (this.MacType == MacType.Unknown) throw new Exception("Invalid MacType");

    }

    public void PrintInfo()
    {
        Log.Info($"{AgreementType} {EncryptType}{KeySize} {MappingType} {MacType}");
    }

    public KeyAgreement AgreementType { get; set; } = KeyAgreement.Unknown;
    public CipherEncryption EncryptType { get; set; } = CipherEncryption.Unknown;
    public Mapping MappingType { get; set; } = Mapping.Unknown;
    public MacType MacType { get; set; } = MacType.Unknown;
    public AlgorithmIdentifier AlgoIdent { get; set; } = null!;
    public byte[] OrgOid { get; } = [];
    public int OrgParameterID { get; }
    public uint KeySize { get; }

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
