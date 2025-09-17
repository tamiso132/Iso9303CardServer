using System;
using System.Collections.Generic;

namespace Encryption;



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

    public KeyAgreement AgreementType { get; set; } = KeyAgreement.Unknown;
    public CipherEncryption EncryptType { get; set; } = CipherEncryption.Unknown;
    public Mapping MappingType { get; set; } = Mapping.Unknown;
    public MacType MacType { get; set; } = MacType.Unknown;
    public AlgorithmIdentifier AlgoIdent { get; set; } = null!;
    public int Len { get; set; }
    public byte[] OrgOid { get; set; } = [];
    public int OrgParameterID { get; set; }

    public static EncryptionInfo Get(byte[] oid, int parameterId)
    {
        int lastID = oid[^1];
        int paceID = oid[^2];

        EncryptionInfo info = new();
        info.OrgOid = oid;
        info.OrgParameterID = parameterId;

        var pace = paceMap[paceID];
        info.AgreementType = pace.Item1;
        info.MappingType = pace.Item2;

        var crypto = cryptoMap[lastID];
        info.EncryptType = crypto.Item1;
        info.MacType = crypto.Item2;
        info.Len = crypto.Item3;

        if (info.AgreementType == KeyAgreement.Unknown) throw new Exception("Invalid KeyAgreement");
        if (info.EncryptType == CipherEncryption.Unknown) throw new Exception("Invalid CipherEncryption");
        if (info.MappingType == Mapping.Unknown) throw new Exception("Invalid Mapping");
        if (info.MacType == MacType.Unknown) throw new Exception("Invalid MacType");

        return info;
    }

    public void PrintInfo()
    {
        Console.WriteLine();
        Console.WriteLine(AgreementType);
        Console.WriteLine(EncryptType);
        Console.WriteLine(MappingType);
        Console.WriteLine(MacType);
        Console.WriteLine();
    }

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
