using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Text;
using Asn1;
using Encryption;
using Helper;
using Interfaces;
using Org.BouncyCastle.Asn1.Icao;
using Org.BouncyCastle.Cms;
using Type;

namespace Parser;


public class EfComInfo
{
    public string LdsVersion { get; set; } = "";
    public string UnicodeVersion { get; set; } = "";
    public List<int> DgTags { get; set; } = new();
}

//EFCOM
public class ImplEfCom : IEfParser<EfComInfo>
{
    public string Name()
    {
        return "Com";
    }

    public EfComInfo ParseFromBytes(byte[] bytes)
    {
        // var ef = new EfComInfo();
        // var reader = new ByteReader(bytes);

        // int tag = reader.ReadInt(1);
        // if (tag != 0x60) throw new Exception("Not a valid EF.COM file");

        // int length = reader.ReadLength();
        // while (reader.HasRemaining())
        // {
        //     int innerTag = reader.ReadInt(1);
        //     int innerLength = reader.ReadLength();
        //     var value = reader.ReadBytes(innerLength);

        //     switch (innerTag)
        //     {
        //         case 0x5F01: ef.LdsVersion = Encoding.ASCII.GetString(value); break;
        //         case 0x5F36: ef.UnicodeVersion = Encoding.ASCII.GetString(value); break;
        //         case 0x5C: ef.DgTags = new List<int>(value); break;
        //         default: break;
        //     }
        // }
        throw new NotImplementedException();
    }
}



public struct ImplCardAccess : IEfParser<ImplCardAccess.Info>
{
    public string Name()
    {
        return "CardAccess";
    }

    public Info ParseFromBytes(byte[] bytes)
    {
        var ef = new Info();
        var allNodes = AsnNode.Parse(new AsnReader(bytes, AsnEncodingRules.DER));



        foreach (var set in allNodes.Filter(Asn1Tag.SetOf))
        {
            foreach (var paceInfo in set.Filter(Asn1Tag.Sequence))
            {
                byte[] oid = paceInfo.GetChildNode(0).GetValueAsOID();
                var ver = paceInfo.GetChildNode(1).GetValueAsInt();
                var paramID = paceInfo.GetChildNode(2).GetValueAsInt();

                var info = new EncryptionInfo(oid, paramID);
                ef.EncryptInfos.Add(info);
            }
        }

        return ef;
    }
    public class Info
    {
        internal Info() { }
        public readonly List<EncryptionInfo> EncryptInfos = [];
    }
}





public struct ImplEFDir : IEfParser<ImplEFDir.Info>
{
    public readonly Info ParseFromBytes(byte[] bytes)
    {
        var ef = new Info();
        var allNodes = AsnNode.Parse(new AsnReader(bytes, AsnEncodingRules.DER));
        foreach (var node in allNodes.GetAllNodes())
        {
        }
        return ef;
    }

    string IEfParser<Info>.Name()
    {
        return "Dir";
    }

    public class Info
    {

    }
}

// -- EF.SOD -- 

public class EFSodInfo
{
    public string LdsVersion { get; set; } = "";
    public string UnicodeVersion { get; set; } = "";
    public string DigestAlgorithm { get; set; } = "";

    public List<DataGroupHashEntry> DataGroupHashes { get; set; } = new();

    // public Dictionary<int, byte[]> DgHashes { get; } = new();
    // public byte[] Signature { get; set; } = Array.Empty<byte>();


    public class DataGroupHashEntry
    {
        public int DataGroupNumber { get; set; } //DG1-16
        public byte[] HashValue { get; set; } //SHA256 Hash
    }

    public static EFSodInfo ParseEFSodLdsV18(byte[] bytes)
    {
        var ef = new EFSodInfo();
        var reader = new AsnReader(bytes, AsnEncodingRules.DER);
        var outerSeq = reader.ReadSequence(); // Outer sequence 


        BigInteger versionInt = (int)reader.ReadInteger(); // Se version
        if (versionInt == 0)
            Log.Info("LDS Legacy version");
        else if (versionInt == 1)
            Log.Info("LDS Version 1.8 (REQUIRED FOR NEW PASSPORTS)");
        else
            Log.Info("UNKNOWN LDS VERSION :(");



        // Digest Algorithm
        var digestSeq = outerSeq.ReadSequence();
        var digestOid = digestSeq.ReadObjectIdentifier();
        ef.DigestAlgorithm = digestOid;
        if (digestSeq.HasData)
            digestSeq.ReadNull();



        // Sequence of sequence
        var dgHashesSeq = outerSeq.ReadSequence();
        while (dgHashesSeq.HasData)
        {
            var dgEntrySeq = dgHashesSeq.ReadSequence();
            var dgNum = (int)dgEntrySeq.ReadInteger();
            var dgHash = dgEntrySeq.ReadOctetString();

            ef.DataGroupHashes.Add(new DataGroupHashEntry { DataGroupNumber = dgNum, HashValue = dgHash });

        }

        // Läs sekvensen som innehåller LDSVersionInfo, Finns redan?
        var ldsVersionSeq = outerSeq.ReadSequence();
        ef.LdsVersion = ldsVersionSeq.ReadCharacterString(UniversalTagNumber.PrintableString);    // ldsVersion
        ef.UnicodeVersion = ldsVersionSeq.ReadCharacterString(UniversalTagNumber.PrintableString); // unicodeVersion



        return ef;
        // throw new NotImplementedException();


    }





    public static byte[] GetSignedDataFromSod(byte[] efSodBytes)
    {

        var cms = new CmsSignedData(efSodBytes);
        var signedContent = cms.SignedContent;

        if (signedContent == null)
            Log.Info("No signed content found in EF.SOD");

        return efSodBytes;
    }
}



public class TLV
{
    public int Tag { get; set; }
    public int Length { get; set; }
    public byte[] Value { get; set; }

}


// Data Groups parsing 
// Data Groups: DG1, DG11, DG12, DG14, DG16
public static class TLVParser
{
    public static List<TLV> Parse(byte[] data)
    {
        var result = new List<TLV>();
        int index = 0;

        while (index < data.Length)
        {
            int tag = data[index++];
            int length = data[index++];

            if (length > 0x80)
            {
                int lengthBytes = length & 0x77;
                length = 0;
                for (int i = 0; i < lengthBytes; i++)
                {
                    length = (length << 8) | data[index++];
                }
            }

            byte[] value = new byte[length];
            Array.Copy(data, index, value, 0, length);
            index += length;

            result.Add(new TLV { Tag = tag, Length = length, Value = value });
        }
        return result;
    }

    public class Dg1Info
    {
        public int DocumentCode { get; set; }
        public int State { get; set; }
        public List<byte> DocumentNumber { get; } = new();
        public byte[] DateOfBirth { get; set; } = Array.Empty<byte>();
        public int Gender { get; set; }
        public byte[] DateExpire { get; set; } = Array.Empty<byte>();
        public byte[] Nationality { get; set; } = Array.Empty<byte>();
        public string Name { get; set; } = "";
        internal Dg1Info() { }
    }

    // DG1
    public class ImplEfDg1TD1 : IEfParser<Dg1Info>
    {
        public string Name()
        {
            return "DG1";
        }

        public Dg1Info ParseFromBytes(byte[] bytes)
        {
            var ef = new Dg1Info();
            var reader = new ByteReader(bytes);
            int tag = reader.ReadInt(1);
            if (tag != 0x61) throw new Exception($"Unexpected tag: 0x{tag:X2}");

            int length = reader.ReadLength();
            int innerTag = reader.ReadInt(2);
            if (innerTag != 0x5F1F) throw new Exception($"Wrong inner tag: 0x{innerTag:X2}");

            ef.DocumentCode = reader.ReadInt(2);
            ef.State = reader.ReadInt(3);
            ef.DocumentNumber.AddRange(reader.ReadBytes(14));

            int isExtended = reader.ReadInt(1);
            if (isExtended == 1) ef.DocumentNumber.AddRange(reader.ReadBytes(15));
            else reader.PaddingNext(15);

            ef.DateOfBirth = reader.ReadBytes(6);
            int checkBirth = reader.ReadInt(1);
            ef.Gender = reader.ReadInt(1);
            ef.DateExpire = reader.ReadBytes(6);
            int checkExpire = reader.ReadInt(1);
            ef.Nationality = reader.ReadBytes(3);

            reader.PaddingNext(12);
            ef.Name = reader.ReadString(30);

            return ef;
        }
    }





    // DG11

    public static void ParseDG11(byte[] dg11)
    {
        var tlvs = TLVParser.Parse(dg11);

        foreach (var tlv in tlvs)
        {
            switch (tlv.Tag)
            {
                case 0x5F0E: // Optional Details
                    Console.WriteLine("Place of Birth: " + System.Text.Encoding.UTF8.GetString(tlv.Value));
                    break;
                case 0x5F10: // Gender
                    Console.WriteLine("Gender: " + System.Text.Encoding.UTF8.GetString(tlv.Value));
                    break;
                case 0x5F11: // Date of Birth
                    Console.WriteLine("Date of Birth: " + System.Text.Encoding.UTF8.GetString(tlv.Value));
                    break;
                default:
                    Console.WriteLine($"Unknown DG11 Tag {tlv.Tag:X2}");
                    break;
            }
        }
    }


    // Dg14
    public static void ParseDG14(byte[] dg14)
    {
        var tlvs = TLVParser.Parse(dg14);

        foreach (var tlv in tlvs)
        {
            if (tlv.Tag == 0x6E) // SecurityInfos
            {
                var innerTlvs = TLVParser.Parse(tlv.Value);
                foreach (var inner in innerTlvs)
                {
                    if (inner.Tag == 0x06) // OID
                    {
                        string oid = string.Join(".", inner.Value.Select(b => b.ToString()));
                        Console.WriteLine("Security Feature OID: " + oid);
                    }
                }
            }
        }
    }


    // DG16
    public static void ParseDG16(byte[] dg16)
    {
        var tlvs = TLVParser.Parse(dg16);

        foreach (var tlv in tlvs)
        {
            switch (tlv.Tag)
            {
                case 0x5F20: // Contact Person Name
                    Console.WriteLine("Contact Name: " + System.Text.Encoding.UTF8.GetString(tlv.Value));
                    break;
                case 0x5F21: // Contact Address
                    Console.WriteLine("Contact Address: " + System.Text.Encoding.UTF8.GetString(tlv.Value));
                    break;
                case 0x5F22: // Contact Phone
                    Console.WriteLine("Contact Phone: " + System.Text.Encoding.UTF8.GetString(tlv.Value));
                    break;
                default:
                    Console.WriteLine($"Unknown DG16 Tag {tlv.Tag:X2}");
                    break;
            }
        }
    }

    // DG12 Utfärdande myndighet VIKTIG för passiveAuthTest.cs

    public class Dg12Info
    {
        public string issuingAuthority { get; set; } = "";
        public string IssuingState { get; set; } = "";
        public string Endorsements { get; set; } = "";
        public string OtherDetails { get; set; } = "";


    }
    public static Dg12Info ParseDG12(byte[] dg12)
    {
        var tlvs = TLVParser.Parse(dg12);
        var info = new Dg12Info();

        foreach (var tlv in tlvs)
        {
            switch (tlv.Tag)
            {
                case 0x5F0B: // Issuing Authority
                    Console.WriteLine("Issuing Authority: " + Encoding.UTF8.GetString(tlv.Value));
                    break;

                case 0x5F0C: // Issuing State or Organisation
                    Console.WriteLine("Issuing State/Org: " + Encoding.UTF8.GetString(tlv.Value));
                    break;

                case 0x5F0D: // Endorsements / Observations
                    Console.WriteLine("Endorsements: " + Encoding.UTF8.GetString(tlv.Value));
                    break;

                case 0x5F0E: // Other details
                    Console.WriteLine("Other Details: " + Encoding.UTF8.GetString(tlv.Value));
                    break;

                default:
                    Console.WriteLine($"Unknown DG12 Tag {tlv.Tag:X2}");
                    break;

            }
        }
        return info;
    }
}




// DG13 Ytterligare dokumentdetaljer ex dokumentnummer, typ av dokument, utfärdande plats
// Kan vara onödig