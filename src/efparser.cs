using System;
using System.Collections.Generic;
using System.Diagnostics;
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



//EFCOM
public class ImplEfCom : IEfParser<ImplEfCom.Info>
{

    public class Info
    {
        public List<int> DgTags { get; set; } = new();
    }
    public string Name()
    {
        return "Com";
    }

    public Info ParseFromBytes(byte[] bytes)
    {
        var sequenceTags = new HashSet<int> { 0x60 };
        Log.Info("bytesCom: " + BitConverter.ToString(bytes));
        var sequenceTagss = TagReader.ReadTagData(bytes, sequenceTags);
        TagReaderExtensions.ToStringFormat(sequenceTagss);
        var sequenceTag = sequenceTagss[0];






        Debug.Assert(sequenceTag.Children.Count == 3, "ChildCount: " + sequenceTag.Children.Count);

        var groupTags = sequenceTag.Children!.FilterByTag(0x5C)[0].Data;

        Log.Info(BitConverter.ToString(groupTags));

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

    public class DataGroupHashEntry
    {
        public int DataGroupNumber { get; set; } //DG1-16
        public byte[] HashValue { get; set; } //SHA256 Hash
    }

    public static EFSodInfo ParseEFSodLdsV18(byte[] bytes)
    {
        var ef = new EFSodInfo();
        var reader = new AsnReader(bytes, AsnEncodingRules.DER);

        AsnReader outerSeq;

        var peekTag = reader.PeekTag();


        // Be able to switch tags depending on old/new passport
        // new -> app tag 23
        // old -> app tag 16

        if (peekTag.TagClass == TagClass.Application && peekTag.TagValue == 23)
        {
            outerSeq = reader.ReadSequence(new Asn1Tag(TagClass.Application, 23));
        }
        else if (peekTag.TagClass == TagClass.Application && peekTag.TagValue == 16)
        {
            outerSeq = reader.ReadSequence(new Asn1Tag(TagClass.Application, 16));
        }
        else if (peekTag.TagClass == TagClass.Universal &&
                (peekTag.TagValue == (int)UniversalTagNumber.Sequence))
        {
            outerSeq = reader.ReadSequence(); // Read as generic sequence

        }
        else
        {
            throw new Exception($"Unknown EF.SOD tag: {peekTag.TagClass} {peekTag.TagValue}");
        }

        Log.Info("outerseq: " + outerSeq);

        Log.Info("hey");




        BigInteger versionInt = outerSeq.ReadInteger(); // Se version
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




}
