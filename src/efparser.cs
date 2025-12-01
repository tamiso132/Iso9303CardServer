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



//EFCOM read, find existing datagroups and read LDS version
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

        var root = TagReader.ReadTagData(bytes, [0x30, 0x31]); //Parse

        foreach (var protocol in root[0].Children)
        {
            byte[] oid = [];
            var ver = 2;
            var paramID = 0;

            var number = protocol.Children.FilterByTag(0x02);

            ver = number[0].Data[0];
            paramID = number[1].Data[0];
            oid = protocol.Children.FilterByTag(0x06)[0].Data;

            var info = new EncryptionInfo(oid, paramID);
            ef.EncryptInfos.Add(info);


            if (ver != 2)
            {
                Log.Error("Version is not 2??");
                throw new NotImplementedException();
            }

            Log.Info(BitConverter.ToString(oid));

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







