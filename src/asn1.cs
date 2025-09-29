namespace Asn1;

using System;
using System.Collections;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Linq;
using System.Text;
using Helper;
using Microsoft.AspNetCore.Razor.TagHelpers;
using Type;
using WebSocketSharp;


public struct AsnBuilder()
{
    private List<byte> _data = [];

    public AsnBuilder AddCustomTag(byte tag, byte[] packetData)
    {
        var packet = new List<byte> { tag, (byte)packetData.Length };
        packet.AddRange(packetData);
        _data.AddRange(packet);
        return this;
    }



    public AsnBuilder AddTag(int tag, byte[] packetData)
    {
        return AddCustomTag((byte)tag, packetData);
    }

    // TODO,  might need to add a tag + length for the whole ASN too
    public byte[] Build() => [.. _data];
}

public class AsnFind(List<AsnNode> nodes)
{
    private readonly List<AsnNode> _topLevelNodes = nodes;

    public List<AsnNode> Filter(Asn1Tag id)
    {
        return [.. _topLevelNodes.Where(n => n.Id == id)];
    }

    public List<AsnNode> GetAllNodes() => _topLevelNodes;
}

public class AsnNode(Asn1Tag id, byte[]? value = null, List<AsnNode>? children = null)
{

    public List<AsnNode> Filter(Asn1Tag id)
    {
        return [.. Children.Where(c => c.Id == id)];
    }

    public AsnNode GetChildNode(int i)
    {
        if (i < Children.Count)
            return Children[i];
        throw new Exception("Accessing non existing child node");
    }

    public byte[] GetValueAsOID() => Value ?? Array.Empty<byte>();

    public byte[] GetValueAsBytes()
    {
        return Value ?? Array.Empty<byte>();
    }


    public int GetValueAsInt()
    {
        if (Value == null) throw new Exception("Value is null");
        int ret = 0;
        foreach (var b in Value)
        {
            ret = (ret << 8) | b;
        }
        return ret;
    }

    // Example parser skeleton, replace ByteReader/AsnInfo with your parser implementation
    public static AsnFind Parse(AsnReader asnReader, Asn1Tag[]? customSeq = null, Asn1Tag[]? customSet = null, bool is_top_level = true)
    {
        // var asnReader = new AsnReader(reader, AsnEncodingRules.DER);

        var nodes = new List<AsnNode>();

        while (asnReader.HasData)
        {
            Asn1Tag tag = asnReader.PeekTag();


            if (tag == Asn1Tag.Sequence)
            {
                var seqReader = asnReader.ReadSequence();
                var children = new List<AsnNode>();
                children.AddRange(Parse(seqReader, is_top_level: false).GetAllNodes());
                nodes.Add(new AsnNode(tag, children: children));
            }
            else if (tag == Asn1Tag.SetOf)
            {
                var setOfReader = asnReader.ReadSetOf();
                var children = new List<AsnNode>();
                children.AddRange(Parse(setOfReader, is_top_level: false).GetAllNodes());
                nodes.Add(new AsnNode(tag, children: children));
            }
            else if (is_top_level)
            {

                var seqReader = asnReader.ReadSequence(tag);
                var children = new List<AsnNode>();
                children.AddRange(Parse(seqReader, is_top_level: false).GetAllNodes());
                nodes.Add(new AsnNode(tag, children: children));
            }
            else
            {
                bool tagFound = false;
                if (customSeq != null)
                {
                    foreach (var s in customSeq)
                    {
                        if (s == tag)
                        {
                            var setOfReader = asnReader.ReadSequence(tag);
                            var children = new List<AsnNode>();
                            children.AddRange(Parse(setOfReader, is_top_level: false).GetAllNodes());
                            nodes.Add(new AsnNode(tag, children: children));
                            tagFound = true;
                            break;
                        }
                    }
                    if (tagFound)
                    {
                        continue;
                    }
                }

                var encodedData = asnReader.ReadEncodedValue().ToArray();

                var sliceStart = 2;
                if (encodedData.Length > 128)
                    sliceStart += 1;

                byte[] data = encodedData[sliceStart..];

                nodes.Add(new AsnNode(tag, value: data));
            }
        }
        return new AsnFind(nodes);
    }


    // Can only be used when all the tags are defined in tagids, otherwise error
    // public void PrintTree(int indent = 0)
    // {
    //     string prefix = new(' ', indent * 2);
    //     TagID Tag = TagID.FromInt(Id);
    //     if (Children.Count > 0)
    //     {
    //         Console.WriteLine($"{prefix}{Tag} (constructed)");
    //         foreach (var child in Children)
    //             child.PrintTree(indent + 1);
    //     }
    //     else if (Value != null)
    //     {
    //         string n = Tag.Id switch
    //         {
    //             TagType.Integer => GetValueAsInt().ToString(),
    //             TagType.OctetString => BitConverter.ToString(Value),
    //             TagType.ObjectIdentifier => BitConverter.ToString(Value), // or OidDecoder
    //             TagType.Boolean => (Value[0] != 0).ToString(),
    //             TagType.Sequence => throw new NotImplementedException(),
    //             TagType.Set => throw new NotImplementedException(),
    //             _ => throw new NotImplementedException(),
    //         };



    //         Console.WriteLine($"{prefix}{Tag}: {n}");
    //     }
    //     else
    //     {
    //         Console.WriteLine($"{prefix}{Tag}: <empty>");
    //     }

    // }

    public void PrintBare(int indent = 0)
    {
        string prefix = new string(' ', indent * 2);

        if (Children.Count > 0)
        {
            Console.WriteLine($"{prefix}{Id:X2} (constructed)");
            foreach (var child in Children)
                child.PrintBare(indent + 1);
        }
        else if (Value != null && Value.Length > 0)
        {
            Console.WriteLine($"{prefix}{Id:X2}: {BitConverter.ToString(Value)}");
        }
        else
        {
            Console.WriteLine($"{prefix}{Id:X2}: <empty>");
        }
    }
    public byte[]? Value { get; } = value;
    public List<AsnNode> Children { get; } = children ?? [];
    public readonly Asn1Tag Id = id;
}



