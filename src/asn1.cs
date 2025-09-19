namespace Asn1;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Helper;
using Type;


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

    public AsnBuilder AddTag(TagID tag, byte[] packetData)
    {
        return AddCustomTag((byte)tag.Id, packetData);
    }

    // TODO,  might need to add a tag + length for the whole ASN too
    public byte[] Build() => [.. _data];
}

public class AsnFind(List<AsnNode> nodes)
{
    private readonly List<AsnNode> _topLevelNodes = nodes;

    public List<AsnNode> Filter(TagID id)
    {
        return [.. _topLevelNodes.Where(n => n.Id == (int)id.Id)];
    }

    public List<AsnNode> Filter(int id)
    {
        return [.. _topLevelNodes.Where(n => n.Id == (int)id)];
    }


    public List<AsnNode> GetAllNodes() => _topLevelNodes;
}

public class AsnNode(int id, byte[]? value = null, List<AsnNode>? children = null)
{

    public List<AsnNode> Filter(TagID id)
    {
        return [.. Children.Where(c => c.Id == (int)id.Id)];
    }

    public AsnNode GetChildNode(int i)
    {
        if (i < Children.Count)
            return Children[i];
        throw new Exception("Accessing non existing child node");
    }

    public byte[] GetValueAsOID() => Value ?? Array.Empty<byte>();

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
    public static AsnFind Parse(ByteReader reader, bool is_top_level = true)
    {
        var nodes = new List<AsnNode>();
        while (reader.HasRemaining())
        {
            AsnInfo info = reader.ReadASN1();
            TagID tag = info.Tag;

            if (tag == TagID.Sequence || tag == TagID.Set || is_top_level)
            {
                var innerReader = new ByteReader(info.Data);
                var children = new List<AsnNode>();
                while (innerReader.HasRemaining())
                    children.AddRange(Parse(innerReader, false).GetAllNodes());
                nodes.Add(new AsnNode((int)tag.Id, children: children));
            }
            else
            {
                nodes.Add(new AsnNode((int)tag.Id, value: info.Data));
            }
        }
        return new AsnFind(nodes);
    }

    // Can only be used when all the tags are defined in tagids, otherwise error
    public void PrintTree(int indent = 0)
    {
        string prefix = new(' ', indent * 2);
        TagID Tag = TagID.FromInt(Id);
        if (Children.Count > 0)
        {
            Console.WriteLine($"{prefix}{Tag} (constructed)");
            foreach (var child in Children)
                child.PrintTree(indent + 1);
        }
        else if (Value != null)
        {
            string n = Tag.Id switch
            {
                TagType.Integer => GetValueAsInt().ToString(),
                TagType.OctetString => BitConverter.ToString(Value),
                TagType.ObjectIdentifier => BitConverter.ToString(Value), // or OidDecoder
                TagType.Boolean => (Value[0] != 0).ToString(),
                TagType.Sequence => throw new NotImplementedException(),
                TagType.Set => throw new NotImplementedException(),
                _ => throw new NotImplementedException(),
            };



            Console.WriteLine($"{prefix}{Tag}: {n}");
        }
        else
        {
            Console.WriteLine($"{prefix}{Tag}: <empty>");
        }

    }

    public void PrintBare(int indent = 0)
    {
        string prefix = new string(' ', indent * 2);

        if (Children.Count > 0)
        {
            Console.WriteLine($"{prefix}0x{Id:X2} (constructed)");
            foreach (var child in Children)
                child.PrintTree(indent + 1);
        }
        else if (Value != null && Value.Length > 0)
        {
            Console.WriteLine($"{prefix}0x{Id:X2}: {BitConverter.ToString(Value)}");
        }
        else
        {
            Console.WriteLine($"{prefix}0x{Id:X2}: <empty>");
        }
    }
    public byte[]? Value { get; } = value;
    public List<AsnNode> Children { get; } = children ?? [];
    public readonly int Id = id;
}
