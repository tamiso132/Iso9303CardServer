// sealed -> means no inheritance allowed


using System.Collections;
using Interfaces;

namespace Type;


public enum TagType : byte
{
    Boolean = 0x01,
    Integer = 0x02,
    OctetString = 0x04,
    ObjectIdentifier = 0x06,
    Sequence = 0x30,
    Set = 0x31,
}

public sealed class TagID
{

    public TagType Id { get; }
    public string TagName { get; }

    private TagID(TagType id, string tagName)
    {
        Id = id;
        TagName = tagName;
    }


    public static readonly TagID Sequence = new(TagType.Boolean, "Sequence");
    public static readonly TagID Set = new(TagType.Set, "Set");
    public static readonly TagID Integer = new(TagType.Integer, "Integer");
    public static readonly TagID OctetString = new(TagType.OctetString, "OctetString");
    public static readonly TagID ObjectIdentifier = new(TagType.ObjectIdentifier, "ObjectIdentifier");
    public static readonly TagID Boolean = new TagID(TagType.Boolean, "Boolean");

    public override string ToString() => TagName;

    internal static TagID FromInt(int rawID)
    {
        return (TagType)rawID switch
        {
            TagType.Integer => Integer,
            TagType.OctetString => OctetString,
            TagType.ObjectIdentifier => ObjectIdentifier,
            TagType.Boolean => Boolean,
            TagType.Sequence => Sequence,
            TagType.Set => Set,
            _ => throw new NotImplementedException(), // catch-all
        };
    }
}


public sealed class EfIdGlobal : IEfID
{
    public byte ShortID { get; }
    private readonly byte[] _fullID;

    private EfIdGlobal(byte shortId, byte[] fullID)
    {
        ShortID = shortId;
        _fullID = fullID;
    }

    public byte[] GetFullID() => (byte[])_fullID.Clone();

    public AppID? AppIdentifier() => null;

    AppID? IEfID.AppIdentifier()
    {
        throw new NotImplementedException();
    }

    public static readonly EfIdGlobal CardAccess = new(0x1C, [0x01, 0x1C]);
    public static readonly EfIdGlobal CardSecurity = new(0x1D, [0x01, 0x1D]);
    public static readonly EfIdGlobal AtrInfo = new(0x01, [0x2F, 0x01]);
    public static readonly EfIdGlobal Dir = new(0x1E, [0x2F, 0x00]);
}

// EF IDs specific to an application
public sealed class EfIdAppSpecific : IEfID
{
    public byte ShortID { get; }
    private readonly byte[] _fullID;

    private EfIdAppSpecific(byte shortId, byte[] fullID)
    {
        ShortID = shortId;
        _fullID = fullID;
    }

    public byte[] GetFullID() => (byte[])_fullID.Clone();

    public AppID? AppIdentifier() => AppID.IdLDS1;


    public static readonly EfIdAppSpecific Com = new(0x1E, [0x01, 0x1E]);
    public static readonly EfIdAppSpecific Dg1 = new(0x01, [0x01, 0x01]);
    public static readonly EfIdAppSpecific Dg2 = new(0x02, [0x01, 0x02]);
    public static readonly EfIdAppSpecific Dg3 = new(0x03, [0x01, 0x03]);
    public static readonly EfIdAppSpecific Dg4 = new(0x04, [0x01, 0x04]);
    public static readonly EfIdAppSpecific Dg5 = new(0x05, [0x01, 0x05]);
    public static readonly EfIdAppSpecific Dg6 = new(0x06, [0x01, 0x06]);
    public static readonly EfIdAppSpecific Dg7 = new(0x07, [0x01, 0x07]);
    public static readonly EfIdAppSpecific Dg8 = new(0x08, [0x01, 0x08]);
    public static readonly EfIdAppSpecific Dg9 = new(0x09, [0x01, 0x09]);
    public static readonly EfIdAppSpecific Dg10 = new(0x0A, [0x01, 0x0A]);
    public static readonly EfIdAppSpecific Dg11 = new(0x0B, [0x01, 0x0B]);
    public static readonly EfIdAppSpecific Dg12 = new(0x0C, [0x01, 0x0C]);
    public static readonly EfIdAppSpecific Dg13 = new(0x0D, [0x01, 0x0D]);
    public static readonly EfIdAppSpecific Dg14 = new(0x0E, [0x01, 0x0E]);
    public static readonly EfIdAppSpecific Dg15 = new(0x0F, [0x01, 0x0F]);
    public static readonly EfIdAppSpecific Dg16 = new(0x10, [0x01, 0x10]);
    public static readonly EfIdAppSpecific Sod = new(0x1D, [0x01, 0x1D]);
}

public sealed class AppID
{
    private readonly byte[] _id;

    private AppID(byte[] id)
    {
        _id = id;
    }

    public byte[] GetID() => (byte[])_id.Clone();

    // Predefined instances
    public static readonly AppID IdLDS1 = new([0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01]);

    public override string ToString() => "Logical Data Structure version 1 (LDS1)";
}



public sealed class SwStatus
{

    #region constant values
    // Static instances
    public static readonly SwStatus Success = new(0x90, 0x00, "Command successful.");
    public static readonly SwStatus MoreDataAvailable = new(0x61, -1, "More data available. Use GET RESPONSE.");
    public static readonly SwStatus WarningNvMemoryUnchanged = new(0x62, -1, "Warning (NV memory unchanged).");
    public static readonly SwStatus WarningNvMemoryChanged = new(0x63, -1, "Warning (NV memory changed).");
    public static readonly SwStatus WrongRespLen = new(0x67, 0x00, "Error: Wrong length in Le field.");
    public static readonly SwStatus FuncInClaNotSupported = new(0x68, 0x00, "Error: Function in CLA not supported.");
    public static readonly SwStatus SecurityNotSatisfied = new(0x69, 0x82, "Error: Security status not satisfied.");
    public static readonly SwStatus AuthMethodBlocked = new(0x69, 0x83, "Error: Authentication method blocked.");
    public static readonly SwStatus ReferencedDataInvalidated = new(0x69, 0x84, "Error: Referenced data invalidated.");
    public static readonly SwStatus ConditionsOfUseNotSatisfied = new(0x69, 0x85, "Error: Conditions of use not satisfied.");
    public static readonly SwStatus CommandNotAllowedNoEfSelected = new(0x69, 0x86, "Error: Command not allowed or no EF selected.");
    public static readonly SwStatus CommandNotAllowedGeneric = new(0x69, -1, "Error: Command not allowed (generic).");
    public static readonly SwStatus FileNotFound = new(0x6A, 0x82, "Error: File or application not found.");
    public static readonly SwStatus RecordNotFound = new(0x6A, 0x83, "Error: Record not found.");
    public static readonly SwStatus NotEnoughMemory = new(0x6A, 0x84, "Error: Not enough memory in file.");
    public static readonly SwStatus LcInconsistentP1P2 = new(0x6A, 0x85, "Error: Lc inconsistent with P1-P2.");
    public static readonly SwStatus IncorrectParameterP1P2 = new(0x6A, 0x86, "Error: Incorrect P1 or P2 parameters.");
    public static readonly SwStatus LcInconsistentTlv = new(0x6A, 0x87, "Error: Lc inconsistent with TLV structure.");
    public static readonly SwStatus DataInvalid = new(0x6A, 0x88, "Error: Referenced data not usable.");
    public static readonly SwStatus FuncNotSupportedByCard = new(0x6A, 0x81, "Error: Function not supported by card.");
    public static readonly SwStatus IncorrectParameterGeneric = new(0x6A, -1, "Error: Incorrect parameters P1-P2 (generic).");
    public static readonly SwStatus InstructionNotSupported = new(0x6D, 0x00, "Error: Instruction code not supported or invalid.");
    public static readonly SwStatus ClassNotSupported = new(0x6E, 0x00, "Error: Class not supported.");
    public static readonly SwStatus CommandAborted = new(0x6F, 0x00, "Error: No precise diagnosis (command aborted).");
    public static readonly SwStatus CardDead = new(0x6F, 0xFF, "Error: Card seems dead or unresponsive.");
    public static readonly SwStatus Unknown = new(-1, -1, "Unknown status.");
    #endregion

    #region fields
    public readonly int Sw1;
    public readonly int Sw2;
    public readonly string Message;

    #endregion

    #region methods
    private SwStatus(int sw1, int sw2, string message)
    {
        Sw1 = sw1;
        Sw2 = sw2;
        Message = message;
    }

    private Dictionary<(int sw1, int sw2), SwStatus> StatusMap = new()
    {
        { (Success.Sw1, Success.Sw2), Success },
        { (MoreDataAvailable.Sw1, MoreDataAvailable.Sw2), MoreDataAvailable },
        { (WarningNvMemoryUnchanged.Sw1, WarningNvMemoryUnchanged.Sw2), WarningNvMemoryUnchanged },
        { (WarningNvMemoryChanged.Sw1, WarningNvMemoryChanged.Sw2), WarningNvMemoryChanged },
        { (WrongRespLen.Sw1, WrongRespLen.Sw2), WrongRespLen },
        { (FuncInClaNotSupported.Sw1, FuncInClaNotSupported.Sw2), FuncInClaNotSupported },
        { (SecurityNotSatisfied.Sw1, SecurityNotSatisfied.Sw2), SecurityNotSatisfied },
        { (AuthMethodBlocked.Sw1, AuthMethodBlocked.Sw2), AuthMethodBlocked },
        { (ReferencedDataInvalidated.Sw1, ReferencedDataInvalidated.Sw2), ReferencedDataInvalidated },
        { (ConditionsOfUseNotSatisfied.Sw1, ConditionsOfUseNotSatisfied.Sw2), ConditionsOfUseNotSatisfied },
        { (CommandNotAllowedNoEfSelected.Sw1, CommandNotAllowedNoEfSelected.Sw2), CommandNotAllowedNoEfSelected },
        { (CommandNotAllowedGeneric.Sw1, CommandNotAllowedGeneric.Sw2), CommandNotAllowedGeneric },
        { (FileNotFound.Sw1, FileNotFound.Sw2), FileNotFound },
        { (RecordNotFound.Sw1, RecordNotFound.Sw2), RecordNotFound },
        { (NotEnoughMemory.Sw1, NotEnoughMemory.Sw2), NotEnoughMemory },
        { (LcInconsistentP1P2.Sw1, LcInconsistentP1P2.Sw2), LcInconsistentP1P2 },
        { (IncorrectParameterP1P2.Sw1, IncorrectParameterP1P2.Sw2), IncorrectParameterP1P2 },
        { (LcInconsistentTlv.Sw1, LcInconsistentTlv.Sw2), LcInconsistentTlv },
        { (DataInvalid.Sw1, DataInvalid.Sw2), DataInvalid },
        { (FuncNotSupportedByCard.Sw1, FuncNotSupportedByCard.Sw2), FuncNotSupportedByCard },
        { (IncorrectParameterGeneric.Sw1, IncorrectParameterGeneric.Sw2), IncorrectParameterGeneric },
        { (InstructionNotSupported.Sw1, InstructionNotSupported.Sw2), InstructionNotSupported },
        { (ClassNotSupported.Sw1, ClassNotSupported.Sw2), ClassNotSupported },
        { (CommandAborted.Sw1, CommandAborted.Sw2), CommandAborted },
        { (CardDead.Sw1, CardDead.Sw2), CardDead },
        { (Unknown.Sw1, Unknown.Sw2), Unknown }
    };

    public static SwStatus FromCombined(int combined)
    {
        int sw1 = (combined >> 8) & 0xFF;
        int sw2 = combined & 0xFF;
        return FromSw1Sw2(sw1, sw2);
    }

    public static SwStatus FromSw1Sw2(int sw1, int sw2)
    {
        if (StatusMap.TryGetValue((sw1, sw2), out var status))
            return status;

        // Handle generic SW1 cases
        if (sw1 == MoreDataAvailable.Sw1) return MoreDataAvailable;
        if (sw1 == WarningNvMemoryUnchanged.Sw1) return WarningNvMemoryUnchanged;
        if (sw1 == WarningNvMemoryChanged.Sw1) return WarningNvMemoryChanged;

        foreach (var kv in StatusMap)
        {
            if (kv.Key.sw1 == sw1 && kv.Key.sw2 == -1)
                return kv.Value;
        }

        Console.WriteLine($"Warning: Unknown SW code: SW1=0x{sw1:X2}, SW2=0x{sw2:X2}");
        return Unknown;
    }
    #endregion
}


public struct ResponseCommand(int sw1, int sw2, byte[]? data = null)
{
    public static ResponseCommand FromBytes(byte[] bytes)
    {
        int sw1 = bytes[^2];
        int sw2 = bytes[^1];

        if (bytes.Length <= 2)
            return new ResponseCommand(sw1, sw2, []);

        byte[] data = bytes[0..(bytes.Length - 2)];

        return new ResponseCommand(sw1, sw2, data);

    }

    public byte[] data = data ?? [];
    public readonly SwStatus status = SwStatus.FromSw1Sw2(sw1, sw2);


}


