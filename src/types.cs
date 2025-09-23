// sealed -> means no inheritance allowed


using System.Collections;
using ErrorHandling;
using Helper;
using Interfaces;

namespace Type;

using TResult = Result<Type.ResponseCommand>;




public sealed class EfIdGlobal : IEfID
{
    public byte ShortID { get; }
    private readonly byte[] _fullID;
    public string Name;

    private EfIdGlobal(byte shortId, byte[] fullID, string name)
    {
        ShortID = shortId;
        _fullID = fullID;
        Name = name;

    }

    public byte[] GetFullID() => (byte[])_fullID.Clone();

    public AppID? AppIdentifier() => null;

    AppID? IEfID.AppIdentifier()
    {
        return null;
    }

    public string GetName()
    {
        return Name;
    }

    public static readonly EfIdGlobal CardAccess = new(0x1C, new byte[] { 0x01, 0x1C }, "CardAccess");
    public static readonly EfIdGlobal CardSecurity = new(0x1D, new byte[] { 0x01, 0x1D }, "CardSecurity");
    public static readonly EfIdGlobal AtrInfo = new(0x01, new byte[] { 0x2F, 0x01 }, "AtrInfo");
    public static readonly EfIdGlobal Dir = new(0x1E, new byte[] { 0x2F, 0x00 }, "Dir");

}

// EF IDs specific to an application
public sealed class EfIdAppSpecific : IEfID
{
    public byte ShortID { get; }
    private readonly byte[] _fullID;
    public readonly string Name;

    private EfIdAppSpecific(byte shortId, byte[] fullID, string name)
    {
        ShortID = shortId;
        _fullID = fullID;
        Name = name;
    }

    public byte[] GetFullID() => (byte[])_fullID.Clone();

    public AppID? AppIdentifier() => AppID.IdLDS1;

    public string GetName()
    {
        return Name;
    }

    public static readonly EfIdAppSpecific Com = new(0x1E, [0x01, 0x1E], "Com");
    public static readonly EfIdAppSpecific Dg1 = new(0x01, [0x01, 0x01], "Dg1");
    public static readonly EfIdAppSpecific Dg2 = new(0x02, [0x01, 0x02], "Dg2");
    public static readonly EfIdAppSpecific Dg3 = new(0x03, [0x01, 0x03], "Dg3");
    public static readonly EfIdAppSpecific Dg4 = new(0x04, [0x01, 0x04], "Dg4");
    public static readonly EfIdAppSpecific Dg5 = new(0x05, [0x01, 0x05], "Dg5");
    public static readonly EfIdAppSpecific Dg6 = new(0x06, [0x01, 0x06], "Dg6");
    public static readonly EfIdAppSpecific Dg7 = new(0x07, [0x01, 0x07], "Dg7");
    public static readonly EfIdAppSpecific Dg8 = new(0x08, [0x01, 0x08], "Dg8");
    public static readonly EfIdAppSpecific Dg9 = new(0x09, [0x01, 0x09], "Dg9");
    public static readonly EfIdAppSpecific Dg10 = new(0x0A, [0x01, 0x0A], "Dg10");
    public static readonly EfIdAppSpecific Dg11 = new(0x0B, [0x01, 0x0B], "Dg11");
    public static readonly EfIdAppSpecific Dg12 = new(0x0C, [0x01, 0x0C], "Dg12");
    public static readonly EfIdAppSpecific Dg13 = new(0x0D, [0x01, 0x0D], "Dg13");
    public static readonly EfIdAppSpecific Dg14 = new(0x0E, [0x01, 0x0E], "Dg14");
    public static readonly EfIdAppSpecific Dg15 = new(0x0F, [0x01, 0x0F], "Dg15");
    public static readonly EfIdAppSpecific Dg16 = new(0x10, [0x01, 0x10], "Dg16");
    public static readonly EfIdAppSpecific Sod = new(0x1D, [0x01, 0x1D], "Sod");

}

public sealed class AppID
{
    private readonly byte[] _id;
    public readonly string Name;

    private AppID(byte[] id, string name)
    {
        _id = id;
        Name = name;
    }

    public byte[] GetID() => (byte[])_id.Clone();

    // Predefined instances// [0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01];
    public static readonly AppID IdLDS1 = new([0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01], "Logical Data Structure version 1");

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

    private static Dictionary<(int sw1, int sw2), SwStatus> StatusMap = new()
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

        Log.Error($"Warning: Unknown SW code: SW1=0x{sw1:X2}, SW2=0x{sw2:X2}");
        return Unknown;
    }

    public bool IsSuccess()
    {
        if (this == Success)
            return true;

        return false;
    }

    #endregion
}


public struct ResponseCommand(int sw1, int sw2, byte[]? data = null)
{
    public readonly E Parse<T, E>() where T : IEfParser<E>, new()
    {
        var t = new T();
        Log.Info("Parsing Elemental File: " + t.Name());
        return t.ParseFromBytes(data);
    }

    public static TResult FromBytes(byte[] bytes)
    {
        if (bytes.Length < 2)
            return TResult.Fail(new Error.ClientErrorFormat("Client response was incorrect (length " + bytes.Length + ": " + BitConverter.ToString(bytes)));

        int sw1 = bytes[^2];
        int sw2 = bytes[^1];


        ResponseCommand resp;
        if (bytes.Length == 2)
            resp = new ResponseCommand(sw1, sw2, []);
        else
        {
            byte[] data = bytes[0..(bytes.Length - 2)];
            resp = new ResponseCommand(sw1, sw2, data);
        }


        return TResult.Success(resp);

    }

    public byte[] data = data ?? [];
    public readonly SwStatus status = SwStatus.FromSw1Sw2(sw1, sw2);


}


