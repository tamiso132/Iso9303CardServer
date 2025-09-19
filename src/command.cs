using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Interfaces;
using Type;
using Asn1;
using Helper;
using System.ComponentModel;

namespace Command;

using E = CommandError;

// TODO, add a command that keeps asking for more bytes if we get error SW that all the bytes has not been sent yet
// TODO, should also add error check for when parsing to Response Command fails
public class Command<T>(ICommunicator communicator, T encryption)
    where T : IServerEncryption<E>
{


    public bool IsActiveApp { get; private set; } = false;

    public async Task<Result<ResponseCommand, E>> ReadBinary(IEfID efID, byte offset = 0x00, byte le = 0x00, byte cla = 0x00)
    {
        var app = efID.AppIdentifier();
        if (_appSelected == app || app == null)
        {
            return await ReadBinaryFullID(efID, offset, le);

        }
        else
        {
            await SelectApplication(app);
            _appSelected = app;
            return await ReadBinaryFullID(efID, offset, le);
        }
    }
    public async Task<Result<ResponseCommand, E>> SelectApplication(AppID app)
    {
        return await ApplicationSelect(app);
    }

    private async Task<Result<ResponseCommand, E>> ElementFileSelect(IEfID fileID, byte cla = 0x00)
    {
        Log.Info("Selecting EF File: " + fileID.GetName());
        byte[] cmd = FormatCommand(cla, 0xA4, 0x02, 0x0C, fileID.GetFullID());
        var result = _encryption.Decode(await _communicator.TransceiveAsync(_encryption.Encrypt(cmd)));
        return Success(ResponseCommand.FromBytes(result.Unwrap()));
    }

    private async Task<Result<ResponseCommand, E>> ApplicationSelect(AppID appID)
    {
        Log.Info("Selecting Application: " + appID.Name);
        byte[] cmd = FormatCommand(0x00, 0xA4, 0x04, 0x0C, appID.GetID());
        var result = _encryption.Decode(await _communicator.TransceiveAsync(_encryption.Encrypt(cmd)));

        if (!result.IsSuccess) return Fail(result.Error);

        IsActiveApp = true;
        return Success(ResponseCommand.FromBytes(result.Unwrap()));
    }

    private async Task<Result<ResponseCommand, E>> ReadBinaryFullID(IEfID efID, byte offset, byte le, byte cla = 0x00)
    {
        var selectResult = await ElementFileSelect(efID);
        if (!selectResult.IsSuccess)
        {
            Console.WriteLine("Element File Select Error");
            return selectResult;
        }

        Log.Info("Reading EF File: " + efID.GetName());
        byte[] cmd = FormatCommand(0x00, 0xB0, 0x00, 0x00, le: le);
        var result = _encryption.Decode(await _communicator.TransceiveAsync(_encryption.Encrypt(cmd)));

        if (!result.IsSuccess) return Fail(result.Error);

        return Success(ResponseCommand.FromBytes(result.Unwrap()));
    }

    public async Task<Result<ResponseCommand, E>> ReadBinaryShort(IEfID efID, byte offset, byte le, byte cla = 0x00)
    {
        byte[] cmd = FormatCommand(cla, 0xB0, efID.ShortID, offset);
        var result = _encryption.Decode(await _communicator.TransceiveAsync(_encryption.Encrypt(cmd)));

        if (!result.IsSuccess) return Fail(result.Error);

        return Success(ResponseCommand.FromBytes(result.Unwrap()));
    }

    public async Task<Result<ResponseCommand, E>> MseSetAT(byte[] oid, int parameterID, byte cla = 0x00)
    {
        byte[] data = new AsnBuilder()
            .AddCustomTag(0x80, oid) // object identifier
            .AddCustomTag(0x83, [0x01]) // MRZ
            .AddCustomTag(0x84, [(byte)parameterID]) // parameter id
            .Build();

        byte[] cmd = FormatCommand(cla, 0x22, 0xC1, 0xA4, data);
        var result = _encryption.Decode(await _communicator.TransceiveAsync(_encryption.Encrypt(cmd)));

        if (!result.IsSuccess)
            return Fail(result.Error);


        return Success(ResponseCommand.FromBytes(result.Value));
    }

    public async Task<Result<ResponseCommand, E>> GeneralAuthenticate()
    {
        byte[] data = new AsnBuilder().AddCustomTag(0x7C, []).Build();
        byte[] cmd = FormatCommand(0x10, 0x86, 0x00, 0x00, data: data);

        var result = _encryption.Decode(await _communicator.TransceiveAsync(_encryption.Encrypt(cmd)));
        if (!result.IsSuccess)
            return Fail(result.Error);

        return Success(ResponseCommand.FromBytes(result.Unwrap()));
    }

    private static byte[] FormatCommand(byte cla, byte ins, byte p1, byte p2, byte[] data = null!, byte? le = null)
    {
        var cmd = new List<byte> { cla, ins, p1, p2 };
        if (data != null && data.Length > 0)
        {
            cmd.Add((byte)data.Length);
            cmd.AddRange(data);
        }
        if (le != null) cmd.Add(le.Value);

        return [.. cmd];
    }




    private static Result<ResponseCommand, E> Success(ResponseCommand cmd) => Result<ResponseCommand, E>.Success(cmd);
    private static Result<ResponseCommand, E> Fail(E e) => Result<ResponseCommand, E>.Fail(e);
    private AppID? _appSelected;
    private readonly ICommunicator _communicator = communicator;
    private readonly T _encryption = encryption;
}

public static class CommandErrorExtension
{
    public static string GetDescription(this CommandError value)
    {
        var field = value.GetType().GetField(value.ToString());
        var attr = (DescriptionAttribute?)Attribute.GetCustomAttribute(field!, typeof(DescriptionAttribute));
        return attr?.Description ?? value.ToString();
    }
}

public enum CommandError
{
    [Description("NFC connection lost")]
    NFCLost,

    [Description("Invalid status word")]
    SWError,

    [Description("Encryption failed")]
    EncryptError,

    [Description("Parse to ResponseCommand Fail")]
    ResponseParseFail,

}


