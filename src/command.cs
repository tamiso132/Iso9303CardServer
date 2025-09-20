using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Interfaces;
using Type;
using Asn1;
using Helper;
using System.ComponentModel;
using ErrorHandling;
using Microsoft.AspNetCore.Authentication;

namespace Command;

using TResult = Result<ResponseCommand>;


// TODO, add a command that keeps asking for more bytes if we get error SW that all the bytes has not been sent yet
// TODO, should also add error check for when parsing to Response Command fails
public class Command<T>(ICommunicator communicator, T encryption)
    where T : IServerEncryption
{


    public bool IsActiveApp { get; private set; } = false;

    public async Task<TResult> ReadBinary(IEfID efID, byte offset = 0x00, byte le = 0x00, byte cla = 0x00)
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
    public async Task<TResult> SelectApplication(AppID app)
    {
        return await ApplicationSelect(app);
    }

    private async Task<TResult> ElementFileSelect(IEfID fileID, byte cla = 0x00)
    {
        Log.Info("Selecting EF File: " + fileID.GetName());
        byte[] cmd = FormatCommand(cla, 0xA4, 0x02, 0x0C, fileID.GetFullID());
        return await SendPackageDecodeResponse(cmd);
    }

    private async Task<TResult> ApplicationSelect(AppID appID)
    {
        Log.Info("Selecting Application: " + appID.Name);
        byte[] cmd = FormatCommand(0x00, 0xA4, 0x04, 0x0C, appID.GetID());
        var result = await SendPackageDecodeResponse(cmd);
        if (result.IsSuccess)
            this._appSelected = appID;

        return result;
    }

    private async Task<TResult> ReadBinaryFullID(IEfID efID, byte offset, byte le, byte cla = 0x00)
    {
        var selectResult = await ElementFileSelect(efID);
        if (!selectResult.IsSuccess)
        {
            Console.WriteLine("Element File Select Error");
            return selectResult;
        }

        Log.Info("Reading EF File: " + efID.GetName());
        byte[] cmd = FormatCommand(0x00, 0xB0, 0x00, 0x00, le: le);
        return await SendPackageDecodeResponse(cmd);
    }

    public async Task<TResult> ReadBinaryShort(IEfID efID, byte offset, byte le, byte cla = 0x00)
    {
        byte[] cmd = FormatCommand(cla, 0xB0, efID.ShortID, offset);
        return await SendPackageDecodeResponse(cmd);
    }

    public async Task<TResult> MseSetAT(byte[] oid, int parameterID, byte cla = 0x00)
    {
        Log.Info("Sending MseSetAT Command");
        byte[] data = new AsnBuilder()
            .AddCustomTag(0x80, oid) // object identifier
            .AddCustomTag(0x83, [0x01]) // MRZ
            .AddCustomTag(0x84, [(byte)parameterID]) // parameter id
            .Build();

        byte[] cmd = FormatCommand(cla, 0x22, 0xC1, 0xA4, data);
        return await SendPackageDecodeResponse(cmd);
    }

    public async Task<TResult> GeneralAuthenticate(byte cla = 0x10)
    {
        Log.Info("Sending General Authenticate Command");
        // byte[] data = new AsnBuilder().AddCustomTag(0x7C, []).Build();
        byte[] raw = [cla, 0x86, 0x00, 0x00, 0x02, 0x7C, 0x00, 0x00];

        return await SendPackageDecodeResponse(raw);
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

    private async Task<TResult> SendPackageDecodeResponse(byte[] cmd)
    {
        var result = _encryption.Decode(await _communicator.TransceiveAsync(_encryption.Encrypt(cmd)));
        if (!result.IsSuccess)
            return Fail(result.Error);

        var response = ResponseCommand.FromBytes(result.Unwrap());
        if (!response.IsSuccess)
            return response;

        if (!response.Value.status.IsSuccess())
        {
            return Fail(new Error.SwError(response.Value.status));
        }

        return response;
    }




    private static TResult Success(ResponseCommand cmd) => TResult.Success(cmd);
    private static TResult Fail(Error e) => TResult.Fail(e);
    private AppID? _appSelected;
    private readonly ICommunicator _communicator = communicator;
    private readonly T _encryption = encryption;
}




enum MSEType // p1 p2
{
    MutualAuthentication = 0xC1A4,
}





