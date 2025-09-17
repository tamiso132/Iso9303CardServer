using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Interfaces;
using Type;
using Asn1;


public class Command<T, E>(ICommunicator communicator, T encryption)
    where T : IServerEncryption<E>
    where E : Enum
{


    public bool IsActiveApp { get; private set; } = false;

    public async Task<Result<ResponseCommand, E>> ReadBinary(IEfID efID, byte offset = 0x00, byte le = 0x00, byte cla = 0x00)
        => await ReadBinaryFullID(efID.GetFullID(), offset, le);

    public async Task<Result<ResponseCommand, E>> SelectApplication(AppID app)
    {
        byte[] appLDS1ID = new byte[] { 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01 };
        return await ApplicationSelect(appLDS1ID);
    }

    private async Task<Result<ResponseCommand, E>> ElementFileSelect(byte[] fileID, byte cla = 0x00)
    {
        byte[] cmd = EncryptIso9303(cla, 0xA4, 0x02, 0x0C, fileID);
        var result = _encryption.Decode(await _communicator.TransceiveAsync(_encryption.Encrypt(cmd)));

        if (!result.IsSuccess) return Fail(result.Error);

        return Success(ResponseCommand.FromBytes(result.Unwrap()));
    }

    private async Task<Result<ResponseCommand, E>> ApplicationSelect(byte[] appID)
    {
        byte[] cmd = EncryptIso9303(0x00, 0xA4, 0x04, 0x0C, appID);
        var result = _encryption.Decode(await _communicator.TransceiveAsync(_encryption.Encrypt(cmd)));

        if (!result.IsSuccess) return Fail(result.Error);

        IsActiveApp = true;
        return Success(ResponseCommand.FromBytes(result.Unwrap()));
    }

    private async Task<Result<ResponseCommand, E>> ReadBinaryFullID(byte[] efID, byte offset, byte le, byte cla = 0x00)
    {
        var selectResult = await ElementFileSelect(efID);
        if (!selectResult.IsSuccess) return Fail(selectResult.Error);

        byte[] cmd = EncryptIso9303(0x00, 0xB0, 0x00, 0x00, le: le);
        var result = _encryption.Decode(await _communicator.TransceiveAsync(_encryption.Encrypt(cmd)));

        if (!result.IsSuccess) return Fail(result.Error);

        return Success(ResponseCommand.FromBytes(result.Unwrap()));
    }

    public async Task<Result<ResponseCommand, E>> ReadBinaryShort(IEfID efID, byte offset, byte le, byte cla = 0x00)
    {
        byte[] cmd = EncryptIso9303(cla, 0xB0, efID.ShortID, offset);
        var result = _encryption.Decode(await _communicator.TransceiveAsync(_encryption.Encrypt(cmd)));

        if (!result.IsSuccess) return Fail(result.Error);

        return Success(ResponseCommand.FromBytes(result.Unwrap()));
    }

    public async Task<Result<ResponseCommand, E>> MseSetAT(byte[] oid, byte[] password, int parameterID, byte[]? chat = null, byte cla = 0x00)
    {
        byte[] data = new AsnBuilder()
            .AddCustomTag(0x80, oid)
            .AddCustomTag(0x83, password)
            .AddCustomTag(0x84, new byte[] { (byte)parameterID })
            .Build();

        byte[] cmd = EncryptIso9303(cla, 0x22, 0xC1, 0xA4, data);
        var result = _encryption.Decode(await _communicator.TransceiveAsync(_encryption.Encrypt(cmd)));

        if (!result.IsSuccess)
            return Fail(result.Error);


        return Success(ResponseCommand.FromBytes(result.Value));
    }

    private byte[] EncryptIso9303(byte cla, byte ins, byte p1, byte p2, byte[] data = null!, byte le = 0x00)
    {
        var cmd = new List<byte> { cla, ins, p1, p2 };
        if (data != null && data.Length > 0)
        {
            cmd.Add((byte)data.Length);
            cmd.AddRange(data);
        }
        if (le != 0x00) cmd.Add(le);
        return cmd.ToArray();
    }

    private Result<ResponseCommand, E> Success(ResponseCommand cmd) => Result<ResponseCommand, E>.Success(cmd);
    private Result<ResponseCommand, E> Fail(E e) => Result<ResponseCommand, E>.Fail(e);

    private readonly ICommunicator _communicator = communicator;
    private readonly T _encryption = encryption;
}
