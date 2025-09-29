using Interfaces;
using Type;
using Asn1;
using Helper;
using ErrorHandling;
using System.Formats.Asn1;

namespace Command;

using TResult = Result<ResponseCommand>;


// TODO, add a command that keeps asking for more bytes if we get error SW that all the bytes has not been sent yet
// TODO, should also add error check for when parsing to Response Command fails
public class Command<T>(ICommunicator communicator, T encryption)
    where T : IServerFormat
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

    public async Task<TResult> SelectDefaultMF()
    {
        Log.Info("Selecting Default MF");
        byte[] cmd = FormatCommand(0x00, 0xA4, 0x00, 0x0C);
        return await SendPackageDecodeResponse(cmd);
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
                                        //  .AddCustomTag(0x84, [(byte)parameterID]) // parameter id
            .Build();

        byte[] cmd = FormatCommand(cla, 0x22, 0xC1, 0xA4, data);
        return await SendPackageDecodeResponse(cmd);
    }

    public async Task<TResult> GeneralAuthenticate(GenAuthType type, byte cla = 0x10)
    {
        Log.Info("Sending General Authenticate Command");

        var writer = new AsnWriter(AsnEncodingRules.DER);
        var ctxSeq = new Asn1Tag(TagClass.ContextSpecific, 0x7C, true);

        using (writer.PushSequence(ctxSeq))
        {
            var data = type.Data();
            if (data.Length != 0)
                writer.WriteEncodedValue(data);
        }

        // byte[] encoded_raw = writer.Encode()[1..];

        //        byte[] raw = [0x10, 0x86, 0x00, 0x00, 0x02, 0x7C, 0x00, 0x00];

        byte[] cmdFormat = FormatCommand(cla, 0x86, 0x00, 0x00, data: writer.Encode()[1..], le: 0x00);


        //Log.Info("Write: " + BitConverter.ToString(raw));

        var result = await SendPackageDecodeResponse(cmdFormat);

        if (result.IsSuccess)
            if (result.Value.data.Length == 0)
                return TResult.Fail(new Error.Other("General Authentication not sending the encrypted nounce!"));


        return result;
    }
    public async Task<TResult> GeneralAuthenticateMapping(byte innerTag, byte[] publicKey)
    {
        Log.Info("General Authentication Mapping");
        // TODO, check if length is bigger then 128
        byte[] innerSequence = [innerTag, (byte)publicKey.Length, .. publicKey];
        byte[] data = [0x7C, (byte)innerSequence.Length, .. innerSequence];



        byte[] cmdFormat = FormatCommand(0x10, 0x86, 0x00, 0x00, data: data, le: 0x00);


        //Log.Info("Write: " + BitConverter.ToString(raw));

        var result = await SendPackageDecodeResponse(cmdFormat);

        if (result.IsSuccess)
            if (result.Value.data.Length == 0)
                return TResult.Fail(new Error.Other("General Authentication not sending the encrypted nounce!"));


        return result;
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
        var result = _serverFormat.DeFormat(await _communicator.TransceiveAsync(_serverFormat.Format(cmd)));
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
    private readonly T _serverFormat = encryption;
}




enum MSEType // p1 p2
{
    MutualAuthentication = 0xC1A4,
}


public abstract record GenAuthType
{
    public abstract byte[] Data();

    public record EncryptedNounce() : GenAuthType
    {
        public override byte[] Data()
        {
            return [];
        }

    }
    public record MappingData(byte[] mappingData) : GenAuthType
    {
        public override byte[] Data()
        {
            // return new AsnBuilder().AddCustomTag(0x81, _mappingData).Build();
            AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);
            var n = new Asn1Tag(TagClass.ContextSpecific, 0x81);
            writer.WriteOctetString(mappingData, n);
            return writer.Encode()[1..];
        }

        private byte[] _mappingData = mappingData;

    }

    public record KeyAgreement(byte[] authToken) : GenAuthType
    {
        public override byte[] Data()
        {

            AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);
            writer.WriteOctetString(_authToken, tag: new Asn1Tag(TagClass.ContextSpecific, 0x86));
            return writer.Encode();
        }

        private byte[] _authToken = authToken;
    }
}


