using Interfaces;
using Type;
using Asn1;
using Helper;
using ErrorHandling;
using System.Formats.Asn1;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Asn1;
using System.Security.Cryptography;
using System.Diagnostics;
using System.Text;
using System.Numerics;
using Org.BouncyCastle.Security;

namespace Command;

using TResult = Result<ResponseCommand>;
using TResultBool = Result<bool>;

public abstract record MessageType
{

    public abstract byte[] FormatCommand<T>(Command<T> command, byte ins, byte p1, byte p2, byte[] data, byte? le = null) where T : IServerFormat;
    public abstract ResponseCommand ParseCommand<T>(Command<T> command, byte[] response) where T : IServerFormat;

    public static Secure SecureMessage => new();
    public static NonSecure NonSecureMessage => new();
    public sealed record Secure : MessageType
    {
        internal Secure() { }
        public override byte[] FormatCommand<T>(Command<T> command, byte ins, byte p1, byte p2, byte[] data, byte? le = null)
        {
            iv = command.GetIV();
            return command.FormatEncryptedCommand(data, ins, p1, p2, iv);
        }

        public override ResponseCommand ParseCommand<T>(Command<T> command, byte[] response)
        {
            return command.ParseEncryptedReponse(response, iv);
        }

        byte[] iv = [];

    }

    public sealed record NonSecure : MessageType
    {
        internal NonSecure() { }
        public override byte[] FormatCommand<T>(Command<T> command, byte ins, byte p1, byte p2, byte[] data, byte? le = null)
        {
            return Command<T>.FormatCommand(0x00, ins, p1, p2, data, le: le);
        }

        public override ResponseCommand ParseCommand<T>(Command<T> command, byte[] response)
        {
            return ResponseCommand.FromBytes(response).Value;
        }

    }

}




// TODO, add a command that keeps asking for more bytes if we get error SW that all the bytes has not been sent yet
// TODO, should also add error check for when parsing to Response Command fails
public class Command<T>(ICommunicator communicator, T encryption)
    where T : IServerFormat
{


    public bool IsActiveApp { get; private set; } = false;

    public async Task<TResult> ReadBinary(MessageType type, IEfID efID, byte offset = 0x00, byte le = 0x00)
    {
        var app = efID.AppIdentifier();
        if (_appSelected == app || app == null)
        {
            return await ReadBinaryFullID(type, efID, offset, le);

        }
        else
        {
            await SelectApplication(type, app);
            _appSelected = app;
            return await ReadBinaryFullID(type, efID, offset, le);
        }
    }
    public async Task<TResult> SelectApplication(MessageType type, AppID app)
    {
        return await ApplicationSelect(type, app);
    }

    public async Task<TResult> SelectDefaultMF(MessageType type)
    {
        Log.Info("Selecting Default MF");
        byte[] cmd = type.FormatCommand(this, 0xA4, 0x00, 0x0C, []);
        return await SendPackageDecodeResponse(type, cmd);
    }

    private async Task<TResult> ElementFileSelect(MessageType type, IEfID fileID)
    {
        Log.Info("Selecting EF File: " + fileID.GetName());
        byte[] data = fileID.GetFullID();
        byte[] cmd = type.FormatCommand<T>(this, 0xA4, 0x02, 0x0C, data);
        return await SendPackageDecodeResponse(type, cmd);
    }

    private async Task<TResult> ApplicationSelect(MessageType type, AppID appID)
    {
        Log.Info("Selecting Application: " + appID.Name);
        byte[] cmd = type.FormatCommand(this, 0xA4, 0x04, 0x0C, appID.GetID());
        var result = await SendPackageDecodeResponse(type, cmd);
        if (result.IsSuccess)
            this._appSelected = appID;

        return result;
    }



    private async Task<TResult> ReadBinaryFullID(MessageType type, IEfID efID, byte offset, byte cla = 0x00)
    {
        var selectResult = await ElementFileSelect(type, efID);
        if (!selectResult.IsSuccess)
        {
            Log.Info("Element File Select Error: " + efID.GetName());
            return selectResult;
        }

        Log.Info("Reading EF File: " + efID.GetName());
        byte[] cmd = type.FormatCommand(this, 0xB0, 0x00, 0x00, [], le: 0x00);
        return await SendPackageDecodeResponse(type, cmd);
    }

    public async Task<TResult> ReadBinaryShort(MessageType type, IEfID efID, byte offset)
    {
        byte[] cmd = type.FormatCommand(this, 0xB0, efID.ShortID, offset, [], le: 0x00);
        return await SendPackageDecodeResponse(type, cmd);
    }

    public async Task<TResult> MseSetAT(MessageType type, byte[] oid, int parameterID, byte cla = 0x00)
    {
        Log.Info("Sending MseSetAT Command");
        byte[] data = new AsnBuilder()
            .AddCustomTag(0x80, oid) // object identifier
            .AddCustomTag(0x83, [0x01]) // MRZ
                                        //  .AddCustomTag(0x84, [(byte)parameterID]) // parameter id
            .Build();

        byte[] cmd = type.FormatCommand<T>(this, 0x22, 0xC1, 0xA4, data);
        return await SendPackageDecodeResponse(type, cmd);
    }

    public async Task<TResult> GeneralAuthenticate(GenAuthType type, byte cla = 0x10)
    {
        Log.Info("Sending General Authenticate Command");

        var typee = new MessageType.NonSecure();

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

        byte[] cmdFormat = typee.FormatCommand(this, 0x86, 0x00, 0x00, data: writer.Encode()[1..], le: 0x00);
        cmdFormat[0] = cla;


        //Log.Info("Write: " + BitConverter.ToString(raw));

        var result = await SendPackageDecodeResponse(typee, cmdFormat);

        if (result.IsSuccess)
            if (result.Value.data.Length == 0)
                return TResult.Fail(new Error.Other("General Authentication not sending the encrypted nounce!"));


        return result;
    }
    public async Task<TResult> GeneralAuthenticateMapping(byte innerTag, byte[] publicKey)
    {
        Log.Info("General Authentication Mapping");
        var type = new MessageType.NonSecure();
        // TODO, check if length is bigger then 128
        byte[] innerSequence = [innerTag, (byte)publicKey.Length, .. publicKey];
        byte[] data = [0x7C, (byte)innerSequence.Length, .. innerSequence];



        byte[] cmdFormat = type.FormatCommand(this, 0x86, 0x00, 0x00, data, le: 0x00);
        cmdFormat[0] = 0x10;


        //Log.Info("Write: " + BitConverter.ToString(raw));

        var result = await SendPackageDecodeResponse(type, cmdFormat);

        if (result.IsSuccess)
            if (result.Value.data.Length == 0)
                return TResult.Fail(new Error.Other("General Authentication not sending the encrypted nounce!"));


        return result;
    }

    public void SetEncryption(byte[] enc, byte[] mac)
    {
        this.encKey = enc;
        this.mac = mac;
    }

    public async Task<TResultBool> GeneralAuthenticateMutual(byte[] icPubKey, byte[] terminalKey, byte[] oid, byte[] macKey)
    {
        var type = new MessageType.NonSecure();
        byte[] innerSequence = [0x06, (byte)oid.Length, .. oid];
        byte[] innerSequence2 = [0x86, (byte)icPubKey.Length, .. icPubKey];

        byte[] innerPacket = [0x7f, 0x49, (byte)(innerSequence.Length + innerSequence2.Length), .. innerSequence, .. innerSequence2];

        var token = CalculateCMAC(innerPacket);

        byte[] tokenHeader = [0x85, (byte)token.Length, .. token];

        byte[] cmd = [0x7C, (byte)tokenHeader.Length, .. tokenHeader];
        byte[] cmdFormat = type.FormatCommand(this, 0x86, 0x00, 0x00, data: cmd, le: 0x00);

        Log.Info("Send: " + BitConverter.ToString(cmdFormat));

        var result = await SendPackageDecodeResponse(type, cmdFormat);



        if (result.IsSuccess)
            if (result.Value.data.Length == 0)
                return Result<bool>.Fail(new Error.Other("General Authentication not sending the encrypted nounce!"));


        byte[] innerSequenceIC = [0x06, (byte)oid.Length, .. oid];
        byte[] innerSequence2IC = [0x86, (byte)terminalKey.Length, .. terminalKey];

        byte[] innerPacketIC = [0x7f, 0x49, (byte)(innerSequenceIC.Length + innerSequence2IC.Length), .. innerSequenceIC, .. innerSequence2IC];


        using (var stream = new Asn1InputStream(result.Value.data))
        {

            Asn1Object obj = stream.ReadObject();  // top-level object
            var chipToken = obj.GetDerEncoded()[4..]; // ic publickey
            bool valid = CMacCheck(chipToken!, innerPacketIC);
            if (valid)
            {
                Log.Info("Mutual Authentication Success!");
                return Result<bool>.Success(valid);
            }
            return Result<bool>.Fail(new Error.AuthenticationToken("Failed to verify authentication token"));
        }

    }



    public static byte[] TestGeneralInput(byte[] icPubKey, byte[] oid, byte[] macKey)
    {
        byte[] innerSequence = [0x06, (byte)oid.Length, .. oid];
        byte[] innerSequence2 = [0x86, (byte)icPubKey.Length, .. icPubKey];

        byte[] innerPacket = [0x7f, 0x49, (byte)(innerSequence.Length + innerSequence2.Length), .. innerSequence, .. innerSequence2];

        return innerPacket;
    }
    public static byte[] TestGeneralToken(byte[] icPubKey, byte[] oid, byte[] macKey)
    {
        byte[] innerSequence = [0x06, (byte)oid.Length, .. oid];
        byte[] innerSequence2 = [0x86, (byte)icPubKey.Length, .. icPubKey];

        byte[] innerPacket = [0x7f, 0x49, (byte)(innerSequence.Length + innerSequence2.Length), .. innerSequence, .. innerSequence2];


        var engine = new CMac(new AesEngine(), 64);
        var token = new byte[8];
        engine.Init(new KeyParameter(macKey));
        engine.BlockUpdate(innerPacket, 0, innerPacket.Length);
        engine.DoFinal(token);

        byte[] tokenHeader = [0x85, (byte)token.Length, .. token];

        byte[] cmd = [0x7C, (byte)tokenHeader.Length, .. tokenHeader];
        byte[] cmdFormat = FormatCommand(0x00, 0x86, 0x00, 0x00, data: cmd, le: 0x00);

        return cmdFormat;
    }
    internal static byte[] FormatCommand(byte cla, byte ins, byte p1, byte p2, byte[] data = null!, byte? le = null)
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

    internal ResponseCommand ParseEncryptedReponse(byte[] packet, byte[] iv)
    {

        byte sw1 = 0;
        byte sw2 = 0;
        if (packet.Length == 4)
        {
            // No data
            sw1 = packet[2];
            sw2 = packet[3];

            return new ResponseCommand(sw1, sw2, null);
        }

        if (packet.Length == 2)
        {
            sw1 = packet[0];
            sw2 = packet[1];
            return new ResponseCommand(sw1, sw2, null);
        }

        Log.Info(BitConverter.ToString(packet));

        Debug.Assert(packet[0] == 0x87);
        Debug.Assert(packet[2] == 0x01);

        byte dataLen = packet[1];

        byte[] encryptedData = packet[2..dataLen];
        sw1 = packet[dataLen + 2];
        sw2 = packet[dataLen + 3];

        byte[] decryptedData = DecryptDataENC(encryptedData, iv);

        return new ResponseCommand(sw1, sw2, decryptedData);

    }



    internal async Task<TResult> SendPackageDecodeResponse(MessageType messageType, byte[] cmd)
    {
        var result = _serverFormat.DeFormat(await _communicator.TransceiveAsync(_serverFormat.Format(cmd)));
        if (!result.IsSuccess)
            return Fail(result.Error);

        ResponseCommand response = messageType.ParseCommand(this, result.Value);

        if (response.status.IsSuccess())
            return TResult.Success(response);

        var tempStatus = response.status;
        while (tempStatus == SwStatus.MoreDataAvailable)
        {
            messageType.FormatCommand(this, 0xC0, 0x00, 0x00, []);
            var extra = _serverFormat.DeFormat(await _communicator.TransceiveAsync(_serverFormat.Format(cmd)));
            ResponseCommand extraResp = messageType.ParseCommand(this, extra.Value);
            byte[] bytes = extraResp.data[0..(extraResp.data.Length - 3)];
            response.data = [.. response.data, .. bytes];
            tempStatus = extraResp.status;
        }

        if (tempStatus.IsSuccess())
            return TResult.Success(response);

        return TResult.Fail(new Error.SwError(response.status));

    }

    private byte[] CalculateCMAC(byte[] data)
    {
        var engine = new CMac(new AesEngine(), 64);
        var calculatedToken = new byte[8];
        engine.Init(new KeyParameter(mac));
        engine.BlockUpdate(data, 0, data.Length);
        engine.DoFinal(calculatedToken);

        return calculatedToken;
    }

    private bool CMacCheck(byte[] chipToken, byte[] data)
    {
        var engine = new CMac(new AesEngine(), 64);
        var calculatedToken = new byte[8];
        engine.Init(new KeyParameter(mac));
        engine.BlockUpdate(data, 0, data.Length);
        engine.DoFinal(calculatedToken);

        return chipToken.SequenceEqual(calculatedToken);

    }
    // SID 91 part 11
    // SSC -> HEADER  -> PADDING -> DO87
    // Add padding to it then calculate MAC over it

    internal byte[] FormatEncryptedCommand(byte[] data, byte ins, byte p1, byte p2, byte[] iv, byte lc = 0x00)
    {


        if ((ins % 2) != 0)
            throw new NotImplementedException("Ins for Odd, is not implemented");

        byte[] cmdHeader = Util.AlignData([0x0C, ins, p1, p2], 16);

        byte[] encryptedData = [.. EncryptDataFormatENC(data, iv)];
        byte[] dataHeader = [0x87, (byte)(encryptedData.Length + 1), 0x01, .. encryptedData];

        byte[] seqCounterHeader = sequenceCounter.ToPaddedLength(16);


        Log.Info("CmdHeader: " + BitConverter.ToString(cmdHeader));
        Log.Info("SeqCounterHeader: " + BitConverter.ToString(seqCounterHeader));
        Log.Info("DataHeader: " + BitConverter.ToString(dataHeader));
        Log.Info("IV: " + BitConverter.ToString(iv));

        byte[] N = Util.AlignData([.. seqCounterHeader, .. cmdHeader, .. dataHeader], 16);
        Log.Info("N: " + BitConverter.ToString(N));
        byte[] token = CalculateCMAC(N);
        byte[] macHeader = [0x8E, 0x08, .. token];

        byte[] package = [0x0C, ins, p1, p2, (byte)(dataHeader.Length + macHeader.Length), .. dataHeader, .. macHeader];




        return package;
    }

    private byte[] EncryptDataFormatENC(byte[] decryptedData, byte[] iv)
    {
        var aligned = Util.AlignData(decryptedData, 16);
        Debug.Assert(aligned.Length % 16 == 0);

        Log.Info("UnencryptedData: " + BitConverter.ToString(decryptedData));
        Log.Info("UnencryptedPaddedData: " + BitConverter.ToString(aligned));

        var cipher = CipherUtilities.GetCipher($"AES/CBC/NOPADDING");
        var ivParameter = new ParametersWithIV(new KeyParameter(encKey), iv);
        cipher.Init(true, ivParameter);
        return cipher.DoFinal(aligned);

    }

    // sid 72, part 11 för secure messaging
    //sid 91
    //     The Send Sequence Counter is set to its new start value, see Section 9.8.6.3 for 3DES and Section
    // 9.8.7.3 for AES.

    private byte[] DecryptDataENC(byte[] encryptedData, byte[] iv)
    {


        using var aes = System.Security.Cryptography.Aes.Create();

        aes.KeySize = 256;
        aes.BlockSize = 128;
        aes.Mode = System.Security.Cryptography.CipherMode.CBC;
        aes.Key = encKey!;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;


        var decryptor = aes.CreateDecryptor();
        byte[] decryptedData = decryptor.TransformFinalBlock(encryptedData, 0, encryptedData.Length);

        for (int i = decryptedData.Length - 1; i >= 0; i--)
        {
            if (decryptedData[i] == 0x80)
            {
                return decryptedData[0..(i - 1)];
            }
        }

        throw new Exception("womp womp no kebab for you :/");

    }



    //! only allowed to call once per command
    internal byte[] GetIV()
    {

        sequenceCounter += 1;
        var cipher = CipherUtilities.GetCipher($"AES/CBC/NOPADDING");
        var iv = new byte[16];
        var ivParameter = new ParametersWithIV(new KeyParameter(encKey), iv);
        cipher.Init(true, ivParameter);

        var paddedSSCBA = sequenceCounter.ToPaddedLength(16);
        return cipher.DoFinal(paddedSSCBA);
    }

    private static TResult Success(ResponseCommand cmd) => TResult.Success(cmd);
    private static TResult Fail(Error e) => TResult.Fail(e);
    private AppID? _appSelected;
    private readonly ICommunicator _communicator = communicator;
    private readonly T _serverFormat = encryption;

    private byte[]? encKey;
    private byte[]? mac;

    private BigInteger sequenceCounter = 0;
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
    // LITTLE ENDIAN

}




