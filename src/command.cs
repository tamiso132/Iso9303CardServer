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

namespace Command;

using TResult = Result<ResponseCommand>;
using TResultBool = Result<bool>;


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

    public void SetEncryption(byte[] enc, byte[] mac)
    {
        this.encKey = enc;
        this.mac = mac;
    }

    public async Task<TResultBool> GeneralAuthenticateMutual(byte[] icPubKey, byte[] terminalKey, byte[] oid, byte[] macKey)
    {
        byte[] innerSequence = [0x06, (byte)oid.Length, .. oid];
        byte[] innerSequence2 = [0x86, (byte)icPubKey.Length, .. icPubKey];

        byte[] innerPacket = [0x7f, 0x49, (byte)(innerSequence.Length + innerSequence2.Length), .. innerSequence, .. innerSequence2];

        var token = CalculateCMAC(innerPacket);

        byte[] tokenHeader = [0x85, (byte)token.Length, .. token];

        byte[] cmd = [0x7C, (byte)tokenHeader.Length, .. tokenHeader];
        byte[] cmdFormat = FormatCommand(0x00, 0x86, 0x00, 0x00, data: cmd, le: 0x00);

        Log.Info("Send: " + BitConverter.ToString(cmdFormat));

        var result = await SendPackageDecodeResponse(cmdFormat);


        string Hex(byte[] data) => BitConverter.ToString(data).Replace("-", " ");
        //  Log.Info("Oid: " + Hex(innerSequence));
        // Log.Info("IcPubKey: " + Hex(innerSequence2));

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
            bool valid = CMacCheck(chipToken, innerPacketIC);
            return Result<bool>.Success(valid);
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
        engine.Reset();
        engine.Init(new KeyParameter(mac));
        engine.BlockUpdate(data, 0, data.Length);
        engine.DoFinal(calculatedToken);

        return chipToken.SequenceEqual(calculatedToken);

    }

    private byte[] FormatEncryptedCommand(byte[] data, byte ins, byte p1, byte p2, byte lc = 0x00)
    {
        if ((ins % 2) != 0)
            throw new NotImplementedException("Ins for Odd, is not implemented");

        byte[] iv = GetIV();

        byte[] lePacket = AlignData16([0x97, 1, 0x00]);
        byte[] encryptedData = encryptDataFormatENC(data, iv);

        //* 0x00 0x00, for extended length type
        byte lengthType = 0x00;

        byte[] packet = [0x0C, ins, p1, p2, .. encryptedData, .. lePacket, lengthType];

        byte[] cmacToken = CalculateCMAC(packet);

        byte[] packetFormat = [.. packet, 0x8e, (byte)cmacToken.Length, .. cmacToken];

        return packetFormat;

    }

    private byte[] encryptDataFormatENC(byte[] decryptedData, byte[] iv)
    {
        using var aes = System.Security.Cryptography.Aes.Create();


        var aligned = AlignData16(decryptedData);

        byte[] dataFormat = [.. aligned];

        // Check so it is aligned by 16
        Debug.Assert(dataFormat.Length % 16 == 0);


        aes.KeySize = 256;
        aes.BlockSize = 128;
        aes.Mode = System.Security.Cryptography.CipherMode.CBC;
        aes.Key = encKey!;
        aes.IV = iv;


        var encryptor = aes.CreateEncryptor();
        byte[] encryptedData = encryptor.TransformFinalBlock(dataFormat, 0, dataFormat.Length);

        // !0x01 says in documentation but wierd af, dunno if correct
        return [0x87, (byte)encryptedData.Length, 0x01, .. encryptedData];
    }

    // sid 72, part 11 för secure messaging
    //     The Send Sequence Counter is set to its new start value, see Section 9.8.6.3 for 3DES and Section
    // 9.8.7.3 for AES.

    private byte[] decryptDataENC(byte[] encryptedData, byte[] iv)
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

        throw new Exception("FUCK");

    }

    //! only allowed to call once per command
    private byte[] GetIV()
    {

        sequenceCounter += 1;
        using var aes = System.Security.Cryptography.Aes.Create();

        aes.KeySize = 256;
        aes.BlockSize = 128;
        aes.Mode = System.Security.Cryptography.CipherMode.ECB;
        aes.Key = encKey!;
        aes.Mode = CipherMode.ECB;

        byte[] msbCounter = [.. sequenceCounter.ToByteArray().Reverse()];
        byte[] alignedData = AlignData16(msbCounter);

        return aes.EncryptEcb([.. alignedData], PaddingMode.None);
    }

    private byte[] AlignData16(byte[] input)
    {
        var diffLen = 16 - ((input.Length + 1) % 16);
        byte padTag = 0x80;
        byte[] padding = [padTag, .. new byte[diffLen]];
        return [.. input, .. padding];
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
}


