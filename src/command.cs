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
using System;
using Encryption;
using System.Runtime.CompilerServices;
using Microsoft.Extensions.ObjectPool;
using Microsoft.AspNetCore.Mvc;

namespace Command;

using TResult = Result<ResponseCommand>;
using TResultBool = Result<bool>;

public abstract record MessageType
{

    public abstract byte[] FormatCommand<T>(Command<T> command, byte ins, byte p1, byte p2, byte[] data, int le = 0x00, byte? cla = null) where T : IServerFormat;
    public abstract Task<TResult> ParseCommand<T>(Command<T> command, byte[] response) where T : IServerFormat;

    public static Secure SecureMessage => new();
    public static NonSecure NonSecureMessage => new();
    public sealed record Secure : MessageType
    {
        const int NonDataLen = 2 + 4;
        internal Secure() { }
        public override byte[] FormatCommand<T>(Command<T> command, byte ins, byte p1, byte p2, byte[] data, int le = 0x00, byte? cla = null)
        {
            _ins = ins;
            _p1 = p1;
            _p2 = p2;
            _data = data;
            _le = le;


            iv = command.GetIV();
            var bytes = command.FormatEncryptedCommand(data, ins, p1, p2, iv, le: le);
            command.sequenceCounter += BigInteger.One;
            return bytes;


        }

        public override async Task<TResult> ParseCommand<T>(Command<T> command, byte[] response)
        {


            if (!CMacCheck(command, response))
            {
                throw new Exception("CMac Response Check Failed");
            }


            var tags = TagReader.ReadTagData(response);

            byte swTag = 0x99;
            var swData = tags.FilterByTag(swTag)[0].Data;

            ResponseCommand respCommand = new(swData[0], swData[1]);





            var dataTag = tags.FilterByTag(0x87);

            if (dataTag.Count > 0)
            {
                int sw1 = response[response.Length - 2];
                int sw2 = response[response.Length - 1];
                var swStatus = SwStatus.FromSw1Sw2(sw1, sw2);


                while (swStatus == SwStatus.MoreDataAvailable)
                {
                    var extraData = await command.SendGetMoreDataRequest(MessageType.SecureMessage);
                    Log.Info("ExtraData: " + BitConverter.ToString(extraData));
                    throw new Exception("Test");
                }

                var respIv = command.GetIV();
                var encryptedData = dataTag[0].Data[1..];
                // var aligned = Util.AlignData(encryptedData, 16);
                var aligned = encryptedData;



                var cipher = CipherUtilities.GetCipher($"AES/CBC/NOPADDING");
                var ivParameter = new ParametersWithIV(new KeyParameter(command.encKey), respIv);
                cipher.Init(false, ivParameter);
                byte[] fullData = cipher.DoFinal(aligned).TruncateData();

                var DataPacketLen = TagReader.Length.GetFullLengthWithTag(fullData);
                int i = 0;
                if (fullData.Length < DataPacketLen)
                {

                    byte[] combData = fullData;


                    while (DataPacketLen > combData.Length)
                    {
                        int nextOffset = combData.Length;
                        _p1 = (byte)((nextOffset >> 8) & 0xFF);
                        _p2 = (byte)(nextOffset & 0xFF);
                        command.sequenceCounter += BigInteger.One;
                        byte[] nextDataResp = (await command.SendPackageRaw(FormatCommand(command, _ins, _p1, _p2, _data, le: DataPacketLen - combData.Length + i))).Value;


                        int sw1_2 = nextDataResp[^2];
                        int sw2_2 = nextDataResp[^1];
                        var swStatus_2 = SwStatus.FromSw1Sw2(sw1_2, sw2_2);

                        if (swStatus_2 != SwStatus.Success)
                        {
                            Log.Error("big fail: " + swStatus_2.Message);
                            break;
                        }

                        var nextDataTags = TagReader.ReadTagData(nextDataResp);

                        var dataTag2 = nextDataTags.FilterByTag(0x87);

                        var encryptedData2 = dataTag2[0].Data[1..];


                        var respIv2 = command.GetIV();
                        var cipher2 = CipherUtilities.GetCipher($"AES/CBC/NOPADDING");
                        var ivParameter2 = new ParametersWithIV(new KeyParameter(command.encKey), respIv2);
                        cipher2.Init(false, ivParameter2);
                        combData = [.. combData, .. cipher2.DoFinal(encryptedData2).TruncateData()];
                        cipher2.Reset();



                    }

                    Log.Info("CombDataLen: " + combData.Length);
                    Log.Info("DataPacketLen: " + DataPacketLen);
                    // debug purpose only
                    //   var checkTags = TagReader.ReadTagData(combData); // should crash if not correclty 


                    ResponseCommand respRet = new(0x90, 0x00, combData);

                    command.sequenceCounter += BigInteger.One;
                    return TResult.Success(respRet);
                }




                respCommand.data = fullData;
            }
            // make ready for next command
            command.sequenceCounter += BigInteger.One;
            //            Log.Info("SSC: " + command.sequenceCounter);
            return TResult.Success(respCommand);
        }

        private bool CMacCheck<T>(Command<T> command, byte[] response) where T : IServerFormat
        {
            //return command.ParseEncryptedReponse(response, iv);
            using var aes = System.Security.Cryptography.Aes.Create();
            List<TagReader.TagEntry> tags = TagReader.ReadTagData(response[0..(response.Length - 2)]);
            TagReaderExtensions.ToStringFormat(tags);
            byte dataTagID = 0x87;
            byte swTagID = 0x99;
            byte macTagID = 0x8E;

            byte[] macFormat = command.sequenceCounter.ToPaddedLength(16);

            var dataTag = tags.FilterByTag(dataTagID);
            if (dataTag.Count > 0)
            {
                macFormat = [.. macFormat, .. dataTag[0].GetHeaderFormat()];
            }

            var swTag = tags.FilterByTag(swTagID);

            if (swTag.Count > 0)
            {
                macFormat = [.. macFormat, .. swTag[0].GetHeaderFormat()];
            }



            byte[] chipToken = tags.FilterByTag(macTagID)[0].Data;


            Debug.Assert(chipToken.Length == 8, "Not reading token correctly");
            Debug.Assert(swTag[0].Data.Length == 2, "Not reading sw correctly");

            byte[] paddedMacInput = Util.AlignData(macFormat, 16);



            byte[] calcCmac = command.CalculateCMAC(paddedMacInput);

            bool isValid = calcCmac.SequenceEqual(chipToken);
            if (!isValid) // TODO, parse data correct, it is not taking into account longform, when doing cmac
            {
                Log.Error("Response: " + BitConverter.ToString(response));
                Log.Error("ChipToken: " + BitConverter.ToString(chipToken));
                Log.Error("PaddedMacInput: " + BitConverter.ToString(paddedMacInput));
                Log.Error("macFormat: " + BitConverter.ToString(macFormat));
                Log.Error("swHeader: " + BitConverter.ToString(swTag[0].GetHeaderFormat()));
                Log.Info("oh well, Kobry for now");
                throw new Exception("Autentication Token Failed");
            }
            return isValid;

        }

        private bool DecryptCheck(byte[] fullData)
        {
            Log.Info("Data bytes: " + BitConverter.ToString(fullData));
            byte[] paddingData = fullData[_le..];


            if (!(paddingData[0] == 0x80))
                throw new Exception("Decryption Failed, " + BitConverter.ToString(fullData));

            if (paddingData.Length > 1)
                return new BigInteger(paddingData[1..]) == 0;

            return true;




        }

        byte[] iv = [];
        int _le = 0;
        byte _ins;
        byte _p1;
        byte _p2;
        byte[] _data = [];


    }

    public sealed record NonSecure : MessageType
    {
        internal NonSecure() { }
        public override byte[] FormatCommand<T>(Command<T> command, byte ins, byte p1, byte p2, byte[] data, int le = 0x00, byte? cla = null)
        {
            return Command<T>.FormatCommand(0x00, ins, p1, p2, data, le: le);
        }

        public override async Task<TResult> ParseCommand<T>(Command<T> command, byte[] response)
        {
            return ResponseCommand.FromBytes(response);
        }

    }



}




// TODO, add a command that keeps asking for more bytes if we get error SW that all the bytes has not been sent yet
// TODO, should also add error check for when parsing to Response Command fails
public class Command<T>(ICommunicator communicator, T encryption)
    where T : IServerFormat
{


    public bool IsActiveApp { get; private set; } = false;

    public async Task<TResult> ReadBinary(MessageType type, IEfID efID, byte offset = 0x00)
    {
        byte le = type == MessageType.SecureMessage ? (byte)0x4 : (byte)0x00;
        var app = efID.AppIdentifier();
        if (_appSelected == app || app == null)
        {
            return await ReadBinaryFullID(type, efID, offset, le: le);

        }
        else
        {
            await SelectApplication(type, app);
            _appSelected = app;
            return await ReadBinaryFullID(type, efID, offset, le: le);
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


    public async Task<TResult> AAStepOne(byte[] ifd)
    {
        byte[] cmd = MessageType.SecureMessage.FormatCommand(this, 0x88, 0x00, 0x00, data: ifd, le: 0xC0);

        return await SendPackageDecodeResponse(MessageType.SecureMessage, cmd);
    }



    private async Task<TResult> ReadBinaryFullID(MessageType type, IEfID efID, byte offset, byte le = 0x00, byte cla = 0x00)
    {
        var selectResult = await ElementFileSelect(type, efID);
        if (!selectResult.IsSuccess)
        {
            Log.Info("Element File Select Error: " + efID.GetName());
            return selectResult;
        }

        Log.Info("Selecting Element File: " + efID.GetName());

        Log.Info("Reading EF File: " + efID.GetName());
        byte[] cmd = type.FormatCommand(this, 0xB0, 0x00, 0x00, [], le: le);
        return await SendPackageDecodeResponse(type, cmd);
    }

    public async Task<TResult> ReadBinaryShort(MessageType type, IEfID efID, byte le = 0x00, byte offset = 0x00)
    {
        byte[] cmd = type.FormatCommand(this, 0xB0, efID.ShortID, offset, [], le: le);
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

    // Implementation using MSE:Set AT and GENERAL AUTHENTICATE
    public async Task<TResult> MseSetAT_ChipAuthentication(MessageType type, byte[] chipAuthOid, byte? keyID)
    {
        Log.Info("Sending MseSetAT Command Chip Authentication");

        var builder = new AsnBuilder()
        .AddCustomTag(0x80, chipAuthOid); // object identifier
        if (keyID != null)
            builder.AddCustomTag(0x84, [(byte)keyID]);


        var data = builder.Build();

        byte[] cmd = type.FormatCommand<T>(this, 0x22, 0x41, 0xA4, data);
        return await SendPackageDecodeResponse(type, cmd);


    }

    public async Task<TResult> GeneralAuthenticate(GenAuthType type, byte cla = 0x10)
    {
        Log.Info("Sending General Authenticate Command");

        var typee = MessageType.NonSecureMessage;

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
        var type = MessageType.NonSecureMessage;
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

    public async Task<TResult> GeneralAuthenticateChipMapping(MessageType type, byte innerTag, byte[] publicKey)
    {
        Log.Info("General Authentication Mapping");
        byte[] innerSequence = [innerTag, (byte)publicKey.Length, .. publicKey];
        byte[] data = [0x7C, (byte)innerSequence.Length, .. innerSequence];

        byte[] nonSecureDebug = MessageType.NonSecureMessage.FormatCommand(this, 0x86, 0x00, 0x00, data, le: 0x00);
        byte[] cmdFormat = type.FormatCommand(this, 0x86, 0x00, 0x00, data, le: 0x02);


        //Log.Info("Write: " + BitConverter.ToString(raw));

        var result = await SendPackageDecodeResponse(type, cmdFormat);

        if (result.IsSuccess)
            if (result.Value.data.Length == 0)
                return TResult.Fail(new Error.Other("General Authentication not sending the encrypted nounce!"));


        return result;
    }

    // public async Task<Result<byte[]>> ReadSecureEf(IEfID efId)
    // {
    //     var result = await ReadBinary(MessageType.SecureMessage, efId);
    //     if (!result.IsSuccess)
    //         return Result<byte[]>.Fail(result.Error);

    //     var response = result.Value;

    //     var tags = TagReader.ReadTagData(response.data);
    //     var dataTag = tags.FilterByTag(0x87);
    //     if (dataTag.Count == 0)
    //         return Result<byte[]>.Success(response.data);

    //     var encryptedData = dataTag[0].Data[1..]; //Skip tag header??
    //     var iv = GetIV();

    //     var cipher = CipherUtilities.GetCipher("AES/CBC/NOPADDING");
    //     var ivParam = new ParametersWithIV(new KeyParameter(encKey), iv);
    //     cipher.Init(false, ivParam);

    //     var decrypted = cipher.DoFinal(encryptedData);

    //     int paddingStart = Array.IndexOf(decrypted, (byte)(0x80));
    //     if(paddingStart < 0)
    //     return Result<byte[]>.Fail(new Error.Other("Decrypt failed"))


    //     return;
    // }

    public void SetEncryption(byte[] enc, byte[] mac)
    {
        this.encKey = enc;
        this.mac = mac;
        this.sequenceCounter = 0x01;
    }


    public async Task<TResultBool> GeneralAuthenticateMutual(byte[] icPubKey, byte[] terminalKey, byte[] oid)
    {
        var type = MessageType.NonSecureMessage;
        byte[] innerSequence = [0x06, (byte)oid.Length, .. oid];
        byte[] innerSequence2 = [0x86, (byte)icPubKey.Length, .. icPubKey];

        byte[] innerPacket = [0x7f, 0x49, (byte)(innerSequence.Length + innerSequence2.Length), .. innerSequence, .. innerSequence2];

        var token = CalculateCMAC(innerPacket);

        byte[] tokenHeader = [0x85, (byte)token.Length, .. token];

        byte[] cmd = [0x7C, (byte)tokenHeader.Length, .. tokenHeader];
        byte[] cmdFormat = type.FormatCommand(this, 0x86, 0x00, 0x00, data: cmd, le: 0x00);

        var result = await SendPackageDecodeResponse(type, cmdFormat);



        if (result.IsSuccess)
            if (result.Value.data.Length == 0)
                return Result<bool>.Fail(new Error.Other("General Authentication not sending the encrypted nounce!"));

        if (!result.IsSuccess)
            return Result<bool>.Fail(result.Error);


        byte[] innerSequenceIC = [0x06, (byte)oid.Length, .. oid];
        byte[] innerSequence2IC = [0x86, (byte)terminalKey.Length, .. terminalKey];

        byte[] innerPacketIC = [0x7f, 0x49, (byte)(innerSequenceIC.Length + innerSequence2IC.Length), .. innerSequenceIC, .. innerSequence2IC];

        var tags = TagReader.ReadTagData(result.Value.data, [0x7f, 0x30, 0x31]);
        var chipToken = tags.Find(0x7C).FindChild(0x86)!.Data;

        // Asn1Object obj = stream.ReadObject();  // top-level object
        // var chipToken = obj.GetDerEncoded()[4..]; // ic publickey
        bool valid = CMacCheck(chipToken!, innerPacketIC); // failar här
        if (valid)
        {
            Log.Info("Mutual Authentication Success!");
            return Result<bool>.Success(valid);
        }
        return Result<bool>.Fail(new Error.AuthenticationToken("Failed to verify authentication token"));

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
    internal static byte[] FormatCommand(byte cla, byte ins, byte p1, byte p2, byte[] data = null!, int? le = null)
    {
        var cmd = new List<byte> { cla, ins, p1, p2 };
        if (data != null && data.Length > 0)
        {
            cmd.Add((byte)data.Length);
            cmd.AddRange(data);
        }
        if (le != null) cmd.Add((byte)(le & 0xFF));

        return [.. cmd];
    }



    internal async Task<TResult> SendPackageDecodeResponse(MessageType messageType, byte[] cmd)
    {
        var result = _serverFormat.DeFormat(await _communicator.TransceiveAsync(_serverFormat.Format(cmd)));
        if (!result.IsSuccess)
            return Fail(result.Error);


        var parseResult = await messageType.ParseCommand(this, result.Value);

        if (!parseResult.IsSuccess)
        {
            return parseResult;
        }

        var response = parseResult.Value;

        if (response.status.IsSuccess())
            return TResult.Success(response);

        var tempStatus = response.status;
        while (tempStatus == SwStatus.MoreDataAvailable)
        {
            Log.Info("Asking for more data");
            var cmd2 = messageType.FormatCommand(this, 0xC0, 0x00, 0x00, []);
            var extra = _serverFormat.DeFormat(await _communicator.TransceiveAsync(_serverFormat.Format(cmd2)));
            var parseExtraResult = await messageType.ParseCommand(this, extra.Value);

            if (!parseResult.IsSuccess)
                return parseResult;

            var extraResp = parseExtraResult.Value;

            byte[] bytes = extraResp.data[0..(extraResp.data.Length - 3)];
            response.data = [.. response.data, .. bytes];
            tempStatus = extraResp.status;
        }

        if (tempStatus.IsSuccess())
            return TResult.Success(response);

        return TResult.Fail(new Error.SwError(response.status));

    }

    internal async Task<byte[]> SendGetMoreDataRequest(MessageType messageType)
    {
        Log.Info("Asking for more data");
        var cmd = messageType.FormatCommand(this, 0xC0, 0x00, 0x00, []);
        var extra = _serverFormat.DeFormat(await _communicator.TransceiveAsync(_serverFormat.Format(cmd)));

        return extra.Value;
    }

    internal async Task<Result<byte[]>> SendPackageRaw(byte[] package)
    {
        var result = _serverFormat.DeFormat(await _communicator.TransceiveAsync(_serverFormat.Format(package)));
        return result;
    }

    internal byte[] CalculateCMAC(byte[] data)
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


        //return true;

        return chipToken.SequenceEqual(calculatedToken);


        //    // 1. Initialize the AES-CMAC algorithm
        // IBlockCipher aes = new AesEngine();
        // IMac cmac = new CMac(aes, 128); // 128-bit CMAC
        // KeyParameter keyParams = new KeyParameter(key);
        // cmac.Init(keyParams);

        // // 2. Process the data
        // cmac.BlockUpdate(data, 0, data.Length);

        // // 3. Get the full 16-byte MAC
        // byte[] fullMac = new byte[cmac.GetMacSize()];
        // cmac.DoFinal(fullMac, 0);

        // // 4. Truncate to the 8 bytes required by the standard
        // byte[] truncatedMac = new byte[8];
        // Array.Copy(fullMac, 0, truncatedMac, 0, 8);


        // Log.Info("Data: " + BitConverter.ToString(data));
        // return truncatedMac;

    }

    // 04-00-7F-00-07-02-02-04-06-04
    //04-00-7F-00-07-02-02-04-02-04


    // SID 91 part 11
    // SSC -> HEADER  -> PADDING -> DO87
    // Add padding to it then calculate MAC over it

    //     For message encryption AES [FIPS 197] SHALL be used in CBC-mode according to [ISO/IEC 10116] with key KSEnc and
    // IV = E(KSEnc, SSC).

    //     For message authentication AES SHALL be used in CMAC-mode [SP 800-38B] with KSMAC with a MAC length of 8 bytes.
    // The datagram to be authenticated SHALL be prepended by the Send Sequence Counter.
    // !TODO fix for LE

    //An extended Lc field consists of three bytes: one byte set to '00' followed by two bytes not set to
    //'0000'. From '0001' to 'FFFF', the two bytes encode Nc from one to 65 535
    internal byte[] FormatEncryptedCommand(byte[] data, byte ins, byte p1, byte p2, byte[] iv, int le = 0x00, byte lc = 0x00, byte? cla = null)
    {

        //        Log.Info($"data: {BitConverter.ToString(data)}, ins: 0x{ins:X2}, p1: 0x{p1:X2}, p2: 0x{p2:X2}, iv: {BitConverter.ToString(iv)}, lc: 0x{lc:X2}, le: 0x{le:X2}");


        byte[] cmdHeader = Util.AlignData([0x0C, ins, p1, p2], 16);




        if (cla != null)
            cmdHeader[0] = (byte)cla;

        byte dataTag = (ins % 2) == 0 ? (byte)0x87 : (byte)0x85;
        //byte dataTag = 0x87;
        byte macTag = 0x8E;
        byte leTag = 0x97;
        byte[] leHeader = [];
        if (le > 0)
        {
            byte[] leBytes;

            // ISO 7816-4: If Le <= 255, use 1 byte. If > 255, use 2 bytes.
            if (le <= 255)
            {
                leBytes = [(byte)le];
            }
            else
            {
                // HERE is where you use your helper
                leBytes = le.IntoLeExtended();
            }

            // Construct DO '97'
            // Tag 97, Length (1 or 2), Value...
            leHeader = new AsnBuilder().AddCustomTag(0x97, leBytes).Build();
        }

        byte[] dataHeader = [];
        if (data.Length > 0)
        {
            byte[] encryptedData = [.. EncryptDataFormatENC(data, iv)];
            dataHeader = [dataTag, (byte)(encryptedData.Length + 1), 0x01, .. encryptedData];
        }


        byte[] seqCounterHeader = sequenceCounter.ToPaddedLength(16);

        byte[] N = Util.AlignData([.. seqCounterHeader, .. cmdHeader, .. dataHeader, .. leHeader], 16);
        //  Log.Info("N: " + BitConverter.ToString(N));
        byte[] token = CalculateCMAC(N);
        byte[] macHeader = [macTag, 0x08, .. token];
        int length = dataHeader.Length + macHeader.Length + leHeader.Length;

        byte[] extendedLen = leHeader.Length > 3 ? [0x00, 0x00] : [0x00];
        byte[] package = [0x0C, ins, p1, p2, (byte)(length), .. dataHeader, .. leHeader, .. macHeader, .. extendedLen];


        return package;
    }

    private byte[] EncryptDataFormatENC(byte[] decryptedData, byte[] iv)
    {
        var aligned = Util.AlignData(decryptedData, 16);

        //Log.Info("UnencryptedData: " + BitConverter.ToString(decryptedData));
        //Log.Info("UnencryptedPaddedData: " + BitConverter.ToString(aligned));

        var cipher = CipherUtilities.GetCipher($"AES/CBC/NOPADDING");
        var ivParameter = new ParametersWithIV(new KeyParameter(encKey), iv);
        cipher.Init(true, ivParameter);
        return cipher.DoFinal(aligned);

    }

    // sid 72, part 11 för secure messaging
    //sid 91
    //     The Send Sequence Counter is set to its new start value, see Section 9.8.7.3 for AES.



    //! only allowed to call once per command
    internal byte[] GetIV()
    {

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

    public byte[]? encKey;
    public byte[]? mac;

    // Initialise SSC to pace starting value
    public BigInteger sequenceCounter = 1;

    public async Task<TResult> InternalAuthenticate(MessageType type, byte[] challenge)
    {
        Log.Info("Skickar Internal Authenticate (AA)...");

        // INS: 0x88 = Internal Authenticate
        // Data: Slumpmässig challenge (8 bytes)
        // Le: 0x00 = Vi förväntar oss ett svar (signaturen)

        // FormatCommand bygger APDU:n: [CLA, INS, P1, P2, Lc, DATA, Le]
        byte[] cmd = type.FormatCommand(this, 0x88, 0x00, 0x00, challenge, le: 0xC0);

        return await SendPackageDecodeResponse(type, cmd);
    }

}




//TODO Remove??

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

        //TODO Remove??
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




