using System.Text.RegularExpressions;
using Interfaces;
using Server;
using Type;
using WebSocketSharp;
using Parser;
using Helper;
using Encryption;
using Command;
using ErrorHandling;
using Org.BouncyCastle.Bcpg;
using Asn1;
using System.Formats.Asn1;
using Org.BouncyCastle.Asn1;
using System.Runtime.Intrinsics.Arm;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Microsoft.AspNetCore.Components.Forms;
namespace App;


public class ClientSession(ICommunicator comm)
{
    public async Task Start()
    {


        byte[] buffer = await _comm.ReadAsync();
        var packet = ServerPacket.TryFromBytes(buffer);
        if (packet.Type == CommandType.NewNFCScan)
        {
            var result = await _cmd.SelectDefaultMF(MessageType.NonSecureMessage);

            if (!result.IsSuccess)
            {
                Log.Error(result.Error.ErrorMessage());
                return;
            }


            result = await _cmd.ReadBinary(MessageType.NonSecureMessage, EfIdGlobal.CardAccess);

            if (!result.IsSuccess)
            {
                Log.Error(result.Error.ErrorMessage());
                return;
            }



            var response = result.Value;




            var info = response.Parse<ImplCardAccess, ImplCardAccess.Info>().EncryptInfos[0];
            info.PrintInfo();





            byte[] key = TestClass.DerivePaceKey(info);



            result = await _cmd.MseSetAT(MessageType.NonSecureMessage, info.OrgOid, info.OrgParameterID);


            if (!result.IsSuccess)
            {
                Log.Error(result.Error.ErrorMessage());
                return;
            }




            var r = await TestClass.ComputeDecryptedNounce(_cmd, info, key, TestClass.PasswordType.MRZ);




            if (!r.IsSuccess)
            {
                Log.Error(r.Error.ErrorMessage());
                return;
            }

            var decryptedNounce = r.Value;
            var rnd = new RandomNumberProvider();
            var ecdh = new ECDH(DomainParameter.BrainpoolP384r1, rnd.GetNextBytes(32));

            result = await _cmd.GeneralAuthenticateMapping(0x81, ecdh.PublicKey);

            if (!result.IsSuccess)
            {
                Log.Error(result.Error.ErrorMessage());
                return;
            }

            // var asn1Result = AsnNode.Parse(new AsnReader(result.Value.data, AsnEncodingRules.BER, new AsnReaderOptions()), [new Asn1Tag(TagClass.ContextSpecific, 0x7C, true), new Asn1Tag(TagClass.ContextSpecific, 0x84, true)]);

            //   Log.Info(asn1Result.GetAllNodes()[0].Id.TagValue.ToString());

            using (var stream = new Asn1InputStream(result.Value.data))
            {
                Asn1Object obj = stream.ReadObject();  // top-level object
                byte[] data2 = obj.GetDerEncoded()[4..];

                ecdh.CalculateSharedSecret(data2);

            }


            // update generator with new shared secret
            ecdh.MapGenerator(decryptedNounce);



            // send new public key and do same
            result = await _cmd.GeneralAuthenticateMapping(0x83, ecdh.PublicKey);


            if (!result.IsSuccess)
            {
                Log.Error(result.Error.ErrorMessage());
                return;
            }
            byte[] icPublicKey = [];
            using (var stream = new Asn1InputStream(result.Value.data))
            {
                Asn1Object obj = stream.ReadObject();  // top-level object
                icPublicKey = obj.GetDerEncoded()[4..]; // ic publickey

                ecdh.CalculateSharedSecret(icPublicKey);
            }

            var tuple = TestClass.DeriveSessionKeys(info, ecdh.SharedSecret);

            byte[] macKey = tuple.Item1;
            byte[] encKey = tuple.Item2;
            _cmd.SetEncryption(encKey, macKey);

            var authResult = await _cmd.GeneralAuthenticateMutual(icPublicKey[0..], ecdh.PublicKey, info.OrgOid, macKey);

            if (!result.IsSuccess)
            {
                Log.Error(result.Error.ErrorMessage());
                return;
            }

            bool isAuth = authResult.Value;

            if (!isAuth)
                Log.Info("AuthenticationToken was not correctly calculated");




            Log.Info("Secure Messaging Established using: PACE, Session started.");

            result = await _cmd.ReadBinary(MessageType.SecureMessage, EfIdGlobal.AtrInfo, le: 0x04);

            if (!result.IsSuccess)
            {
                Log.Error(result.Error.ErrorMessage());
                return;
            }

            // Time for EF.SOD
            result = await _cmd.ReadBinary(MessageType.SecureMessage, EfIdAppSpecific.Sod);

            if (!result.IsSuccess)
            {
                Log.Error(result.Error.ErrorMessage());
                return;
            }

            Log.Info(BitConverter.ToString(result.Value.data));

            //await EPassAuth.PassiveAuthentication.VerifySodSignature(); ??

            try
            {
                var efSodInfo = EFSodInfo.ParseEFSodLdsV18(result.Value.data);

                Log.Info("EF.SOD is parsed!");
                Log.Info("Digest algorithm: " + efSodInfo.DigestAlgorithm);
                Log.Info("LDS Version: " + efSodInfo.LdsVersion);
                Log.Info("Unicode Version: " + efSodInfo.UnicodeVersion);

                foreach (var dg in efSodInfo.DataGroupHashes)
                {
                    Log.Info($"DG{dg.DataGroupNumber}: : {BitConverter.ToString(dg.HashValue)}");
                }
            }
            catch (Exception ex)
            {
                Log.Error("Failed to parse: " + ex.Message);
            }

            Log.Info("All commands completed without a problem");

        }

        // await ReadFileWithSM(sm, EfIdGlobal.SOD);

    }

    // Read EF.SOD file in terminal, From this we need to: TODO
    // Parse??
    // Extract list of data group hashes and what algorithm is used
    // Find the SignerInfo and/or DSC


    // private async Task ReadFileWithSM(SecureMessaging sm, ushort fileID)
    // {
    //     byte[] fileBytes = [(byte)(fileID >> 8), (byte)(fileID & 0xFF)];
    //     byte[] select = [0x00, 0xA4, 0x02, 0x0C, 0x02, .. fileBytes];

    //     var wrappedSelect = sm.WrapCommand(select);
    //     var result = _cmd.SendRaw(wrappedSelect);
    //     if (!result.IsSuccess)
    //     {
    //         Log.Error("Failed selecting EF.SOD");
    //         return;
    //     }

    //     List<byte> allData = new();
    //     int offset = 0;
    //     const int chunkSize = 0xFF;

    //     while (true)
    //     {
    //         byte p1 = (byte)((offset >> 8) & 0xFF);
    //         byte p2 = (byte)(offset & 0xFF);
    //         byte[] read = [0x00, 0xB0, p1, p2, (byte)chunkSize];
    //         var wrappedRead = sm.WrapCommand(read);

    //         var readResult = await _cmd.SendRaw(wrappedRead);
    //         if (!readResult.IsSuccess)
    //         {
    //             Log.Error("Failed Reading EF.SOD");
    //             break;
    //         }

    //         var response = sm.UnwrapResponse(readResult.Value);

    //         if (response.Length == 0)
    //             break;

    //         allData.AddRange(response);
    //         offset += response.Length;

    //         if (response.Length < chunkSize)
    //             break;




    //     }

    //         Log.Info("✅ EF.SOD successfully read");
    //         Log.Info(Convert.ToBase64String(allData.ToArray()));
    // }

    private readonly ICommunicator _comm = comm;
    private readonly Command<ServerEncryption> _cmd = new(comm, new ServerEncryption());
}

// TODO Implement Secure messaging
// Add SSC, Wrapper, unwrapper


public class ServerEncryption : IServerFormat
{

    byte[] IServerFormat.Format(byte[] input)
    {
        byte[] lengthBytes = BitConverter.GetBytes(input.Length);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(lengthBytes);

        return [(byte)CommandType.Package, .. lengthBytes, .. input];
    }

    Result<byte[]> IServerFormat.DeFormat(byte[] input)
    {
        var packet = ServerPacket.TryFromBytes(input);
        if (packet.Type == CommandType.Package)
            return Result<byte[]>.Success(packet.Data);

        Console.WriteLine("Error: " + packet.Type.ToString());
        return Result<byte[]>.Fail(new Error.Parse("Decoding packet failed, does not have correct server format"));
    }

};


