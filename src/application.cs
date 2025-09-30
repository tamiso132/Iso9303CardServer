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
namespace App;


public class ClientSession(ICommunicator comm)
{
    public async Task Start()
    {


        byte[] buffer = await _comm.ReadAsync();
        var packet = ServerPacket.TryFromBytes(buffer);
        if (packet.Type == CommandType.NewNFCScan)
        {
            var result = await _cmd.SelectDefaultMF();



            if (!result.IsSuccess)
            {
                Log.Error(result.Error.ErrorMessage());
                return;
            }

            result = await _cmd.ReadBinary(EfIdGlobal.CardAccess);

            if (!result.IsSuccess)
            {
                Log.Error(result.Error.ErrorMessage());
                return;
            }


            var response = result.Value;
            var info = response.Parse<ImplCardAccess, ImplCardAccess.Info>().EncryptInfos[0];
            info.PrintInfo();

            if (!result.IsSuccess)
            {
                Log.Error(result.Error.ErrorMessage());
                return;
            }

            byte[] key = TestClass.DerivePaceKey(info);



            result = await _cmd.MseSetAT(info.OrgOid, info.OrgParameterID);


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

            result = await _cmd.GeneralAuthenticateMutual(icPublicKey, info.OrgOid, macKey);




            if (!result.IsSuccess)
            {
                Log.Error(result.Error.ErrorMessage());
                return;
            }

            Log.Info("All commands completed without a problem");
        }
    }

    private readonly ICommunicator _comm = comm;
    private readonly Command<ServerEncryption> _cmd = new(comm, new ServerEncryption());
}


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


