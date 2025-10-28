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
using Org.BouncyCastle.Cms;
using System.Text;
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
            {
                Log.Error("AuthenticationToken was not correctly calculated");
                return;
            }



            Log.Info("Secure Messaging Established using: PACE, Session started.");

            // Change to LDS1 MUST be secure
            result = await _cmd.SelectApplication(MessageType.SecureMessage, AppID.IdLDS1);


            if (!result.IsSuccess)
            {
                Log.Error(result.Error.ErrorMessage());
                return;
            }


            // Time for EF.SOD
            result = await _cmd.ReadBinary(MessageType.SecureMessage, EfIdAppSpecific.Sod);
            Log.Info(BitConverter.ToString(result.Value.data));

            if (!result.IsSuccess)
            {
                Log.Error(result.Error.ErrorMessage());
                return;
            }

            //Log.Info("Found EF.SOD");

            response = result.Value;
            var tags = TagReader.ReadTagData(result.Value.data, [0x77, 0x30, 0x31, 0xA0, 0xA3, 0xA1]);
            tags.PrintAll();


            var data = tags[0].Children[0].Children.FilterByTag(0xA0)[0].Data;

            var cmsTags = TagReader.ReadTagData(data, [0x30]);
            cmsTags.PrintAll();

            // Skriver in all data i filer, First step of passive authentication
            File.WriteAllBytes("EFSodDumpcmstag.bin", cmsTags[0].GetHeaderFormat());
            byte[] binBytes = tags[0].Data;
            Org.BouncyCastle.X509.X509Certificate? dscCertBouncyCastle = SodHelper.ReadSodData(binBytes); // Helper to find and print SOD information

            // Use passiveAuthTest.cs for step 2 and 3
            Log.Info("Starting Passive authentication...");

            string masterListPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "masterlist-cscas"); // Directory to masterlist
            bool step2Success = SodHelper.PerformPassiveAuthStep2(dscCertBouncyCastle, masterListPath);

            if (step2Success)
            {
                Log.Info("STEP 2 DONE");
            }
            else
            {
                Log.Error("Pa failed in step 2");
            }
        }
        

            Log.Info("All commands completed without a problem");

        

    }
            // Step 2: Valideringskedja
            // Use FindCSCACert??, verifyCertChain

            // OSCP (Online Certificate Status Protocol)
            // Check revokation list??, this requires us to send the certificate to a revokation server which responds if the certificate is valid or not

            // Step 3: Verify data-group hashes
            // Use verifyDatagroupHashes


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


