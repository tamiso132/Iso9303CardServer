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
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Microsoft.AspNetCore.Components.Forms;
using Org.BouncyCastle.Cms;
using System.Text;
using Microsoft.Extensions.ObjectPool;
namespace App;


public class ClientSession(ICommunicator comm)
{
    public async Task Start()
    {

        byte[] buffer = await _comm.ReadAsync();
        var packet = ServerPacket.TryFromBytes(buffer);
        if (packet.Type == CommandType.NewNFCScan)
        {
            (await _cmd.SelectDefaultMF(MessageType.NonSecureMessage)).UnwrapOrThrow();

            var response = (await _cmd.ReadBinary(MessageType.NonSecureMessage, EfIdGlobal.CardAccess)).UnwrapOrThrow();

            var info = response.Parse<ImplCardAccess, ImplCardAccess.Info>().EncryptInfos[0];
            info.PrintInfo();

            byte[] key = PassHelper.DerivePaceKey(info);


            (await _cmd.MseSetAT(MessageType.NonSecureMessage, info.OrgOid, info.OrgParameterID)).UnwrapOrThrow();

            var decryptedNounce = (await PassHelper.ComputeDecryptedNounce(_cmd, info, key, PassHelper.PasswordType.MRZ)).UnwrapOrThrow();


            var ecdh = new ECDH(DomainParameter.BrainpoolP384r1);

            response = (await _cmd.GeneralAuthenticateMapping(0x81, ecdh.PublicKey)).UnwrapOrThrow();
            ecdh.ParseCalculateSharedSecret(response.data);


            // update generator with new shared secret
            ecdh.MapGenerator(decryptedNounce);



            // send new public key and do same
            response = (await _cmd.GeneralAuthenticateMapping(0x83, ecdh.PublicKey)).UnwrapOrThrow();


            byte[] icPublicKey = ecdh.ParseCalculateSharedSecret(response.data);
            var tuple = PassHelper.DeriveSessionKeys(info, ecdh.SharedSecret);

            _cmd.SetEncryption(tuple.Item1, tuple.Item2);

            if (!(await _cmd.GeneralAuthenticateMutual(icPublicKey[0..], ecdh.PublicKey, info.OrgOid)).UnwrapOrThrow())
            {
                Log.Error("AuthenticationToken was not correctly calculated");
                return;
            }

            Log.Info("Secure Messaging Established using: PACE, Session started.");

            // Change to LDS1 MUST be secure
            (await _cmd.SelectApplication(MessageType.SecureMessage, AppID.IdLDS1)).UnwrapOrThrow();

            response = (await _cmd.ReadBinary(MessageType.SecureMessage, EfIdAppSpecific.Sod)).UnwrapOrThrow();


            byte[] sodrawBytes = response.data;

            SodContent sodFile = EfSodParser.ParseFromHexString(response.data);

            Log.Info("Nr of data groups in EF.SOD: " + sodFile.DataGroupHashes.Count.ToString());
            Log.Info("Using algorithm: " + sodFile.HashAlgorithmOid.GetAlgorithmName());
            //     Log.Info("Using algorithm: " + sodFile.HashAlgorithmOid.GetAlgorithmName());

            var tags = TagReader.ReadTagData(sodrawBytes, [0x77, 0x30, 0x31, 0xA0, 0xA3, 0xA1]);
            //   tags.PrintAll();


            var data = tags[0].Children[0].Children.FilterByTag(0xA0)[0].Data;

            var cmsTags = TagReader.ReadTagData(data, [0x30]);
            //  cmsTags.PrintAll();

            // Skriver in all data i filer, First step of passive authentication
            File.WriteAllBytes("EFSodDumpcmstag.bin", cmsTags[0].GetHeaderFormat());
            byte[] binBytes = tags[0].Data;


            Org.BouncyCastle.X509.X509Certificate dscCertBouncyCastle = SodHelper.ReadSodData(binBytes)!; // Helper to find and print SOD information


            // Use passiveAuthTest.cs for step 2 and 3
            Log.Info("Starting Passive authentication...");

            string masterListPath = Path.Combine(Environment.CurrentDirectory, "masterlist-cscas"); // Directory to masterlist 
            if (!SodHelper.PerformPassiveAuthStep2(dscCertBouncyCastle, masterListPath))
            {
                Log.Error("STEP 2 Failed for passive authentication");
                return;
            }

            Log.Info("PA step 3 start...");

            foreach (var dg in sodFile.DataGroupHashes)
            {
                if (dg.DataGroupNumber == 3 || dg.DataGroupNumber == 4)
                {
                    //NEED EAC TO READ THOSE DG
                    continue;
                }
                Log.Info($"Verifierar DG {dg.DataGroupNumber}...");


                EfIdAppSpecific dgID = dg.DataGroupNumber.IntoDgFileID();
                response = (await _cmd.ReadBinary(MessageType.SecureMessage, dgID)).UnwrapOrThrow();


                byte[] dgData = response.data;
                byte[] calculatedHashData = HashCalculator.CalculateSHAHash(sodFile.HashAlgorithmOid.GetAlgorithmName(), dgData);

                Log.Info($"Chip hash says: {BitConverter.ToString(dg.Hash)}");
                Log.Info($"Calculated Hash: {BitConverter.ToString(calculatedHashData)}");

                if (!calculatedHashData.SequenceEqual(dg.Hash))
                {
                    Log.Error($"Hash wrong for {dg.DataGroupNumber}, PA failed");
                    TestClass.PrintByteComparison(calculatedHashData, dg.Hash);
                    return;
                }
                Log.Info($"Hash ok for DG {dg.DataGroupNumber}");
            }
            Log.Info("Step 3 PA OK");
            Log.Info("Full Passive Authentication Complete!");

        }

        Log.Info("All commands completed without a problem");

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


