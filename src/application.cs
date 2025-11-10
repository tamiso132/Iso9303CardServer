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
using Org.BouncyCastle.Utilities;
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

            await SetupSecureMessaging();
            //            await SetupPassiveAuthentication();
            await SetupChipAuthentication();

        }

        Log.Info("All commands completed without a problem");

    }

    public async Task SetupSecureMessaging()
    {
        var response = (await _cmd.ReadBinary(MessageType.NonSecureMessage, EfIdGlobal.CardAccess)).UnwrapOrThrow();

        var info = response.Parse<ImplCardAccess, ImplCardAccess.Info>().EncryptInfos[0];
        info.PrintInfo();

        byte[] key = PassHelper.DerivePaceKey(info);


        (await _cmd.MseSetAT(MessageType.NonSecureMessage, info.OrgOid, info.OrgParameterID)).UnwrapOrThrow();

        var decryptedNounce = (await PassHelper.ComputeDecryptedNounce(_cmd, info, key, PassHelper.PasswordType.MRZ)).UnwrapOrThrow();


        _ecdh = new ECDH(DomainParameter.BrainpoolP384r1);

        response = (await _cmd.GeneralAuthenticateMapping(0x81, _ecdh.PublicKey)).UnwrapOrThrow();
        _ecdh.ParseCalculateSharedSecret(response.data);


        // update generator with new shared secret
        _ecdh.MapGenerator(decryptedNounce);



        // send new public key and do same
        response = (await _cmd.GeneralAuthenticateMapping(0x83, _ecdh.PublicKey)).UnwrapOrThrow();


        byte[] icPublicKey = _ecdh.ParseCalculateSharedSecret(response.data);
        var tuple = PassHelper.DeriveSessionKeys(info, _ecdh.SharedSecret);

        _cmd.SetEncryption(tuple.Item2, tuple.Item1);

        if (!(await _cmd.GeneralAuthenticateMutual(icPublicKey[0..], _ecdh.PublicKey, info.OrgOid)).UnwrapOrThrow())
        {
            Log.Error("AuthenticationToken was not correctly calculated");
            return;
        }

        (await _cmd.SelectApplication(MessageType.SecureMessage, AppID.IdLDS1)).UnwrapOrThrow();

        Log.Info("Secure Messaging Established using: PACE, Session started.");
    }

    public async Task SetupPassiveAuthentication()
    {
        var response = (await _cmd.ReadBinary(MessageType.SecureMessage, EfIdAppSpecific.Sod)).UnwrapOrThrow();


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
                Log.Info($"Found DG: {dg.DataGroupNumber}, Need EAC (Extended Acess Controll) to verify this datagroup");
                continue;
            }
            Log.Info($"Verifierar DG {dg.DataGroupNumber}...");


            EfIdAppSpecific dgID = dg.DataGroupNumber.IntoDgFileID();
            response = (await _cmd.ReadBinary(MessageType.SecureMessage, dgID)).UnwrapOrThrow();


            byte[] dgData = response.data;
            byte[] calculatedHashData = HashCalculator.CalculateSHAHash(sodFile.HashAlgorithmOid.GetAlgorithmName(), dgData);

            Log.Info($"Chip Hash says: {BitConverter.ToString(dg.Hash)}");
            Log.Info($"Calculated Hashvalue: {BitConverter.ToString(calculatedHashData)}");

            if (!calculatedHashData.SequenceEqual(dg.Hash))
            {
                Log.Error($"Hash wrong for DG{dg.DataGroupNumber}, PA failed");
                TestClass.PrintByteComparison(calculatedHashData, dg.Hash);
                return;
            }
            Log.Info($"Hashvalue ok for DG {dg.DataGroupNumber}");
        }
        Log.Info("Step 3 PA OK");
        Log.Info("Full Passive Authentication Complete!");
    }

    public async Task SetupChipAuthentication()
    {
        var dg14Response = (await _cmd.ReadBinary(MessageType.SecureMessage, EfIdAppSpecific.Dg14)).UnwrapOrThrow();
        byte[] dg14Bytes = dg14Response.data;
        var tags = TagReader.ReadTagData(dg14Bytes, [0x30, 0x31, 0x6E]).FilterByTag(0x6E).GetChildren().FilterByTag(0x31).GetChildren();
        Log.Info(tags.Count.ToString());
        foreach (var tag in tags)
        {
            Log.Info(tag.ToStringFormat());
        }

        foreach (var tag in tags[1..])
        {
            var oid = tag.FilterByTag(0x06)[0].Data;
            var version = tag.FilterByTag(0x02)[0].Data[0];

            // version 2 is for chip authentication
            if (version != 2)
                continue;

            var parameterID = tag.FilterByTag(0x02)[1].Data[0];


            Log.Info("oid: " + oid.ToOidStr() + ", version: " + version.ToString() + ", parameterID: " + parameterID);
        }
    }


    ECDH _ecdh;
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


