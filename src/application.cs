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
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Math;
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


        var _ecdh = new ECDH(DomainParameter.GetFromId(info.OrgParameterID));

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
        // Read and store DG14
        var dg14Response = (await _cmd.ReadBinary(MessageType.SecureMessage, EfIdAppSpecific.Dg14)).UnwrapOrThrow();
        byte[] dg14Bytes = dg14Response.data;

        var root = TagReader.ReadTagData(dg14Bytes, [0x30, 0x31, 0x6E]).FilterByTag(0x6E)[0]; //Parse


        var publicKeyInfo = root.FindChild(0x31).FindChild(0x30)!;
        Log.Info(root.ToStringFormat());


        var keyAgreement = publicKeyInfo.FindChild(0x06)!.Data.ToOidStr(); //OID tag, find algorithm

        var keyID = keyAgreement[^1]; // if  2 = ECDH, if 1 = DH

        var subjectPublicKeyInfo = publicKeyInfo.FindChild(0x30);
        var algoritmIdentifier = subjectPublicKeyInfo.FindChild(0x30).FindChild(0x06); // only used when SUBJECT PUBLIC KEY INFO, is MISSING
        var explicitParameters = subjectPublicKeyInfo.FindChild(0x30).FindChild(0x30)!;

        // ECDH Curve parameters
        var p = explicitParameters.Children[1].FindChild(0x02)!.Data;
        var a = explicitParameters.Children[2].Children[0].Data;
        var b = explicitParameters.Children[2].Children[1].Data;
        var g = explicitParameters.Children[3].Data;
        var n = explicitParameters.Children[4].Data;
        var h = explicitParameters.Children[5].Data;

        var publicKey = subjectPublicKeyInfo.FindChild(0x03)!.Data; //Chips public CA-Key
        Log.Info("KeyAgreementID: " + keyID);
        Log.Info("--- Explicit Curve Parameters (från Container) ---");
        Log.Info($"Prime (p):      {BitConverter.ToString(p)}");
        Log.Info($"Coeff (a):      {BitConverter.ToString(a)}");
        Log.Info($"Coeff (b):      {BitConverter.ToString(b)}");
        Log.Info($"Base (G):       {BitConverter.ToString(g)}");
        Log.Info($"Order (n):      {BitConverter.ToString(n)}");
        Log.Info($"Cofactor (h):   {BitConverter.ToString(h)}");
        Log.Info($"Public Key (Y): {BitConverter.ToString(publicKey)}");
        Log.Info("--------------------------------------------------");






        var version = new DerInteger(1);

        var fieldTypeOid = new DerObjectIdentifier("1.2.840.10045.1.1"); // OID för prime-field
        var pAsn1 = new DerInteger(new BigInteger(1, p));
        var fieldId = new DerSequence(fieldTypeOid, pAsn1);

        var aAsn1 = new DerOctetString(a);
        var bAsn1 = new DerOctetString(b);
        var curve = new DerSequence(aAsn1, bAsn1);

        var gAsn1 = new DerOctetString(g);
        var nAsn1 = new DerInteger(new BigInteger(1, n));
        var hAsn1 = new DerInteger(new BigInteger(1, h));

        // TODO, can be simplified
        var explicitParametersDer = new DerSequence(
            version,  // Children[0]
            fieldId,  // Children[1]
            curve,    // Children[2]
            gAsn1,    // Children[3]
            nAsn1,    // Children[4]
            hAsn1     // Children[5]
        ).GetDerEncoded()!;


        var protocols = root.FindChild(0x31)!.Children[1..];
        byte[]? chipAuthOid = null;

        foreach (var protocol in protocols)
        {
            var protocolVer = protocol.FindChild(0x02)!.Data[0]; // version, 1 for chipauth

            if (protocolVer == 1)
            {
                var oidTag = protocol.FindChild(0x06);
                if (oidTag != null)
                {
                    chipAuthOid = oidTag.Data;
                    Log.Info($"Found oid for protocol: {chipAuthOid.ToString}");
                    break;
                }
            }
        }
        if (chipAuthOid == null)
        {
            Log.Error($"No found OID for CA-protocol");
            return;
        }
        //         var chipAuthOid = protocol.FindChild(0x06)!.Data.ToOidStr().Split(".");
        //         var tag = chipAuthOid[8];

        //         if (tag != "3")
        //             continue;
        //         //TODO, get the protocol and stuff
        //         //  var prot = Encryption
        //     }

        // }


        //   Log.Info(BitConverter.ToString(explicitParametersDer));


        (await _cmd.MseSetAT_ChipAuthentication(MessageType.SecureMessage, chipAuthOid, publicKey)).UnwrapOrThrow();


        ECDH ecdh = new ECDH(explicitParametersDer); //Create curve using parameters taken from DG14
        Log.Info(BitConverter.ToString(publicKey));
        ecdh.CalculateSharedSecret(publicKey); // Remove??
        ecdh.GenerateEphemeralKeys(new RandomNumberProvider()); // Generate temporary keys

        byte[] terminalEphemeralPublicKey = ecdh.PublicKey; // K_pub_T 

        Log.Info("Send general authenticate CA");

        // Send general authenticate
        var caResponse = (await _cmd.GeneralAuthenticateMapping(0x81, terminalEphemeralPublicKey)).UnwrapOrThrow();









        // foreach (var tag in tags[1..])
        // {
        //     var oid = tag.FilterByTag(0x06)[0].Data;
        //     var version = tag.FilterByTag(0x02)[0].Data[0];

        //     // version 2 is for chip authentication
        //     if (version != 2)
        //         continue;

        //     var parameterID = tag.FilterByTag(0x02)[1].Data[0];


        //     Log.Info("oid: " + oid.ToOidStr() + ", version: " + version.ToString() + ", parameterID: " + parameterID);
        // }
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


