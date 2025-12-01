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
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Crypto.Digests;
using System.Data.SqlTypes;
using Org.BouncyCastle.Crypto;
using System.Runtime.Intrinsics.Arm;
using System;
using System.Diagnostics;
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


            // Secure Messaging
            await SetupSecureMessaging();

            // Passive autentication and decide if CA or AA

            AuthMethod nextMethod = await SetupPassiveAuthentication();


            if (nextMethod == AuthMethod.CA)
            {
                Log.Info("Using Chip Authentication....");
                await SetupChipAuthentication();
            }
            else if (nextMethod == AuthMethod.AA)
            {
                Log.Info("Using Active Authentication....");
                
                await SetupActiveAuthentication();
            }
            else
            {
                Log.Warn("No extended authentication method avalible (CA/AA)");
                //return;
            }

            
        }
        Log.Info("All commands completed without a problem");
    }

    public async Task SetupSecureMessaging()
    {
        var response = (await _cmd.ReadBinary(MessageType.NonSecureMessage, EfIdGlobal.CardAccess)).UnwrapOrThrow();

        var infos = response.Parse<ImplCardAccess, ImplCardAccess.Info>().EncryptInfos;
        var info = infos[0];
        // foreach (var i in infos)
        // {
        //     i.PrintInfo();
        //     if (i.OrgOid[^2] == 6) // CAM
        //     {
        //         info = i;
        //     }
        // }

        info.PrintInfo();


        byte[] key = PassHelper.DerivePaceKey(info);


        (await _cmd.MseSetAT(MessageType.NonSecureMessage, info.OrgOid, info.OrgParameterID)).UnwrapOrThrow();

        var decryptedNounce = (await PassHelper.ComputeDecryptedNounce(_cmd, info, key, PassHelper.PasswordType.MRZ)).UnwrapOrThrow();


        var _ecdh = new ECDH(DomainParameter.GetFromId(info.OrgParameterID));
        _ecdh.GenerateEphemeralKeys(new RandomNumberProvider());

        response = (await _cmd.GeneralAuthenticateMapping(0x81, _ecdh.PublicKey)).UnwrapOrThrow();
        _ecdh.ParseCalculateSharedSecret(response.data);


        // update generator with new shared secret
        _ecdh.MapGenerator(decryptedNounce);

        _ecdh.GenerateEphemeralKeys(new RandomNumberProvider());



        // send new public key and do same
        response = (await _cmd.GeneralAuthenticateMapping(0x83, _ecdh.PublicKey)).UnwrapOrThrow();


        byte[] icPublicKey = _ecdh.ParseCalculateSharedSecret(response.data);
        var tuple = PassHelper.DeriveSessionKeys(_ecdh.SharedSecret);

        _cmd.SetEncryption(tuple.Item2, tuple.Item1);

        Log.Info("hello: " + BitConverter.ToString(info.OrgOid));

        if (!(await _cmd.GeneralAuthenticateMutual(icPublicKey, _ecdh.PublicKey, info.OrgOid)).UnwrapOrThrow())
        {
            Log.Error("AuthenticationToken was not correctly calculated");
            return;
        }

        (await _cmd.SelectApplication(MessageType.SecureMessage, AppID.IdLDS1)).UnwrapOrThrow();

        (await _cmd.ReadBinary(MessageType.SecureMessage, EfIdAppSpecific.Dg1)).UnwrapOrThrow();

        Log.Info("Secure Messaging Established using: PACE, Session started.");
    }

    public async Task<AuthMethod> SetupPassiveAuthentication()
    {
        var response = (await _cmd.ReadBinary(MessageType.SecureMessage, EfIdAppSpecific.Sod)).UnwrapOrThrow();

        bool dg15Find = false;
        bool dg14Find = false;

        SodContent sodFile = EfSodParser.ParseFromHexString(response.data);

        Log.Info("Nr of data groups in EF.SOD: " + sodFile.DataGroupHashes.Count.ToString());
        Log.Info("Using algorithm: " + sodFile.HashAlgorithmOid.GetAlgorithmName());

        Log.Info("Starting Passive authentication...");

        string masterListPath = Path.Combine(Environment.CurrentDirectory, "masterlist-cscas"); // Directory to masterlist 
        if (!SodHelper.PerformPassiveAuthStep2(sodFile.DocumentSignerCertificate, masterListPath))
        {
            Log.Error("STEP 2 Failed for passive authentication");
            return AuthMethod.None;
        
        }

        Log.Info("PA step 3 start...");

        foreach (var dg in sodFile.DataGroupHashes)
        {
            if (dg.DataGroupNumber == 3 || dg.DataGroupNumber == 4)
            {
                //NEED EAC TO READ THOSE DG
                Log.Warn($"Found DG: {dg.DataGroupNumber}, Need EAC (Extended Acess Controll) to verify this datagroup");
                continue;
            }

            if (dg.DataGroupNumber == 15)
            {
                dg15Find = true;
            }

            if (dg.DataGroupNumber == 14)
            {
                dg14Find = true;
            }




            EfIdAppSpecific dgID = dg.DataGroupNumber.IntoDgFileID();
            response = (await _cmd.ReadBinary(MessageType.SecureMessage, dgID)).UnwrapOrThrow();


            byte[] dgData = response.data;
            byte[] calculatedHashData = HashCalculator.CalculateSHAHash(sodFile.HashAlgorithmOid.GetAlgorithmName(), dgData);

            if (dg.DataGroupNumber == 14)
            {
                File.WriteAllBytes("dg14Wrong.txt", dgData);
            }


            // Log.Info($"Chip Hash says: {BitConverter.ToString(dg.Hash)}");
            // Log.Info($"Calculated Hashvalue: {BitConverter.ToString(calculatedHashData)}");

            // Manipulerad hash går inte genom detta steg
            if (!calculatedHashData.SequenceEqual(dg.Hash))
            {
                TestClass.PrintByteComparison(calculatedHashData, dg.Hash);
                Log.Error($"Hash wrong for DG{dg.DataGroupNumber}, PA failed");
                return AuthMethod.None;
            }
            //   Log.Info($"Hashvalue ok for DG {dg.DataGroupNumber}");
        }
        Log.Info("Step 3 PA OK");
        Log.Info("Full Passive Authentication Complete!");

        // Chose CA or AA here
        // if DG15 only -> AA
        // if DG14 only -> CA
        // if DG15 AND DG 14 -> CA (Must)

        if (dg14Find)
        {
            Log.Info("DG14 in chip, use CA");
            return AuthMethod.CA;
        }

        if (dg15Find)
        {
            Log.Info("DG15 ONLY, use AA");
            return AuthMethod.AA;
        }

        Log.Info("Neither DG14 or DG15 in chip, cant use CA or AA");
        return AuthMethod.None;

    }

    // I application.cs

    public void DebugDecryptSignature(RsaKeyParameters pubKey, byte[] signature)
    {
        try
        {
            Log.Info("--- DEBUG: Raw RSA Decrypt ---");

            // Använd ren RSA-motor utan padding/logik
            var engine = new Org.BouncyCastle.Crypto.Engines.RsaEngine();
            engine.Init(false, pubKey); // false = decrypt (med publik nyckel för att verifiera signatur)

            // Dekryptera signaturen 
            byte[] decrypted = engine.ProcessBlock(signature, 0, signature.Length);

            Log.Info($"Decrypted Data (EM): {BitConverter.ToString(decrypted)}");

            // ISO 9796-2 ska börja med 0x6A och sluta med en hash eller trailer (t.ex. 34CC).
            // Om det är PKCS#1 v1.5 börjar det med 00 01 FF ...
        }
        catch (Exception ex)
        {
            Log.Error($"Debug decrypt failed: {ex.Message}");
        }
    }


    // TODO, måste även fixa för ECDSA. Just nu är RSA hårdkodat
    public async Task SetupActiveAuthentication()
    {
        var dg15Response = (await _cmd.ReadBinary(MessageType.SecureMessage, EfIdAppSpecific.Dg15)).UnwrapOrThrow();
        var root = TagReader.ReadTagData(dg15Response.data, [0x30, 0x31, 0x6F]);

        var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(root[0].Data, out int _);
        RSAParameters p = rsa.ExportParameters(false);


        var ifd = new RandomNumberProvider().GetNextBytes(8);

        var sig = (await _cmd.AAStepOne(ifd)).UnwrapOrThrow();
        Log.Info("SigLength: " + sig.data.Length + "\n" + BitConverter.ToString(sig.data));


        BigInteger exponent = new([.. p.Exponent!.Reverse()], false);
        BigInteger modulus = new([.. p.Modulus!.Reverse(), 0x00], false);

        var rsaParam = new RsaKeyParameters(false, modulus, exponent);
        var rsaEngine = new RsaEngine();

        try
        {
            rsaEngine.Init(false, rsaParam);
            var decrypted = rsaEngine.ProcessBlock(sig.data, 0, sig.data.Length);
            HashAlgoType hashOP;
            // 2. Determine Algorithm from Trailer
            byte[] trailer = decrypted[^2..];
            int digestLen;
            int trailerLen = 2;

            if (trailer.SequenceEqual([(byte)0x38, (byte)0xCC]))
            {
                digestLen = 224 / 8;
                hashOP = HashAlgoType.Sha224;

            }
            else if (trailer.SequenceEqual([(byte)0x36, (byte)0xCC]))
            {
                hashOP = HashAlgoType.Sha384;
                digestLen = 384 / 8;
            }
            else if (trailer.SequenceEqual([(byte)0x35, (byte)0xCC]))
            {
                hashOP = HashAlgoType.Sha512;
                digestLen = 512 / 8;
            }
            else if (trailer.SequenceEqual([(byte)0x34, (byte)0xCC]))
            {
                hashOP = HashAlgoType.Sha256;
                digestLen = 256 / 8;
            }

            else
            {
                throw new Exception($"Unknown Trailer: {trailer:X2}");
            }

            byte[] digest = decrypted[^(digestLen + trailerLen)..^trailerLen];
            byte[] m1 = decrypted[1..^(digestLen + trailerLen)]; // +1 skips Header(0x6A)

            // 4. Reconstruct the Message (M* = M1 + M2)
            byte[] m = [.. m1, .. ifd];

            // 5. Calculate Hash (Must match the algorithm!)
            byte[] calDigest;
            calDigest = HashCalculator.ComputeHash(hashOP, m);

            if (calDigest.SequenceEqual(digest))
            {
                Log.Info("Active Authentication is succesful!");
            }

        }

        catch
        {
            Log.Info("bad");
            throw new Exception("");
        }

    }



   

    public async Task SetupChipAuthentication()
    {
        // Read and store DG14
        var dg14Response = (await _cmd.ReadBinary(MessageType.SecureMessage, EfIdAppSpecific.Dg14)).UnwrapOrThrow();
        byte[] dg14Bytes = dg14Response.data;

        var root = TagReader.ReadTagData(dg14Bytes, [0x30, 0x31, 0x6E]).FilterByTag(0x6E)[0]; //Parse

        Log.Info(root.ToStringFormat());
        //  var publicKeyInfo = root.FindChild(0x31).FindChild(0x30)!;

        var objects = root.FindChild(0x31);

        var chipAuthOidBytes = Array.Empty<byte>();
        byte[] pubKey = [];
        byte[] p = [];
        byte[] a = [];
        byte[] b = [];
        byte[] g = [];
        byte[] n = [];
        byte[] h = [];
        byte? keyID = null;

        byte[] encodedParameters = [];



        foreach (var objectP in objects!.Children) // first find protocol
        {
            var oid = objectP.FindChild(0x06)!;
            if (oid.Data[^3] == 0x03 && chipAuthOidBytes.Length == 0) // chip protocol
            {
                // id 
                // 1 -> 3des
                // 2 -> CMAC_AES 128
                // 3 -> CMAC_AES 192
                // 4 -> CMAC_AES 256
                var id = oid.Data[^1];

                if (id == 1) // I do not support 3des
                    continue;

                // keyType 
                // 1 -> DH
                // 2 -> ECDH
                var keyType = oid.Data[^2];

                if (keyType == 1) // have not implemented DH
                    continue;

                var integers = objectP.Children.FilterByTag(0x02);
                if (integers.Count > 1) // there is keyID
                {
                    keyID = integers[1].Data[0];
                }


                chipAuthOidBytes = oid.Data;
                break;
            }
        }

        foreach (var objectP in objects!.Children)
        {
            var oid = objectP.FindChild(0x06)!;

            // TODO, sometimes there is only parameter id of a known curve instead of explicit parameters
            if (p.Length == 0 && oid.Data[^3] == 0x02 && oid.Data[^2] == 1) // public key
            {
                if (keyID != null) // need to get linked public key
                {
                    bool isPubKeyProtocol = objectP.FindChild(0x02)!.Data[0] == keyID;

                    if (!isPubKeyProtocol)
                        continue;

                    Log.Info("Choose KeyId: " + BitConverter.ToString(objectP.FindChild(0x02)!.Data));
                }
                // priority ecdh
                byte keyType = oid.Data[^1];

                if (keyType == 1) // have not implemented DH
                    continue;

                //  Log.Info(objectP.ToStringFormat());

                var subjectPublicKeyInfo = objectP.FindChild(0x30)!;

                pubKey = subjectPublicKeyInfo.FindChild(0x03)!.Data;

                var domainParameters = subjectPublicKeyInfo.FindChild(0x30)!.FindChild(0x30);

                encodedParameters = subjectPublicKeyInfo.FindChild(0x30).FindChild(0x30)!.Data;


                var sequences = domainParameters!.Children.FilterByTag(0x30);
                var integers = domainParameters.Children.FilterByTag(0x02);


                // Log.Info(domainParameters.ToStringFormat());

                p = sequences[0].FindChild(0x02)!.Data[1..]; // remove 00
                a = sequences[1].Children[0]!.Data;
                b = sequences[1].Children[1]!.Data;
                g = domainParameters.FindChild(0x04)!.Data;
                n = integers[1].Data[1..];// remove 0x00
                h = integers[2].Data;
                // EXIST KEY ID
                // Should only exist if there is multiple public keys
            }

        }

        if (chipAuthOidBytes.Length == 0 || p.Length == 0)
        {
            throw new Exception("Chip Auth is not supported");
        }


        var publicKey = pubKey!;
        if (keyID != null)
            Log.Info("KeyIDRef: " + keyID);

        Log.Info("--- Explicit Curve Parameters (från Container) ---");
        Log.Info($"Prime (p):      {BitConverter.ToString(p!)}");
        Log.Info($"Coeff (a):      {BitConverter.ToString(a!)}");
        Log.Info($"Coeff (b):      {BitConverter.ToString(b!)}");
        Log.Info($"Base (G):       {BitConverter.ToString(g!)}");
        Log.Info($"Order (n):      {BitConverter.ToString(n!)}");
        Log.Info($"Cofactor (h):   {BitConverter.ToString(h!)}");
        Log.Info($"Public Key (Y): {BitConverter.ToString(publicKey)}");
        Log.Info("Chose Chip Authentication OID: " + chipAuthOidBytes.ToOidStr());
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

        //  TestClass.PrintByteComparison(explicitParametersDer, encodedParameters); 

        //  Log.Info("DerEncodedStructure: " + BitConverter.ToString(explicitParametersDer));


        ECDH ecdh = new(DomainParameter.GetFromDerEncoded(explicitParametersDer)); //Create curve using parameters taken from DG14
                                                                                   //ecdh.PrintECParameters(); ec parameters seem correct
                                                                                   // ecdh.GenerateEphemeralKeys(new RandomNumberProvider()); // Generate temporary keys
                                                                                   //  ecdh.CalculateSharedSecret(publicKey);

        ecdh.GenerateEphemeralKeys(new RandomNumberProvider());

        Log.Info(BitConverter.ToString(ecdh.PublicKey));

        (await _cmd.MseSetAT_ChipAuthentication(MessageType.SecureMessage, chipAuthOidBytes, keyID)).UnwrapOrThrow();
        (await _cmd.GeneralAuthenticateChipMapping(MessageType.SecureMessage, 0x80, ecdh.PublicKey)).UnwrapOrThrow(); // should return 0x7C00 -> empty dynamic auth data

        ecdh.CalculateSharedSecret(publicKey[1..]);
        var tuple = PassHelper.DeriveSessionKeys(ecdh.SharedSecret);

        // Restarting secure messaging
        _cmd.SetEncryption(tuple.Item2, tuple.Item1);


        byte[] terminalEphemeralPublicKey = ecdh.PublicKey; // K_pub_T 

        Log.Info("Send general authenticate CA");


        // if error, it means different shared secret, aka ENC and MAC should fail as they are derived from shared secret
        // so chip is cloned
        (await _cmd.ReadBinary(MessageType.SecureMessage, EfIdAppSpecific.Dg1)).UnwrapOrThrow();

        Log.Info("Chip Authentication Completed!");

        // // Send general authenticate
        // var caResponse = (await _cmd.GeneralAuthenticateMapping(0x81, terminalEphemeralPublicKey)).UnwrapOrThrow();






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

public enum AuthMethod
{
    None,
    AA, // Active Authentication
    CA  // Chip Authentication
}
