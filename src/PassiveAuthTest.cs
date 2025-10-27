
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.ConstrainedExecution;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Helper;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509.Store;
using Org.BouncyCastle.X509;
using System.Linq.Expressions;
using Org.BouncyCastle.Security;
using Microsoft.AspNetCore.Mvc.ApplicationModels;
using Parser;



// Trivialt test, får antagligen modda lite/ ändra implementeringar

/// <summary>
/// Kör hela passive authentication-flödet:
/// 1. Hitta CSCA från masterlist baserat på DG12
/// 2. Extrahera DSC från EF.SOD
/// 3. Verifiera kedja (DSC -> CSCA)
/// 4. Verifiera EF.SOD signatur
/// 5. Verifiera hashvärden för alla DGs
/// </summary>

namespace EPassAuth
{
    public static class PassiveAuthentication
    {

        public static bool Verify(
            string issuingCountry,
            byte[] efSodBytes,
            List<X509Certificate2> masterListCscas,
            Dictionary<int, byte[]> dataGroups)
        {
            Log.Info($"Identifying country...");
            // 1. Hitta CSCA i masterlist baserat på DG12
            var cscaCert = FindCscaCert(issuingCountry, masterListCscas);
            if (cscaCert == null)
                throw new Exception(" No CSCA found for the country" + issuingCountry);

            Log.Info($" Found CSCA-certificate for {issuingCountry}:");
            Log.Info($" Subject: {cscaCert.Subject}");
            Log.Info($" Issuer : {cscaCert.Issuer}");
            Log.Info($" FriendlyName: {cscaCert.FriendlyName}");

            // 2. Extrahera DSC från EF.SOD (ASN.1 parsing)
            var dscCert = ExtractDscFromSod(efSodBytes);
            if (dscCert == null)
                throw new Exception("Could not extract DSC from EF.SOD file");

            Log.Info("Extracted DSC from EF.SOD");

            // Parsar EF.SOD till EFSodInfo
            var sodInfo = Parser.EFSodInfo.ParseEFSodLdsV18(efSodBytes);

            // 3. Bygg kedja: DSC -> CSCA
            if (!VerifyCertChain(dscCert, cscaCert))
                throw new Exception("DSC couldnt be verified against CSCA");

            Log.Info("Verified chain between DSC och CSCA");

            // 4. Verifiera EF.SOD signaturen
            if (!VerifySodSignature(efSodBytes, dscCert))
                throw new Exception("EF.SOD signature is invalid");

            Log.Info("Verified EF.SOD signature");

            // 5. Verifiera DG-hashar mot EF.SOD
            if (!VerifyDataGroupHashes(sodInfo, dataGroups))
                throw new Exception("Datagrupp-hashes does not match EF.SOD");

            Log.Info("DH-hashes verified against SOD");
            return true;
        }

        public static X509Certificate2? FindCscaCert(string issuingCountry, List<X509Certificate2> masterList)
        {
            return masterList.FirstOrDefault(c =>
                c.Subject.Contains(issuingCountry, StringComparison.OrdinalIgnoreCase));
        }


        // Extracts DSC from SOD file to verify the signature
        public static X509Certificate2 ExtractDscFromSod(byte[] efSodBytes)
        {
            try
            {
                // Läs in CMS-data
                var cms = new CmsSignedData(efSodBytes);

                // Hämta certifikatstore
                var store = cms.GetCertificates();

                // Skapa en selector som matchar alla certifikat
                var selector = new X509CertStoreSelector();
                var bcCerts = store.EnumerateMatches(selector); // Nu returneras en ICollection

                foreach (var obj in bcCerts)
                {
                    var bcCert2 = obj as Org.BouncyCastle.X509.X509Certificate;
                    if (bcCert2 != null)
                    {
                        var rawData = bcCert2.GetEncoded();
                        var dscCert = new X509Certificate2(rawData);

                        Log.Info("Extracted DSC-certifikate from EF.SOD");
                        Log.Info($" Subject: {dscCert.Subject}");
                        Log.Info($" Issuer : {dscCert.Issuer}");
                        return dscCert;
                    }
                }

                Log.Info("ERROR: could not find DSC in EF.SOD");
                return null;
            }
            catch (Exception ex)
            {
                Log.Info("ERROR: Failed extraction of DSC: " + ex.Message);
                return null;
            }
        }



        public static bool VerifyCertChain(X509Certificate2 dsc, X509Certificate2 csca)
        {
            var chain = new X509Chain();
            chain.ChainPolicy.ExtraStore.Add(csca);
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;

            return chain.Build(dsc);
        }

        public static bool VerifySodSignature(byte[] efSodBytes, X509Certificate2 dscCert)
        {
            // TODO: ASN.1 parsing för att få:
            //   - signedAttributes (hashar för DGs)
            //   - signaturen
            //   - algoritm
            // Använd sedan dscCert.GetRSAPublicKey().VerifyData(...)


            var cms = new CmsSignedData(efSodBytes);
            var signerInfos = cms.GetSignerInfos();
            var signers = signerInfos.GetSigners();
            var parser = new X509CertificateParser();
            var bcCert = parser.ReadCertificate(dscCert.RawData);   


            foreach (SignerInformation signer in signers)
            {
                var pubKey = bcCert.GetPublicKey();
                if (signer.Verify(pubKey))
                {
                    Log.Info("EF.SOD info valid :)");
                    return true;
                }
            }

            Log.Info("EF.SOD info not valid :(");
            return false;
        }

        // optional, Verify data group hashes using parser
        public static bool VerifyDataGroupHashes(EFSodInfo sod, Dictionary<int, byte[]> dataGroups)
        {
            using var sha256 = SHA256.Create();

            foreach (var dgHashEntry in sod.DataGroupHashes)
            {
                int dgNum = dgHashEntry.DataGroupNumber;
                if (!dataGroups.TryGetValue(dgNum, out byte[] dgBytes))
                {
                    Log.Info("Warning :(");
                    return false;
                }

                byte[] hash = sha256.ComputeHash(dgBytes);

                if (!hash.SequenceEqual(dgHashEntry.HashValue))
                {
                    Log.Info("Warning 2 :(");
                    return false;
                }

                Log.Info($" DG{dgNum} hash matches EF.SOD");
            }

            return true;
        }


    }
}

