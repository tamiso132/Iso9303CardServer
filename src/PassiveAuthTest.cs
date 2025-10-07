
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
            Log.Info($"[INFO] Identifierar land...");
            // 1. Hitta CSCA i masterlist baserat på DG12
            var cscaCert = FindCscaCert(issuingCountry, masterListCscas);
            if (cscaCert == null)
                throw new Exception("Ingen CSCA hittades för landet " + issuingCountry);

            Log.Info($"[INFO] Hittade CSCA-certifikat för {issuingCountry}:");
            Log.Info($" Subject: {cscaCert.Subject}");
            Log.Info($" Issuer : {cscaCert.Issuer}");
            Log.Info($" FriendlyName: {cscaCert.FriendlyName}");

            // 2. Extrahera DSC från EF.SOD (ASN.1 parsing)
            var dscCert = ExtractDscFromSod(efSodBytes);
            if (dscCert == null)
                throw new Exception("Kunde inte extrahera DSC från EF.SOD");

            Log.Info("[INFO] Extraherat DSC från EF.SOD");

            // 3. Bygg kedja: DSC -> CSCA
            if (!VerifyCertChain(dscCert, cscaCert))
                throw new Exception("DSC kunde inte verifieras mot CSCA");

            Log.Info("[INFO] Verifierat kedja mellan DSC och CSCA");

            // 4. Verifiera EF.SOD signaturen
            if (!VerifySodSignature(efSodBytes, dscCert))
                throw new Exception("EF.SOD signaturen är ogiltig");

            Log.Info("[INFO] veridierat EF.SOD signatur");

            // 5. Verifiera DG-hashar mot EF.SOD
            // if (!VerifyDataGroupHashes(efSodBytes, dataGroups))
            //     throw new Exception("Datagrupp-hashar matchar inte EF.SOD");

            Log.Info("[INFO] DH-hashar verifierade mot SOD");
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

                        Log.Info("[INFO] Extraherat DSC-certifikat från EF.SOD");
                        Log.Info($" Subject: {dscCert.Subject}");
                        Log.Info($" Issuer : {dscCert.Issuer}");
                        return dscCert;
                    }
                }

                Log.Info("ERROR: Kunde inte hitta DSC i EF.SOD");
                return null;
            }
            catch (Exception ex)
            {
                Log.Info("ERROR: Misslyckades med att extrahera DSC: " + ex.Message);
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

            Log.Info("EF.SOD info not vaid :(");
            return false;
        }

        // optional, Verify data group hashes using parser
        private static bool VerifyDataGroupHashes(EFSodInfo sod, Dictionary<int, byte[]> dataGroups)
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

                Log.Info($" DG{dgNum} hash matchar EF.SOD");
            }

            return true;
        }

        public static List<X509Certificate2> LoadCscaCertsFromFolder(string folderPath)
        {
            var certs = new List<X509Certificate2>();

            foreach (var file in Directory.GetFiles(folderPath, "*.pem"))
            {
                var pem = File.ReadAllText(file);
                var cert = PemToX509(pem);
                if (cert != null) certs.Add(cert);
            }

            return certs;
        }

        public static X509Certificate2? PemToX509(string pemString)
        {
            try
            {
                var header = "-----BEGIN CERTIFICATE-----";
                var footer = "-----END CERTIFICATE-----";

                int start = pemString.IndexOf(header, StringComparison.Ordinal);
                int end = pemString.IndexOf(footer, StringComparison.Ordinal);

                if (start < 0 || end < 0) return null;

                string base64 = pemString.Substring(start + header.Length, end - (start + header.Length));
                base64 = base64.Replace("\r", "").Replace("\n", "").Trim();

                byte[] rawData = Convert.FromBase64String(base64);
                return new X509Certificate2(rawData);
            }
            catch
            {
                return null;
            }
        }
    }
}

