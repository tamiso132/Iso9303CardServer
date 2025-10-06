
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


// Trivialt test, får antagligen modda lite/ ändra implementeringar

namespace EPassAuth
{
    public static class PassiveAuthentication
    {
        /// <summary>
        /// Kör hela passive authentication-flödet:
        /// 1. Hitta CSCA från masterlist baserat på DG12
        /// 2. Extrahera DSC från EF.SOD
        /// 3. Verifiera kedja (DSC -> CSCA)
        /// 4. Verifiera EF.SOD signatur
        /// 5. Verifiera hashvärden för alla DGs
        /// </summary>
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

            // 2. Extrahera DSC från EF.SOD (ASN.1 parsing krävs här – stub)
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
            if (!VerifyDataGroupHashes(efSodBytes, dataGroups))
                throw new Exception("Datagrupp-hashar matchar inte EF.SOD");

            Log.Info("[INFO] DH-hashar verifierade mot SOD");
            return true;
        }

        public static X509Certificate2? FindCscaCert(string issuingCountry, List<X509Certificate2> masterList)
        {
            return masterList.FirstOrDefault(c =>
                c.Subject.Contains(issuingCountry, StringComparison.OrdinalIgnoreCase));
        }

        public static X509Certificate2 ExtractDscFromSod(byte[] efSodBytes)
        {
            var cms = new CmsSignedData(efSodBytes);
            var certStore = cms.GetCertificates();
            var certs = certStore.Equals(null);
            
             
            foreach (X509Certificate2 cert in certs)
            {
                return new X509Certificate2(certStore.Equals());
            }
            return null;
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

            foreach (SignerInformation signer in signers)
            {
                var verifier = new JcaSimpleSignerInfoVerifierBuilder().Build(dscCert);
                if (signer.Verify(verifier))
                {
                    Log.Info("EF.SOD signature is valid");
                    
                    return true;
                }

            }
            Log.Info("EF.SOD signature not valid :(");
            return false;
        }

        private static bool VerifyDataGroupHashes(byte[] efSodBytes, Dictionary<int, byte[]> dataGroups)
        {
            // TODO: ASN.1 parsing av EF.SOD för att hämta lagrade DG-hashar
            // Jämför sedan med SHA256/SHA1 på dina faktiska DG bytes
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

