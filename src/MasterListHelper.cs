using System;
using System.Collections.Generic;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Security;
using System.IO;

namespace EpassValidation
{
    public static class MasterListHelper
    {
        const string mlPath = "C:/Users/foffe/ICAO_ml_July2025.ml";

        /// <summary>
        /// Läser en ICAO Master List (.ml) och returnerar alla certifikat.
        /// </summary>
        public static List<X509Certificate2> ReadMasterList(string mlPath)
        {
            byte[] data = File.ReadAllBytes(mlPath);

            // SignedCms används eftersom ML är en PKCS#7-signerad container
            SignedCms cms = new SignedCms();
            cms.Decode(data);

            var certs = new List<X509Certificate2>();
            foreach (var cert in cms.Certificates)
            {
                certs.Add(cert);
            }

            return certs;
        }

        /// <summary>
        /// Läser en CRL (Certificate Revocation List) och returnerar alla spärrade serienummer.
        /// </summary>
        public static List<string> ReadCRL(string crlPath)
        {
            var crlBytes = File.ReadAllBytes(crlPath);
            var parser = new X509CrlParser();
            var crl = parser.ReadCrl(crlBytes);

            var revoked = new List<string>();
            foreach (X509CrlEntry entry in crl.GetRevokedCertificates())
            {
                revoked.Add(entry.SerialNumber.ToString(16));
            }

            return revoked;
        }

        /// <summary>
        /// Hjälpmetod för att skriva ut info om ett certifikat.
        /// </summary>
        public static void PrintCertInfo(X509Certificate2 cert)
        {
            Console.WriteLine("================================");
            Console.WriteLine($"Subject: {cert.Subject}");
            Console.WriteLine($"Issuer: {cert.Issuer}");
            Console.WriteLine($"Giltig från: {cert.NotBefore}");
            Console.WriteLine($"Giltig till: {cert.NotAfter}");
            Console.WriteLine($"Thumbprint: {cert.Thumbprint}");
            Console.WriteLine("================================");
        }
    }
}
