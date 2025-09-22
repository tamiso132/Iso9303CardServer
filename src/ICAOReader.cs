using System;
using System.IO;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.X509;

class ICAOReader
{
    // Läs ICAO Master List (.ml)
    public static void ReadMasterList(string filePath)
    {
        try
        {
            byte[] mlData = File.ReadAllBytes(filePath);

            // PKCS#7 (CMS) struktur
            SignedCms cms = new SignedCms();
            cms.Decode(mlData);

            Console.WriteLine($"=== ICAO Master List ===");
            Console.WriteLine($"Number of certificates: {cms.Certificates.Count}\n");

            foreach (var cert in cms.Certificates)
            {
                Console.WriteLine($"Country/Org: {cert.Subject}");
                Console.WriteLine($"Issued by: {cert.Issuer}");
                Console.WriteLine($"Validation: {cert.NotBefore} – {cert.NotAfter}");
                Console.WriteLine($"Thumbprint: {cert.Thumbprint}");
                Console.WriteLine("---------------------------------------------------");
            }
        } //
        catch (Exception ex)
        {
            Console.WriteLine($"Fel vid läsning av ML: {ex.Message}"); //ex.message?
        }
    }

    // read CRL file (.crl) using BouncyCastle
    public static void ReadCRL(string filePath)
    {
        try
        {
            var parser = new X509CrlParser();
            var crl = parser.ReadCrl(File.ReadAllBytes(filePath));

            Console.WriteLine("=== Certificate Revocation List (CRL) ===");
            Console.WriteLine($"Issued by: {crl.IssuerDN}");
            Console.WriteLine($"Next update: {crl.NextUpdate}");
            Console.WriteLine($"Number of revoked certificates: {crl.GetRevokedCertificates().Count}\n");

            foreach (var entry in crl.GetRevokedCertificates())
            {
                Console.WriteLine($"Revoked certificate: {entry.SerialNumber}");
                Console.WriteLine($"Revoked on: {entry.RevocationDate}");
                Console.WriteLine("---------------------------------------------------");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}"); // What error?
        }
    }
}
