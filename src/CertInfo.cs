using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

// In order to read and write from a specific cerificate
class CertInfo
{
    // Reads a file into byte array
    internal static byte[] ReadFile(string fileName)
    {
        FileStream f = new FileStream(fileName, FileMode.Open, FileAccess.Read);
        int size = (int)f.Length;
        byte[] data = new byte[size];
        size = f.Read(data, 0, size);
        f.Close();
        return data;
    }

    // Show certificate info
    public static void ShowCertificateInfo(string filePath)
    {

        if (filePath.Length < 1)
        {
            Console.WriteLine("Usage: CertInfo <filename>");
            return;
        }
        try
        {
            byte[] rawData = ReadFile(filePath);
            X509Certificate2 x509 = new X509Certificate2(rawData);

            // TODO Skriva allt i konselen??????
            Console.WriteLine("=== Certifikat-info ===");
            Console.WriteLine($"Subject: {x509.Subject}");
            Console.WriteLine($"Issuer: {x509.Issuer}");
            Console.WriteLine($"Version: {x509.Version}");
            Console.WriteLine($"Valid Date: {x509.NotBefore}");
            Console.WriteLine($"Expiry Date: {x509.NotAfter}");
            Console.WriteLine($"Thumbprint: {x509.Thumbprint}");
            Console.WriteLine($"Serial Number: {x509.SerialNumber}");
            Console.WriteLine($"Public Key Format: {x509.PublicKey.Oid.FriendlyName}");
            Console.WriteLine($"Raw Data Length: {x509.RawData.Length}");

            //Samma?
            Console.WriteLine("{0}Certificate to string: {1}{0}", Environment.NewLine, x509.ToString(true));
            Console.WriteLine("{0}Certificate to XML String: {1}{0}", Environment.NewLine, x509.PublicKey.Key.ToXmlString(false));
            //Samma?
            Console.WriteLine($"ToString: {x509.ToString(true)}");
            Console.WriteLine("========================\n");

            X509Store store = new X509Store();
            store.Open(OpenFlags.MaxAllowed);
            store.Add(x509);
            store.Close();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Fel vid läsning av certifikat: {ex.Message}");
        }
    }
}
