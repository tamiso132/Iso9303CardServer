using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

// In order to read and write from a specific cerificate
public class CertInfo
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

       X509Store store = new X509Store("MY",StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

        X509Certificate2Collection collection = (X509Certificate2Collection)store.Certificates;
        X509Certificate2Collection fcollection = (X509Certificate2Collection)collection.Find(X509FindType.FindByTimeValid,DateTime.Now,false);
      //  X509Certificate2Collection scollection = X509Certificate2UI.SelectFromCollection(fcollection, "Test Certificate Select","Select a certificate from the following list to get information on that certificate",X509SelectionFlag.MultiSelection);
        Console.WriteLine("Number of certificates: {0}{1}",fcollection.Count,Environment.NewLine);

       foreach (X509Certificate2 x509 in fcollection)
        {
            try
            {
                byte[] rawdata = x509.RawData;
            //     Console.WriteLine("Content Type: {0}{1}",X509Certificate2.GetCertContentType(rawdata),Environment.NewLine);
            //     Console.WriteLine("Friendly Name: {0}{1}",x509.FriendlyName,Environment.NewLine);
            //     Console.WriteLine("Certificate Verified?: {0}{1}",x509.Verify(),Environment.NewLine);
            //     Console.WriteLine("Simple Name: {0}{1}",x509.GetNameInfo(X509NameType.SimpleName,true),Environment.NewLine);
            //     Console.WriteLine("Signature Algorithm: {0}{1}",x509.SignatureAlgorithm.FriendlyName,Environment.NewLine);
            //     Console.WriteLine("Public Key: {0}{1}",x509.PublicKey.Key.ToXmlString(false),Environment.NewLine);
            //     Console.WriteLine("Certificate Archived?: {0}{1}",x509.Archived,Environment.NewLine);
            //     Console.WriteLine("Length of Raw Data: {0}{1}",x509.RawData.Length,Environment.NewLine);
            //     X509Certificate2UI.DisplayCertificate(x509);
            //     x509.Reset();
             }
            catch (CryptographicException)
            {
                Console.WriteLine("Information could not be written out for this certificate.");
            }
        }
        store.Close();
    }
}

