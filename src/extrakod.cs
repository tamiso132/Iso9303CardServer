/*

using System;
using System.Security.Cryptography;
using System.Security.Permissions;
using System.IO;
using System.Security.Cryptography.X509Certificates;


// Detta läser specifika cerifikat men inte hela .ml filen (Master list)

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.Text;

// To run this sample use the Certificate Creation Tool (Makecert.exe) to generate a test X.509 certificate and
// place it in the local user store.
// To generate an exchange key and make the key exportable run the following command from a Visual Studio command prompt:

//makecert -r -pe -n "CN=CERT_SIGN_TEST_CERT" -b 01/01/2010 -e 01/01/2012 -sky exchange -ss my
namespace X509CertEncrypt
{
    class Program
    {

        // Path variables for source, encryption, and
        // decryption folders. Must end with a backslash.
        private static string encrFolder = @"C:\Encrypt\";
        private static string decrFolder = @"C:\Decrypt\";
        private static string originalFile = "TestData.txt";
        private static string encryptedFile = "TestData.enc";

        static void Main(string[] args)
        {

            // Create an input file with test data.
            StreamWriter sw = File.CreateText(originalFile);
            sw.WriteLine("Test data to be encrypted");
            sw.Close();

            // Get the certificate to use to encrypt the key.
            X509Certificate2 cert = GetCertificateFromStore("CN=CERT_SIGN_TEST_CERT");
            if (cert == null)
            {
                Console.WriteLine("Certificate 'CN=CERT_SIGN_TEST_CERT' not found.");
                Console.ReadLine();
            }

            // Encrypt the file using the public key from the certificate.
            EncryptFile(originalFile, (RSA)cert.PublicKey.Key);

            // Decrypt the file using the private key from the certificate.
            DecryptFile(encryptedFile, cert.GetRSAPrivateKey());

            //Display the original data and the decrypted data.
            Console.WriteLine("Original:   {0}", File.ReadAllText(originalFile));
            Console.WriteLine("Round Trip: {0}", File.ReadAllText(decrFolder + originalFile));
            Console.WriteLine("Press the Enter key to exit.");
            Console.ReadLine();
        }
        private static X509Certificate2 GetCertificateFromStore(string certName)
        {

            // Get the certificate store for the current user.
            X509Store store = new X509Store(StoreLocation.CurrentUser);
            try
            {
                store.Open(OpenFlags.ReadOnly);

                // Place all certificates in an X509Certificate2Collection object.
                X509Certificate2Collection certCollection = store.Certificates;
                // If using a certificate with a trusted root you do not need to FindByTimeValid, instead:
                // currentCerts.Find(X509FindType.FindBySubjectDistinguishedName, certName, true);
                X509Certificate2Collection currentCerts = certCollection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);
                X509Certificate2Collection signingCert = currentCerts.Find(X509FindType.FindBySubjectDistinguishedName, certName, false);
                if (signingCert.Count == 0)
                    return null;
                // Return the first certificate in the collection, has the right name and is current.
                return signingCert[0];
            }
            finally
            {
                store.Close();
            }
        }

        // Encrypt a file using a public key.
        private static void EncryptFile(string inFile, RSA rsaPublicKey)
        {
            using (Aes aes = Aes.Create())
            {
                // Create instance of Aes for
                // symmetric encryption of the data.
                aes.KeySize = 256;
                aes.Mode = CipherMode.CBC;
                using (ICryptoTransform transform = aes.CreateEncryptor())
                {
                    RSAPKCS1KeyExchangeFormatter keyFormatter = new RSAPKCS1KeyExchangeFormatter(rsaPublicKey);
                    byte[] keyEncrypted = keyFormatter.CreateKeyExchange(aes.Key, aes.GetType());

                    // Create byte arrays to contain
                    // the length values of the key and IV.
                    byte[] LenK = new byte[4];
                    byte[] LenIV = new byte[4];

                    int lKey = keyEncrypted.Length;
                    LenK = BitConverter.GetBytes(lKey);
                    int lIV = aes.IV.Length;
                    LenIV = BitConverter.GetBytes(lIV);

                    // Write the following to the FileStream
                    // for the encrypted file (outFs):
                    // - length of the key
                    // - length of the IV
                    // - encrypted key
                    // - the IV
                    // - the encrypted cipher content

                    int startFileName = inFile.LastIndexOf("\\") + 1;
                    // Change the file's extension to ".enc"
                    string outFile = encrFolder + inFile.Substring(startFileName, inFile.LastIndexOf(".") - startFileName) + ".enc";
                    Directory.CreateDirectory(encrFolder);

                    using (FileStream outFs = new FileStream(outFile, FileMode.Create))
                    {

                        outFs.Write(LenK, 0, 4);
                        outFs.Write(LenIV, 0, 4);
                        outFs.Write(keyEncrypted, 0, lKey);
                        outFs.Write(aes.IV, 0, lIV);

                        // Now write the cipher text using
                        // a CryptoStream for encrypting.
                        using (CryptoStream outStreamEncrypted = new CryptoStream(outFs, transform, CryptoStreamMode.Write))
                        {

                            // By encrypting a chunk at
                            // a time, you can save memory
                            // and accommodate large files.
                            int count = 0;

                            // blockSizeBytes can be any arbitrary size.
                            int blockSizeBytes = aes.BlockSize / 8;
                            byte[] data = new byte[blockSizeBytes];
                            int bytesRead = 0;

                            using (FileStream inFs = new FileStream(inFile, FileMode.Open))
                            {
                                do
                                {
                                    count = inFs.Read(data, 0, blockSizeBytes);
                                    outStreamEncrypted.Write(data, 0, count);
                                    bytesRead += count;
                                }
                                while (count > 0);
                                inFs.Close();
                            }
                            outStreamEncrypted.FlushFinalBlock();
                            outStreamEncrypted.Close();
                        }
                        outFs.Close();
                    }
                }
            }
        }


        // Decrypt a file using a private key.
        private static void DecryptFile(string inFile, RSA rsaPrivateKey)
        {

            // Create instance of Aes for
            // symmetric decryption of the data.
            using (Aes aes = Aes.Create())
            {
                aes.KeySize = 256;
                aes.Mode = CipherMode.CBC;

                // Create byte arrays to get the length of
                // the encrypted key and IV.
                // These values were stored as 4 bytes each
                // at the beginning of the encrypted package.
                byte[] LenK = new byte[4];
                byte[] LenIV = new byte[4];

                // Construct the file name for the decrypted file.
                string outFile = decrFolder + inFile.Substring(0, inFile.LastIndexOf(".")) + ".txt";

                // Use FileStream objects to read the encrypted
                // file (inFs) and save the decrypted file (outFs).
                using (FileStream inFs = new FileStream(encrFolder + inFile, FileMode.Open))
                {

                    inFs.Seek(0, SeekOrigin.Begin);
                    inFs.Seek(0, SeekOrigin.Begin);
                    inFs.Read(LenK, 0, 3);
                    inFs.Seek(4, SeekOrigin.Begin);
                    inFs.Read(LenIV, 0, 3);

                    // Convert the lengths to integer values.
                    int lenK = BitConverter.ToInt32(LenK, 0);
                    int lenIV = BitConverter.ToInt32(LenIV, 0);

                    // Determine the start position of
                    // the cipher text (startC)
                    // and its length(lenC).
                    int startC = lenK + lenIV + 8;
                    int lenC = (int)inFs.Length - startC;

                    // Create the byte arrays for
                    // the encrypted Aes key,
                    // the IV, and the cipher text.
                    byte[] KeyEncrypted = new byte[lenK];
                    byte[] IV = new byte[lenIV];

                    // Extract the key and IV
                    // starting from index 8
                    // after the length values.
                    inFs.Seek(8, SeekOrigin.Begin);
                    inFs.Read(KeyEncrypted, 0, lenK);
                    inFs.Seek(8 + lenK, SeekOrigin.Begin);
                    inFs.Read(IV, 0, lenIV);
                    Directory.CreateDirectory(decrFolder);
                    // Use RSA
                    // to decrypt the Aes key.
                    byte[] KeyDecrypted = rsaPrivateKey.Decrypt(KeyEncrypted, RSAEncryptionPadding.Pkcs1);

                    // Decrypt the key.
                    using (ICryptoTransform transform = aes.CreateDecryptor(KeyDecrypted, IV))
                    {

                        // Decrypt the cipher text from
                        // from the FileSteam of the encrypted
                        // file (inFs) into the FileStream
                        // for the decrypted file (outFs).
                        using (FileStream outFs = new FileStream(outFile, FileMode.Create))
                        {

                            int count = 0;

                            int blockSizeBytes = aes.BlockSize / 8;
                            byte[] data = new byte[blockSizeBytes];

                            // By decrypting a chunk a time,
                            // you can save memory and
                            // accommodate large files.

                            // Start at the beginning
                            // of the cipher text.
                            inFs.Seek(startC, SeekOrigin.Begin);
                            using (CryptoStream outStreamDecrypted = new CryptoStream(outFs, transform, CryptoStreamMode.Write))
                            {
                                do
                                {
                                    count = inFs.Read(data, 0, blockSizeBytes);
                                    outStreamDecrypted.Write(data, 0, count);
                                }
                                while (count > 0);

                                outStreamDecrypted.FlushFinalBlock();
                                outStreamDecrypted.Close();
                            }
                            outFs.Close();
                        }
                        inFs.Close();
                    }
                }
            }
        }
    }
}

// För att ladda in masterfilen behövs något i stil med:

using System.Security.Cryptography.Pkcs;

// Ladda ML-filen
byte[] mlData = File.ReadAllBytes("ICAO_ml_July2025.ml");

// Parsar PKCS#7
SignedCms cms = new SignedCms();
cms.Decode(mlData);

// Här får du ut alla CSCA-certifikat
foreach (var cert in cms.Certificates)
{
    Console.WriteLine(cert.Subject);
}


// The following example creates a command-line executable that takes a certificate
// file as an argument and prints various certificate properties to the console.
class CertInfo
{
    //Reads a file.
    internal static byte[] ReadFile(string fileName)
    {
        FileStream f = new FileStream(fileName, FileMode.Open, FileAccess.Read);
        int size = (int)f.Length;
        byte[] data = new byte[size];
        size = f.Read(data, 0, size);
        f.Close();
        return data;
    }
    //Main method begins here.
    static void Main(string[] args)
    {
        //Test for correct number of arguments.
        if (args.Length < 1)
        {
            Console.WriteLine("Usage: CertInfo <filename>");
            return;
        }
        try
        {
            byte[] rawData = ReadFile(args[0]);
            //Create X509Certificate2 object from .cer file.
            X509Certificate2 x509 = new X509Certificate2(rawData);

            //Print to console information contained in the certificate.
            Console.WriteLine("{0}Subject: {1}{0}", Environment.NewLine, x509.Subject);
            Console.WriteLine("{0}Issuer: {1}{0}", Environment.NewLine, x509.Issuer);
            Console.WriteLine("{0}Version: {1}{0}", Environment.NewLine, x509.Version);
            Console.WriteLine("{0}Valid Date: {1}{0}", Environment.NewLine, x509.NotBefore);
            Console.WriteLine("{0}Expiry Date: {1}{0}", Environment.NewLine, x509.NotAfter);
            Console.WriteLine("{0}Thumbprint: {1}{0}", Environment.NewLine, x509.Thumbprint);
            Console.WriteLine("{0}Serial Number: {1}{0}", Environment.NewLine, x509.SerialNumber);
            Console.WriteLine("{0}Friendly Name: {1}{0}", Environment.NewLine, x509.PublicKey.Oid.FriendlyName);
            Console.WriteLine("{0}Public Key Format: {1}{0}", Environment.NewLine, x509.PublicKey.EncodedKeyValue.Format(true));
            Console.WriteLine("{0}Raw Data Length: {1}{0}", Environment.NewLine, x509.RawData.Length);
            Console.WriteLine("{0}Certificate to string: {1}{0}", Environment.NewLine, x509.ToString(true));
            Console.WriteLine("{0}Certificate to XML String: {1}{0}", Environment.NewLine, x509.PublicKey.Key.ToXmlString(false));

            //Add the certificate to a X509Store.
            X509Store store = new X509Store();
            store.Open(OpenFlags.MaxAllowed);
            store.Add(x509);
            store.Close();
        }
        catch (DirectoryNotFoundException)
        {
            Console.WriteLine("Error: The directory specified could not be found.");
        }
        catch (IOException)
        {
            Console.WriteLine("Error: A file in the directory could not be accessed.");
        }
        catch (NullReferenceException)
        {
            Console.WriteLine("File must be a .cer file. Program does not have access to that type of file.");
        }
    }
}

// För CRL filer kan vi använda Bouncycastle + att en parser behövs

using Org.BouncyCastle.X509;

// Läs CRL
var parser = new X509CrlParser();
var crl = parser.ReadCrl(File.ReadAllBytes("revocations.crl"));

// Lista spärrade certifikat
foreach (var entry in crl.GetRevokedCertificates())
{
    Console.WriteLine("Revoked serial: " + entry.SerialNumber);
}


*/

