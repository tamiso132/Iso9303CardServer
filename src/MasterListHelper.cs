using System;
using System.Collections.Generic;
using System.IO;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.X509;

namespace EpassValidation
{
    public static class MasterListHelper
    {
        public static List<Org.BouncyCastle.X509.X509Certificate> ReadAllCertificatesFromMl(string mlPath)
        {
            byte[] mlBytes = File.ReadAllBytes(mlPath);

            // Parse top-level ASN.1
            Asn1Object top = Asn1Object.FromByteArray(mlBytes);
            ContentInfo ci = ContentInfo.GetInstance(top);
            SignedData sd = SignedData.GetInstance(ci.Content);

            Asn1Set certSet = sd.Certificates;
            var parser = new X509CertificateParser();
            var all = new List<Org.BouncyCastle.X509.X509Certificate>();

            if (certSet == null)
                return all;

            foreach (Asn1Encodable enc in certSet)
            {
                var obj = enc.ToAsn1Object();
                Console.WriteLine($"ASN.1 type: {obj.GetType().Name}");

                if (obj is Asn1TaggedObject tagged)
                {
                    obj = tagged.GetObject().ToAsn1Object();
                    Console.WriteLine("  Unwrapped tagged object -> " + obj.GetType().Name);
                }

                try
                {
                    var cert = parser.ReadCertificate(obj.GetEncoded());
                    if (cert != null)
                    {
                        Console.WriteLine("  ✅ Parsed certificate: " + cert.SubjectDN);
                        all.Add(cert);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("  ⚠️ Could not parse: " + ex.Message);
                }
            }


            return all;
        }

        public static void PrintBcCerts(IEnumerable<Org.BouncyCastle.X509.X509Certificate> certs)
        {
            int i = 1;
            foreach (var cert in certs)
            {
                Console.WriteLine($"=== Cert #{i++} ===");
                Console.WriteLine($"Subject: {cert.SubjectDN}");
                Console.WriteLine($"Issuer:  {cert.IssuerDN}");
                Console.WriteLine($"Valid:   {cert.NotBefore} – {cert.NotAfter}");
                Console.WriteLine($"Serial:  {cert.SerialNumber}");
                Console.WriteLine();
            }
        }
    }
}
