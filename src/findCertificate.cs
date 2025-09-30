using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Helper;
using Parser;
using System.Security.Cryptography.X509Certificates;
using static Parser.TLVParser;
using Microsoft.VisualBasic;

namespace CertificateTools;

// 1. Verify Issuer
// 2. Verify Issuing date
// 3. Check keyUsage, BasicConstrains, policydemands
// 4. Check Revocation List 
// 5. Demand that root(or somewhere in the chain) matches a CSCA from ML

public static class CertificateFinder
{

    public static List<X509Certificate2> FindRelevantCertificates(
        Dg12Info dg12, List<X509Certificate2> masterlist)
    {
        var relevant = new List<X509Certificate2>();

        foreach (var cert in masterlist)
        {
            var subject = cert.Subject ?? "";
            if (!string.IsNullOrEmpty(dg12.IssuingState) && subject.Contains(dg12.IssuingState, StringComparison.OrdinalIgnoreCase))
            {
                relevant.Add(cert);
            }

            if (!string.IsNullOrEmpty(dg12.issuingAuthority) && subject.Contains(dg12.issuingAuthority, StringComparison.OrdinalIgnoreCase))
            {
                relevant.Add(cert);
                continue;

            }
        }

        return relevant.Distinct().ToList();
    }
}





// public class CertificateFinder
// {
//     private readonly string _certFolder;

//     public CertificateFinder(string certFolder)
//     {
//         _certFolder = certFolder;
//     }

//     public X509Certificate2? FindByDG12(DG12 dg12Info)
//     {
//         string issuingCountry = dg12Info.issuingCountry;
//         string issuingAuthority = dg12Info.issuingAuthority;

//         foreach (var certFile in Directory.GetFiles(_certFolder, "*.pem"))
//         {
//             var pem = File.ReadAllText(certFile);
//             var cert = PemToX509(pem);

//             if (cert == null) continue;

//             if (cert.Issuer.Contains(issuingCountry, StringComparison.OrdinalIgnoreCase) ||
//                cert.Issuer.Contains(issuingAuthority, StringComparison.OrdinalIgnoreCase))
//             {
//                 return cert;
//             }

//         }

//         return null;
//     }

//     private X509Certificate2? PemToX509(string pemString)
//     {
//         try
//         {
//             var header = "-----BEGIN CERTIFICATE-----";
//             var footer = "-----END CERTIFICATE-----";

//             int start = pemString.IndexOf(header, StringComparison.Ordinal);
//             int end = pemString.IndexOf(footer, StringComparison.Ordinal);

//             if (start < 0 || end < 0)
//                 throw new Exception("PEM Format error: missing header or fotter");

//             string base64 = pemString.Substring(start + header.Length, end - (start + header.Length));

//             base64 = base64.Replace("\r", "").Replace("\n", "").Trim();

//             byte[] rawData = Convert.FromBase64String(base64);
//             return new X509Certificate2(rawData);


//         }
//         catch (Exception ex)
//         {
//             Log.Info("PEM parse error" + ex.Message);
//             return null;
//         }

//     }
// }