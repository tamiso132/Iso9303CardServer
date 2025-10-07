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
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Security;
using System.Runtime.ConstrainedExecution;

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
            var issuer = cert.Issuer ?? "";

            bool matchesState = !string.IsNullOrEmpty(dg12.IssuingState) && subject.Contains(dg12.IssuingState, StringComparison.OrdinalIgnoreCase);
            bool matchesAuthority = !string.IsNullOrEmpty(dg12.issuingAuthority) && subject.Contains(dg12.issuingAuthority, StringComparison.OrdinalIgnoreCase);

            bool validNow = DateTime.UtcNow >= cert.NotBefore && DateTime.UtcNow <= cert.NotAfter;

            if ((matchesState || matchesAuthority) && validNow)
            {
                relevant.Add(cert);
            } 
           
        }

        return relevant.Distinct().ToList();
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




