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






