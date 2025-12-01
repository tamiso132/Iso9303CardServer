using Helper;
using Org.BouncyCastle.Utilities;

// TODO remove entire file?
public class DataGroupHash
{
    public int DataGroupNumber { get; set; }
    public byte[] Hash { get; set; }
    public override string ToString() => $"DG{DataGroupNumber}: {BitConverter.ToString(Hash).Replace("-", "")}";
}

public class SodContent
{
    /// <summary>
    /// OID-strängen som berättar vilken algoritm
    /// som ska användas för att hasha EncapsulatedContentBytes.
    /// </summary>
    public string HashAlgorithmOid { get; set; }

    /// <summary>
    /// Den parsade listan av hash-värden för varje Data Group (DG1, DG2, etc.) som finns i ldsSecurityObject.
    /// Dessa jämförs mot de faktiska hasharna av filerna vi läser från chippet för att garantera att datan är äkta.
    /// </summary>
    public List<DataGroupHash> DataGroupHashes { get; set; } = new List<DataGroupHash>();

    /// <summary>
    /// Document Signer (DS)-certifikatet (X.509) som hittades i SOD-filen.
    /// Från detta extraherar vi den Publika Nyckeln (Public Key) som krävs för att verifiera Signaturen.
    /// Detta certifikat måste i sin tur valideras mot landets CSCA (Master List).
    /// </summary>
    public byte[] DocumentSignerCertificate { get; set; }

    /// <summary>
    /// Den kryptografiska signaturen (bytes) extraherad från SignerInfo.
    /// Detta är resultatet av att utfärdaren signerade 'SignedAttributesBytes' med sin privata nyckel.
    /// </summary>
    public byte[] Signature { get; set; }

    // NEW REQUIRED FIELDS FOR VERIFICATION
    /// <summary>
    /// Rådatan (bytes) för hela ldsSecurityObject (eContent).
    /// VERIFIERING STEG 1: Du måste hasha denna blob (med HashAlgorithmOid) och jämföra resultatet 
    /// med hash-värdet som ligger inbäddat i 'SignedAttributesBytes' (under attributet MessageDigest).
    /// </summary>
    public byte[] EncapsulatedContentBytes { get; set; }

    /// <summary>
    /// Rådatan (bytes) för SignedAttributes-strukturen (inklusive Tag 0xA0 och Length).
    /// VERIFIERING STEG 2: Signaturen ovan är skapad över just denna blob.
    /// OBS: Innan du skickar denna till en 'Verify'-funktion måste du ofta byta 
    /// den första byten (Tag) från 0xA0 (Context Specific) till 0x31 (SET OF).
    /// </summary>
    public byte[] SignedAttributesBytes { get; set; }

    public override string ToString()
    {
        string hashes = string.Join("\n  ", DataGroupHashes.Select(h => h.ToString()));
        return $"HashAlg. OID: {HashAlgorithmOid}\n" +
               $"DG Hashes:\n  {hashes}\n" +
               $"DS Cert. Length: {DocumentSignerCertificate?.Length ?? 0} bytes\n" +
               $"Signature Length: {Signature?.Length ?? 0} bytes";
    }
}

// --- 3. NY Parser-logik (Byggd på din TagReader) ---

public static class EfSodParser
{
    // Taggar som vi vet innehåller andra taggar och ska parsas rekursivt
    private static readonly HashSet<int> sequenceTags = new HashSet<int>
    {
        0x30, // SEQUENCE
        0x31, // SET OF
        0xA0, // [0] CONSTRUCTED (SignedData, eContent)
        0xA1, // [1] CONSTRUCTED (Certificates)
        0x77  // [Application 23] Wrapper
    };

  

    /// <summary>
    /// Huvudingångspunkt för att parsa en EF.SOD hex-sträng.
    /// </summary>
    public static SodContent ParseFromHexString(byte[] hexString)
    {
        var content = new SodContent();
        byte[] rawData = hexString;

        var rootTags = TagReader.ReadTagData(rawData, sequenceTags);

        // Hitta ContentInfo (0x30), som antingen är root eller barn till 0x77
        var contentInfo = rootTags.FilterByTag(0x30).FirstOrDefault();
        if (contentInfo == null)
        {
            contentInfo = rootTags.FilterByTag(0x77).FirstOrDefault()?.Children.FilterByTag(0x30).FirstOrDefault();
        }
        if (contentInfo == null) throw new InvalidOperationException("Hittade inte root 0x30 (ContentInfo) eller 0x77 wrapper.");

        // 3. Hitta SignedData ([0] -> [0x30])
        var signedData = contentInfo.Children.FilterByTag(0xA0).FirstOrDefault();
        var signedDataSeq = signedData?.Children.FilterByTag(0x30).FirstOrDefault();
        if (signedDataSeq == null) throw new InvalidOperationException("Hittade inte 0xA0 -> 0x30 (SignedData SEQUENCE).");

        var signedDataChildren = signedDataSeq.Children;

        // 4. Hämta DigestAlgorithm (första 0x31 SET)
        var digestAlgsSet = signedDataChildren.FilterByTag(0x31).FirstOrDefault();
        var algOid = digestAlgsSet?.Children.FilterByTag(0x30).FirstOrDefault()?.Children.FilterByTag(0x06).FirstOrDefault();
        if (algOid != null)
        {
            content.HashAlgorithmOid = BitConverter.ToString(algOid.Data).Replace("-", ".");
        }


        // 5. Hämta Certifikat ([1] 0xA1)
        var certsWrapper = signedDataChildren.FilterByTag(0xA0).FirstOrDefault();
        var dsCert = certsWrapper?.Children.FilterByTag(0x30).FirstOrDefault(); // Det första (och enda) certifikatet
        if (dsCert != null)
        {
            content.DocumentSignerCertificate = dsCert.GetHeaderFormat();
        }

        // 6. Hämta Signatur (sista 0x31 SET)
        var signerInfosSet = signedDataChildren.FilterByTag(0x31).LastOrDefault();
        var signerInfoSeq = signerInfosSet?.Children.FilterByTag(0x30).FirstOrDefault();

        if (signerInfoSeq != null)
        {
            // 1. Leta först efter OCTET STRING (0x04) - Detta är standard för Pass (RSA/ECDSA)
            var sigOctetString = signerInfoSeq.Children.FilterByTag(0x04).FirstOrDefault();

            if (sigOctetString != null && sigOctetString.Data.Length > 0)
            {
                content.Signature = sigOctetString.Data;
            }
            else
            {
                // 2. Fallback: Leta efter BIT STRING (0x03)
                var sigBitString = signerInfoSeq.Children.FilterByTag(0x03).FirstOrDefault();
                if (sigBitString != null && sigBitString.Data.Length > 0)
                {
                    // För BIT STRING är första byten "unused bits". Hoppa över den.
                    content.Signature = sigBitString.Data.Skip(1).ToArray();
                }
            }

            var signedAttrsTag = signerInfoSeq.Children.FilterByTag(0xA0).FirstOrDefault();
            if (signedAttrsTag != null)
                content.SignedAttributesBytes = signedAttrsTag.GetHeaderFormat();
        }


        // 7. Hämta DG Hashes (från EncapContentInfo, den första 0x30-sekvensen)
        var encapContentInfo = signedDataChildren.FilterByTag(0x30).FirstOrDefault();
        // [0xA0] eContent -> [0x04] OCTET STRING
        var eContentOctetString = encapContentInfo?.Children.FilterByTag(0xA0).FirstOrDefault()?.Children.FilterByTag(0x04).FirstOrDefault();
        if (eContentOctetString == null)
        {
            throw new InvalidOperationException("Hittade inte eContent [0xA0] -> [0x04] (LDSSecurityObject).");
        }

        content.EncapsulatedContentBytes = eContentOctetString.Data;

        var ldsRootTags = TagReader.ReadTagData(eContentOctetString.Data, sequenceTags);

        var ldsSeq = ldsRootTags.FilterByTag(0x30).FirstOrDefault();
        // Hitta DataGroupHashes (den *andra* 0x30-sekvensen inuti LDSSecurityObject)
        var dataGroupHashesSeq = ldsSeq?.Children.FilterByTag(0x30).Skip(1).FirstOrDefault();

        if (dataGroupHashesSeq != null)
        {
            // Loopa igenom varje DG-hash (som alla är 0x30-sekvenser)
            foreach (var dgHashSeq in dataGroupHashesSeq.Children.FilterByTag(0x30))
            {
                var dgNumTag = dgHashSeq.Children.FilterByTag(0x02).FirstOrDefault(); // 0x02 INTEGER
                var dgHashTag = dgHashSeq.Children.FilterByTag(0x04).FirstOrDefault(); // 0x04 OCTET STRING

                if (dgNumTag != null && dgHashTag != null)
                {
                    // Konvertera DG-numret (INTEGER) från big-endian bytes
                    int dgNumber = 0;
                    
                    for (int j = 0; j < dgNumTag.Data.Length; j++)
                    {
                        dgNumber = (dgNumber << 8) | dgNumTag.Data[j];
                    }

                    content.DataGroupHashes.Add(new DataGroupHash
                    {
                        DataGroupNumber = dgNumber,
                        Hash = dgHashTag.Data
                    });
                }
            }
        }



        return content;
    }
}