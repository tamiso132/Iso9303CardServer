// --- 2. Dataklasser (Från min tidigare kod) ---

using Helper;

public class DataGroupHash
{
    public int DataGroupNumber { get; set; }
    public byte[] Hash { get; set; }
    public override string ToString() => $"DG{DataGroupNumber}: {BitConverter.ToString(Hash).Replace("-", "")}";
}

public class SodContent
{
    public string HashAlgorithmOid { get; set; }
    public List<DataGroupHash> DataGroupHashes { get; set; } = new List<DataGroupHash>();
    public byte[] DocumentSignerCertificate { get; set; }
    public byte[] Signature { get; set; }

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
    /// Privat hjälpfunktion: Konverterar en hex-sträng till en byte array.
    /// </summary>
    private static byte[] ConvertHexStringToByteArray(string hexString)
    {
        string cleanHex = hexString.Replace("-", "").Replace(" ", "").Replace("\n", "").Replace("\r", "");
        if (cleanHex.Length % 2 != 0)
        {
            throw new ArgumentException("Hex-strängen har ett udda antal tecken.");
        }

        byte[] data = new byte[cleanHex.Length / 2];
        for (int i = 0; i < data.Length; i++)
        {
            string byteValue = cleanHex.Substring(i * 2, 2);
            data[i] = Convert.ToByte(byteValue, 16);
        }
        return data;
    }

    /// <summary>
    /// Huvudingångspunkt för att parsa en EF.SOD hex-sträng.
    /// </summary>
    public static SodContent ParseFromHexString(byte[] hexString)
    {
        var content = new SodContent();
        byte[] rawData = hexString;

        // 1. Bygg det primära T(L)V-trädet
        // Din TagReader kommer att hantera 0x77-taggen automatiskt om den finns,
        // eftersom vi la till 0x77 i sequenceTags.
        var rootTags = TagReader.ReadTagData(rawData, sequenceTags);

        // 2. Starta navigationen
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
        var certsWrapper = signedDataChildren.FilterByTag(0xA1).FirstOrDefault();
        var dsCert = certsWrapper?.Children.FilterByTag(0x30).FirstOrDefault(); // Det första (och enda) certifikatet
        if (dsCert != null)
        {
            // Använd din GetHeaderFormat för att återskapa hela certifikatets DER-data
            content.DocumentSignerCertificate = dsCert.GetHeaderFormat();
        }

        // 6. Hämta Signatur (sista 0x31 SET)
        var signerInfosSet = signedDataChildren.FilterByTag(0x31).LastOrDefault();
        var signerInfoSeq = signerInfosSet?.Children.FilterByTag(0x30).FirstOrDefault();
        if (signerInfoSeq != null)
        {
            // Signaturen är en 0x03 BIT STRING
            var sigBitString = signerInfoSeq.Children.FilterByTag(0x03).FirstOrDefault();
            if (sigBitString != null && sigBitString.Data.Length > 0)
            {
                // Första byten i en BIT STRING är "unused bits", hoppa över den
                content.Signature = sigBitString.Data.Skip(1).ToArray();
            }
        }

        // 7. Hämta DG Hashes (från EncapContentInfo, den första 0x30-sekvensen)
        var encapContentInfo = signedDataChildren.FilterByTag(0x30).FirstOrDefault();
        // [0xA0] eContent -> [0x04] OCTET STRING
        var eContentOctetString = encapContentInfo?.Children.FilterByTag(0xA0).FirstOrDefault()?.Children.FilterByTag(0x04).FirstOrDefault();
        if (eContentOctetString == null)
        {
            throw new InvalidOperationException("Hittade inte eContent [0xA0] -> [0x04] (LDSSecurityObject).");
        }

        // --- VIKTIGT STEG ---
        // Datan *inuti* denna OCTET STRING är en ny TLV-struktur.
        // Vi måste anropa din TagReader *igen* på den datan.
        var ldsRootTags = TagReader.ReadTagData(eContentOctetString.Data, sequenceTags);

        var ldsSeq = ldsRootTags.FilterByTag(0x30).FirstOrDefault();
        // Hitta DataGroupHashes (den *andra* 0x30-sekvensen inuti LDSSecurityObject)
        var dataGroupHashesSeq = ldsSeq?.Children.FilterByTag(0x30).LastOrDefault();

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