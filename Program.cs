using WebSocketSharp;
using WebSocketSharp.Server;
using App;
using Server;
using System.Collections.Concurrent;
using EpassValidation;
using System.Collections;
using System.Security.Cryptography.X509Certificates;
using Helper;

// Load the ML file (DER encoded)
byte[] mlBytes = File.ReadAllBytes("masterlist-cscas/C=AT,O=GV,OU=BMI,CN=CSCA-AUSTRIA56.pem");


// Step 1: unwrap CMS chain
var cmsChain = new System.Collections.Generic.List<byte[]>();
byte[] currentBytes = mlBytes;

var cert = X509CertificateLoader.LoadCertificate(currentBytes);
Log.Info(cert.IssuerName.Name);




// // Parse CMS SignedData
// CmsSignedData cms = new CmsSignedData(mlBytes);

// cms.GetAttributeCertificates();

// // Extract certificates
// var certStore = cms.GetCertificates();
// foreach (var cert in certStore.EnumerateMatches(selector: (ISelector<X509Certificate>)new Select()))
// {
//     Console.WriteLine("Issuer: " + cert.IssuerDN);
//     Console.WriteLine("Subject: " + cert.SubjectDN);
//     Console.WriteLine("Valid from: " + cert.NotBefore + " to " + cert.NotAfter);
//     Console.WriteLine();
// }
// // Low-level ASN.1 parse of ContentInfo -> SignedData -> certificates
// try
// {
//     var parser = new X509CertificateParser();
//     Asn1Object top = Asn1Object.FromByteArray(mlBytes);
//     ContentInfo ci = ContentInfo.GetInstance(top);
//     SignedData sd = SignedData.GetInstance(ci.Content);
//     Asn1Set certSet = sd.Certificates;

//     var all = new List<Org.BouncyCastle.X509.X509Certificate>();
//     if (certSet != null)
//     {
//         foreach (Asn1Encodable enc in certSet)
//         {
//             Asn1Object obj = enc.ToAsn1Object();

//             // Unwrap tagged CertificateChoices if present
//             if (obj is Asn1TaggedObject tagged)
//                 obj = tagged.GetObject().ToAsn1Object();

//             try
//             {
//                 byte[] der = obj.GetEncoded();
//                 var bcCert = parser.ReadCertificate(der);
//                 if (bcCert != null)
//                     all.Add(bcCert);
//             }
//             catch
//             {
//                 // ignore non-X509/corrupt entries
//             }
//         }
//     }

//     Console.WriteLine($"Low-level parsed count: {all.Count}");
//     foreach (var c in all)
//         Console.WriteLine("Subject: " + c.SubjectDN);
// }
// catch (Exception ex)
// {
//     Console.WriteLine("Low-level parse failed: " + ex.Message);
// }


/*
var config = File.ReadAllLines("config.txt");
string? ip = null;
string? port = null;

foreach (var line in config)
{
    var parts = line.Split('=', 2);
    if (parts.Length != 2) continue;

    var key = parts[0].Trim();
    var value = parts[1].Trim();

    if (key.Equals("IP", StringComparison.OrdinalIgnoreCase))
        ip = value;
    else if (key.Equals("Port", StringComparison.OrdinalIgnoreCase))
        port = value;
}

if (ip == null || port == null)
{
    Console.WriteLine("IP or Port not found in config.");
    return;
}

var wssv = new WebSocketServer($"ws://{ip}:{port}");

wssv.AddWebSocketService<WsSession>("/");

wssv.Start();
Console.WriteLine("WebSocket server started, waiting for connections...");
bool isQuit = false;


while (!isQuit)
{
    if (Console.KeyAvailable)
    {
        isQuit = Console.ReadKey(true).Key == ConsoleKey.Escape;
    }

    await WsSession.AwaitAll();
}
wssv.Stop();


public class WsSession : WebSocketBehavior
{
    protected override void OnOpen()
    {
        Console.WriteLine("Client connected");
        var app = new ClientSession(new WebSocketTransport(Context.WebSocket));
        string id = Guid.NewGuid().ToString();

        clients[id] = app;
        _running[id] = app.Start();

    }

    protected override void OnMessage(MessageEventArgs e)
    {
        // Console.WriteLine("Message from client: " + e.Data);
    }

    protected override void OnClose(CloseEventArgs e)
    {
        Console.WriteLine("Client disconnected");
    }

    /*Should only be used in debug*/ /*
    public static async Task AwaitAll()
    {
        foreach (var kvp in _running.ToArray()) // snapshot
        {
            await kvp.Value;
            _running.TryRemove(kvp.Key, out _);
            clients.TryRemove(kvp.Key, out _);
        }
    }

    private static readonly ConcurrentDictionary<string, ClientSession> clients = new();
    private static readonly ConcurrentDictionary<string, Task> _running = new();
}
*/
// Reading lists 
// Maybe baby:


// string mlPath = "C:/Users/foffe/ICAO_ml_July2025.ml";

// try
// {
//     var allCerts = MasterListHelper.ReadAllCerificates(mlPath);
//     Console.WriteLine($"Totalt antal certifikat i Master List: {allCerts.Count}\n");

//     MasterListHelper.PrintCertificates(allCerts);
// }
// catch (Exception ex)
// {
//     Console.WriteLine("Fel vid läsning av Master List:");
//     Console.WriteLine(ex.Message);
// }




