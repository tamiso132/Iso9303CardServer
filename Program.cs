using WebSocketSharp;
using WebSocketSharp.Server;
using App;
using Server;
using System.Collections.Concurrent;
using System.Collections;
using System.Security.Cryptography.X509Certificates;
using Helper;
using Encryption;

// Load the ML file (DER encoded)
// byte[] mlBytes = [File.ReadAllBytes("masterlist-cscas/C=AT,O=GV,OU=BMI,CN=CSCA-AUSTRIA56.pem")];


// // Step 1: unwrap CMS chain
// var cmsChain = new System.Collections.Generic.List<byte[]>();
// byte[] currentBytes = mlBytes;

// var cert = X509CertificateLoader.LoadCertificate(currentBytes);
// Log.Info(cert.IssuerName.Name);



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

    /*Should only be used in debug*/
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



//testNonceDecrypt.testings();

// Användning av Data groups ex:
// byte[] dg11Bytes = ReadFileFromChip(0x6B);
// DG11 dg11 = DG11.Parse(dg11Bytes);

// byte[] dg14Bytes = ReadFileFromChip(0x6E);
// DG14 dg14 = DG14.Parse(dg14Bytes);

// byte[] dg16Bytes = ReadFileFromChip(0x70);
// DG16 dg16 = DG16.Parse(dg16Bytes);

// Deciding Certificate from dg12:

// byte[] dg12Bytes = ReadFileFromChip(0x??);
// DG12 dg12 = DG12.Parse(dg12Bytes);

//var masterlist = Load("masterlist-cscas");
//var dg12Info = TLVParser.ParseDG12(dg12Bytes);
//var relevantCerts = CertificateFinder.FindRelevantCertificates(dg12Info, masterList);
