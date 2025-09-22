using WebSocketSharp;
using WebSocketSharp.Server;
using App;
using Server;
using System.Collections.Concurrent;
using EpassValidation;
using System.Security.Cryptography.X509Certificates;


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



string mlPath = "C:/Users/foffe/ICAO_ml_July2025.ml";

//Console.WriteLine("=== ICAO Master List validering ===");

try
{
    // Läs certifikaten från Master List
   /* List<X509Certificate2> certs = MasterListHelper.ReadMasterList(mlPath);
    Console.WriteLine($"{certs.Count}");
    Console.WriteLine($"Hittade {certs.Count} certifikat i Master List.\n");
*/
    CertInfo.ShowCertificateInfo(mlPath);
    

    // Skriv ut lite info om de första certifikaten
    // for (int i = 0; i < Math.Min(5, certs.Count); i++)
    // {
    //     MasterListHelper.PrintCertInfo(certs[i]);
    // }
    //     Console.WriteLine($"{certs.Count}");
            
             }
catch (Exception ex)
{
    Console.WriteLine("Fel vid läsning av Master List:");
    Console.WriteLine(ex.Message);
}

            Console.WriteLine("\nKlar!");
            Console.ReadLine();
            