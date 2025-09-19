using WebSocketSharp;
using WebSocketSharp.Server;
using App;
using Server;


var config = File.ReadAllLines("config.txt");
string ip = null;
string port = null;

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

// Create a WebSocket server on your LAN IP and port
var wssv = new WebSocketServer($"ws://{ip}:{port}");

// Add a service for all clients ("/" path)
wssv.AddWebSocketService<WsSession>("/");

// Start the server
wssv.Start();
Console.WriteLine("WebSocket server started, waiting for connections...");
Console.ReadLine();
wssv.Stop();
//Console.ReadKey(true);

// Define a WebSocket behavior for each client
public class WsSession : WebSocketBehavior
{
    protected override void OnOpen()
    {
        Console.WriteLine("Client connected");
        var app = new ClientSession(new WebSocketTransport(Context.WebSocket));
        apps.Add(app);
        _ = app.Start(); // Start asynchronously
    }

    protected override void OnMessage(MessageEventArgs e)
    {
        // Console.WriteLine("Message from client: " + e.Data);
    }

    protected override void OnClose(CloseEventArgs e)
    {
        Console.WriteLine("Client disconnected");
    }

    readonly List<ClientSession> apps = [];
}
