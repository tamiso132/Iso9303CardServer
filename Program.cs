using WebSocketSharp;
using WebSocketSharp.Server;
using App;
using Server;



// Create a WebSocket server on your LAN IP and port
var wssv = new WebSocketServer("ws://192.168.0.108:5000");

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
