using System.Collections.Concurrent;
using System.Text;
using Interfaces;
using WebSocketSharp;

namespace Server;


public enum CommandType : byte
{
    NewNFCScan = 0x01, //If new scan was made
    NFCLost, // lost connection to current scan
    Error, // Error with the command that was sent
    Package, // regular package
}

public static class MyErrorExtensions
{
    public static string GetMessage(this CommandType error)
    {
        return error switch
        {
            CommandType.NewNFCScan => "New NFC Scan",
            CommandType.NFCLost => "NFC was Lost",
            CommandType.Error => "Error",
            CommandType.Package => "OK",
            _ => throw new NotImplementedException(),
        };
    }
}


    public class CommandPacket
    {

        private CommandPacket(CommandType type, uint len, byte[] data)
        {
            this.Type = type;
            this.Length = len;
            this.Data = data;
        }
        public static CommandPacket TryFromBytes(byte[] bytes)
        {
            if (bytes.Length < 2)
                throw new ArgumentException("response is invalid: " + bytes);

            return new CommandPacket((CommandType)bytes[0], BitConverter.ToUInt32(bytes.AsSpan()[1..5]), bytes[5..]);
        }

        public byte[] ToBytes()
        {
            byte[] bytes = new byte[1 + 4 + (Data?.Length ?? 0)];
            bytes[0] = (byte)Type;

            byte[] lengthBytes = BitConverter.GetBytes(Length);

            Array.Copy(lengthBytes, 0, bytes, 1, 4);

            if (Data != null)
                Array.Copy(Data, 0, bytes, 5, Data.Length);

            return bytes;
        }

        public readonly CommandType Type;
        public readonly byte[] Data = [];
        public readonly uint Length;
        public override string ToString() => $"{Type}: {Encoding.UTF8.GetString(Data)}";
    }

    public class WebSocketTransport : ICommunicator
    {
        private readonly WebSocket _socket;
        private readonly ConcurrentQueue<byte[]> _incoming = new ConcurrentQueue<byte[]>();
        private TaskCompletionSource<bool> _messageReceived = new();

        public WebSocketTransport(WebSocket socket)
        {
            _socket = socket;
            _socket.OnMessage += (sender, e) =>
            {
                _incoming.Enqueue(e.RawData);
                _messageReceived.TrySetResult(true); // signal a waiting ReadAsync
            };
        }

        public async Task<byte[]> ReadAsync()
        {
            while (_incoming.IsEmpty)
                await _messageReceived.Task;

            if (_incoming.TryDequeue(out var data))
            {
                if (_incoming.IsEmpty)
                    _messageReceived = new TaskCompletionSource<bool>();
                return data;
            }

            return Array.Empty<byte>();
        }

        // Writes raw bytes
        public Task WriteAsync(byte[] data)
        {
            Console.WriteLine("Sending: " + BitConverter.ToString(data[5..]));
            _socket.Send(data);
            return Task.CompletedTask;
        }
    }
