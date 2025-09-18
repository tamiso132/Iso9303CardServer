using System.Text.RegularExpressions;
using Interfaces;
using Server;
using Type;
using WebSocketSharp;
using Parser;
using Helper;
namespace App;


public class ClientSession(ICommunicator comm)
{
    public async Task Start()
    {


        byte[] buffer = await _comm.ReadAsync();
        var packet = CommandPacket.TryFromBytes(buffer);
        if (packet.Type == CommandType.NewNFCScan)
        {
            var result = await _cmd.ReadBinary(EfIdGlobal.CardAccess);
            if (!result.IsSuccess)
            {
                Console.WriteLine("Error: " + result.Error.GetMessage());
                return;
            }
            var response = result.Value;
            Console.WriteLine(BitConverter.ToString(response.data));
            var parsed = new ImplCardAccess().ParseFromBytes(response.data);


            result = await _cmd.ReadBinary(EfIdGlobal.Dir);
            if (result.Value.status != SwStatus.Success) // if missing, then only 
            {
                if (result.Value.status == SwStatus.FileNotFound)
                {

                }
                else
                {
                    Console.WriteLine("NFC Error: " + result.Value.status.Message);
                }
            }
            if (!result.IsSuccess)
            {

                Console.WriteLine("Error: " + result.Error.GetMessage());
                return;
            }





        }
    }

    private readonly ICommunicator _comm = comm;
    private readonly Command<ServerEncryption, CommandType> _cmd = new(comm, new ServerEncryption());
}


public class ServerEncryption : IServerEncryption<CommandType>
{

    public byte[] Encrypt(byte[] input)
    {
        byte[] lengthBytes = BitConverter.GetBytes(input.Length);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(lengthBytes);

        return [(byte)CommandType.Package, .. lengthBytes, .. input];
    }


    public Result<byte[], CommandType> Decode(byte[] input)
    {
        var packet = CommandPacket.TryFromBytes(input);
        if (packet.Type == CommandType.Package)
        {
            return Result<byte[], CommandType>.Success(packet.Data);
        }
        Console.WriteLine("Error: " + packet.Type.ToString());
        return Result<byte[], CommandType>.Fail(CommandType.Error);
    }
};


