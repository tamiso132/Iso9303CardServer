using System.Text.RegularExpressions;
using Interfaces;
using Server;
using Type;
using WebSocketSharp;
using Parser;
using Helper;
using Encryption;
using Command;
using ErrorHandling;
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
                Log.Error(result.Error.ErrorMessage());
            }

            var response = result.Value;
            var info = response.Parse<ImplCardAccess, ImplCardAccess.Info>().EncryptInfos[0];

            if (!result.IsSuccess)
            {
                Log.Error(result.Error.ErrorMessage());
                return;
            }



            byte[] key = TestClass.DerivePaceKey(info);

            result = await _cmd.MseSetAT(info.OrgOid, info.OrgParameterID);



            if (!result.IsSuccess)
                return;

            if (!result.Value.status.IsSuccess())
                return;


            if (!result.IsSuccess)
            {
                Log.Error(result.Error.ErrorMessage());
                return;
            }

            if (!result.Value.status.IsSuccess())
            {
                Log.Error(result.Error.ErrorMessage());
                return;
            }

                await TestClass.ComputeDecryptedNounce(_cmd, info, key);

            Log.Info("All commands completed without a problem");

        }
    }

    private readonly ICommunicator _comm = comm;
    private readonly Command<ServerEncryption> _cmd = new(comm, new ServerEncryption());
}


public class ServerEncryption : IServerEncryption
{

    byte[] IServerEncryption.Encrypt(byte[] input)
    {
        byte[] lengthBytes = BitConverter.GetBytes(input.Length);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(lengthBytes);

        return [(byte)CommandType.Package, .. lengthBytes, .. input];
    }

    Result<byte[]> IServerEncryption.Decode(byte[] input)
    {
        var packet = CommandPacket.TryFromBytes(input);
        if (packet.Type == CommandType.Package)
        {
            return Result<byte[]>.Success(packet.Data);
        }
        Console.WriteLine("Error: " + packet.Type.ToString());
        return Result<byte[]>.Fail(new Error.Parse("Decoding packet failed, does not have correct server format"));
    }

};


