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
        var packet = ServerPacket.TryFromBytes(buffer);
        if (packet.Type == CommandType.NewNFCScan)
        {
            var result = await _cmd.SelectDefaultMF();



            if (!result.IsSuccess)
            {
                Log.Error(result.Error.ErrorMessage());
                return;
            }

            result = await _cmd.ReadBinary(EfIdGlobal.CardAccess);

            if (!result.IsSuccess)
            {
                Log.Error(result.Error.ErrorMessage());
                return;
            }


            var response = result.Value;
            var info = response.Parse<ImplCardAccess, ImplCardAccess.Info>().EncryptInfos[0];

            if (!result.IsSuccess)
            {
                Log.Error(result.Error.ErrorMessage());
                return;
            }
             byte[] key = TestClass.DerivePaceKey(info);
            
            Log.Info("orgID: " + BitConverter.ToString(info.OrgOid));

            result = await _cmd.MseSetAT(info.OrgOid, info.OrgParameterID);


            if (!result.IsSuccess)
            {
                Log.Error(result.Error.ErrorMessage());
                return;
            }


            if (!result.IsSuccess)
            {
                Log.Error(result.Error.ErrorMessage());
                return;
            }

            //  await _cmd.GeneralAuthenticate(new GenAuthType.MappingData([]));
            //  return;
            var r = await TestClass.ComputeDecryptedNounce(_cmd, info, key, TestClass.PasswordType.MRZ);


            if (!r.IsSuccess)
            {
                Log.Error(r.Error.ErrorMessage());
                return;
            }



            Log.Info("All commands completed without a problem");

        }
    }

    private readonly ICommunicator _comm = comm;
    private readonly Command<ServerEncryption> _cmd = new(comm, new ServerEncryption());
}


public class ServerEncryption : IServerFormat
{

    byte[] IServerFormat.Format(byte[] input)
    {
        byte[] lengthBytes = BitConverter.GetBytes(input.Length);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(lengthBytes);

        return [(byte)CommandType.Package, .. lengthBytes, .. input];
    }

    Result<byte[]> IServerFormat.DeFormat(byte[] input)
    {
        var packet = ServerPacket.TryFromBytes(input);
        if (packet.Type == CommandType.Package)
            return Result<byte[]>.Success(packet.Data);

        Console.WriteLine("Error: " + packet.Type.ToString());
        return Result<byte[]>.Fail(new Error.Parse("Decoding packet failed, does not have correct server format"));
    }

};


