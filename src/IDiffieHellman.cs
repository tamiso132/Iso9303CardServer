
//using _365id.Services.NfcService.Decoding.Infrastructure;
//using _365id.Services.NfcService.Decoding.Processing.PACE.Tags;
using Org.BouncyCastle.Math;

namespace _365id.Services.NfcService.Decoding.Processing.PACE;

public interface IDiffieHellman
{
    public BigInteger PrivateKey { get; }
    public byte[] PublicKey { get; }
    public byte[] SharedSecret { get; }
    public void MapGenerator(byte[] nonce);
    public byte[] Generator { get; }
    public void CalculateSharedSecret(byte[] publicKey);
    public void CalculateSharedSecret(EphemeralPublicKey icPublicKey);
    public void CalculateSharedSecret(MappingData icPublicKey);
    public void GenerateEphemeralKeys(byte[] newPrivateKey);
    public void GenerateEphemeralKeys(IRandomNumberProvider randomNumberProvider);
    public IEnumerable<byte> GetChipAuthenticationInput();
    public IEnumerable<byte> GetChipAuthenticationInput(byte[] publicKey);
}