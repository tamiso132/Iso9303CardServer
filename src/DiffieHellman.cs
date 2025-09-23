

//using _365id.Services.NfcService.Decoding.Infrastructure;
//using _365id.Services.NfcService.Decoding.Processing.PACE.Tags;
using System.Security.Cryptography;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Math;

namespace _365id.Services.NfcService.Decoding.Processing.PACE;

public class DiffieHellman : ECDiffieHellman
{
    public BigInteger PrivateKey { get; set; }
    public byte[] PublicKey
    {
        get
        {
            return _generator.ModPow(PrivateKey, ModpGroup.P).ToByteArrayUnsigned();
        }
    }

    private BigInteger _biSharedSecret { get; set; }

    private BigInteger _generator { get; set; }

    public byte[] SharedSecret
    {
        get
        {
            return _biSharedSecret.ToByteArray();
        }
    }
    private ModpGroup ModpGroup { get; set; }

    public DiffieHellman(int parameterId, byte[] privateKey, byte[]? generator = null)
    {
        ModpGroup = ModpGroupIdentifiers.GetByParameterId(parameterId);
        _biSharedSecret = BigInteger.One;
        PrivateKey = new BigInteger(1, privateKey);
        if (generator is null)
            _generator = ModpGroup.G;
        else
            _generator = new BigInteger(1, generator);
    }

    /// <summary>
    /// Creates a new generator function using the input nonce
    /// </summary>
    /// <param name="nonce">Random seed value provided by IC used to calculate the generator function</param>
    /// <returns>true if new valid generator was mapped, otherwise false.</returns>
    public void MapGenerator(byte[] nonce)
    {
        var iNonce = new BigInteger(1, nonce);
        _generator = _generator.ModPow(iNonce, ModpGroup.P).ModMultiply(_biSharedSecret, ModpGroup.P);
    }

    public byte[] Generator
    {
        get
        {
            return _generator.ToByteArrayUnsigned();
        }
    }

    /// <summary>
    /// Create new keys on this object, typically after mapping the generator
    /// </summary>
    /// <param name="newPrivateKey"></param>
    public void GenerateEphemeralKeys(byte[] newPrivateKey)
    {
        PrivateKey = new BigInteger(1, newPrivateKey);
    }

    /// <summary>
    /// Create new keys on this object, using RNG from the given RNG source
    /// </summary>
    /// <param name="randomNumberProvider">The RNG source</param>
    public void GenerateEphemeralKeys(IRandomNumberProvider randomNumberProvider)
    => GenerateEphemeralKeys(randomNumberProvider.GetNextBytes(20));

    /// <summary>
    /// Get input data used for generating the authentication code
    /// </summary>
    /// <returns></returns>
    public IEnumerable<byte> GetChipAuthenticationInput()
    {
        return GetChipAuthenticationInput(PublicKey);
    }

    /// <summary>
    /// Get input data used for generating the authentication code
    /// </summary>
    /// <param name="publicKey">The public key to be included in the input data</param>
    /// <returns></returns>
    public IEnumerable<byte> GetChipAuthenticationInput(byte[] publicKey)
    {
        byte[] len = TagHelpers.EncodeLength(publicKey.Length);
        return [0x84, .. len, .. publicKey];
    }

    /// <summary>
    /// Calculates the ephemeral shared secret for this session
    /// </summary>
    /// <param name="publicKey">The IC's public key</param>
    /// <returns>true if we successfully created a shared secret.</returns>
    public void CalculateSharedSecret(byte[] publicKey)
    {
        BigInteger publicKeyBI = new(1, publicKey);
        _biSharedSecret = publicKeyBI.ModPow(PrivateKey, ModpGroup.P);
    }

    public void CalculateSharedSecret(EphemeralPublicKey icPublicKey)
    => CalculateSharedSecret(icPublicKey.Data());

    public void CalculateSharedSecret(MappingData icPublicKey)
    => CalculateSharedSecret(icPublicKey.Data());
}