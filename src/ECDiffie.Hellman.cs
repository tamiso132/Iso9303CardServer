
// using _365id.Services.NfcService.Decoding.Infrastructure;
// using _365id.Services.NfcService.Decoding.Processing.PACE.Tags;
// using Org.BouncyCastle.Asn1;
// using Org.BouncyCastle.Asn1.X9;
// using Org.BouncyCastle.Math;
// using Org.BouncyCastle.Math.EC;
// using Serilog;
// using System.Diagnostics.CodeAnalysis;
// using System.Runtime.InteropServices.Marshalling;

// namespace _365id.Services.NfcService.Decoding.Processing.PACE;

// /// <summary>
// /// This class implements the terminal side of the Elliptic Curve Diffie Hellman algorithm
// /// </summary>
// public class ECDiffieHellman : IDiffieHellman
// {
//     public BigInteger PrivateKey { get; set; }
//     public byte[] PublicKey
//     {
//         get
//         {
//             return ECPublicKey.GetEncoded();
//         }
//     }
//     private DerObjectIdentifier Parameters { get; set; }
//     private X9ECParameters ECParameters { get; set; }
//     private ECPoint ECPublicKey
//     {
//         get
//         {
//             return _generator.Multiply(PrivateKey).Normalize();
//         }
//     }
//     private ECPoint _generator { get; set; }
//     private ECPoint _ecSharedSecret { get; set; }
//     public byte[] SharedSecret
//     {
//         get
//         {
//             return _ecSharedSecret.Normalize().XCoord.GetEncoded();
//         }
//     }

//     public ECDiffieHellman(int parameterId, byte[] privateKey, byte[]? generator = null)
//     {
//         PrivateKey = new BigInteger(1, privateKey);
//         if (!PACEHelper.TryGetParameter(parameterId, out var parameters))
//             throw new Exception($"Invalid parameter {parameterId}");
//         Parameters = parameters;
//         ECParameters = ECNamedCurveTable.GetByOid(Parameters);
//         _ecSharedSecret = ECParameters.G;
//         if (generator is null)
//             _generator = ECParameters.G;
//         else
//             _generator = ECParameters.Curve.DecodePoint(generator).Normalize();
//     }

//     public byte[] Generator
//     {
//         get
//         {
//             return _generator.GetEncoded();
//         }
//     }


//     /// <summary>
//     /// Creates a new generator function using the provided PACE scheme.
//     /// </summary>
//     /// <param name="nonce">Random seed value provided by IC used to calculate the generator function</param>
//     /// <returns>true if new valid generator was mapped, otherwise false.</returns>
//     public void MapGenerator(byte[] nonce)
//     {
//         var iNonce = new BigInteger(1, nonce);
//         _generator = _generator.Multiply(iNonce).Add(_ecSharedSecret);
//     }

//     public void GenerateEphemeralKeys(byte[] newPrivateKey)
//     {
//         PrivateKey = new BigInteger(1, newPrivateKey);
//     }
//     public void GenerateEphemeralKeys(IRandomNumberProvider randomNumberProvider)
//     {
//         PrivateKey = new BigInteger(1, randomNumberProvider.GetNextBytes(32));
//     }

//     /// <summary>
//     /// Calculates the ephemeral shared secret for this session
//     /// </summary>
//     /// <param name="publicKey">The IC's public key</param>
//     /// <returns>true if we successfully created a shared secret.</returns>
//     public void CalculateSharedSecret(byte[] encodedPoint)
//     {
//         var publicKeyIC = ECParameters.Curve.DecodePoint(encodedPoint);
//         _ecSharedSecret = publicKeyIC.Multiply(PrivateKey);
//     }

//     public void CalculateSharedSecret(MappingData icPublicKey)
//      => CalculateSharedSecret(icPublicKey.Data());

//     public void CalculateSharedSecret(EphemeralPublicKey icPublicKey)
//      => CalculateSharedSecret(icPublicKey.Data());

//     public IEnumerable<byte> GetChipAuthenticationInput(byte[] publicKey)
//     {
//         var pointHeader = new byte[] { 0x86, (byte)publicKey.Length };
//         return pointHeader.Concat(publicKey);
//     }
//     public IEnumerable<byte> GetChipAuthenticationInput()
//     {
//         return GetChipAuthenticationInput(PublicKey);
//     }

//     public ECPoint? DecodePoint(byte[] encoded)
//     => ECNamedCurveTable.GetByOid(Parameters).Curve.DecodePoint(encoded);
// }