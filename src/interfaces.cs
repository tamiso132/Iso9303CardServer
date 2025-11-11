
using System.Data;
using ErrorHandling;
using Type;

namespace Interfaces;

/// <summary>
/// Interface for parsing EF (Elementary File) data from raw bytes.
/// T represents the type of object returned after parsing.
/// </summary>
/// <typeparam name="T">Type produced by the parser</typeparam>
public interface IEfParser<out T>
{
    string Name();
    T ParseFromBytes(byte[] bytes);
}

/// <summary>
/// Interface representing an Elementary File ID (EF ID).
/// Provides access to short ID, full ID bytes, and optional associated application.
/// </summary>
public interface IEfID
{
    /// <summary>Short identifier for the EF</summary>
    byte ShortID { get; }

    /// <summary>Full ID bytes for the EF</summary>
    byte[] GetFullID();

    /// <summary>Associated application ID, if any</summary>
    AppID? AppIdentifier();

    string GetName();
}

/// <summary>
/// Interface representing a cryptographic algorithm.
/// Defines methods for encrypting and decrypting data.
/// </summary>
/// TODO Remove?
public interface ICryptoAlgorithm
{
    /// <summary>Encrypt input bytes</summary>
    byte[] Encrypt(byte[] input);

    /// <summary>Decrypt input bytes</summary>
    byte[] Decrypt(byte[] input);
}

/// <summary>
///Different communications should implement this.
///Websocket, NFC and USB etc.
/// </summary>
public interface ICommunicator
{
    public Task<byte[]> ReadAsync();
    public Task WriteAsync(byte[] data);

    async Task<byte[]> TransceiveAsync(byte[] data)
    {
        await WriteAsync(data);
        return await ReadAsync();
    }
}

/// <summary>
///Different server formats should implement this
///How a certain server format data during communication with a client
/// SHOULD NOT BE CONFUSED WITH ANY pace/bac encryption or APDU.
/// </summary>
public interface IServerFormat
{
    public byte[] Format(byte[] input);
    public Result<byte[]> DeFormat(byte[] input);

}

