// using System;
// using System.Text;
// using System.Security.Cryptography;

// public class testNonceDecrypt
// {
//     public static void testings()
//     {
//         Console.WriteLine("🔐 Testar DecryptNonce...");

//         // Exempelvärden (byt ut mot riktiga)
//         byte[] encryptedNonce = new byte[16] { 0x12, 0x34, 0x56, 0x78, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B };
//         byte[] password = Encoding.UTF8.GetBytes("123456");            // CAN eller MRZ
//         var paceInfo = new PACEInfo();                                 // din egen typ
//         var passwordType = PasswordType.MRZ;                           // välj MRZ eller CAN

//         if (DecryptNonce(paceInfo, encryptedNonce, password, passwordType, out byte[] decrypted))
//         {
//             Console.WriteLine("✅ Dekryptering lyckades!");
//             Console.WriteLine("Decrypted Nonce: " + BitConverter.ToString(decrypted));
//         }
//         else
//         {
//             Console.WriteLine("❌ Dekryptering misslyckades!");
//         }
//     }

//     // Här klistrar du in din DecryptNonce-metod

    
//     public static bool DecryptNonce(PACEInfo paceInfo, byte[] encryptedNonce, byte[] password, PasswordType passwordType, out byte[] decryptedNonce)
//     {
//         decryptedNonce = Array.Empty<byte>();
//         try
//         {
//             using var aes = Aes.Create();
//             aes.Key = SHA256.HashData(password)[..16]; // demo: enkel nyckel
//             aes.IV = new byte[16];
//             aes.Padding = PaddingMode.None; // <--- viktigt för test med slumpdata


//             using var decryptor = aes.CreateDecryptor();
//             decryptedNonce = decryptor.TransformFinalBlock(encryptedNonce, 0, encryptedNonce.Length);
//             return true;
//         }
//         catch (CryptographicException ex)
//         {
//             Console.WriteLine($"Crypto error: {ex.Message}");
//             return false;
//         }
//     }
// }

// // placeholder klasser så koden kompilerar
// public class PACEInfo { }
// public enum PasswordType { MRZ, CAN }
