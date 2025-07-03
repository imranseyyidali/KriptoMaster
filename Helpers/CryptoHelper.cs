using System.Security.Cryptography;
using System.Text;

namespace Sifreleme.Helpers
{
    public static class CryptoHelper
    {
        //GenerateRsaKeys---------------------------------------
        public static (string publicKey, string privateKey) GenerateRsaKeys()
        {
            using var rsa = RSA.Create(2048);
            return (
                Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo()),
                Convert.ToBase64String(rsa.ExportPkcs8PrivateKey())
            );
        }
        //------------------------------------------------------

        //EncryptWithRsa----------------------------------------
        public static string EncryptWithRsa(string plainText, string base64PublicKey)
        {
            using var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(base64PublicKey), out _);
            var bytes = Encoding.UTF8.GetBytes(plainText);
            var encrypted = rsa.Encrypt(bytes, RSAEncryptionPadding.Pkcs1);
            return Convert.ToBase64String(encrypted);
        }
        //------------------------------------------------------

        //DecryptWithRsa----------------------------------------
        public static string DecryptWithRsa(string encryptedText, string base64PrivateKey)
        {
            using var rsa = RSA.Create();
            rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(base64PrivateKey), out _);
            var bytes = Convert.FromBase64String(encryptedText);
            var decrypted = rsa.Decrypt(bytes, RSAEncryptionPadding.Pkcs1);
            return Encoding.UTF8.GetString(decrypted);
        }
        //------------------------------------------------------

        //ComputeSha512Hash-------------------------------------
        public static string ComputeSha512Hash(string rawData)
        {
            using var sha512 = SHA512.Create();
            var bytes = sha512.ComputeHash(Encoding.UTF8.GetBytes(rawData));
            return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
        }
    }

}
