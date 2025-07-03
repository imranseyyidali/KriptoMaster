using System.Security.Cryptography;
using System.Text;

namespace SifrelemeProjesi.Models
{
    public class EccService
    {
        public ECDiffieHellman? PrivateKey;
        public ECDiffieHellmanPublicKey? PublicKey;

        //GenerateKeys----------------------------------------
        public void GenerateKeys()
        {
            PrivateKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            PublicKey = PrivateKey.PublicKey;
        }
        //-----------------------------------------------------

        //Encrypt----------------------------------------------
        public string Encrypt(string plainText)
        {
            if (PublicKey == null)
                throw new InvalidOperationException("Public key not generated");

            var data = Encoding.UTF8.GetBytes(plainText);
            
            // Generate ephemeral key pair for this encryption
            using (var ephemeralKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256))
            {
                // Derive shared secret
                var sharedSecret = ephemeralKey.DeriveKeyMaterial(PublicKey);
                
                // Use shared secret to derive AES key
                using (var aes = Aes.Create())
                {
                    aes.KeySize = 256;
                    aes.GenerateIV();
                    
                    // Derive AES key from shared secret
                    using (var deriveBytes = new Rfc2898DeriveBytes(sharedSecret, aes.IV, 10000, HashAlgorithmName.SHA256))
                    {
                        aes.Key = deriveBytes.GetBytes(32); // 256 bits
                    }

                    // Encrypt the data with AES
                    using (var encryptor = aes.CreateEncryptor())
                    {
                        var encryptedData = encryptor.TransformFinalBlock(data, 0, data.Length);
                        
                        // Combine ephemeral public key + IV + encrypted data
                        var ephemeralPublicKeyBytes = ephemeralKey.ExportSubjectPublicKeyInfo();
                        var result = new byte[4 + ephemeralPublicKeyBytes.Length + 4 + aes.IV.Length + encryptedData.Length];
                        var offset = 0;
                        
                        // Write ephemeral public key length
                        BitConverter.GetBytes(ephemeralPublicKeyBytes.Length).CopyTo(result, offset);
                        offset += 4;
                        
                        // Write ephemeral public key
                        ephemeralPublicKeyBytes.CopyTo(result, offset);
                        offset += ephemeralPublicKeyBytes.Length;
                        
                        // Write IV length
                        BitConverter.GetBytes(aes.IV.Length).CopyTo(result, offset);
                        offset += 4;
                        
                        // Write IV
                        aes.IV.CopyTo(result, offset);
                        offset += aes.IV.Length;
                        
                        // Write encrypted data
                        encryptedData.CopyTo(result, offset);
                        
                        return Convert.ToBase64String(result);
                    }
                }
            }
        }
        //-----------------------------------------------------

        //Decrypt----------------------------------------------
        public string Decrypt(string cipherText)
        {
            if (PrivateKey == null)
                throw new InvalidOperationException("Private key not generated");

            var encryptedData = Convert.FromBase64String(cipherText);
            var offset = 0;
            
            // Read ephemeral public key length
            var ephemeralKeyLength = BitConverter.ToInt32(encryptedData, offset);
            offset += 4;
            
            // Read ephemeral public key
            var ephemeralPublicKeyBytes = new byte[ephemeralKeyLength];
            Array.Copy(encryptedData, offset, ephemeralPublicKeyBytes, 0, ephemeralKeyLength);
            offset += ephemeralKeyLength;
            
            // Read IV length
            var ivLength = BitConverter.ToInt32(encryptedData, offset);
            offset += 4;
            
            // Read IV
            var iv = new byte[ivLength];
            Array.Copy(encryptedData, offset, iv, 0, ivLength);
            offset += ivLength;
            
            // Read encrypted data
            var data = new byte[encryptedData.Length - offset];
            Array.Copy(encryptedData, offset, data, 0, data.Length);
            
            // Import ephemeral public key
            using (var ephemeralKey = ECDiffieHellman.Create())
            {
                ephemeralKey.ImportSubjectPublicKeyInfo(ephemeralPublicKeyBytes, out _);
                
                // Derive shared secret
                var sharedSecret = PrivateKey.DeriveKeyMaterial(ephemeralKey.PublicKey);
                
                // Use shared secret to derive AES key
                using (var aes = Aes.Create())
                {
                    aes.KeySize = 256;
                    aes.IV = iv;
                    
                    // Derive AES key from shared secret
                    using (var deriveBytes = new Rfc2898DeriveBytes(sharedSecret, aes.IV, 10000, HashAlgorithmName.SHA256))
                    {
                        aes.Key = deriveBytes.GetBytes(32); // 256 bits
                    }
                    
                    // Decrypt the data with AES
                    using (var decryptor = aes.CreateDecryptor())
                    {
                        var decryptedData = decryptor.TransformFinalBlock(data, 0, data.Length);
                        return Encoding.UTF8.GetString(decryptedData);
                    }
                }
            }
        }
        //-----------------------------------------------------
    }
}
