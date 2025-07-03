using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text;

namespace Controllers
{
    public class EccController : Controller
    {
        private static string publicKeyText = string.Empty;
        private static string privateKeyText = string.Empty;

        [HttpGet]
        public IActionResult Encrypt()
        {
            ViewBag.PublicKey = TempData["PublicKey"] ?? publicKeyText ?? string.Empty;
            ViewBag.PrivateKey = TempData["PrivateKey"] ?? privateKeyText ?? string.Empty;
            return View();
        }

        [HttpPost]
        [ActionName("Encrypt")]
        public IActionResult EncryptPost(string plainText, string publicKey)
        {
            if (string.IsNullOrWhiteSpace(publicKey))
            {
                ViewBag.EncryptedText = "Lütfen geçerli bir açık anahtar (PEM) giriniz.";
                ViewBag.InputPlainText = plainText;
                ViewBag.PublicKey = publicKeyText ?? string.Empty;
                ViewBag.PrivateKey = privateKeyText ?? string.Empty;
                return View("Encrypt");
            }

            if (string.IsNullOrWhiteSpace(plainText))
            {
                ViewBag.EncryptedText = "Lütfen şifrelenecek metni giriniz.";
                ViewBag.InputPlainText = plainText;
                ViewBag.PublicKey = publicKey;
                ViewBag.PrivateKey = privateKeyText ?? string.Empty;
                return View("Encrypt");
            }

            try
            {
                using (var ecc = ECDiffieHellman.Create())
                {
                    ecc.ImportFromPem(publicKey.ToCharArray());
                    
                    // Simulate encryption (in real implementation, you would use ECDH key exchange)
                    byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                    string encryptedText = Convert.ToBase64String(plainBytes);
                    
                    ViewBag.EncryptedText = encryptedText;
                    ViewBag.InputPlainText = plainText;
                    ViewBag.PublicKey = publicKey;
                    ViewBag.PrivateKey = privateKeyText ?? string.Empty;
                    return View("Encrypt");
                }
            }
            catch (Exception ex)
            {
                ViewBag.EncryptedText = "Bir hata oluştu: " + ex.Message;
                ViewBag.InputPlainText = plainText;
                ViewBag.PublicKey = publicKey;
                ViewBag.PrivateKey = privateKeyText ?? string.Empty;
                return View("Encrypt");
            }
        }

        [HttpGet]
        public IActionResult Decrypt()
        {
            ViewBag.PublicKey = publicKeyText ?? string.Empty;
            ViewBag.PrivateKey = privateKeyText ?? string.Empty;
            return View();
        }

        [HttpPost]
        [ActionName("Decrypt")]
        public IActionResult DecryptPost(string encryptedText, string privateKey)
        {
            if (string.IsNullOrWhiteSpace(privateKey))
            {
                ViewBag.DecryptedText = "Lütfen geçerli bir özel anahtar (PEM) giriniz.";
                ViewBag.InputEncryptedText = encryptedText;
                ViewBag.PublicKey = publicKeyText ?? string.Empty;
                ViewBag.PrivateKey = privateKeyText ?? string.Empty;
                return View();
            }

            if (string.IsNullOrWhiteSpace(encryptedText))
            {
                ViewBag.DecryptedText = "Lütfen çözülecek metni giriniz.";
                ViewBag.InputEncryptedText = encryptedText;
                ViewBag.PublicKey = publicKeyText ?? string.Empty;
                ViewBag.PrivateKey = privateKey;
                return View();
            }

            try
            {
                using (var ecc = ECDiffieHellman.Create())
                {
                    ecc.ImportFromPem(privateKey.ToCharArray());
                    
                    // Simulate decryption (in real implementation, you would use ECDH key exchange)
                    byte[] encryptedBytes = Convert.FromBase64String(encryptedText);
                    string decryptedText = Encoding.UTF8.GetString(encryptedBytes);
                    
                    ViewBag.DecryptedText = decryptedText;
                    ViewBag.InputEncryptedText = encryptedText;
                    ViewBag.PublicKey = publicKeyText ?? string.Empty;
                    ViewBag.PrivateKey = privateKey;
                    return View();
                }
            }
            catch (Exception ex)
            {
                ViewBag.DecryptedText = "Bir hata oluştu: " + ex.Message;
                ViewBag.InputEncryptedText = encryptedText;
                ViewBag.PublicKey = publicKeyText ?? string.Empty;
                ViewBag.PrivateKey = privateKey;
                return View();
            }
        }

        [HttpPost]
        public IActionResult GenerateKeys()
        {
            using (var ecc = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256))
            {
                var privateKeyBytes = ecc.ExportPkcs8PrivateKey();
                var publicKeyBytes = ecc.ExportSubjectPublicKeyInfo();

                var privateKeyPem = ExportPrivateKeyToPem(privateKeyBytes);
                var publicKeyPem = ExportPublicKeyToPem(publicKeyBytes);

                publicKeyText = publicKeyPem;
                privateKeyText = privateKeyPem;

                TempData["PublicKey"] = publicKeyPem;
                TempData["PrivateKey"] = privateKeyPem;
            }
            return RedirectToAction("Encrypt");
        }

        private string ExportPrivateKeyToPem(byte[] privateKeyBytes)
        {
            var builder = new StringBuilder();
            builder.AppendLine("-----BEGIN PRIVATE KEY-----");
            builder.AppendLine(Convert.ToBase64String(privateKeyBytes, Base64FormattingOptions.InsertLineBreaks));
            builder.AppendLine("-----END PRIVATE KEY-----");
            return builder.ToString();
        }

        private string ExportPublicKeyToPem(byte[] publicKeyBytes)
        {
            var builder = new StringBuilder();
            builder.AppendLine("-----BEGIN PUBLIC KEY-----");
            builder.AppendLine(Convert.ToBase64String(publicKeyBytes, Base64FormattingOptions.InsertLineBreaks));
            builder.AppendLine("-----END PUBLIC KEY-----");
            return builder.ToString();
        }
    }
} 