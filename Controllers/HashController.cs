using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text;

namespace SifrelemeProjesi.Controllers
{
    public class HashController : Controller
    {
        [HttpGet]
        public IActionResult Sha512()
        {
            return View();
        }

        [HttpGet]
        public IActionResult Sha256()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Sha512(string? input, IFormFile? file)
        {
            string? hashResult = null;
            bool isFileMode = false;

            if (!string.IsNullOrEmpty(input))
            {
                using var sha = SHA512.Create();
                byte[] bytes = Encoding.UTF8.GetBytes(input);
                byte[] hash = await Task.Run(() => sha.ComputeHash(bytes));
                hashResult = BitConverter.ToString(hash).Replace("-", "").ToLower();
            }
            else if (file != null && file.Length > 0)
            {
                using var sha = SHA512.Create();
                using var stream = file.OpenReadStream();
                byte[] hash = await Task.Run(() => sha.ComputeHash(stream));
                hashResult = BitConverter.ToString(hash).Replace("-", "").ToLower();
                isFileMode = true;
            }

            ViewBag.HashResult = hashResult;
            ViewBag.InputText = input ?? string.Empty;
            ViewBag.IsFileMode = isFileMode;
            ViewBag.ShowHash = !string.IsNullOrEmpty(hashResult);

            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Sha256(string? input, IFormFile? file)
        {
            string? hashResult = null;
            bool isFileMode = false;

            if (!string.IsNullOrEmpty(input))
            {
                using var sha = SHA256.Create();
                byte[] bytes = Encoding.UTF8.GetBytes(input);
                byte[] hash = await Task.Run(() => sha.ComputeHash(bytes));
                hashResult = BitConverter.ToString(hash).Replace("-", "").ToLower();
            }
            else if (file != null && file.Length > 0)
            {
                using var sha = SHA256.Create();
                using var stream = file.OpenReadStream();
                byte[] hash = await Task.Run(() => sha.ComputeHash(stream));
                hashResult = BitConverter.ToString(hash).Replace("-", "").ToLower();
                isFileMode = true;
            }

            ViewBag.HashResult = hashResult;
            ViewBag.InputText = input ?? string.Empty;
            ViewBag.IsFileMode = isFileMode;
            ViewBag.ShowHash = !string.IsNullOrEmpty(hashResult);

            return View();
        }
    }
}
