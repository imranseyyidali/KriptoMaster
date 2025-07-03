using System.Text;
using System.Security.Cryptography;

namespace SifrelemeProjesi.Models
{
    public class Sha512Service
    {
        public string ComputeHash(string input)
        {
            using (SHA512 sha = SHA512.Create())
            {
                byte[] bytes = Encoding.UTF8.GetBytes(input);
                byte[] hash = sha.ComputeHash(bytes);
                return BitConverter.ToString(hash).Replace("-", "").ToLower();
            }
        }
    }
}
