using System;
using System.Security.Cryptography;
using System.Text;

namespace KatanaContrib.Security.Odnoklassniki
{
    internal static class StringExtensions
    {
        internal static string GetMd5Hash(this string input)
        {
            var provider = new MD5CryptoServiceProvider();
            var bytes = Encoding.UTF8.GetBytes(input);
            bytes = provider.ComputeHash(bytes);
            return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
        }
    }
}
