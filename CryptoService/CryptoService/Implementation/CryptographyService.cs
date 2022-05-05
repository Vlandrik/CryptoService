using System.Security.Cryptography;
using System.Text;

namespace CryptoService.Implementation
{
    public class CryptographyService
    {
        private readonly string _pass;

        public CryptographyService(string pass)
        {
            _pass = pass;
        }

        // Only 128 can be used in Core
        private const int BlockSize = 128;
        private const int KeySize = BlockSize / 8;
        private const int DerivationIterations = 1000;
        private const string AlgorithmName = "Aes";

        public string Encrypt(string inputText)
        {
            // Generate Salt and IV
            var saltStringBytes = GenerateKeySizeBitsOfRandomEntropy();
            var ivStringBytes = GenerateKeySizeBitsOfRandomEntropy();
            var plainTextBytes = Encoding.UTF8.GetBytes(inputText);

            using var passwordAndSalt = new Rfc2898DeriveBytes(_pass, saltStringBytes, DerivationIterations);
            var keyBytes = passwordAndSalt.GetBytes(KeySize);

            using var symmetricKey = Aes.Create(AlgorithmName);

            if (symmetricKey == null)
                throw new ArgumentException("Algorithm Name is not valid");

            symmetricKey.BlockSize = BlockSize;
            symmetricKey.Mode = CipherMode.CBC;
            symmetricKey.Padding = PaddingMode.PKCS7;

            using var encryptor = symmetricKey.CreateEncryptor(keyBytes, ivStringBytes);
            using var memoryStream = new MemoryStream();
            using var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write);

            cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
            cryptoStream.FlushFinalBlock();

            // Final bytes of concatenation random salt bytes, random IV bytes and cipher bytes.
            var cipherTextBytes = saltStringBytes;
            cipherTextBytes = cipherTextBytes.Concat(ivStringBytes).ToArray();
            cipherTextBytes = cipherTextBytes.Concat(memoryStream.ToArray()).ToArray();

            memoryStream.Close();
            cryptoStream.Close();

            return Convert.ToBase64String(cipherTextBytes);
        }

        public string Decrypt(string inputText)
        {
            // Stream of: [KeySize bytes of Salt] + [KeySize bytes of IV] + [N bytes of CipherText]
            var cipherTextBytesWithSaltAndIv = Convert.FromBase64String(inputText);

            // Get Salt by extracting the first KeySize bytes then KeySize bytes of IV
            var saltStringBytes = cipherTextBytesWithSaltAndIv.Take(KeySize).ToArray();
            var ivStringBytes = cipherTextBytesWithSaltAndIv.Skip(KeySize).Take(KeySize).ToArray();

            // Get text bytes without Salt and IV
            var cipherTextBytes = cipherTextBytesWithSaltAndIv.Skip(KeySize * 2).Take(cipherTextBytesWithSaltAndIv.Length - (KeySize * 2))
                .ToArray();

            using var password = new Rfc2898DeriveBytes(_pass, saltStringBytes, DerivationIterations);

            var keyBytes = password.GetBytes(KeySize);

            using var symmetricKey = Aes.Create(AlgorithmName);

            if (symmetricKey == null)
                throw new ArgumentException("Algorithm Name is not valid");

            symmetricKey.BlockSize = BlockSize;
            symmetricKey.Mode = CipherMode.CBC;
            symmetricKey.Padding = PaddingMode.PKCS7;

            using var decryptor = symmetricKey.CreateDecryptor(keyBytes, ivStringBytes);
            using var decryptorMemoryStream = new MemoryStream(cipherTextBytes);
            using var decryptorCryptoStream = new CryptoStream(decryptorMemoryStream, decryptor, CryptoStreamMode.Read);

            var decryptorPlainTextBytes = new byte[cipherTextBytes.Length];
            var decryptedByteCount = 0;

            while (decryptedByteCount < decryptorPlainTextBytes.Length)
            {
                var bytesRead = decryptorCryptoStream.Read(decryptorPlainTextBytes, decryptedByteCount,
                    decryptorPlainTextBytes.Length - decryptedByteCount);

                if (bytesRead == 0)
                    break;

                decryptedByteCount += bytesRead;
            }

            decryptorMemoryStream.Close();
            decryptorCryptoStream.Close();

            return Encoding.UTF8.GetString(decryptorPlainTextBytes, 0, decryptedByteCount);
        }

        private static byte[] GenerateKeySizeBitsOfRandomEntropy()
        {
            var randomBytes = new byte[KeySize];
            using var rngCsp = RandomNumberGenerator.Create();

            // Fill the array with cryptographically secure random bytes.
            rngCsp.GetBytes(randomBytes);

            return randomBytes;
        }
    }
}