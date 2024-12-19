using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace ASVaultEncryption
{
    public class Vault
    {
        private readonly byte[] key;
        private readonly byte[] iv;

        public Vault(string password)
        {
            using (var sha256 = SHA256.Create())
            {
                key = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
            }
            iv = new byte[16]; // IV should be 16 bytes for AES
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(iv);
            }
        }

        public string Encrypt(string plainText)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        using (var sw = new StreamWriter(cs))
                        {
                            sw.Write(plainText);
                        }
                    }
                    var encrypted = ms.ToArray();
                    var result = new byte[iv.Length + encrypted.Length];
                    Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
                    Buffer.BlockCopy(encrypted, 0, result, iv.Length, encrypted.Length);
                    return Convert.ToBase64String(result);
                }
            }
        }

        public string Decrypt(string cipherText)
        {
            var fullCipher = Convert.FromBase64String(cipherText);
            using (var aes = Aes.Create())
            {
                var iv = new byte[aes.BlockSize / 8];
                var cipher = new byte[fullCipher.Length - iv.Length];

                Buffer.BlockCopy(fullCipher, 0, iv, 0, iv.Length);
                Buffer.BlockCopy(fullCipher, iv.Length, cipher, 0, cipher.Length);

                aes.Key = key;
                aes.IV = iv;
                var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using (var ms = new MemoryStream(cipher))
                {
                    using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    {
                        using (var sr = new StreamReader(cs))
                        {
                            return sr.ReadToEnd();
                        }
                    }
                }
            }
        }

        public void EncryptFile(string inputFile, string outputFile)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (var fsOutput = new FileStream(outputFile, FileMode.Create))
                {
                    // Write the IV to the output file first
                    fsOutput.Write(iv, 0, iv.Length);

                    using (var cs = new CryptoStream(fsOutput, encryptor, CryptoStreamMode.Write))
                    {
                        using (var fsInput = new FileStream(inputFile, FileMode.Open))
                        {
                            fsInput.CopyTo(cs);
                        }
                    }
                }
            }
        }

        public void DecryptFile(string inputFile, string outputFile)
        {
            using (var aes = Aes.Create())
            {
                var iv = new byte[aes.BlockSize / 8];
                using (var fsInput = new FileStream(inputFile, FileMode.Open))
                {
                    // Read the IV from the input file
                    fsInput.Read(iv, 0, iv.Length);

                    var decryptor = aes.CreateDecryptor(key, iv);

                    using (var cs = new CryptoStream(fsInput, decryptor, CryptoStreamMode.Read))
                    {
                        using (var fsOutput = new FileStream(outputFile, FileMode.Create))
                        {
                            cs.CopyTo(fsOutput);
                        }
                    }
                }
            }
        }

        public string DecryptStringFromFile(string inputFile)
        {
            using (var fsInput = new FileStream(inputFile, FileMode.Open))
            {
                var iv = new byte[16];
                fsInput.Read(iv, 0, iv.Length);

                using (var aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;

                    var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    using (var cs = new CryptoStream(fsInput, decryptor, CryptoStreamMode.Read))
                    {
                        using (var sr = new StreamReader(cs))
                        {
                            return sr.ReadToEnd();
                        }
                    }
                }
            }
        }
    }
}
