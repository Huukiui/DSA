using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Text.Json;
using System.IO;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace DSA
{
    public class DSA
    {
        private DSAParameters _privateKey;
        private DSAParameters _publicKey;

        public void GenerateKeys()
        {
            using (DSACryptoServiceProvider dsa = new DSACryptoServiceProvider())
            {
                _privateKey = dsa.ExportParameters(true);  // Приватний ключ
                _publicKey = dsa.ExportParameters(false); // Публічний ключ
                Console.WriteLine($"\nPublic: {_publicKey}\n");
                Console.WriteLine($"\nPrivate: {_privateKey}\n");
            }
        }

        public DSA() => GenerateKeys();

        public void ExportKeys(string privateKeyPath, string publicKeyPath)
        {
            File.WriteAllText(privateKeyPath, JsonSerializer.Serialize(_privateKey));
            File.WriteAllText(publicKeyPath, JsonSerializer.Serialize(_publicKey));
            Console.WriteLine("Exported keys.");
        }

        public void ImportKeys(string privateKeyPath, string publicKeyPath)
        {
            if (File.Exists(privateKeyPath))
            {
                _privateKey = JsonSerializer.Deserialize<DSAParameters>(File.ReadAllText(privateKeyPath));
            }
            if (File.Exists(publicKeyPath))
            {
                _publicKey = JsonSerializer.Deserialize<DSAParameters>(File.ReadAllText(publicKeyPath));
            }
            Console.WriteLine("Imported keys.");
            Console.WriteLine($"\nPublic: {_publicKey}\n");
            Console.WriteLine($"\nPrivate: {_privateKey}\n");
        }

        private byte[] ComputeHash(Stream dataStream)
        {
            using (SHA1 sha1 = SHA1.Create())
            {
                return sha1.ComputeHash(dataStream);
            }
        }

        public byte[] SignHash(byte[] hash)
        {
            using (DSACryptoServiceProvider dsa = new DSACryptoServiceProvider())
            {
                dsa.ImportParameters(_privateKey);
                return dsa.SignHash(hash, CryptoConfig.MapNameToOID("SHA1"));
            }
        }

        public byte[] SignString(string input)
        {  
            using (SHA1 sha1 = SHA1.Create())
            {
                byte[] dataBytes = Encoding.UTF8.GetBytes(input);
                byte[] hash =  sha1.ComputeHash(dataBytes);
                return SignHash(hash);
            }
        }

        public bool VerifyHash(byte[] hash, byte[] signature)
        {
            using (DSACryptoServiceProvider dsa = new DSACryptoServiceProvider())
            {
                dsa.ImportParameters(_publicKey);
                return dsa.VerifyHash(hash, CryptoConfig.MapNameToOID("SHA1"), signature);
            }
        }

        public byte[] SignFile(string filePath)
        {
            using (FileStream fileStream = File.OpenRead(filePath))
            {
                byte[] hash = ComputeHash(fileStream);
                return SignHash(hash);
            }
        }

        public bool VerifyFile(string filePath, byte[] signature)
        {
            using (FileStream fileStream = File.OpenRead(filePath))
            {
                byte[] hash = ComputeHash(fileStream);
                return VerifyHash(hash, signature);
            }
        }

        public void SaveSignature(string filePath, byte[] signature)
        {
            File.WriteAllText(filePath, BitConverter.ToString(signature).Replace("-", ""));
        }

        public byte[] LoadSignature(string filePath)
        {
            string hex = File.ReadAllText(filePath);
            int length = hex.Length / 2;
            byte[] signature = new byte[length];
            for (int i = 0; i < length; i++)
            {
                signature[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return signature;
        }
    }
}
