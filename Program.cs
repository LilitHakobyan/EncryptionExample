using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Serialization;

namespace EncryptionExample
{

    public class RsaEncryption
    {
        private readonly RSACryptoServiceProvider RSA_SERVICE = new (2048);
        private readonly RSAParameters PRIVATE_KEY;
        private readonly RSAParameters PUBLIC_KEY;

        public RsaEncryption()
        {
            this.PRIVATE_KEY = RSA_SERVICE.ExportParameters(true);
            this.PUBLIC_KEY = RSA_SERVICE.ExportParameters(false);
        }

        public string GetPublicKey()
        {
            var stringWriter = new StringWriter();
            var xmlSerializer = new XmlSerializer(typeof(RSAParameters));

            // serialize public key
            xmlSerializer.Serialize(stringWriter,this.PUBLIC_KEY);
            return stringWriter.ToString();
        }

        public string Encrypt(string plainText)
        {
            RSA_SERVICE.ImportParameters(this.PUBLIC_KEY);

            var data = Encoding.Unicode.GetBytes(plainText);
            var cypher = RSA_SERVICE.Encrypt(data, false);

            return Convert.ToBase64String(cypher);
        }

        public string Decrypt(string cypherText)
        {
            var dataBytes = Convert.FromBase64String(cypherText);
            RSA_SERVICE.ImportParameters(this.PRIVATE_KEY);

            var plainText = RSA_SERVICE.Decrypt(dataBytes, false);

            return Encoding.Unicode.GetString(plainText);
        }
    }

    public class Program
    {
        static void Main(string[] args)
        {
            var rsa = new RsaEncryption();

            Console.WriteLine($"Public key: {rsa.GetPublicKey()} \n");

            Console.WriteLine("Enter text to encrypt");
            var text = Console.ReadLine();

            if (string.IsNullOrWhiteSpace(text))
            {
                Console.WriteLine("Text is null");
                return;
            }

            var cypher = rsa.Encrypt(text);
            Console.WriteLine($"Encrypted text : {cypher}");

            Console.WriteLine("Press any key to decrypt");
            Console.ReadLine();

            var plainText = rsa.Decrypt(cypher);
            Console.WriteLine($"Decrypted text : {plainText}");

            Console.ReadKey();
        }
    }
}
