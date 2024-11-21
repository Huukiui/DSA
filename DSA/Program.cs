using System.Security.Cryptography;

namespace DSA
{
    internal class Program
    {
        static void Main(string[] args)
        {
            DSA dsa = new DSA();
            while (true)
            {
                Console.Clear();
                Console.WriteLine("\nМеню:");
                Console.WriteLine("1. Generate new keys");
                Console.WriteLine("2. Export keys");
                Console.WriteLine("3. Import keys");
                Console.WriteLine("4. Sign file");
                Console.WriteLine("5. Verify file signature");
                Console.WriteLine("6. Sign input");
                Console.WriteLine("7. Exit");
                Console.Write("Choose an option: ");
                string choice = Console.ReadLine();

                switch (choice)
                {
                    case "1":
                        dsa.GenerateKeys();
                        Console.WriteLine("Press any key to return....");
                        Console.ReadKey();
                        break;

                    case "2":
                        ExportKeys(dsa);
                        break;

                    case "3":
                        ImportKeys(dsa);
                        break;

                    case "4":
                        SignFile(dsa);
                        break;

                    case "5":
                        Verify(dsa);
                        break;

                    case "6":
                       SignInput(dsa);
                        break;

                    case "7":
                        Console.WriteLine("Closing the program.");
                        return;

                    default:
                        Console.WriteLine("Invalid option. Try again.");
                        break;
                }
            }
        }

        private static void ImportKeys(DSA dsa)
        {
            Console.Write("Enter file path to private key: ");
            string privateKeyPath = Console.ReadLine();
            Console.Write("Enter file path to public key: ");
            string publicKeyPath = Console.ReadLine();
            dsa.ImportKeys(privateKeyPath, publicKeyPath);

            Console.WriteLine("Press any key to return....");
            Console.ReadKey();
        }

        private static void ExportKeys(DSA dsa)
        {
            Console.Write("Enter file name to save private key: ");
            string privateKeyPath = Console.ReadLine();
            Console.Write("Enter file name to save public key: ");
            string publicKeyPath = Console.ReadLine();
            dsa.ExportKeys(privateKeyPath, publicKeyPath);

            Console.WriteLine("Press any key to return....");
            Console.ReadKey();
        }

        private static void SignFile(DSA dsa)
        {
            Console.Write("Enter file path to sign: ");
            string filePath = Console.ReadLine();
            if (File.Exists(filePath))
            {
                byte[] signature = dsa.SignFile(filePath);
                Console.WriteLine($"Sign: {BitConverter.ToString(signature).Replace("-", "")}");
                dsa.SaveSignature(filePath + ".sig", signature);
                Console.WriteLine($"Sign saved into file: {filePath}.sig");
            }
            else
            {
                Console.WriteLine("File doesnt exist.");
            }

            Console.WriteLine("Press any key to return....");
            Console.ReadKey();
        }

        private static void SignInput(DSA dsa)
        {
            Console.Write("Enter text to sign: ");
            string input = Console.ReadLine();
            byte[] signature = dsa.SignString(input);
            Console.WriteLine($"Sign: {BitConverter.ToString(signature).Replace("-", "")}");

            Console.WriteLine("Press any key to return....");
            Console.ReadKey();
        }

        private static void Verify(DSA dsa)
        {
            Console.Write("Enter file path to verify: ");
            string filePath = Console.ReadLine();
            Console.Write("Enter file path to signature file: ");
            string signaturePath = Console.ReadLine();
            if (File.Exists(filePath) && File.Exists(signaturePath))
            {
                byte[] signature = dsa.LoadSignature(signaturePath);
                bool isVerified = dsa.VerifyFile(filePath, signature);
                Console.WriteLine($"Signature verification result: {(isVerified ? "Success" : "Failure")}");
            }
            else
            {
                Console.WriteLine("File or signature doesnt exist.");
            }

            Console.WriteLine("Press any key to return....");
            Console.ReadKey();
        }
    }
}
