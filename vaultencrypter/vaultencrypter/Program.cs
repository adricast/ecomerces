using System;
using System.IO;
using ASVaultEncryption;

namespace VaultEncrypter
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Ingrese la contraseña para encriptar/desencriptar:");
            string password = Console.ReadLine();

            var vault = new Vault(password);

            while (true)
            {
                Console.WriteLine("Seleccione una opción:");
                Console.WriteLine("1. Encriptar archivo");
                Console.WriteLine("2. Desencriptar archivo");
                Console.WriteLine("3. Mostrar cadena de conexión desde archivo encriptado");
                Console.WriteLine("4. Salir");

                string option = Console.ReadLine();

                switch (option)
                {
                    case "1":
                        Console.WriteLine("Ingrese la ruta del archivo que desea encriptar:");
                        string inputFile = Console.ReadLine();

                        if (!File.Exists(inputFile))
                        {
                            Console.WriteLine("El archivo no existe. Por favor, verifique la ruta e intente nuevamente.");
                            break;
                        }

                        string encryptedFile = Path.Combine(Path.GetDirectoryName(inputFile), Path.GetFileNameWithoutExtension(inputFile) + ".enc");

                        try
                        {
                            vault.EncryptFile(inputFile, encryptedFile);
                            Console.WriteLine($"Archivo {inputFile} encriptado a {encryptedFile}");
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Error al encriptar el archivo: {ex.Message}");
                        }
                        break;

                    case "2":
                        Console.WriteLine("Ingrese la ruta del archivo que desea desencriptar:");
                        string encryptedInputFile = Console.ReadLine();

                        if (!File.Exists(encryptedInputFile))
                        {
                            Console.WriteLine("El archivo no existe. Por favor, verifique la ruta e intente nuevamente.");
                            break;
                        }

                        string decryptedFile = Path.Combine(Path.GetDirectoryName(encryptedInputFile), Path.GetFileNameWithoutExtension(encryptedInputFile) + ".txt");

                        try
                        {
                            vault.DecryptFile(encryptedInputFile, decryptedFile);
                            Console.WriteLine($"Archivo desencriptado a {decryptedFile}");
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Error al desencriptar el archivo: {ex.Message}");
                        }
                        break;

                    case "3":
                        Console.WriteLine("Ingrese la ruta del archivo encriptado para mostrar la cadena de conexión:");
                        string encryptedInputFileForConnection = Console.ReadLine();

                        if (!File.Exists(encryptedInputFileForConnection))
                        {
                            Console.WriteLine("El archivo no existe. Por favor, verifique la ruta e intente nuevamente.");
                            break;
                        }

                        try
                        {
                            // Crear un archivo temporal para desencriptar el contenido
                            string tempDecryptedFile = Path.GetTempFileName();
                            vault.DecryptFile(encryptedInputFileForConnection, tempDecryptedFile);

                            // Leer la cadena de conexión desde el archivo temporal
                            string connectionString = File.ReadAllText(tempDecryptedFile);
                            Console.WriteLine($"Cadena de conexión: {connectionString}");

                            // Eliminar el archivo temporal
                            File.Delete(tempDecryptedFile);
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Error al leer la cadena de conexión: {ex.Message}");
                        }
                        break;

                    case "4":
                        return;

                    default:
                        Console.WriteLine("Opción no válida. Por favor, seleccione una opción válida.");
                        break;
                }
            }
        }
    }
}
