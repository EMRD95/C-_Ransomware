using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Linq;
using System.Collections.Generic;

class Program2
{
	static bool isPasswordValid = false;
    static void Main()
    {
        string userFolderPath = Environment.GetEnvironmentVariable("USERPROFILE");
        List<string> foldersToDecrypt = new List<string>
        {
            Path.Combine(userFolderPath, "Documents"),
            Path.Combine(userFolderPath, "Pictures")
        };
        Console.Write("Enter decryption password: ");
        string password = Console.ReadLine();

    foreach (var folderPath in foldersToDecrypt)
    {
        string hashFilePath = Path.Combine(folderPath, "passwordHash.txt");
        if (File.Exists(hashFilePath))
        {
            string savedHash = File.ReadAllText(hashFilePath).Trim();
            if (VerifyPasswordHash(password, savedHash))
            {
                isPasswordValid = true;
                break;
            }
        }
    }

    if (!isPasswordValid)
    {
        Console.WriteLine("Invalid password. Decryption aborted.");
        return;
    }

    // Proceed with decryption
    foreach (var folderPath in foldersToDecrypt)
    {
        DecryptFolder(folderPath, password);
    }
}

static void DecryptFolder(string folderPath, string password)
{
    try
    {
        var files = Directory.GetFiles(folderPath);
        foreach (var file in files)
        {
            try
            {
                DecryptFile(file, password);
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine("Access denied for file: " + file + ". Skipping...");
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred with file: " + file + ". Error: " + ex.Message);
            }
        }

        var subdirectories = Directory.GetDirectories(folderPath);
        foreach (var directory in subdirectories)
        {
            DecryptFolder(directory, password);
        }

        Console.WriteLine("Decryption complete for folder: " + folderPath);
    }
    catch (Exception ex)
    {
        Console.WriteLine("An error occurred in folder " + folderPath + ": " + ex.Message);
    }
}

    static string ComputeHash(string input)
    {
        using (SHA256 sha256Hash = SHA256.Create())
        {
            byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(input));
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < bytes.Length; i++)
            {
                builder.Append(bytes[i].ToString("x2"));
            }
            return builder.ToString();
        }
    }
	
static bool VerifyPasswordHash(string password, string savedHash)
{
    string computedHash = ComputeHash(password);
    return savedHash.Equals(computedHash);
}

static void DecryptFile(string filePath, string password)
{
    byte[] header = Encoding.UTF8.GetBytes("EncryptedFile00");
    byte[] fileHeader = new byte[header.Length];
    byte[] salt = new byte[16];

    using (FileStream inputFile = File.OpenRead(filePath))
    {
        // Read and check the header
        if (inputFile.Length > fileHeader.Length + salt.Length)
        {
            inputFile.Read(fileHeader, 0, fileHeader.Length);
            if (!fileHeader.SequenceEqual(header))
            {
                Console.WriteLine("File " + filePath + " does not have the correct header. Skipping...");
                return;
            }

            // Continue with decryption
            inputFile.Read(salt, 0, salt.Length);
        }
        else
        {
            Console.WriteLine("File " + filePath + " is not valid for decryption. Skipping...");
            return;
        }
    }

    // Now that the inputFile stream is closed, proceed with creating the output file
    string tempFilePath = filePath + ".tmp"; // Temporary file for decrypted content

    var key = new Rfc2898DeriveBytes(password, salt, 10000).GetBytes(32);
    using (var symmetricKey = new RijndaelManaged())
    {
        symmetricKey.KeySize = 256;
        symmetricKey.BlockSize = 128;
        symmetricKey.Padding = PaddingMode.Zeros;

        using (FileStream inputFile = File.OpenRead(filePath))
        using (FileStream outputFile = File.Create(tempFilePath))
        {
            // Skip the header and salt part in the input file
            inputFile.Seek(header.Length + salt.Length, SeekOrigin.Begin);

            using (CryptoStream cryptoStream = new CryptoStream(outputFile, symmetricKey.CreateDecryptor(key, new byte[16]), CryptoStreamMode.Write))
            {
                try
                {
                    inputFile.CopyTo(cryptoStream);
                }
                catch (CryptographicException ex)
                {
                    Console.WriteLine("Decryption failed for file " + filePath + ". Error: " + ex.Message);
                    File.Delete(tempFilePath); // Clean up temporary file
                    return;
                }
            }
        }
    }

    File.Delete(filePath); // Delete the original encrypted file
    File.Move(tempFilePath, filePath); // Replace it with the decrypted file
}


}