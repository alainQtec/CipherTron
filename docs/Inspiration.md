## Google's [Paranoid Project](https://github.com/google/paranoid_crypto)

After reading though this [repo](https://github.com/google/paranoid_crypto), I began to worry that my encrypted API keys and secrets weren't all that secure.

So I set out to build custom encryption and data protection functions that I'd be confident in and that would keep my data safe.

By default, .NET includes useful classes such as 'System.Security.Cryptography,' which may be accessed using cli.

However, as more powerful gear becomes available to everyone, encryptions are getting simpler to crack.

I wanted something weird, nerdy and different.

## Common **Algorithms**

When you google, you'll find that there are few common algorithms that most people use:

- **`AES`** ([Advanced Encryption Standard](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)): AES is a widely-used symmetric encryption algorithm that is known for its strong security and high performance.

It is the standard encryption algorithm used by the U.S. government and is often considered to be one of the most secure encryption algorithms available.

- **`RSA`** ([Rivest-Shamir-Adleman](<https://en.wikipedia.org/wiki/RSA_(cryptosystem)>)): RSA is an asymmetric encryption algorithm that is commonly used for encrypting messages that are sent over the internet.

It is considered to be one of the most secure encryption algorithms, but it can be slow to encrypt large amounts of data.

- **`ECC`** ([Elliptic Curve Cryptography](https://en.wikipedia.org/wiki/Elliptic-curve_cryptography)): ECC is a relatively new encryption algorithm that is based on the principles of elliptic curve theory.

It offers strong security and good performance, and is becoming increasingly popular for encrypting data in applications such as mobile devices and internet of things (IoT) devices.

Ultimately, the best encryption algorithm for you will depend on your specific security requirements and the constraints of your application.

But, as I already said, I wanted an approach that would be difficult to break even with a strong Rig. Some simple cli tool or a PowerShell module.

Something for those who wish to be paranoid about encrypting their data.

## Hybrid Encryption

Someone using this method wants to go hardcore as possible so all of the above are mixed/used together.

Hybrid encryption is a method of encrypting data that combines the use of both symmetric and asymmetric encryption.

In hybrid encryption, the data is first encrypted using a symmetric key, which is a type of encryption that uses the same key for both encryption and decryption.
This symmetrically encrypted data is then encrypted again using an asymmetric key, which is a type of encryption that uses a different key for encryption and decryption. The resulting encrypted data is much more secure than using either type of encryption on its own.

Here is a basic example in C# :

```c#
using System;
using System.IO;
using System.Security.Cryptography;

namespace HybridEncryptionExample
{
    class Program
    {
        static void Main(string[] args)
        {
            // Generate a random symmetric key.
            var aes = new AesCryptoServiceProvider();
            aes.GenerateKey();

            // Encrypt the symmetric key using the public key of the recipient.
            var rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(recipientPublicKey);
            var encryptedKey = rsa.Encrypt(aes.Key, true);

            // Encrypt the data using the symmetric key.
            var encryptor = aes.CreateEncryptor();
            using (var encryptedDataStream = new MemoryStream())
            using (var encryptorStream = new CryptoStream(encryptedDataStream, encryptor, CryptoStreamMode.Write))
            {
                encryptorStream.Write(dataToEncrypt, 0, dataToEncrypt.Length);
            }
            var encryptedData = encryptedDataStream.ToArray();

            // Combine the encrypted key and the encrypted data into a single message.
            var message = new byte[encryptedKey.Length + encryptedData.Length];
            Array.Copy(encryptedKey, 0, message, 0, encryptedKey.Length);
            Array.Copy(encryptedData, 0, message, encryptedKey.Length, encryptedData.Length);

            // Send the encrypted message to the recipient.
            SendMessage(message);
        }
    }
}

// In this example, we use the AesCryptoServiceProvider class to generate a random symmetric key, 
// and then use the RSACryptoServiceProvider class to encrypt the symmetric key using the public key of the recipient.
// The data to be encrypted is then encrypted using the symmetric key, and the encrypted key and encrypted data 
// are combined into a single message. This message can then be sent to the recipient, who can use their private key
// to decrypt the symmetric key and then use the decrypted symmetric key to decrypt the data.
```

This is what Inspired `[CipherTron](https://github.com/alainQtec/CipherTron)` module, It's the same implementation but in PowerShell, plus other tweaks.

