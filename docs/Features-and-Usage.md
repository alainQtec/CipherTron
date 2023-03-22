![LogoText](https://user-images.githubusercontent.com/79479952/188858942-da5021ad-35a2-4793-836b-3305e153e1df.png)

This module Includes custom 'data encryption' and protection functions:

## **Encrpt-Decrpt**

Data encryption and Protection functions

**[Encrypt-Object](https://github.com/alainQtec/CipherTron/blob/main/Private/CipherTron.Core/CipherTron.Core.psm1)**, **[Decrypt-Object](https://github.com/alainQtec/CipherTron/blob/main/Private/CipherTron.Core/CipherTron.Core.psm1)**, **[Protect-Data](https://github.com/alainQtec/CipherTron/blob/main/Private/CipherTron.Core/CipherTron.Core.psm1)** and **[UnProtect-Data](https://github.com/alainQtec/CipherTron/blob/main/Private/CipherTron.Core/CipherTron.Core.psm1)**

### Data Encryption

Applies several hybrid encryptions to an Object or a file.
Encryption can be applied to any item that can be converted to a byte array.
This function may currently encrypt Objects (i.e., "System. Object") and files.
The function employs Rijndael AES-256, Rivest-Shamir-Adleman encryption (RSA), MD5 Triple D.E.S, and other algorithms.
Yeah, it gets Pretty paranoid!

There is an option to store your encryption key(s) in Windows Password vault so that the
decryption function (Decrypt-Object) can use them without need of your input again.

```PowerShell
Encrypt-Object "Message"
```

### Data Protection

...

## **Secure Communication**

### WebSockets

The [System.Net.WebSockets namespace](https://learn.microsoft.com/en-us/dotnet/api/system.net.websockets) provides classes that you can use to create a WebSockets connection, send and receive data, and manage the connection.

You can use these classes to create your own cmdlets or functions that provide WebSockets support in PowerShell.

If you want to establish a secure WebSockets connection to another computer, you can use the New-WebSocketsSession cmdlet in PowerShell.
This cmdlet allows you to create a WebSockets connection to a remote server and send and receive data over the connection.
You can use the -SslProtocol parameter to specify the SSL/TLS protocol to use for the connection.

Ex:

```PowerShell
$session = New-WebSocketsSession -Uri "wss://example.com/websockets"

# Send a message over the WebSockets connection
Send-WebSocketsMessage -Session $session -Text "Hello, World!"

# Receive a message from the WebSockets connection
$message = Receive-WebSocketsMessage -Session $session

# Close the WebSockets connection
Close-WebSocketsSession -Session $session
```
### SSH

If you want to establish a secure shell (SSH) connection to another computer, you can use the `New-SshSession` cmdlet in PowerShell.
This cmdlet allows you to create an SSH connection to a remote computer and execute commands on it.
You can use the -Cipher parameter to specify the encryption cipher to use for the connection.

Ex:

```PowerShell
New-SshSession ... 😑🗿
```
