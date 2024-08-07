using namespace System.IO
using namespace System.Web
using namespace System.Text
using namespace System.Net.Http
using namespace System.Security
using namespace System.Runtime.InteropServices

# .SYNOPSIS
#     Ciphertron is a personnal Cryptography assistance bot writen Purelly written in PowerShell
# .DESCRIPTION
#     CipherTron can do all sorts of stuff:
#         + It can act as your Password manger.
#         + It can also be used as a simple chat bot (This is still in Beta)
#     This is the Core, so all ../CipherTron.psm1 functions are built based on classes in this file.
# .NOTES
#     [+] Most of the methods work. (Most).
#     [+] This file is over 4000 lines of code (All in One), so use regions code folding if your editor supports it.
# .LINK
#     https://gist.github.com/alainQtec/217860de99e8ddb89a8820add6f6980f
# .LINK
#     https://github.com/alainQtec/CipherTron/blob/main/Private/CipherTron.Core/CipherTron.Core.psm1
# .EXAMPLE
#     iex $((Invoke-RestMethod -Method Get https://api.github.com/gists/217860de99e8ddb89a8820add6f6980f).files.'CipherTron.Core.ps1'.content)
#     $bot = [CipherTron]::new()
#     $bot.Chat()
#Requires -Version 5.1

# Load all necessary dlls:
$script:RuntimeDir = [Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory(); @(
    'Microsoft.PowerShell.Commands.Utility'
).ForEach({ [void][System.Reflection.Assembly]::LoadFile([System.IO.Path]::Combine($RuntimeDir, "$_.dll")) })
# Load localizedData:
$dataFile = [System.IO.FileInfo]::new([IO.Path]::Combine((Get-Variable -ValueOnly ExecutionContext).SessionState.path.CurrentLocation.Path, "en-US", "CipherTron.strings.psd1"))
if ($dataFile.Exists) {
    $script:localizedData = [scriptblock]::Create("$([IO.File]::ReadAllText($dataFile))").Invoke()
} else {
    Write-Warning 'FileNotFound: Unable to find the LocalizedData file CipherTron.strings.psd1.'
}
#region    Helpers

#region    enums

enum EncryptionScope {
    User    # The encrypted data can be decrypted with the same user on any machine.
    Machine # The encrypted data can only be decrypted with the same user on the same machine it was encrypted on.
}

enum CipherType {
    Caesar
    Polybius
}
enum keyStoreMode {
    Vault
    KeyFile
    SecureString
}
enum KeyExportPolicy {
    NonExportable
    ExportableEncrypted
    Exportable
}
enum KeyProtection {
    None
    Protect
    ProtectHigh
    ProtectFingerPrint
}
enum KeyUsage {
    None
    EncipherOnly
    CRLSign
    CertSign
    KeyAgreement
    DataEncipherment
    KeyEncipherment
    NonRepudiation
    DigitalSignature
    DecipherOnly
}
enum X509ContentType {
    Unknown
    Cert
    SerializedCert
    Pfx
    PEM
    Pkcs12
    SerializedStore
    Pkcs7
    Authenticode
}
enum SdCategory {
    Token
    Password
}
enum ExpType {
    Milliseconds
    Years
    Months
    Days
    Hours
    Minutes
    Seconds
}
enum CertStoreName {
    MY
    ROOT
    TRUST
    CA
}
# Only Encryption algorithms that are widely trusted and used in real-world
enum CryptoAlgorithm {
    AesGCM # AES-GCM (Galois/Counter Mode). A strong encryption on its own that doesn't necessarily with its built-in authentication functions. Its a mode of operation for AES that provides both confidentiality and authenticity for the encrypted data. GCM provides faster encryption and decryption compared to CBC mode and is widely used for secure communication, especially in VPN and TLS/SSL apps.
    ChaCha20 # ChaCha20 + SHA256 in this case. I would prefer ChaCha20Poly1305 but the Poly1305 class is still not working/usable. But no wories, ChaCha20 is like the salsa of the cryptography world, it's got the moves to keep your data secure and grooving to its own beat! :) Get it? [ref] to the dance-like steps performed in the algorithm's mixing process? Nevermind ... Its a symmetric key encryption algorithm, based on salsa20 algorithm. ChaCha20 provides the encryption, while Poly1305 (or SHA256 in this case) provides the authentication. This combination provides both confidentiality and authenticity for the encrypted data.
    RsaAesHMAC # RSA + AES + HMAC: This combination uses RSA for key exchange, AES for encryption, and HMAC (hash-based message authentication code) for authentication. This provides a secure mechanism for exchanging keys and encrypting data, as well as a way to verify the authenticity of the data. ie: By combining RSA and AES, one can take advantage of both algorithms' strengths: RSA is used to securely exchange the AES key, while AES is be used for the actual encryption and decryption of the data. This way, RSA provides security for key exchange, and AES provides fast encryption and decryption for the data.
    RsaECDSA # RSA + ECDSA (Elliptic Curve Digital Signature Algorithm) are public-key cryptography algorithms that are often used together. RSA can be used for encrypting data, while ECDSA can be used for digital signatures, providing both confidentiality and authenticity for the data.
    RsaOAEP # RSA-OAEP (Optimal Asymmetric Encryption Padding)
}
# System.Security.Cryptography.RSAEncryptionPadding Names
enum RSAPadding {
    Pkcs1
    OaepSHA1
    OaepSHA256
    OaepSHA384
    OaepSHA512
}
enum Compression {
    Gzip
    Deflate
    ZLib
    # Zstd # Todo: Add Zstandard. (The one from facebook. or maybe zstd-sharp idk. I just can't find a way to make it work in powershell! no dll nothing!)
}

enum CredFlags {
    None = 0x0
    PromptNow = 0x2
    UsernameTarget = 0x4
}

enum CredType {
    Generic = 1
    DomainPassword = 2
    DomainCertificate = 3
    DomainVisiblePassword = 4
    GenericCertificate = 5
    DomainExtended = 6
    Maximum = 7
    MaximumEx = 1007 # (Maximum + 1000)
}

enum CredentialPersistence {
    Session = 1
    LocalComputer = 2
    Enterprise = 3
}

#endregion enums

class InvalidArgumentException : System.Exception {
    [string]$paramName
    [string]$Message
    InvalidArgumentException() {
        $this.message = 'Invalid argument'
    }
    InvalidArgumentException([string]$paramName) {
        $this.paramName = $paramName
        $this.message = "Invalid argument: $paramName"
    }
    InvalidArgumentException([string]$paramName, [string]$message) {
        $this.paramName = $paramName
        $this.message = $message
    }
}

# Static class for calling the native credential functions
class CredentialNotFoundException : System.Exception, System.Runtime.Serialization.ISerializable {
    [string]$Message; [Exception]$InnerException; hidden $Info; hidden $Context
    CredentialNotFoundException() { $this.Message = 'CredentialNotFound' }
    CredentialNotFoundException([string]$message) { $this.Message = $message }
    CredentialNotFoundException([string]$message, [Exception]$InnerException) { ($this.Message, $this.InnerException) = ($message, $InnerException) }
    CredentialNotFoundException([System.Runtime.Serialization.SerializationInfo]$info, [System.Runtime.Serialization.StreamingContext]$context) { ($this.Info, $this.Context) = ($info, $context) }
}
class IntegrityCheckFailedException : System.Exception {
    [string]$Message; [Exception]$InnerException;
    IntegrityCheckFailedException() { }
    IntegrityCheckFailedException([string]$message) { $this.Message = $message }
    IntegrityCheckFailedException([string]$message, [Exception]$innerException) { $this.Message = $message; $this.InnerException = $innerException }
}
class InvalidPasswordException : System.Exception {
    [string]$Message; [string]hidden $Passw0rd; [securestring]hidden $Password; [System.Exception]$InnerException
    InvalidPasswordException() { $this.Message = "Invalid password" }
    InvalidPasswordException([string]$Message) { $this.message = $Message }
    InvalidPasswordException([string]$Message, [string]$Passw0rd) { ($this.message, $this.Passw0rd, $this.InnerException) = ($Message, $Passw0rd, [System.Exception]::new($Message)) }
    InvalidPasswordException([string]$Message, [securestring]$Password) { ($this.message, $this.Password, $this.InnerException) = ($Message, $Password, [System.Exception]::new($Message)) }
    InvalidPasswordException([string]$Message, [string]$Passw0rd, [System.Exception]$InnerException) { ($this.message, $this.Passw0rd, $this.InnerException) = ($Message, $Passw0rd, $InnerException) }
    InvalidPasswordException([string]$Message, [securestring]$Password, [System.Exception]$InnerException) { ($this.message, $this.Password, $this.InnerException) = ($Message, $Password, $InnerException) }
}

class cPsObject : PsObject {
    cPsObject([System.Object]$Object) {
        $types = (($Object | Get-Member).Typename | Sort-Object -Unique)
        $ogtyp = if ($types.count -eq 1) { $types -as 'type' } else { $Object.GetType() }
        $b64sb = [convert]::ToBase64String($(if ($types.Equals("System.Byte")) { [byte[]]$Object } else { [xconvert]::BytesFromObject($Object) }))
        $this.PsObject.properties.add([psscriptproperty]::new('Type', [scriptblock]::Create("[Type]'$ogtyp'")))
        $this.PsObject.properties.add([psscriptproperty]::new('Bytes', [scriptblock]::Create("[Convert]::FromBase64String('$b64sb')")))
        $this.PsObject.properties.add([psscriptproperty]::new('SecScope', [scriptblock]::Create('[EncryptionScope]::User')))
        $this.PsObject.Methods.Add(
            [psscriptmethod]::new(
                'Protect', {
                    $_bytes = $this.Bytes; $Entropy = [System.Text.Encoding]::UTF8.GetBytes([CryptoBase]::GetUniqueMachineId())[0..15]
                    $_bytes = [xconvert]::ToProtected($_bytes, $Entropy, $this.SecScope)
                    $this.PsObject.properties.add([psscriptproperty]::new('Bytes', [scriptblock]::Create($_bytes)))
                }
            )
        )
        $this.PsObject.Methods.Add(
            [psscriptmethod]::new(
                'UnProtect', {
                    $_bytes = $this.Bytes; $Entropy = [System.Text.Encoding]::UTF8.GetBytes([CryptoBase]::GetUniqueMachineId())[0..15]
                    $_bytes = [xconvert]::ToUnProtected($_bytes, $Entropy, $this.SecScope)
                    $this.PsObject.properties.add([psscriptproperty]::new('Bytes', [scriptblock]::Create($_bytes)))
                }
            )
        )
        $this.PsObject.Methods.Add(
            [psscriptmethod]::new(
                'Tostring', {
                    return $this.PsObject.properties.value[0].name
                }
            )
        )
    }
}

# .SYNOPSIS
# A simple progress utility class
# .EXAMPLE
# $OgForeground = (Get-Variable host).Value.UI.RawUI.ForegroundColor
# (Get-Variable host).Value.UI.RawUI.ForegroundColor = [ConsoleColor]::Green
# for ($i = 0; $i -le 100; $i++) {
#     [ProgressUtil]::WriteProgressBar($i)
#     [System.Threading.Thread]::Sleep(50)
# }
# (Get-Variable host).Value.UI.RawUI.ForegroundColor = $OgForeground
# [progressUtil]::WaitJob("waiting", { Start-Sleep -Seconds 3 })
class ProgressUtil {
    static hidden [string] $_block = '■';
    static hidden [string] $_back = "`b";
    static hidden [string[]] $_twirl = @(
        "+■0", "-\\|/", "|/-\\"
    );
    static [int] $_twirlIndex = 0
    static hidden [string]$frames
    static [void] WriteProgressBar([int]$percent) {
        [ProgressUtil]::WriteProgressBar($percent, $true)
    }
    static [void] WriteProgressBar([int]$percent, [bool]$update) {
        [ProgressUtil]::WriteProgressBar($percent, $update, [int]([Console]::WindowWidth * 0.7))
    }
    static [void] WriteProgressBar([int]$percent, [bool]$update, [int]$PBLength) {
        [ValidateNotNull()][int]$PBLength = $PBLength
        [ValidateNotNull()][int]$percent = $percent
        [ValidateNotNull()][bool]$update = $update
        [ProgressUtil]::_back = "`b" * [Console]::WindowWidth
        if ($update) { [Console]::Write([ProgressUtil]::_back) }
        [Console]::Write("["); $p = [int](($percent / 100.0) * $PBLength + 0.5)
        for ($i = 0; $i -lt $PBLength; $i++) {
            if ($i -ge $p) {
                [Console]::Write(' ');
            } else {
                [Console]::Write([ProgressUtil]::_block);
            }
        }
        [Console]::Write("] {0,3:##0}%", $percent);
    }
    static [System.Management.Automation.Job] WaitJob([string]$progressMsg, [scriptblock]$Job) {
        return [ProgressUtil]::WaitJob($progressMsg, $(Start-Job -ScriptBlock $Job))
    }
    static [System.Management.Automation.Job] WaitJob([string]$progressMsg, [System.Management.Automation.Job]$Job) {
        [Console]::CursorVisible = $false;
        [ProgressUtil]::frames = [ProgressUtil]::_twirl[0]
        [int]$length = [ProgressUtil]::frames.Length;
        $originalY = [Console]::CursorTop
        while ($Job.JobStateInfo.State -notin ('Completed', 'failed')) {
            for ($i = 0; $i -lt $length; $i++) {
                [ProgressUtil]::frames.Foreach({ [Console]::Write("$progressMsg $($_[$i])") })
                [System.Threading.Thread]::Sleep(50)
                [Console]::Write(("`b" * ($length + $progressMsg.Length)))
                [Console]::CursorTop = $originalY
            }
        }
        Write-Host "`b$progressMsg ... " -NoNewline -ForegroundColor Magenta
        [System.Management.Automation.Runspaces.RemotingErrorRecord[]]$Errors = $Job.ChildJobs.Where({
                $null -ne $_.Error
            }
        ).Error;
        if ($Job.JobStateInfo.State -eq "Failed" -or $Errors.Count -gt 0) {
            $errormessages = [string]::Empty
            if ($null -ne $Errors) {
                $errormessages = $Errors.Exception.Message -join "`n"
            }
            Write-Host "Completed with errors.`n`t$errormessages" -ForegroundColor Red
        } else {
            Write-Host "Done." -ForegroundColor Green
        }
        [Console]::CursorVisible = $true;
        return $Job
    }
}
class NetworkManager {
    [string] $HostName
    static [System.Net.IPAddress[]] $IPAddresses
    static [recordTbl] $DownloadOptions = [recordTbl]::New(@{
            ShowProgress      = $true
            ProgressBarLength = [int]([Console]::WindowWidth * 0.7)
            ProgressMessage   = [string]::Empty
            RetryTimeout      = 1000 #(milliseconds)
            Headers           = @{}
            Proxy             = $null
            Force             = $false
        }
    )
    static [string] $caller

    NetworkManager ([string]$HostName) {
        $this.HostName = $HostName
        $this::IPAddresses = [System.Net.Dns]::GetHostAddresses($HostName)
    }
    static [string] GetResponse ([string]$URL) {
        [System.Net.HttpWebRequest]$Request = [System.Net.HttpWebRequest]::Create($URL)
        $Request.Method = "GET"
        $Request.Timeout = 10000 # 10 seconds
        [System.Net.HttpWebResponse]$Response = [System.Net.HttpWebResponse]$Request.GetResponse()
        if ($Response.StatusCode -eq [System.Net.HttpStatusCode]::OK) {
            [System.IO.Stream]$ReceiveStream = $Response.GetResponseStream()
            [System.IO.StreamReader]$ReadStream = [System.IO.StreamReader]::new($ReceiveStream)
            [string]$Content = $ReadStream.ReadToEnd()
            $ReadStream.Close()
            $Response.Close()
            return $Content
        } else {
            throw "The request failed with status code: $($Response.StatusCode)"
        }
    }
    static [void] BlockAllOutbound() {
        $HostOs = [cryptobase]::Get_Host_Os()
        if ($HostOs -eq "Linux") {
            sudo iptables -P OUTPUT DROP
        } else {
            netsh advfirewall set allprofiles firewallpolicy blockinbound, blockoutbound
        }
    }
    static [void] UnblockAllOutbound() {
        $HostOs = [cryptobase]::Get_Host_Os()
        if ($HostOs -eq "Linux") {
            sudo iptables -P OUTPUT ACCEPT
        } else {
            netsh advfirewall set allprofiles firewallpolicy blockinbound, allowoutbound
        }
    }
    static [IO.FileInfo] DownloadFile([uri]$url) {
        # No $outFile so we create ones ourselves, and use suffix to prevent duplicaltes
        $randomSuffix = [Guid]::NewGuid().Guid.subString(15).replace('-', [string]::Join('', (0..9 | Get-Random -Count 1)))
        return [NetworkManager]::DownloadFile($url, "$(Split-Path $url.AbsolutePath -Leaf)_$randomSuffix");
    }
    static [IO.FileInfo] DownloadFile([uri]$url, [string]$outFile) {
        return [NetworkManager]::DownloadFile($url, $outFile, $false)
    }
    static [IO.FileInfo] DownloadFile([uri]$url, [string]$outFile, [bool]$Force) {
        [ValidateNotNullOrEmpty()][uri]$url = $url; [ValidateNotNull()][bool]$Force = ($Force -as [bool])
        [ValidateNotNullOrEmpty()][string]$outFile = $outFile; $stream = $null;
        $fileStream = $null; $name = Split-Path $url -Leaf;
        $request = [System.Net.HttpWebRequest]::Create($url)
        $request.UserAgent = "Mozilla/5.0"
        $response = $request.GetResponse()
        $contentLength = $response.ContentLength
        $stream = $response.GetResponseStream()
        $buffer = New-Object byte[] 1024
        $outPath = [CryptoBase]::GetUnResolvedPath($outFile)
        if ([System.IO.Directory]::Exists($outFile)) {
            if (!$Force) { throw [InvalidArgumentException]::new("outFile", "Please provide valid file path, not a directory.") }
            $outPath = Join-Path -Path $outFile -ChildPath $name
        }
        $Outdir = [IO.Path]::GetDirectoryName($outPath)
        if (![System.IO.Directory]::Exists($Outdir)) { [void][System.IO.Directory]::CreateDirectory($Outdir) }
        if ([IO.File]::Exists($outPath)) {
            if (!$Force) { throw "$outFile already exists" }
            Remove-Item $outPath -Force -ErrorAction Ignore | Out-Null
        }
        $fileStream = [System.IO.FileStream]::new($outPath, [IO.FileMode]::Create, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        $totalBytesReceived = 0
        $totalBytesToReceive = $contentLength
        $OgForeground = (Get-Variable host).Value.UI.RawUI.ForegroundColor
        $Progress_Msg = [NetworkManager]::DownloadOptions.ProgressMessage
        if ([string]::IsNullOrWhiteSpace($Progress_Msg)) { $Progress_Msg = "[+] Downloading $name to $Outfile" }
        Write-Host $Progress_Msg -ForegroundColor Magenta
        (Get-Variable host).Value.UI.RawUI.ForegroundColor = [ConsoleColor]::Green
        while ($totalBytesToReceive -gt 0) {
            $bytesRead = $stream.Read($buffer, 0, 1024)
            $totalBytesReceived += $bytesRead
            $totalBytesToReceive -= $bytesRead
            $fileStream.Write($buffer, 0, $bytesRead)
            if ([NetworkManager]::DownloadOptions.ShowProgress) {
                [ProgressUtil]::WriteProgressBar([int]($totalBytesReceived / $contentLength * 100), $true, [NetworkManager]::DownloadOptions.progressBarLength);
            }
        }
        (Get-Variable host).Value.UI.RawUI.ForegroundColor = $OgForeground
        try { Invoke-Command -ScriptBlock { $stream.Close(); $fileStream.Close() } -ErrorAction SilentlyContinue } catch { $null }
        return (Get-Item $outFile)
    }
    static [void] UploadFile ([string]$SourcePath, [string]$DestinationURL) {
        Invoke-RestMethod -Uri $DestinationURL -Method Post -InFile $SourcePath
    }
    static [bool] TestConnection ([string]$HostName) {
        [ValidateNotNullOrEmpty()][string]$HostName = $HostName
        if (![bool]("System.Net.NetworkInformation.Ping" -as 'type')) { Add-Type -AssemblyName System.Net.NetworkInformation };
        $cs = $null; $cc = [NetworkManager]::caller; $re = @{ true = @{ m = "Success"; c = "Green" }; false = @{ m = "Failed"; c = "Red" } }
        Write-Host "$cc Testing Connection ... " -ForegroundColor Blue -NoNewline
        try {
            [System.Net.NetworkInformation.PingReply]$PingReply = [System.Net.NetworkInformation.Ping]::new().Send($HostName);
            $cs = $PingReply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success
        } catch [System.Net.Sockets.SocketException], [System.Net.NetworkInformation.PingException] {
            $cs = $false
        } catch {
            $cs = $false;
            Write-Error $_
        }
        $re = $re[$cs.ToString()]
        Write-Host $re.m -ForegroundColor $re.c
        return $cs
    }
}

class EncodingBase : System.Text.ASCIIEncoding {
    EncodingBase() {}
    static [byte[]] GetBytes([string] $text) {
        return [EncodingBase]::new().GetBytes($text)
    }
    static [string] GetString([byte[]]$bytes) {
        return [EncodingBase]::new().GetString($bytes)
    }
    static [char[]] GetChars([byte[]]$bytes) {
        return [EncodingBase]::new().GetChars($bytes)
    }
}

#region    CryptoBase
class CryptoBase {
    static hidden [string] $caller
    [ValidateNotNull()][byte[]]hidden $_salt
    [ValidateNotNull()][byte[]]hidden $_bytes
    static [ValidateNotNull()][EncryptionScope] $EncryptionScope
    [ValidateNotNull()][securestring]hidden $_Password
    [ValidateNotNull()][CryptoAlgorithm]hidden $_Algorithm

    CryptoBase() {}

    static [string] GetRandomName() {
        return [CryptoBase]::GetRandomName((Get-Random -min 16 -max 80));
    }
    static [string] GetRandomName([int]$Length) {
        return [string][CryptoBase]::GetRandomName($Length, $Length);
    }
    static [string] GetRandomName([bool]$IncludeNumbers) {
        $Length = Get-Random -min 16 -max 80
        return [string][CryptoBase]::GetRandomName($Length, $Length, $IncludeNumbers);
    }
    static [string] GetRandomName([int]$Length, [bool]$IncludeNumbers) {
        return [string][CryptoBase]::GetRandomName($Length, $Length, $IncludeNumbers);
    }
    static [string] GetRandomName([int]$minLength, [int]$maxLength) {
        return [string][CryptoBase]::GetRandomName($minLength, $maxLength, $false);
    }
    static [string] GetRandomName([int]$minLength, [int]$maxLength, [bool]$IncludeNumbers) {
        [int]$iterations = 2; $MinrL = 3; $MaxrL = 999 #Gotta have some restrictions, or one typo could slow down an entire script.
        if ($minLength -lt $MinrL) { Write-Warning "Length is below the Minimum required 'String Length'. Try $MinrL or greater." ; Break }
        if ($maxLength -gt $MaxrL) { Write-Warning "Length is greater the Maximum required 'String Length'. Try $MaxrL or lower." ; Break }
        $samplekeys = if ($IncludeNumbers) {
            [string]::Join('', ([int[]](97..122) | ForEach-Object { [string][char]$_ }) + (0..9))
        } else {
            [string]::Join('', ([int[]](97..122) | ForEach-Object { [string][char]$_ }))
        }
        return [string][CryptoBase]::GetRandomSTR($samplekeys, $iterations, $minLength, $maxLength);
    }
    static [byte[]] GetDerivedBytes() {
        return [CryptoBase]::GetDerivedBytes(16)
    }
    static [byte[]] GetDerivedBytes([int]$Length) {
        return [CryptoBase]::GetDerivedBytes([xconvert]::ToSecurestring([CryptoBase]::GetRandomName(16)), $Length)
    }
    static [byte[]] GetDerivedBytes([securestring]$password) {
        return [CryptoBase]::GetDerivedBytes($password, 16)
    }
    static [byte[]] GetDerivedBytes([securestring]$password, [int]$Length) {
        $pswd = [xconvert]::ToSecurestring($(switch ([CryptoBase]::EncryptionScope.ToString()) {
                    "Machine" {
                        [System.Text.Encoding]::UTF8.GetBytes([CryptoBase]::GetUniqueMachineId())
                    }
                    Default {
                        [convert]::FromBase64String("hsKgmva9wZoDxLeREB1udw==")
                    }
                }
            )
        )
        $s6lt = [System.Security.Cryptography.Rfc2898DeriveBytes]::new($password, [System.Text.Encoding]::UTF8.GetBytes([xconvert]::ToString($password))).GetBytes(16)
        return [CryptoBase]::GetDerivedBytes($pswd, $s6lt, $Length)
    }
    static [byte[]] GetDerivedBytes([securestring]$password, [byte[]]$salt, [int]$Length) {
        return [System.Security.Cryptography.Rfc2898DeriveBytes]::new($password, $salt, 1000).GetBytes($Length);
    }
    static [byte[]] GetKey() {
        return [CryptoBase]::GetKey(16);
    }
    static [byte[]] GetKey([int]$Length) {
        return [CryptoBase]::GetKey([xconvert]::ToSecurestring([CryptoBase]::GeneratePassword()), $Length)
    }
    static [byte[]] GetKey([securestring]$password) {
        return [CryptoBase]::GetKey($password, 16)
    }
    static [byte[]] GetKey([securestring]$password, [int]$Length) {
        return [CryptoBase]::GetDerivedBytes($password, $Length)
    }
    static [byte[]] GetKey([securestring]$password, [byte[]]$salt) {
        return [CryptoBase]::GetKey($password, $salt, 16)
    }
    static [byte[]] GetKey([securestring]$password, [byte[]]$salt, [int]$Length) {
        return [CryptoBase]::GetDerivedBytes($password, $salt, $Length)
    }
    # can be used to generate random IV
    static [byte[]] GetRandomEntropy() {
        [byte[]]$entropy = [byte[]]::new(16);
        [void][System.Security.Cryptography.RNGCryptoServiceProvider]::new().GetBytes($entropy)
        return $entropy;
    }
    # Uses a cryptographic hash function (SHA-256) to generate a unique machine ID
    static hidden [string] GetRandomSTR([string]$InputSample, [int]$iterations, [int]$minLength, [int]$maxLength) {
        if ($maxLength -lt $minLength) { throw [System.ArgumentOutOfRangeException]::new('MinLength', "'MaxLength' cannot be less than 'MinLength'") }
        if ($iterations -le 0) { Write-Warning 'Negative and Zero Iterations are NOT Possible!'; return [string]::Empty }
        [char[]]$chars = [char[]]::new($InputSample.Length);
        $chars = $InputSample.ToCharArray();
        $Keys = [System.Collections.Generic.List[string]]::new();
        $rand = [Random]::new();
        [int]$size = $rand.Next([int]$minLength, [int]$maxLength);
        for ($i = 0; $i -lt $iterations; $i++) {
            [byte[]] $data = [Byte[]]::new(1);
            $crypto = [System.Security.Cryptography.RNGCryptoServiceProvider]::new();
            $data = [Byte[]]::new($size);
            $crypto.GetNonZeroBytes($data);
            $result = [System.Text.StringBuilder]::new($size);
            foreach ($b In $data) { $result.Append($chars[$b % ($chars.Length - 1)]) };
            [void]$Keys.Add($result.ToString());
        }
        $STR = [string]::Join('', $keys)
        if ($STR.Length -gt $maxLength) {
            $STR = $STR.Substring(0, $maxLength);
        }
        return $STR;
    }
    static [string] GeneratePassword() {
        return [string][CryptoBase]::GeneratePassword(19);
    }
    static [string] GeneratePassword([int]$Length) {
        return [string][CryptoBase]::GeneratePassword($Length, $false, $false, $false, $false);
    }
    static [string] GeneratePassword([int]$Length, [bool]$StartWithLetter) {
        return [string][CryptoBase]::GeneratePassword($Length, $StartWithLetter, $false, $false, $false);
    }
    static [string] GeneratePassword([int]$Length, [bool]$StartWithLetter, [bool]$NoSymbols, [bool]$UseAmbiguousCharacters, [bool]$UseExtendedAscii) {
        # https://stackoverflow.com/questions/55556/characters-to-avoid-in-automatically-generated-passwords
        [string]$possibleCharacters = [char[]](33..126 + 161..254); $MinrL = 14; $MaxrL = 999 # Gotta have some restrictions, or one typo could endup creating insanely long or small Passwords, ex 30000 intead of 30.
        if ($Length -lt $MinrL) { Write-Warning "Length is below the Minimum required 'Password Length'. Try $MinrL or greater."; Break }
        if ($Length -gt $MaxrL) { Write-Warning "Length is greater the Maximum required 'Password Length'. Try $MaxrL or lower."; Break }
        # Warn the user if they've specified mutually-exclusive options.
        if ($NoSymbols -and $UseExtendedAscii) { Write-Warning 'The -NoSymbols parameter was also specified.  No extended ASCII characters will be used.' }
        do {
            $Passw0rd = [string]::Empty; $x = $null; $r = 0
            #This person Wants a really good password, so We retry Until we get a 60% strong password.
            do {
                do {
                    do {
                        do {
                            do {
                                $x = [int][char][string][CryptoBase]::GetRandomSTR($possibleCharacters, 1, 1, 1);
                                # Write-Verbose "Use character: $([char]$x) : $x"
                            } While ($x -eq 127 -Or (!$UseExtendedAscii -and $x -gt 127))
                            # The above Do..While loop does this:
                            #  1. Don't allow ASCII 127 (delete).
                            #  2. Don't allow extended ASCII, unless the user wants it.
                        } While (!$UseAmbiguousCharacters -and ($x -In @(49, 73, 108, 124, 48, 79)))
                        # The above loop disallows 1 (ASCII 49), I (73), l (108),
                        # | (124), 0 (48) or O (79) -- unless the user wants those.
                    } While ($NoSymbols -and ($x -lt 48 -Or ($x -gt 57 -and $x -lt 65) -Or ($x -gt 90 -and $x -lt 97) -Or $x -gt 122))
                    # If the -NoSymbols parameter was specified, this loop will ensure
                    # that the character is neither a symbol nor in the extended ASCII
                    # character set.
                } While ($r -eq 0 -and $StartWithLetter -and !(($x -ge 65 -and $x -le 90) -Or ($x -ge 97 -and $x -le 122)))
                # If the -StartWithLetter parameter was specified, this loop will make
                # sure that the first character is an upper- or lower-case letter.
                $Passw0rd = $Passw0rd.Trim()
                $Passw0rd += [string][char]$x; $r++
            } until ($Passw0rd.length -eq $Length)
        } until ([int][CryptoBase]::GetPasswordStrength($Passw0rd) -gt 60)
        return $Passw0rd;
    }
    [int] static GetPasswordStrength([string]$passw0rd) {
        # Inspired by: https://www.security.org/how-secure-is-my-password/
        $passwordDigits = [System.Text.RegularExpressions.Regex]::new("\d", [System.Text.RegularExpressions.RegexOptions]::Compiled);
        $passwordNonWord = [System.Text.RegularExpressions.Regex]::new("\W", [System.Text.RegularExpressions.RegexOptions]::Compiled);
        $passwordUppercase = [System.Text.RegularExpressions.Regex]::new("[A-Z]", [System.Text.RegularExpressions.RegexOptions]::Compiled);
        $passwordLowercase = [System.Text.RegularExpressions.Regex]::new("[a-z]", [System.Text.RegularExpressions.RegexOptions]::Compiled);
        [int]$strength = 0; $digits = $passwordDigits.Matches($passw0rd); $NonWords = $passwordNonWord.Matches($passw0rd); $Uppercases = $passwordUppercase.Matches($passw0rd); $Lowercases = $passwordLowercase.Matches($passw0rd);
        if ($digits.Count -ge 2) { $strength += 10 };
        if ($digits.Count -ge 5) { $strength += 10 };
        if ($NonWords.Count -ge 2) { $strength += 10 };
        if ($NonWords.Count -ge 5) { $strength += 10 };
        if ($passw0rd.Length -gt 8) { $strength += 10 };
        if ($passw0rd.Length -ge 16) { $strength += 10 };
        if ($Lowercases.Count -ge 2) { $strength += 10 };
        if ($Lowercases.Count -ge 5) { $strength += 10 };
        if ($Uppercases.Count -ge 2) { $strength += 10 };
        if ($Uppercases.Count -ge 5) { $strength += 10 };
        return $strength;
    }
    static [bool] IsBase64String([string]$base64) {
        return $(try { [void][Convert]::FromBase64String($base64); $true } catch { $false })
    }
    static [bool] IsValidAES([System.Security.Cryptography.Aes]$aes) {
        return [bool]$(try { [CryptoBase]::CheckProps($aes); $? } catch { $false })
    }
    static [void] CheckProps([System.Security.Cryptography.Aes]$Aes) {
        $MissingProps = @(); $throw = $false
        Write-Verbose "$([CryptoBase]::caller) [+] Checking Encryption Properties ... $(('Mode','Padding', 'keysize', 'BlockSize') | ForEach-Object { if ($null -eq $Aes.Algo.$_) { $MissingProps += $_ } };
            if ($MissingProps.Count -eq 0) { "Done. All AES Props are Good." } else { $throw = $true; "System.ArgumentNullException: $([string]::Join(', ', $MissingProps)) cannot be null." }
        )"
        if ($throw) { throw [System.ArgumentNullException]::new([string]::Join(', ', $MissingProps)) }
    }
    static [string] GetResolvedPath([string]$Path) {
        return [CryptoBase]::GetResolvedPath($((Get-Variable ExecutionContext).Value.SessionState), $Path)
    }
    static [string] GetResolvedPath([System.Management.Automation.SessionState]$session, [string]$Path) {
        $paths = $session.Path.GetResolvedPSPathFromPSPath($Path);
        if ($paths.Count -gt 1) {
            throw [System.IO.IOException]::new([string]::Format([cultureinfo]::InvariantCulture, "Path {0} is ambiguous", $Path))
        } elseif ($paths.Count -lt 1) {
            throw [System.IO.IOException]::new([string]::Format([cultureinfo]::InvariantCulture, "Path {0} not Found", $Path))
        }
        return $paths[0].Path
    }
    static [string] GetUnResolvedPath([string]$Path) {
        return [CryptoBase]::GetUnResolvedPath($((Get-Variable ExecutionContext).Value.SessionState), $Path)
    }
    static [string] GetUnResolvedPath([System.Management.Automation.SessionState]$session, [string]$Path) {
        return $session.Path.GetUnresolvedProviderPathFromPSPath($Path)
    }
    static [System.Type] CreateEnum([string]$Name, [bool]$IsPublic, [string[]]$Members) {
        # Example:
        # $MacMseries = [cryptobase]::CreateEnum('Mseries', $true, ('M1', 'M2', 'M3'))
        # $MacMseries::M1 | gm
        # Todo: Explore more about [System.Reflection.Emit.EnumBuilder], so we can add more features. ex: Flags, instead of [string[]]$Members we can have [hastable]$Members etc.
        try {
            if ([string]::IsNullOrWhiteSpace($Name)) { throw [InvalidArgumentException]::new('Name', 'Name can not be null or space') }
            $DynAssembly = [System.Reflection.AssemblyName]::new("EmittedEnum")
            $AssmBuilder = [System.Reflection.Emit.AssemblyBuilder]::DefineDynamicAssembly($DynAssembly, ([System.Reflection.Emit.AssemblyBuilderAccess]::Save -bor [System.Reflection.Emit.AssemblyBuilderAccess]::Run)) # Only run in memory
            $ModulBuildr = $AssmBuilder.DefineDynamicModule("DynamicModule")
            $type_attrib = if ($IsPublic) { [System.Reflection.TypeAttributes]::Public }else { [System.Reflection.TypeAttributes]::NotPublic }
            $enumBuilder = [System.Reflection.Emit.EnumBuilder]$ModulBuildr.DefineEnum($name, $type_attrib, [System.Int32]);
            for ($i = 0; $i -lt $Members.count; $i++) { [void]$enumBuilder.DefineLiteral($Members[$i], $i) }
            [void]$enumBuilder.CreateType()
        } catch {
            throw $_
        }
        return ($Name -as [Type])
    }
    static [System.Security.Cryptography.Aes] GetAes() { return [CryptoBase]::GetAes(1) }
    static [System.Security.Cryptography.Aes] GetAes([int]$Iterations) {
        $salt = $null; $password = $null;
        Set-Variable -Name password -Scope Local -Visibility Private -Option Private -Value $([xconvert]::ToSecurestring([CryptoBase]::GeneratePassword()));
        Set-Variable -Name salt -Scope Local -Visibility Private -Option Private -Value $([CryptoBase]::GetDerivedBytes(16));
        return [CryptoBase]::GetAes($password, $salt, $Iterations)
    }
    static [System.Security.Cryptography.Aes] GetAes([securestring]$password, [byte[]]$salt, [int]$iterations) {
        $aes = $null; $M = $null; $P = $null; $k = $null;
        Set-Variable -Name aes -Scope Local -Visibility Private -Option Private -Value $([System.Security.Cryptography.AesManaged]::new());
        #Note: 'Zeros' Padding was avoided, see: https://crypto.stackexchange.com/questions/1486/how-to-choose-a-padding-mode-with-aes # Personally I prefer PKCS7 as the best padding.
        for ($i = 1; $i -le $iterations; $i++) { ($M, $P, $k) = ((Get-Random ('ECB', 'CBC')), (Get-Random ('PKCS7', 'ISO10126', 'ANSIX923')), (Get-Random (128, 192, 256))) }
        $aes.Mode = & ([scriptblock]::Create("[System.Security.Cryptography.CipherMode]::$M"));
        $aes.Padding = & ([scriptblock]::Create("[System.Security.Cryptography.PaddingMode]::$P"));
        $aes.keysize = $k;
        $aes.Key = [CryptoBase]::GetKey($password, $salt);
        $aes.IV = [CryptoBase]::GetRandomEntropy();
        return $aes
    }
    # Use a cryptographic hash function (SHA-256) to generate a unique machine ID
    static [string] GetUniqueMachineId() {
        $Id = [string]($Env:MachineId)
        $vp = (Get-Variable VerbosePreference).Value
        try {
            Set-Variable VerbosePreference -Value $([System.Management.Automation.ActionPreference]::SilentlyContinue)
            $sha256 = [System.Security.Cryptography.SHA256]::Create()
            $HostOS = $(if ($(Get-Variable PSVersionTable -Value).PSVersion.Major -le 5 -or $(Get-Variable IsWindows -Value)) { "Windows" }elseif ($(Get-Variable IsLinux -Value)) { "Linux" }elseif ($(Get-Variable IsMacOS -Value)) { "macOS" }else { "UNKNOWN" });
            if ($HostOS -eq "Windows") {
                if ([string]::IsNullOrWhiteSpace($Id)) {
                    $machineId = Get-CimInstance -ClassName Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID
                    Set-Item -Path Env:\MachineId -Value $([convert]::ToBase64String($sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($machineId))));
                }
                $Id = [string]($Env:MachineId)
            } elseif ($HostOS -eq "Linux") {
                # $Id = (sudo cat /sys/class/dmi/id/product_uuid).Trim() # sudo prompt is a nono
                # Lets use mac addresses
                $Id = ([string[]]$(ip link show | grep "link/ether" | awk '{print $2}') -join '-').Trim()
                $Id = [convert]::ToBase64String($sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Id)))
            } elseif ($HostOS -eq "macOS") {
                $Id = (system_profiler SPHardwareDataType | Select-String "UUID").Line.Split(":")[1].Trim()
                $Id = [convert]::ToBase64String($sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Id)))
            } else {
                throw "Error: HostOS = '$HostOS'. Could not determine the operating system."
            }
        } catch {
            throw $_
        } finally {
            $sha256.Clear(); $sha256.Dispose()
            Set-Variable VerbosePreference -Value $vp
        }
        return $Id
    }
    static [string] Get_Host_Os() {
        # Todo: Should return one of these: [Enum]::GetNames([System.PlatformID])
        return $(if ($(Get-Variable IsWindows -Value)) { "Windows" }elseif ($(Get-Variable IsLinux -Value)) { "Linux" }elseif ($(Get-Variable IsMacOS -Value)) { "macOS" }else { "UNKNOWN" })
    }
    static [IO.DirectoryInfo] Get_dataPath([string]$appName, [string]$SubdirName) {
        $_Host_OS = [CryptoBase]::Get_Host_Os()
        $dataPath = if ($_Host_OS -eq 'Windows') {
            [System.IO.DirectoryInfo]::new([IO.Path]::Combine($Env:HOME, "AppData", "Roaming", $appName, $SubdirName))
        } elseif ($_Host_OS -in ('Linux', 'MacOs')) {
            [System.IO.DirectoryInfo]::new([IO.Path]::Combine((($env:PSModulePath -split [IO.Path]::PathSeparator)[0] | Split-Path | Split-Path), $appName, $SubdirName))
        } elseif ($_Host_OS -eq 'Unknown') {
            try {
                [System.IO.DirectoryInfo]::new([IO.Path]::Combine((($env:PSModulePath -split [IO.Path]::PathSeparator)[0] | Split-Path | Split-Path), $appName, $SubdirName))
            } catch {
                Write-Warning "Could not resolve chat data path"
                Write-Warning "HostOS = '$_Host_OS'. Could not resolve data path."
                [System.IO.Directory]::CreateTempSubdirectory(($SubdirName + 'Data-'))
            }
        } else {
            throw [InvalidOperationException]::new('Could not resolve data path. Get_Host_OS FAILED!')
        }
        if (!$dataPath.Exists) { [CryptoBase]::Create_Dir($dataPath) }
        return $dataPath
    }
    static [void] Create_Dir([string]$Path) {
        [CryptoBase]::Create_Dir([System.IO.DirectoryInfo]::new($Path))
    }
    static [void] Create_Dir([System.IO.DirectoryInfo]$Path) {
        [ValidateNotNullOrEmpty()][System.IO.DirectoryInfo]$Path = $Path
        $nF = @(); $p = $Path; while (!$p.Exists) { $nF += $p; $p = $p.Parent }
        [Array]::Reverse($nF); $nF | ForEach-Object { $_.Create(); Write-Verbose "Created $_" }
    }
    [securestring] static GetPassword() {
        $ThrowOnFailure = $true
        return [CryptoBase]::GetPassword($ThrowOnFailure);
    }
    [securestring] static GetPassword([string]$Prompt) {
        return [CryptoBase]::GetPassword($Prompt, $true)
    }
    [securestring] static GetPassword([bool]$ThrowOnFailure) {
        return [CryptoBase]::GetPassword("Password", $ThrowOnFailure)
    }
    static [securestring] GetPassword([string]$Prompt, [bool]$ThrowOnFailure) {
        if ([CryptoBase]::EncryptionScope.ToString() -eq "Machine") {
            return [xconvert]::ToSecurestring([CryptoBase]::GetUniqueMachineId())
        } else {
            $pswd = [SecureString]::new(); $_caller = 'PasswordManager'; if ([CryptoBase]::caller) {
                $_caller = [CryptoBase]::caller
            }
            Set-Variable -Name pswd -Scope Local -Visibility Private -Option Private -Value $(Read-Host -Prompt "$_caller $Prompt" -AsSecureString);
            if ($ThrowOnFailure -and ($null -eq $pswd -or $([string]::IsNullOrWhiteSpace([xconvert]::ToString($pswd))))) {
                throw [InvalidPasswordException]::new("Please Provide a Password that isn't Null or WhiteSpace.", $pswd, [System.ArgumentNullException]::new("Password"))
            }
            return $pswd;
        }
    }
    static [void] ValidateCompression([string]$Compression) {
        if ($Compression -notin ([Enum]::GetNames('Compression' -as 'Type'))) { Throw [System.InvalidCastException]::new("The name '$Compression' is not a valid [Compression]`$typeName.") };
    }
}
#endregion CryptoBase

class RecordBase {
    RecordBase() {}
    [void] Add([string]$key, [System.Object]$value) {
        [ValidateNotNullOrEmpty()][string]$key = $key
        if (!$this.HasNoteProperty($key)) {
            $htab = [hashtable]::new(); $htab.Add($key, $value); $this.Add($htab)
        } else {
            Write-Warning "Config.Add() Skipped $Key. Key already exists."
        }
    }
    [void] Add([hashtable]$table) {
        [ValidateNotNullOrEmpty()][hashtable]$table = $table
        $Keys = $table.Keys | Where-Object { !$this.HasNoteProperty($_) -and ($_.GetType().FullName -eq 'System.String' -or $_.GetType().BaseType.FullName -eq 'System.ValueType') }
        foreach ($key in $Keys) {
            if ($key -notin ('File', 'Remote', 'LastWriteTime')) {
                $this | Add-Member -MemberType NoteProperty -Name $key -Value $table[$key]
            } else {
                $this.$key = $table[$key]
            }
        }
    }
    [void] Add([hashtable[]]$items) {
        foreach ($item in $items) { $this.Add($item) }
    }
    [void] Add([System.Collections.Generic.List[hashtable]]$items) {
        foreach ($item in $items) { $this.Add($item) }
    }
    [void] Set([string]$key, [System.Object]$value) {
        $htab = [hashtable]::new(); $htab.Add($key, $value)
        $this.Set($htab)
    }
    [void] Set([hashtable]$table) {
        [ValidateNotNullOrEmpty()][hashtable]$table = $table
        $Keys = $table.Keys | Where-Object { $_.GetType().FullName -eq 'System.String' -or $_.GetType().BaseType.FullName -eq 'System.ValueType' } | Sort-Object -Unique
        foreach ($key in $Keys) {
            if (!$this.psObject.Properties.Name.Contains($key)) {
                $this | Add-Member -MemberType NoteProperty -Name $key -Value $table[$key] -Force
            } else {
                $this.$key = $table[$key]
            }
        }
    }
    [void] Set([hashtable[]]$items) {
        foreach ($item in $items) { $this.Set($item) }
    }
    [void] Set([System.Collections.Specialized.OrderedDictionary]$dict) {
        $dict.Keys.Foreach({ $this.Set($_, $dict["$_"]) });
    }
    [bool] HasNoteProperty([object]$Name) {
        [ValidateNotNullOrEmpty()][string]$Name = $($Name -as 'string')
        return (($this | Get-Member -Type NoteProperty | Select-Object -ExpandProperty name) -contains "$Name")
    }
    [array] ToArray() {
        $array = @(); $props = $this | Get-Member -MemberType NoteProperty
        if ($null -eq $props) { return @() }
        $props.name | ForEach-Object { $array += @{ $_ = $this.$_ } }
        return $array
    }
    [string] ToJson() {
        return [string]($this | Select-Object -ExcludeProperty count | ConvertTo-Json -Depth 3)
    }
    [System.Collections.Specialized.OrderedDictionary] ToOrdered() {
        $dict = [System.Collections.Specialized.OrderedDictionary]::new(); $Keys = $this.PsObject.Properties.Where({ $_.Membertype -like "*Property" }).Name
        if ($Keys.Count -gt 0) {
            $Keys | ForEach-Object { [void]$dict.Add($_, $this."$_") }
        }
        return $dict
    }
    static [hashtable[]] Read([string]$FilePath) {
        $pass = $null; $cfg = $null
        try {
            [ValidateNotNullOrEmpty()][string]$FilePath = [AesGCM]::GetUnResolvedPath($FilePath)
            if (![IO.File]::Exists($FilePath)) { throw [FileNotFoundException]::new("File '$FilePath' was not found") }
            if ([string]::IsNullOrWhiteSpace([AesGCM]::caller)) { [AesGCM]::caller = [RecordBase]::caller }
            Set-Variable -Name pass -Scope Local -Visibility Private -Option Private -Value $(if ([CryptoBase]::EncryptionScope.ToString() -eq "User") { Read-Host -Prompt "$([RecordBase]::caller) Paste/write a Password to decrypt configs" -AsSecureString }else { [xconvert]::ToSecurestring([AesGCM]::GetUniqueMachineId()) })
            $_ob = [xconvert]::Deserialize([xconvert]::ToDeCompressed([AesGCM]::Decrypt([base85]::Decode([IO.File]::ReadAllText($FilePath)), $pass)))
            $cfg = [hashtable[]]$_ob.Keys.ForEach({ @{ $_ = $_ob.$_ } })
        } catch {
            throw $_.Exeption
        } finally {
            Remove-Variable Pass -Force -ErrorAction SilentlyContinue
        }
        return $cfg
    }
    static [hashtable[]] EditFile([IO.FileInfo]$File) {
        $result = @(); $private:config_ob = $null; $fswatcher = $null; $process = $null;
        [ValidateScript({ if ([IO.File]::Exists($_)) { return $true } ; throw [FileNotFoundException]::new("File '$_' was not found") })][IO.FileInfo]$File = $File;
        $OutFile = [IO.FileInfo][IO.Path]::GetTempFileName()
        $UseVerbose = [bool]$((Get-Variable verbosePreference -ValueOnly) -eq "continue")
        try {
            [NetworkManager]::BlockAllOutbound()
            if ($UseVerbose) { "[+] Edit Config started .." | Write-Host -ForegroundColor Magenta }
            [RecordBase]::Read($File.FullName) | ConvertTo-Json | Out-File $OutFile.FullName -Encoding utf8BOM
            Set-Variable -Name OutFile -Value $(Rename-Item $outFile.FullName -NewName ($outFile.BaseName + '.json') -PassThru)
            $process = [System.Diagnostics.Process]::new()
            $process.StartInfo.FileName = 'nvim'
            $process.StartInfo.Arguments = $outFile.FullName
            $process.StartInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Maximized
            $process.Start(); $fswatcher = [FileMonitor]::MonitorFile($outFile.FullName, [scriptblock]::Create("Stop-Process -Id $($process.Id) -Force"));
            if ($null -eq $fswatcher) { Write-Warning "Failed to start FileMonitor"; Write-Host "Waiting nvim process to exit..." $process.WaitForExit() }
            $private:config_ob = [IO.FILE]::ReadAllText($outFile.FullName) | ConvertFrom-Json
        } finally {
            [NetworkManager]::UnblockAllOutbound()
            if ($fswatcher) { $fswatcher.Dispose() }
            if ($process) {
                "[+] Neovim process {0} successfully" -f $(if (!$process.HasExited) {
                        $process.Kill($true)
                        "closed"
                    } else {
                        "exited"
                    }
                ) | Write-Host -ForegroundColor Green
                $process.Close()
                $process.Dispose()
            }
            Remove-Item $outFile.FullName -Force
            if ($UseVerbose) { "[+] FileMonitor Log saved in variable: `$$([fileMonitor]::LogvariableName)" | Write-Host -ForegroundColor Magenta }
            if ($null -ne $config_ob) { $result = $config_ob.ForEach({ [xconvert]::ToHashTable($_) }) }
            if ($UseVerbose) { "[+] Edit Config completed." | Write-Host -ForegroundColor Magenta }
        }
        return $result
    }
    [void] Save() {
        $pass = $null;
        try {
            Write-Host "$([RecordBase]::caller) Save records to file: $($this.File) ..." -ForegroundColor Blue
            Set-Variable -Name pass -Scope Local -Visibility Private -Option Private -Value $(if ([CryptoBase]::EncryptionScope.ToString() -eq "User") { Read-Host -Prompt "$([RecordBase]::caller) Paste/write a Password to encrypt configs" -AsSecureString } else { [xconvert]::ToSecurestring([AesGCM]::GetUniqueMachineId()) })
            $this.LastWriteTime = [datetime]::Now; [IO.File]::WriteAllText($this.File, [Base85]::Encode([AesGCM]::Encrypt([xconvert]::ToCompressed($this.ToByte()), $pass)), [System.Text.Encoding]::UTF8)
            Write-Host "$([RecordBase]::caller) Save records " -ForegroundColor Blue -NoNewline; Write-Host "Completed." -ForegroundColor Green
        } catch {
            throw $_.Exeption
        } finally {
            Remove-Variable Pass -Force -ErrorAction SilentlyContinue
        }
    }
    [void] Import([String]$FilePath) {
        Write-Host "$([RecordBase]::caller) Import records: $FilePath ..." -ForegroundColor Green
        $this.Set([RecordBase]::Read($FilePath))
        Write-Host "$([RecordBase]::caller) Import records Complete" -ForegroundColor Green
    }
    [byte[]] ToByte() {
        return [xconvert]::Serialize($this)
    }
    [string] ToString() {
        $r = $this.ToArray(); $s = ''
        $shortnr = [scriptblock]::Create({
                param([string]$str, [int]$MaxLength)
                while ($str.Length -gt $MaxLength) {
                    $str = $str.Substring(0, [Math]::Floor(($str.Length * 4 / 5)))
                }
                return $str
            }
        )
        if ($r.Count -gt 1) {
            $b = $r[0]; $e = $r[-1]
            $0 = $shortnr.Invoke("{'$($b.Keys)' = '$($b.values.ToString())'}", 40)
            $1 = $shortnr.Invoke("{'$($e.Keys)' = '$($e.values.ToString())'}", 40)
            $s = "@($0 ... $1)"
        } elseif ($r.count -eq 1) {
            $0 = $shortnr.Invoke("{'$($r[0].Keys)' = '$($r[0].values.ToString())'}", 40)
            $s = "@($0)"
        } else {
            $s = '@()'
        }
        return $s
    }
}

#region    Custom_ObjectConverter
class xconvert : System.ComponentModel.TypeConverter {
    xconvert() {}
    static [string] Base32ToHex([string]$base32String) {
        return [System.BitConverter]::ToString([System.Text.Encoding]::UTF8.GetBytes($base32String)).Replace("-", "").ToLower()
    }
    static [string] Base32FromHex([string]$hexString) {
        return [System.Text.Encoding]::UTF8.GetString(([byte[]] -split ($hexString -replace '..', '0x$& ')))
    }
    static [string] GuidFromHex([string]$hexString) {
        return [System.Guid]::new(([byte[]] -split ($hexString -replace '..', '0x$& '))).ToString()
    }
    static [string] Tostring([k3Y]$K3Y) {
        if ($null -eq $K3Y) { return [string]::Empty };
        $NotNullProps = ('User', 'UID', 'Expiration');
        $K3Y | Get-Member -MemberType Properties | ForEach-Object { $Prop = $_.Name; if ($null -eq $K3Y.$Prop -and $Prop -in $NotNullProps) { throw [System.ArgumentNullException]::new($Prop) } };
        $CustomObject = [xconvert]::ToPSObject($K3Y);
        return [string][xconvert]::ToCompressed([System.Convert]::ToBase64String([xconvert]::BytesFromObject($CustomObject)));
    }
    static [string] ToString([byte[]]$Bytes) {
        return [string][System.Convert]::ToBase64String($Bytes);
    }
    static [string[]] ToString([int[]]$CharCodes) {
        $String = @(); foreach ($n in $CharCodes) { $String += [string][char]$n }
        return $String
    }
    static [string] ToString([System.Security.SecureString]$SecureString) {
        [string]$Pstr = [string]::Empty;
        [IntPtr]$zero = [IntPtr]::Zero;
        if ($null -eq $SecureString -or $SecureString.Length -eq 0) {
            return [string]::Empty;
        }
        try {
            Set-Variable -Name zero -Scope Local -Visibility Private -Option Private -Value ([System.Runtime.InteropServices.Marshal]::SecurestringToBSTR($SecureString));
            Set-Variable -Name Pstr -Scope Local -Visibility Private -Option Private -Value ([System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($zero));
        } finally {
            if ($zero -ne [IntPtr]::Zero) {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($zero);
            }
        }
        return $Pstr;
    }
    static [string] ToString([int[]]$CharCodes, [string]$separator) {
        return [string]::Join($separator, [xconvert]::ToString($CharCodes));
    }
    static [string] ToString([int]$value, [int]$toBase) {
        [char[]]$baseChars = switch ($toBase) {
            # Binary
            2 { @('0', '1') }
            # Hexadecimal
            16 { @('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f') }
            # Hexavigesimal
            26 { @('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p') }
            # Sexagesimal
            60 { @('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x') }
            Default {
                throw [System.ArgumentException]::new("Invalid Base.")
            }
        }
        return [xconvert]::IntToString($value, $baseChars);
    }
    static [string] ToString([guid]$guid) {
        return [System.Text.Encoding]::UTF8.GetString([xconvert]::FromHexString($guid.ToString().Replace('-', '')))
        # I just assumed all guids use UTF8 for encoding, but idk maybe they are also encrypted?!
        # ie: This is just a way to reverse the ToGuid() method. does not apply on real guids.
    }
    static [guid] ToGuid([string]$InputText) {
        # Creates a string that passes guid regex checks (ie: not a real guid)
        if ($InputText.Trim().Length -ne 16) {
            throw [System.InvalidOperationException]::new('$InputText.Trim().Length Should Be exactly 16. Ex: [xconvert]::ToGuid([CryptoBase]::GetRandomName(16))')
        }
        return [guid]::new([System.BitConverter]::ToString([System.Text.Encoding]::UTF8.GetBytes($InputText)).Replace("-", "").ToLower().Insert(8, "-").Insert(13, "-").Insert(18, "-").Insert(23, "-"))
    }
    static [SecureString] ToSecurestring([string]$String) {
        $SecureString = $null; Set-Variable -Name SecureString -Scope Local -Visibility Private -Option Private -Value ([System.Security.SecureString]::new());
        if (![string]::IsNullOrEmpty($String)) {
            $Chars = $String.toCharArray()
            ForEach ($Char in $Chars) {
                $SecureString.AppendChar($Char)
            }
        }
        $SecureString.MakeReadOnly();
        return $SecureString
    }
    static [int[]] StringToCharCode([string[]]$string) {
        [bool]$encoderShouldEmitUTF8Identifier = $false; $Codes = @()
        $Encodr = [System.Text.UTF8Encoding]::new($encoderShouldEmitUTF8Identifier)
        for ($i = 0; $i -lt $string.Count; $i++) {
            $Codes += [int[]]$($Encodr.GetBytes($string[$i]))
        }
        return $Codes;
    }
    static [datetime] ToDateTime([string]$dateString) {
        # Dynamically detect the system's date and time format and use it to parse the $dateString.
        $currentCulture = [System.Threading.Thread]::CurrentThread.CurrentCulture
        $dateTimeFormat = $currentCulture.DateTimeFormat; $datetime = @()
        $dateFormats = $dateTimeFormat.GetAllDateTimePatterns()
        $culture = [System.Globalization.CultureInfo]::InvariantCulture
        foreach ($format in $dateFormats) {
            try {
                $datetime += [DateTime]::ParseExact($dateString, $format, $culture);
            } catch {
                continue
            }
        }
        if ($datetime.Count -ne 1) {
            throw 'An error occurred while parsing the input $dateString to a DateTime object.'
        }
        return $datetime[0]
    }
    static [bool] StringToBoolean([string]$Text) {
        $Text = switch -Wildcard ($Text) {
            "1*" { "true"; break }
            "0*" { "false"; break }
            "yes*" { "true"; break }
            "no*" { "false"; break }
            "true*" { "true"; break }
            "false*" { "false"; break }
            "*true*" { "true"; break }
            "*false*" { "false"; break }
            "yeah*" { "true"; break }
            "y*" { "true"; break }
            "n*" { "false"; break }
            Default { "false" }
        }
        return [convert]::ToBoolean($Text)
    }
    static [string] ToCaesarCipher([string]$Text, [int]$Key) {
        [ValidateNotNullOrEmpty()][string]$Text = $Text; $Cipher = [string]::Empty;
        $alphabet = $null; New-Variable -Name alphabet -Option Constant -Value "abcdefghijklmnopqrstuvwxyz" -Force;
        for ($i = 0; $i -lt $Text.Length; $i++) {
            if ($Text[$i] -eq " ") {
                $Cipher += " ";
            } else {
                [int]$index = $alphabet.IndexOf($text[$i]) + $Key
                if ($index -gt 26) {
                    $index = $index - 26
                }
                $Cipher += $alphabet[$index];
            }
        }
        return $Cipher
    }
    static [string] FromCaesarCipher([string]$Cipher, [int]$Key) {
        [ValidateNotNullOrEmpty()][string]$Cipher = $Cipher.ToLower(); $Output = [string]::Empty;
        $alphabet = $null; New-Variable -Name alphabet -Value "abcdefghijklmnopqrstuvwxyz" -Option Constant -Force;
        for ($i = 0; $i -lt $Cipher.Length; $i++) {
            if ($Cipher[$i] -eq " ") {
                $Output += " ";
            } else {
                $Output += $alphabet[($alphabet.IndexOf($Cipher[$i]) - $Key)];
            }
        };
        return $Output;
    }
    static [string] ToPolybiusCipher([string]$Text, [string]$Key) {
        [ValidateNotNullOrEmpty()][string]$Text = $Text.ToLower();
        [ValidateNotNullOrEmpty()][string]$Key = $Key.ToLower(); $Cipher = [string]::Empty
        [xconvert]::ValidatePolybiusCipher($Text, $Key, "Encrypt")
        [Array]$polybiusTable = New-Object 'string[,]' 5, 5;
        $letter = 0;
        for ($i = 0; $i -lt 5; $i++) {
            for ($j = 0; $j -lt 5; $j++) {
                $polybiusTable[$i, $j] = $Key[$letter];
                $letter++;
            }
        };
        $Text = $Text.Replace(" ", "");
        for ($i = 0; $i -lt $Text.Length; $i++) {
            for ($j = 0; $j -lt 5; $j++) {
                for ($k = 0; $k -lt 5; $k++) {
                    if ($polybiusTable[$j, $k] -eq $Text[$i]) {
                        $Cipher += [string]$j + [string]$k + " ";
                    }
                }
            }
        }
        return $Cipher
    }
    static [string] FromPolybiusCipher([string]$Cipher, [string]$Key) {
        [ValidateNotNullOrEmpty()][string]$Cipher = $Cipher.ToLower();
        [ValidateNotNullOrEmpty()][string]$Key = $Key.ToLower(); $Output = [string]::Empty
        [xconvert]::ValidatePolybiusCipher($Cipher, $Key, "Decrypt")
        [Array]$polybiusTable = New-Object 'string[,]' 5, 5;
        $letter = 0;
        for ($i = 0; $i -lt 5; $i++) {
            for ($j = 0; $j -lt 5; $j++) {
                $polybiusTable[$i, $j] = $Key[$letter];
                $letter++;
            }
        };
        $SplitInput = $Cipher.Split(" ");
        foreach ($pair in $SplitInput) {
            $Output += $polybiusTable[[convert]::ToInt32($pair[0], 10), [convert]::ToInt32($pair[1], 10)];
        };
        return $Output;
    }
    static hidden [void] ValidatePolybiusCipher([string]$Text, [string]$Key, [string]$Action) {
        if ($Text -notmatch "^[a-z ]*$" -and ($Action -ne 'Decrypt')) {
            throw('Text must only have alphabetical characters');
        }
        if ($Key.Length -ne 25) {
            throw('Key must be 25 characters in length');
        }
        if ($Key -notmatch "^[a-z]*$") {
            throw('Key must only have alphabetical characters');
        }
        for ($i = 0; $i -lt 25; $i++) {
            for ($j = 0; $j -lt 25; $j++) {
                if (($Key[$i] -eq $Key[$j]) -and ($i -ne $j)) {
                    throw('Key must have no repeating letters');
                }
            }
        }
    }
    static [string] StringToBinStR ([string]$string) {
        return [xconvert]::BinaryToBinStR([xconvert]::BinaryFromString("$string"), $false)
    }
    static [string] StringToBinStR ([string]$string, [bool]$Tidy) {
        return [xconvert]::BinaryToBinStR([xconvert]::BinaryFromString("$string"), $Tidy)
    }
    static [string] StringFromBinStR ([string]$BinStR) {
        return [xconvert]::BinaryToString([xconvert]::BinaryFromBinStR($BinStR))
    }
    static [string] ToObfuscated([string]$inputString) {
        $Inpbytes = [System.Text.Encoding]::UTF8.GetBytes($inputString); $rn = [System.Random]::new(); # Hides Byte Array in a random String
        return [string]::Join('', $($Inpbytes | ForEach-Object { [string][char]$rn.Next(97, 122) + $_ }));
    }
    static [string] ToDeObfuscated([string]$obfuscatedString) {
        $az = [int[]](97..122) | ForEach-Object { [string][char]$_ };
        $outbytes = [byte[]][string]::Concat($(($obfuscatedString.ToCharArray() | ForEach-Object { if ($_ -in $az) { [string][char]32 } else { [string]$_ } }) | ForEach-Object { $_ })).Trim().split([string][char]32);
        return [System.Text.Encoding]::UTF8.GetString($outbytes)
    }
    [PSCustomObject[]] static ToPSObject([xml]$XML) {
        $Out = @(); foreach ($Object in @($XML.Objects.Object)) {
            $PSObject = [PSCustomObject]::new()
            foreach ($Property in @($Object.Property)) {
                $PSObject | Add-Member NoteProperty $Property.Name $Property.InnerText
            }
            $Out += $PSObject
        }
        return $Out
    }
    static [string] ToCsv([System.Object]$Obj) {
        return [xconvert]::ToCsv($Obj, @('pstypenames', 'BaseType'), 2, 0)
    }
    static [string] ToCsv([System.Object]$Obj, [int]$depth) {
        return [xconvert]::ToCsv($Obj, @('pstypenames', 'BaseType'), $depth, 0)
    }
    static [string] ToCsv([System.Object]$Obj, [string[]]$excludedProps, [int]$depth, [int]$currentDepth = 0) {
        $get_Props = [scriptblock]::Create({
                param([Object]$Objct, [string[]]$excluded)
                $Props = $Objct | Get-Member -Force -MemberType Properties; if ($excluded.Count -gt 0) { $Props = $Props | Where-Object { $_.Name -notin $excluded } }
                $Props = $Props | Select-Object -ExpandProperty Name
                return $Props
            }
        )
        $Props = $get_Props.Invoke($Obj, $excludedProps)
        $csv = [string]::Empty
        $csv += '"' + ($Props -join '","') + '"' + "`n";
        $vals = @()
        foreach ($name in $Props) {
            $_props = $get_Props.Invoke($Obj.$name, $excludedProps)
            if ($null -ne $_props) {
                if ($_props.count -gt 0 -and $currentDepth -lt $depth) {
                    $currentDepth++
                    $vals += [xconvert]::ToCsv($Obj.$name, $excludedProps, $depth, $currentDepth)
                } elseif ($null -ne $Obj.$name) {
                    $vals += $Obj.$name.Tostring()
                } else {
                    $vals += $name.Tostring()
                }
            }
        }
        $fs = '"{' + ((0 .. ($vals.Count - 1)) -join '}","{') + '}"';
        $csv += $fs -f $vals
        return $csv
    }
    static [PsObject] FromCsv([string]$text) {
        $obj = $null
        $lines = $text -split "\r?\n"
        if ($lines.Count -lt 2) {
            throw "CSV contains no data"
        }
        $header = $lines[0] -split ','
        $objs = foreach ($line in $lines[1..($lines.Count - 1)]) {
            $values = $line -split ','
            $obj = New-Object psobject
            for ($i = 0; $i -lt $header.Length; $i++) {
                $prop = $header[$i].Trim('"')
                if ($null -ne $values[$i]) {
                    $val = $values[$i].Trim('"')
                    if (![string]::IsNullOrEmpty($val)) {
                        $obj | Add-Member -MemberType NoteProperty -Name $prop -Value $val
                    }
                }
            }
            $obj
        }
        return $objs
    }
    static [byte[]] FromBase32String([string]$string) {
        [ValidateNotNullOrEmpty()][string]$string = $string;
        $string = $string.ToLower(); $B32CHARSET = "abcdefghijklmnopqrstuvwxyz234567"
        $B32CHARSET_Pattern = "^[A-Z2-7 ]+_*$"; [byte[]]$result = $null
        if (!($string -match $B32CHARSET_Pattern)) {
            Throw "Invalid Base32 data encountered in input stream."
        }
        $InputStream = [System.IO.MemoryStream]::new([System.Text.Encoding]::UTF8.GetBytes($string), 0, $string.Length)
        $BinaryReader = [System.IO.BinaryReader]::new($InputStream)
        $OutputStream = [System.IO.MemoryStream]::new()
        $BinaryWriter = [System.IO.BinaryWriter]::new($OutputStream)
        Try {
            While ([System.Char[]]$CharsRead = $BinaryReader.ReadChars(8)) {
                [System.Byte[]]$B32Bytes = , 0x00 * 5
                [System.UInt16]$CharLen = 8 - ($CharsRead -Match "_").Count
                [System.UInt16]$ByteLen = [Math]::Floor(($CharLen * 5) / 8)
                [System.Byte[]]$BinChunk = , 0x00 * $ByteLen
                if ($CharLen -lt 8) {
                    [System.Char[]]$WorkingChars = , "a" * 8
                    [Array]::Copy($CharsRead, $WorkingChars, $CharLen)
                    [Array]::Resize([ref]$CharsRead, 8)
                    [Array]::Copy($WorkingChars, $CharsRead, 8)
                }
                $B32Bytes[0] = (($B32CHARSET.IndexOf($CharsRead[0]) -band 0x1F) -shl 3) -bor (($B32CHARSET.IndexOf($CharsRead[1]) -band 0x1C) -shr 2)
                $B32Bytes[1] = (($B32CHARSET.IndexOf($CharsRead[1]) -band 0x03) -shl 6) -bor (($B32CHARSET.IndexOf($CharsRead[2]) -band 0x1F) -shl 1) -bor (($B32CHARSET.IndexOf($CharsRead[3]) -band 0x10) -shr 4)
                $B32Bytes[2] = (($B32CHARSET.IndexOf($CharsRead[3]) -band 0x0F) -shl 4) -bor (($B32CHARSET.IndexOf($CharsRead[4]) -band 0x1E) -shr 1)
                $B32Bytes[3] = (($B32CHARSET.IndexOf($CharsRead[4]) -band 0x01) -shl 7) -bor (($B32CHARSET.IndexOf($CharsRead[5]) -band 0x1F) -shl 2) -bor (($B32CHARSET.IndexOf($CharsRead[6]) -band 0x18) -shr 3)
                $B32Bytes[4] = (($B32CHARSET.IndexOf($CharsRead[6]) -band 0x07) -shl 5) -bor ($B32CHARSET.IndexOf($CharsRead[7]) -band 0x1F)
                [System.Buffer]::BlockCopy($B32Bytes, 0, $BinChunk, 0, $ByteLen)
                $BinaryWriter.Write($BinChunk)
            }
            $result = $OutputStream.ToArray()
        } catch {
            Write-Error "Exception: $($_.Exception.Message)"
            Break
        } finally {
            $BinaryReader.Close()
            $BinaryReader.Dispose()
            $BinaryWriter.Close()
            $BinaryWriter.Dispose()
            $InputStream.Close()
            $InputStream.Dispose()
            $OutputStream.Close()
            $OutputStream.Dispose()
        }
        return $result
    }
    static [string] ToBase32String([byte[]]$bytes) {
        return [xconvert]::ToBase32String($bytes, $false)
    }
    static [string] ToBase32String([string]$String) {
        return [xconvert]::ToBase32String($String, $false)
    }
    static [string] ToBase32String([byte[]]$bytes, [bool]$Formatt) {
        return [xconvert]::ToBase32String([System.IO.MemoryStream]::New($bytes), $Formatt)
    }
    static [string] ToBase32String([string]$String, [bool]$Formatt) {
        return [xconvert]::ToBase32String([System.Text.Encoding]::ASCII.GetBytes($String), $Formatt)
    }
    static [string] ToBase32String([System.IO.Stream]$Stream, [bool]$Formatt) {
        $BinaryReader = [System.IO.BinaryReader]::new($Stream);
        $Base32Output = [System.Text.StringBuilder]::new(); $result = [string]::Empty
        $B32CHARSET = "abcdefghijklmnopqrstuvwxyz234567"
        Try {
            While ([byte[]]$BytesRead = $BinaryReader.ReadBytes(5)) {
                [System.Boolean]$AtEnd = ($BinaryReader.BaseStream.Length -eq $BinaryReader.BaseStream.Position)
                [System.UInt16]$ByteLength = $BytesRead.Length
                if ($ByteLength -lt 5) {
                    [byte[]]$WorkingBytes = , 0x00 * 5
                    [System.Buffer]::BlockCopy($BytesRead, 0, $WorkingBytes, 0, $ByteLength)
                    [Array]::Resize([ref]$BytesRead, 5)
                    [System.Buffer]::BlockCopy($WorkingBytes, 0, $BytesRead, 0, 5)
                }
                [System.Char[]]$B32Chars = , 0x00 * 8
                [System.Char[]]$B32Chunk = , "_" * 8
                $B32Chars[0] = ($B32CHARSET[($BytesRead[0] -band 0xF8) -shr 3])
                $B32Chars[1] = ($B32CHARSET[(($BytesRead[0] -band 0x07) -shl 2) -bor (($BytesRead[1] -band 0xC0) -shr 6)])
                $B32Chars[2] = ($B32CHARSET[($BytesRead[1] -band 0x3E) -shr 1])
                $B32Chars[3] = ($B32CHARSET[(($BytesRead[1] -band 0x01) -shl 4) -bor (($BytesRead[2] -band 0xF0) -shr 4)])
                $B32Chars[4] = ($B32CHARSET[(($BytesRead[2] -band 0x0F) -shl 1) -bor (($BytesRead[3] -band 0x80) -shr 7)])
                $B32Chars[5] = ($B32CHARSET[($BytesRead[3] -band 0x7C) -shr 2])
                $B32Chars[6] = ($B32CHARSET[(($BytesRead[3] -band 0x03) -shl 3) -bor (($BytesRead[4] -band 0xE0) -shr 5)])
                $B32Chars[7] = ($B32CHARSET[$BytesRead[4] -band 0x1F])
                [Array]::Copy($B32Chars, $B32Chunk, ([Math]::Ceiling(($ByteLength / 5) * 8)))
                if ($BinaryReader.BaseStream.Position % 8 -eq 0 -and $Formatt -and !$AtEnd) {
                    [void]$Base32Output.Append($B32Chunk)
                    [void]$Base32Output.Append("`r`n")
                } else {
                    [void]$Base32Output.Append($B32Chunk)
                }
            }
            [string]$result = $Base32Output.ToString()
        } catch {
            Write-Error "Exception: $($_.Exception.Message)"
            Break
        } finally {
            $BinaryReader.Close()
            $BinaryReader.Dispose()
            $Stream.Close()
            $Stream.Dispose()
        }
        return $result
    }
    [PsCustomObject] static ToPSObject([System.Object]$Obj) {
        $PSObj = [PSCustomObject]::new();
        $Obj | Get-Member -MemberType Properties | ForEach-Object {
            $Name = $_.Name; $PSObj | Add-Member -Name $Name -MemberType NoteProperty -Value $(if ($null -ne $Obj.$Name) { if ("Deserialized" -in (($Obj.$Name | Get-Member).TypeName.Split('.') | Sort-Object -Unique)) { $([xconvert]::ToPSObject($Obj.$Name)) } else { $Obj.$Name } } else { $null })
        }
        return $PSObj
    }
    static [System.Object] FromPSObject([PSCustomObject]$PSObject) {
        return [xconvert]::FromPSObject($PSObject, $PSObject.PSObject.TypeNames[0])
    }
    static [System.Object] FromPSObject([PSCustomObject]$PSObject, [string]$typeName) {
        # /!\ not working as expected /!\
        $Type = [Type]::GetType($typeName, $false)
        if ($Type) {
            $Obj = [Activator]::CreateInstance($Type)
            $PSObject.PSObject.Properties | ForEach-Object {
                $Name = $_.Name
                $Value = $_.Value
                if ($Value -is [PSCustomObject]) {
                    $Value = [xconvert]::FromPSObject($Value)
                }
                $Obj.$Name = $Value
            }
            return $Obj
        } else {
            return $PSObject
        }
    }
    static [byte[]] ToProtected([byte[]]$Bytes) {
        $p = [xconvert]::ToSecurestring([CryptoBase]::GetUniqueMachineId())
        return [AesGCM]::Encrypt($Bytes, $p, [CryptoBase]::GetDerivedBytes($p))
    }
    static [byte[]] ToUnProtected([byte[]]$Bytes) {
        $p = [xconvert]::ToSecurestring([CryptoBase]::GetUniqueMachineId())
        return [AesGCM]::Decrypt($Bytes, $p, [CryptoBase]::GetDerivedBytes($p))
    }
    static [byte[]] ToCompressed([byte[]]$Bytes) {
        return [xconvert]::ToCompressed($Bytes, 'Gzip');
    }
    static [string] ToCompressed([string]$Plaintext) {
        return [convert]::ToBase64String([xconvert]::ToCompressed([System.Text.Encoding]::UTF8.GetBytes($Plaintext)));
    }
    static [byte[]] ToCompressed([byte[]]$Bytes, [string]$Compression) {
        if (("$Compression" -as 'Compression') -isnot 'Compression') {
            Throw [System.InvalidCastException]::new("Compression type '$Compression' is unknown! Valid values: $([Enum]::GetNames([compression]) -join ', ')");
        }
        $outstream = [System.IO.MemoryStream]::new()
        $Comstream = switch ($Compression) {
            "Gzip" { New-Object System.IO.Compression.GzipStream($outstream, [System.IO.Compression.CompressionLevel]::Optimal) }
            "Deflate" { New-Object System.IO.Compression.DeflateStream($outstream, [System.IO.Compression.CompressionLevel]::Optimal) }
            "ZLib" { New-Object System.IO.Compression.ZLibStream($outstream, [System.IO.Compression.CompressionLevel]::Optimal) }
            Default { throw "Failed to Compress Bytes. Could Not resolve Compression!" }
        }
        [void]$Comstream.Write($Bytes, 0, $Bytes.Length); $Comstream.Close(); $Comstream.Dispose();
        [byte[]]$OutPut = $outstream.ToArray(); $outStream.Close()
        return $OutPut;
    }
    static [byte[]] ToDeCompressed([byte[]]$Bytes) {
        return [xconvert]::ToDeCompressed($Bytes, 'Gzip');
    }
    static [string] ToDecompressed([string]$Base64Text) {
        return [System.Text.Encoding]::UTF8.GetString([xconvert]::ToDecompressed([convert]::FromBase64String($Base64Text)));
    }
    static [byte[]] ToDeCompressed([byte[]]$Bytes, [string]$Compression) {
        if (("$Compression" -as 'Compression') -isnot 'Compression') {
            Throw [System.InvalidCastException]::new("Compression type '$Compression' is unknown! Valid values: $([Enum]::GetNames([compression]) -join ', ')");
        }
        $inpStream = [System.IO.MemoryStream]::new($Bytes)
        $ComStream = switch ($Compression) {
            "Gzip" { New-Object System.IO.Compression.GzipStream($inpStream, [System.IO.Compression.CompressionMode]::Decompress); }
            "Deflate" { New-Object System.IO.Compression.DeflateStream($inpStream, [System.IO.Compression.CompressionMode]::Decompress); }
            "ZLib" { New-Object System.IO.Compression.ZLibStream($inpStream, [System.IO.Compression.CompressionMode]::Decompress); }
            Default { throw "Failed to DeCompress Bytes. Could Not resolve Compression!" }
        }
        $outStream = [System.IO.MemoryStream]::new();
        [void]$Comstream.CopyTo($outStream); $Comstream.Close(); $Comstream.Dispose(); $inpStream.Close()
        [byte[]]$OutPut = $outstream.ToArray(); $outStream.Close()
        return $OutPut;
    }
    static [string] ToRegexEscapedString([string]$LiteralText) {
        if ([string]::IsNullOrEmpty($LiteralText)) { $LiteralText = [string]::Empty }
        return [regex]::Escape($LiteralText);
    }
    static [System.Collections.Hashtable] FromRegexCapture([System.Text.RegularExpressions.Match]$Match, [regex]$Regex) {
        if (!$Match.Groups[0].Success) {
            throw New-Object System.ArgumentException('Match does not contain any captures.', 'Match')
        }
        $h = @{}
        foreach ($name in $Regex.GetGroupNames()) {
            if ($name -eq 0) {
                continue
            }
            $h.$name = $Match.Groups[$name].Value
        }
        return $h
    }
    static [System.Collections.Hashtable] ToHashTable([PsObject]$object) {
        $ht = @{}; foreach ($property in $object.PsObject.Properties) {
            $ht[$property.Name] = $property.Value
        }
        return $ht
    }
    static hidden [string] IntToString([Int]$value, [char[]]$baseChars) {
        [int]$i = 32;
        [char[]]$buffer = [Char[]]::new($i);
        [int]$targetBase = $baseChars.Length;
        do {
            $buffer[--$i] = $baseChars[$value % $targetBase];
            $value = $value / $targetBase;
        } while ($value -gt 0);
        [char[]]$result = [Char[]]::new(32 - $i);
        [Array]::Copy($buffer, $i, $result, 0, 32 - $i);
        return [string]::new($result)
    }
    static [string] ToHexString([byte[]]$Bytes) {
        return [string][System.BitConverter]::ToString($bytes).replace('-', [string]::Empty).Tolower();
    }
    static [byte[]] FromHexString([string]$HexString) {
        $outputLength = $HexString.Length / 2;
        $output = [byte[]]::new($outputLength);
        $numeral = [char[]]::new(2);
        for ($i = 0; $i -lt $outputLength; $i++) {
            $HexString.CopyTo($i * 2, $numeral, 0, 2);
            $output[$i] = [Convert]::ToByte([string]::new($numeral), 16);
        }
        return $output;
    }
    static [byte[]] BytesFromObject([object]$obj) {
        return [xconvert]::BytesFromObject($obj, $false);
    }
    static [byte[]] BytesFromObject([object]$obj, [bool]$protect) {
        if ($null -eq $obj) { return $null }; $bytes = $null;
        if ($obj.GetType() -eq [string] -and $([regex]::IsMatch([string]$obj, '^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$') -and ![string]::IsNullOrWhiteSpace([string]$obj) -and !$obj.Length % 4 -eq 0 -and !$obj.Contains(" ") -and !$obj.Contains(" ") -and !$obj.Contains("`t") -and !$obj.Contains("`n"))) {
            $bytes = [convert]::FromBase64String($obj);
        } elseif ($obj.GetType() -eq [byte[]]) {
            $bytes = [byte[]]$obj
        } else {
            # Serialize the Object:
            $bytes = [xconvert]::Serialize($obj)
        }
        if ($protect) {
            # Protecteddata: https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.protecteddata.unprotect?
            $bytes = [byte[]][xconvert]::ToProtected($bytes);
        }
        return $bytes
    }
    static [byte[]] Serialize($Obj) {
        return [Text.Encoding]::UTF8.GetBytes([System.Management.Automation.PSSerializer]::Serialize($Obj))
    }
    static [Object] Deserialize([byte[]]$data) {
        return [System.Management.Automation.PSSerializer]::Deserialize([Text.Encoding]::UTF8.GetString($data))
    }
    static [Object[]] DeserializeAsList([byte[]]$data) {
        return [System.Management.Automation.PSSerializer]::DeserializeAsList([Text.Encoding]::UTF8.GetString($data))
    }
    [System.Collections.BitArray] static BinaryFromString([string]$string) {
        [string]$BinStR = [string]::Empty;
        foreach ($ch In $string.ToCharArray()) {
            $BinStR += [Convert]::ToString([int]$ch, 2).PadLeft(8, '0');
        }
        return [xconvert]::BinaryFromBinStR($BinStR)
    }
    static [string] BinaryToString([System.Collections.BitArray]$BitArray) {
        [string]$finalString = [string]::Empty;
        # Manually read the first 8 bits and
        while ($BitArray.Length -gt 0) {
            $ba_tempBitArray = [System.Collections.BitArray]::new($BitArray.Length - 8);
            $int_binaryValue = 0;
            if ($BitArray[0]) { $int_binaryValue += 1 };
            if ($BitArray[1]) { $int_binaryValue += 2 };
            if ($BitArray[2]) { $int_binaryValue += 4 };
            if ($BitArray[3]) { $int_binaryValue += 8 };
            if ($BitArray[4]) { $int_binaryValue += 16 };
            if ($BitArray[5]) { $int_binaryValue += 32 };
            if ($BitArray[6]) { $int_binaryValue += 64 };
            if ($BitArray[7]) { $int_binaryValue += 128 };
            $finalString += [Char]::ConvertFromUtf32($int_binaryValue);
            $int_counter = 0;
            for ($i = 8; $i -lt $BitArray.Length; $i++) {
                $ba_tempBitArray[$int_counter++] = $BitArray[$i];
            }
            $BitArray = $ba_tempBitArray;
        }
        return $finalString;
    }
    static [string] BytesToBinStR([byte[]]$Bytes) {
        return [xconvert]::BytesToBinStR($Bytes, $true);
    }
    static [string] BytesToBinStR([byte[]]$Bytes, [bool]$Tidy) {
        $bitArray = [System.Collections.BitArray]::new($Bytes);
        return [xconvert]::BinaryToBinStR($bitArray, $Tidy);
    }
    static [byte[]] BytesFromBinStR([string]$binary) {
        $binary = [string]::Join('', $binary.Split())
        $length = $binary.Length; if ($length % 8 -ne 0) {
            Throw [System.IO.InvalidDataException]::new("Your string is invalid. Make sure it has no typos.")
        }
        $list = [System.Collections.Generic.List[Byte]]::new()
        for ($i = 0; $i -lt $length; $i += 8) {
            [string]$binStr = $binary.Substring($i, 8)
            [void]$list.Add([Convert]::ToByte($binStr, 2));
        }
        return $list.ToArray();
    }
    static [byte[]] BytesFromBinary([System.Collections.BitArray]$binary) {
        return [xconvert]::BytesFromBinStR([xconvert]::BinaryToBinStR($binary))
    }
    static [string] BinaryToBinStR([System.Collections.BitArray]$binary) {
        $BinStR = [string]::Empty # (Binary String)
        for ($i = 0; $i -lt $binary.Length; $i++) {
            if ($binary[$i]) {
                $BinStR += "1 ";
            } else {
                $BinStR += "0 ";
            }
        }
        return $BinStR.Trim()
    }
    static [string] BinaryToBinStR([System.Collections.BitArray]$binary, [bool]$Tidy) {
        [string]$binStr = [xconvert]::BinaryToBinStR($binary)
        if ($Tidy) { $binStr = [string]::Join('', $binStr.Split()) }
        return $binStr
    }
    [System.Collections.BitArray] static BinaryFromBinStR([string]$binary) {
        return [System.Collections.BitArray]::new([xconvert]::BytesFromBinStR($binary))
    }
    static [void] ObjectToFile($Object, [string]$OutFile) {
        [xconvert]::ObjectToFile($Object, $OutFile, $false);
    }
    static [void] ObjectToFile($Object, [string]$OutFile, [bool]$encrypt) {
        try {
            $OutFile = [CryptoBase]::GetUnResolvedPath($OutFile)
            try {
                $resolved = [CryptoBase]::GetResolvedPath($OutFile);
                if ($?) { $OutFile = $resolved }
            } catch [System.Management.Automation.ItemNotFoundException] {
                New-Item -Path $OutFile -ItemType File | Out-Null
            } catch {
                throw $_
            }
            Export-Clixml -InputObject $Object -Path $OutFile
            if ($encrypt) { $(Get-Item $OutFile).Encrypt() }
        } catch {
            Write-Error $_
        }
    }
    [Object[]] static ToOrdered($InputObject) {
        $obj = $InputObject
        $convert = [scriptBlock]::Create({
                Param($obj)
                if ($obj -is [System.Management.Automation.PSCustomObject]) {
                    # a custom object: recurse on its properties
                    $oht = [ordered]@{}
                    foreach ($prop in $obj.psobject.Properties) {
                        $oht.Add($prop.Name, $(Invoke-Command -ScriptBlock $convert -ArgumentList $prop.Value))
                    }
                    return $oht
                } elseif ($obj -isnot [string] -and $obj -is [System.Collections.IEnumerable] -and $obj -isnot [System.Collections.IDictionary]) {
                    # A collection of sorts (other than a string or dictionary (hash table)), recurse on its elements.
                    return @(foreach ($el in $obj) { Invoke-Command -ScriptBlock $convert -ArgumentList $el })
                } else {
                    # a non-custom object, including .NET primitives and strings: use as-is.
                    return $obj
                }
            }
        )
        return $(Invoke-Command -ScriptBlock $convert -ArgumentList $obj)
    }
    [object] static ObjectFromFile([string]$FilePath) {
        return [xconvert]::ObjectFromFile($FilePath, $false)
    }
    [object] static ObjectFromFile([string]$FilePath, [string]$Type) {
        return [xconvert]::ObjectFromFile($FilePath, $Type, $false);
    }
    [object] static ObjectFromFile([string]$FilePath, [bool]$Decrypt) {
        $FilePath = [CryptoBase]::GetResolvedPath($FilePath); $Object = $null
        try {
            if ($Decrypt) { $(Get-Item $FilePath).Decrypt() }
            $Object = Import-Clixml -Path $FilePath
        } catch {
            Write-Error $_
        }
        return $Object
    }
    [object] static ObjectFromFile([string]$FilePath, [string]$Type, [bool]$Decrypt) {
        $FilePath = [CryptoBase]::GetResolvedPath($FilePath); $Object = $null
        try {
            if ($Decrypt) { $(Get-Item $FilePath).Decrypt() }
            $Object = (Import-Clixml -Path $FilePath) -as "$Type"
        } catch {
            Write-Error $_
        }
        return $Object
    }
    static [byte[]] StreamToByteArray([System.IO.Stream]$Stream) {
        $ms = [System.IO.MemoryStream]::new();
        $Stream.CopyTo($ms);
        $arr = $ms.ToArray();
        if ($null -ne $ms) { $ms.Flush(); $ms.Close(); $ms.Dispose() } else { Write-Warning "[x] MemoryStream was Not closed!" };
        return $arr;
    }
    [string]hidden static Reverse([string]$text) {
        [char[]]$array = $text.ToCharArray(); [array]::Reverse($array);
        return [String]::new($array);
    }
}
#endregion Custom_ObjectConverter

#region    Base85
# .SYNOPSIS
#     Base85 encoding
# .DESCRIPTION
#     A binary-to-text encoding scheme that uses 85 printable ASCII characters to represent binary data
# .EXAMPLE
#     $b = [System.Text.Encoding]::UTF8.GetBytes("Hello world")
#     [base85]::Encode($b)
#     [System.Text.Encoding]::UTF8.GetString([base85]::Decode("87cURD]j7BEbo7"))
# .EXAMPLE
#     [Base85]::GetString([Base85]::Decode([Base85]::Encode('Hello world!'))) | Should -Be 'Hello world!'
class Base85 : EncodingBase {
    static [String] $NON_A85_Pattern = "[^\x21-\x75]"

    Base85() {}
    static [string] Encode([string]$text) {
        return [Base85]::Encode([Base85]::new().GetBytes($text), $false)
    }
    static [string] Encode([byte[]]$Bytes) {
        return [Base85]::Encode($Bytes, $false)
    }
    static [string] Encode([byte[]]$Bytes, [bool]$Format) {
        # Using Format means we'll add "<~" Prefix and "~>" Suffix marks to output text
        [System.IO.Stream]$InputStream = New-Object -TypeName System.IO.MemoryStream(, $Bytes)
        [System.Object]$Timer = [System.Diagnostics.Stopwatch]::StartNew()
        [System.Object]$BinaryReader = New-Object -TypeName System.IO.BinaryReader($InputStream)
        [System.Object]$Ascii85Output = [System.Text.StringBuilder]::new()
        if ($Format) {
            [void]$Ascii85Output.Append("<~")
            [System.UInt16]$LineLen = 2
        }
        $EncodedString = [string]::Empty
        Try {
            Write-Debug "[base85] Encoding started at $([Datetime]::Now.Add($timer.Elapsed).ToString()) ..."
            While ([Byte[]]$BytesRead = $BinaryReader.ReadBytes(4)) {
                [System.UInt16]$ByteLength = $BytesRead.Length
                if ($ByteLength -lt 4) {
                    [System.Byte[]]$WorkingBytes = , 0x00 * 4
                    [System.Buffer]::BlockCopy($BytesRead, 0, $WorkingBytes, 0, $ByteLength)
                    [Array]::Resize([ref]$BytesRead, 4)
                    [System.Buffer]::BlockCopy($WorkingBytes, 0, $BytesRead, 0, 4)
                }
                if ([BitConverter]::IsLittleEndian) {
                    [Array]::Reverse($BytesRead)
                }
                [System.Char[]]$A85Chars = , 0x00 * 5
                [System.UInt32]$Sum = [BitConverter]::ToUInt32($BytesRead, 0)
                [System.UInt16]$ByteLen = [Math]::Ceiling(($ByteLength / 4) * 5)
                if ($ByteLength -eq 4 -And $Sum -eq 0) {
                    [System.Char[]]$A85Chunk = "z"
                } else {
                    [System.Char[]]$A85Chunk = , 0x00 * $ByteLen
                    $A85Chars[0] = [Base85]::GetChars([Math]::Floor(($Sum / [Math]::Pow(85, 4)) % 85) + 33)[0]
                    $A85Chars[1] = [Base85]::GetChars([Math]::Floor(($Sum / [Math]::Pow(85, 3)) % 85) + 33)[0]
                    $A85Chars[2] = [Base85]::GetChars([Math]::Floor(($Sum / [Math]::Pow(85, 2)) % 85) + 33)[0]
                    $A85Chars[3] = [Base85]::GetChars([Math]::Floor(($Sum / 85) % 85) + 33)[0]
                    $A85Chars[4] = [Base85]::GetChars([Math]::Floor($Sum % 85) + 33)[0]
                    [Array]::Copy($A85Chars, $A85Chunk, $ByteLen)
                }
                forEach ($A85Char in $A85Chunk) {
                    [void]$Ascii85Output.Append($A85Char)
                    if (!$Format) {
                        if ($LineLen -eq 64) {
                            [void]$Ascii85Output.Append("`r`n")
                            $LineLen = 0
                        } else {
                            $LineLen++
                        }
                    }
                }
            }
            if ($Format) {
                if ($LineLen -le 62) {
                    [void]$Ascii85Output.Append("~>")
                } else {
                    [void]$Ascii85Output.Append("~`r`n>")
                }
            }
            $EncodedString = $Ascii85Output.ToString()
        } catch {
            Write-Error "Exception: $($_.Exception.Message)"
            break;
        } finally {
            $BinaryReader.Close()
            $BinaryReader.Dispose()
            $InputStream.Close()
            $InputStream.Dispose()
            $Timer.Stop()
            [String]$TimeLapse = "[base85] Encoding completed in $($Timer.Elapsed.Hours) hours, $($Timer.Elapsed.Minutes) minutes, $($Timer.Elapsed.Seconds) seconds, $($Timer.Elapsed.Milliseconds) milliseconds"
            Write-Debug $TimeLapse
        }
        return $EncodedString
    }
    static [void] Encode([IO.FileInfo]$File) {
        [Base85]::Encode($File, $false, $File.FullName);
    }
    static [void] Encode([IO.FileInfo]$File, [bool]$Protect) {
        [Base85]::Encode($File, $Protect, $File.FullName);
    }
    static [void] Encode([IO.FileInfo]$File, [bool]$Protect, [string]$OutFile) {
        [Base85]::Encode($File, [securestring]$(if ($Protect) { [AesGCM]::GetPassword() }else { [securestring]::new() }), $OutFile)
    }
    static [void] Encode([IO.FileInfo]$File, [securestring]$Password, [string]$OutFile) {
        [ValidateNotNullOrEmpty()][string]$OutFile = [CryptoBase]::GetUnResolvedPath($OutFile);
        [ValidateNotNullOrEmpty()][IO.FileInfo]$File = [CryptoBase]::GetResolvedPath($File.FullName);
        if (![string]::IsNullOrWhiteSpace([xconvert]::ToString($Password))) { [AesGCM]::Encrypt($File, $Password, $File.FullName) };
        $streamReader = [System.IO.FileStream]::new($File.FullName, [System.IO.FileMode]::Open)
        $ba = [byte[]]::New($streamReader.Length);
        [void]$streamReader.Read($ba, 0, [int]$streamReader.Length);
        [void]$streamReader.Close();
        $encodedString = [Base85]::Encode($ba)
        $encodedBytes = [EncodingBase]::new().GetBytes($encodedString);
        $streamWriter = [System.IO.FileStream]::new($OutFile, [System.IO.FileMode]::OpenOrCreate);
        [void]$streamWriter.Write($encodedBytes, 0, $encodedBytes.Length);
        [void]$streamWriter.Close()
    }
    static [byte[]] Decode([string]$text) {
        $text = $text.Replace(" ", "").Replace("`r`n", "").Replace("`n", "")
        $decoded = $null; if ($text.StartsWith("<~") -or $text.EndsWith("~>")) {
            $text = $text.Replace("<~", "").Replace("~>", "")
        }
        if ($text -match $([Base85]::NON_A85_Pattern)) {
            Throw "Invalid Ascii85 data detected in input stream."
        }
        [System.Object]$InputStream = New-Object -TypeName System.IO.MemoryStream([System.Text.Encoding]::ASCII.GetBytes($text), 0, $text.Length)
        [System.Object]$BinaryReader = New-Object -TypeName System.IO.BinaryReader($InputStream)
        [System.Object]$OutputStream = New-Object -TypeName System.IO.MemoryStream
        [System.Object]$BinaryWriter = New-Object -TypeName System.IO.BinaryWriter($OutputStream)
        [System.Object]$Timer = [System.Diagnostics.Stopwatch]::StartNew()
        Try {
            Write-Debug "[base85] Decoding started at $([Datetime]::Now.Add($timer.Elapsed).ToString()) ..."
            While ([System.Byte[]]$BytesRead = $BinaryReader.ReadBytes(5)) {
                [System.UInt16]$ByteLength = $BytesRead.Length
                if ($ByteLength -lt 5) {
                    [System.Byte[]]$WorkingBytes = , 0x75 * 5
                    [System.Buffer]::BlockCopy($BytesRead, 0, $WorkingBytes, 0, $ByteLength)
                    [Array]::Resize([ref]$BytesRead, 5)
                    [System.Buffer]::BlockCopy($WorkingBytes, 0, $BytesRead, 0, 5)
                }
                [System.UInt16]$ByteLen = [Math]::Floor(($ByteLength * 4) / 5)
                [System.Byte[]]$BinChunk = , 0x00 * $ByteLen
                if ($BytesRead[0] -eq 0x7A) {
                    $BinaryWriter.Write($BinChunk)
                    [bool]$IsAtEnd = ($BinaryReader.BaseStream.Length -eq $BinaryReader.BaseStream.Position)
                    if (!$IsAtEnd) {
                        $BinaryReader.BaseStream.Position = $BinaryReader.BaseStream.Position - 4
                        Continue
                    }
                } else {
                    [System.UInt32]$Sum = 0
                    $Sum += ($BytesRead[0] - 33) * [Math]::Pow(85, 4)
                    $Sum += ($BytesRead[1] - 33) * [Math]::Pow(85, 3)
                    $Sum += ($BytesRead[2] - 33) * [Math]::Pow(85, 2)
                    $Sum += ($BytesRead[3] - 33) * 85
                    $Sum += ($BytesRead[4] - 33)
                    [System.Byte[]]$A85Bytes = [System.BitConverter]::GetBytes($Sum)
                    if ([BitConverter]::IsLittleEndian) {
                        [Array]::Reverse($A85Bytes)
                    }
                    [System.Buffer]::BlockCopy($A85Bytes, 0, $BinChunk, 0, $ByteLen)
                    $BinaryWriter.Write($BinChunk)
                }
            }
            $decoded = $OutputStream.ToArray()
        } catch {
            Write-Error "Exception: $($_.Exception.Message)"
            break
        } finally {
            $BinaryReader.Close()
            $BinaryReader.Dispose()
            $BinaryWriter.Close()
            $BinaryWriter.Dispose()
            $InputStream.Close()
            $InputStream.Dispose()
            $OutputStream.Close()
            $OutputStream.Dispose()
            $Timer.Stop()
            [String]$TimeLapse = "[base85] Decoding completed after $($Timer.Elapsed.Hours) hours, $($Timer.Elapsed.Minutes) minutes, $($Timer.Elapsed.Seconds) seconds, $($Timer.Elapsed.Milliseconds) milliseconds"
            Write-Debug $TimeLapse
        }
        return $decoded
    }
    static [void] Decode([IO.FileInfo]$File) {
        [Base85]::Decode($File, $false, $File);
    }
    static [void] Decode([IO.FileInfo]$File, [bool]$UnProtect) {
        [Base85]::Decode($File, $UnProtect, $File);
    }
    static [void] Decode([IO.FileInfo]$File, [bool]$UnProtect, [string]$OutFile) {
        [Base85]::Decode($File, [securestring]$(if ($UnProtect) { [AesGCM]::GetPassword() }else { [securestring]::new() }), $OutFile)
    }
    static [void] Decode([IO.FileInfo]$File, [securestring]$Password, [string]$OutFile) {
        [ValidateNotNullOrEmpty()][string]$OutFile = [CryptoBase]::GetUnResolvedPath($OutFile);
        [ValidateNotNullOrEmpty()][IO.FileInfo]$File = [CryptoBase]::GetResolvedPath($File.FullName);
        [byte[]]$ba = [IO.FILE]::ReadAllBytes($File.FullName)
        [byte[]]$da = [Base85]::Decode([EncodingBase]::new().GetString($ba))
        [void][IO.FILE]::WriteAllBytes($OutFile, $da)
        if (![string]::IsNullOrWhiteSpace([xconvert]::ToString($Password))) { [AesGCM]::Decrypt([IO.FileInfo]::new($OutFile), $Password, $OutFile) }
    }
}
#endregion Base85

# .SYNOPSIS
#     A class to convert dot ascii arts to b64string & vice versa
# .DESCRIPTION
#     Cli art created from sites like https://lachlanarthur.github.io/Braille-ASCII-Art/ can only be embeded as b64 string
#     So this class helps speed up the conversion process
# .EXAMPLE
#     $b64str = [cliart]::ToBase64String((Get-Item ./ascii))
#     [CliArt]::FromBase64String($b64str) | Write-Host -ForegroundColor Green
class CliArt {
    hidden [string]$Base64String
    CliArt([byte[]]$ArtBytes) {
        $this.Base64String = [CliArt]::ToBase64String($ArtBytes)
    }
    CliArt([IO.FileInfo]$Artfile) {
        $this.Base64String = [CliArt]::ToBase64String($Artfile)
    }
    CliArt([string]$Base64String) {
        $this.Base64String = $Base64String
    }
    static [string] ToBase64String([byte[]]$ArtBytes) {
        return [convert]::ToBase64String([xconvert]::ToCompressed([System.Text.Encoding]::UTF8.GetBytes([base85]::Encode($ArtBytes))))
    }
    static [string] ToBase64String([IO.FileInfo]$Artfile) {
        return [CliArt]::ToBase64String([IO.File]::ReadAllBytes($Artfile.FullName))
    }
    static [string] FromBase64String([string]$B64String) {
        return [System.Text.Encoding]::UTF8.GetString([Base85]::Decode([System.Text.Encoding]::UTF8.GetString([xconvert]::ToDeCompressed([convert]::FromBase64String($B64String)))))
    }
    [string] ToString() {
        return [CliArt]::FromBase64String($this.Base64String)
    }
}

#region     GitHub
class GitHub {
    static $webSession
    static [string] $UserName
    static hidden [bool] $IsInteractive = $false
    static hidden [string] $TokenFile = [GitHub]::GetTokenFile()

    static [PSObject] createSession() {
        return [Github]::createSession([Github]::UserName)
    }
    static [PSObject] createSession([string]$UserName) {
        [GitHub]::SetToken()
        return [GitHub]::createSession($UserName, [GitHub]::GetToken())
    }
    static [Psobject] createSession([string]$GitHubUserName, [securestring]$clientSecret) {
        [ValidateNotNullOrEmpty()][string]$GitHubUserName = $GitHubUserName
        [ValidateNotNullOrEmpty()][string]$GithubToken = $GithubToken = [xconvert]::Tostring([securestring]$clientSecret)
        $encodedAuth = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("$($GitHubUserName):$($GithubToken)"))
        $web_session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        [void]$web_session.Headers.Add('Authorization', "Basic $($encodedAuth)")
        [void]$web_session.Headers.Add('Accept', 'application/vnd.github.v3+json')
        [GitHub]::webSession = $web_session
        return $web_session
    }
    static [void] SetToken() {
        [GitHub]::SetToken([xconvert]::Tostring((Read-Host -Prompt "[GitHub] Paste/write your api token" -AsSecureString)), $(Read-Host -Prompt "[GitHub] Paste/write a Password to encrypt the token" -AsSecureString))
    }
    static [void] SetToken([string]$token, [securestring]$password) {
        if (![IO.File]::Exists([GitHub]::TokenFile)) { New-Item -Type File -Path ([GitHub]::TokenFile) -Force | Out-Null }
        [IO.File]::WriteAllText([GitHub]::TokenFile, [convert]::ToBase64String([AesGCM]::Encrypt([system.Text.Encoding]::UTF8.GetBytes($token), $password)), [System.Text.Encoding]::UTF8);
    }
    static [securestring] GetToken() {
        $sectoken = $null; $session_pass = [xconvert]::ToSecurestring('123');
        try {
            if ([GitHub]::IsInteractive) {
                if ([string]::IsNullOrWhiteSpace((Get-Content ([GitHub]::TokenFile) -ErrorAction Ignore))) {
                    Write-Host "[GitHub] You'll need to set your api token first. This is a One-Time Process :)" -ForegroundColor Green
                    [GitHub]::SetToken()
                    Write-Host "[GitHub] Good, now let's use the api token :)" -ForegroundColor DarkGreen
                } elseif ([GitHub]::ValidateBase64String([IO.File]::ReadAllText([GitHub]::TokenFile))) {
                    Write-Host "[GitHub] Encrypted token found in file: $([GitHub]::TokenFile)" -ForegroundColor DarkGreen
                } else {
                    throw [System.Exception]::New("Unable to read token file!")
                }
                $session_pass = Read-Host -Prompt "[GitHub] Input password to use your token" -AsSecureString
            } else {
                #Fix: Temporary Workaround: Thisz a pat from one of my GitHub a/cs.It Can only read/write gists. Will expire on 1/1/2025. DoNot Abuse this or I'll take it down!!
                $et = "OOLqqov4ugMQAtFcWqbzRwNBD65uf9JOZ+jzx1RtcHAZtnKaq1zkIpBcuv1MQfOkvIr/V066Zgsaq5Gka+VhlbqhV8apm8zcQomYjYqLaECKAonFeeo9MqvaP1F2VLgXokrxD1M6weLwS7KC+dyvAgv10IEvLzWFMw=="
                [GitHub]::SetToken([convert]::ToBase64String([AesGCM]::Decrypt([convert]::FromBase64String($et), $session_pass)), $session_pass)
            }
            $sectoken = [xconvert]::ToSecurestring([system.Text.Encoding]::UTF8.GetString(
                    [AesGCM]::Decrypt([Convert]::FromBase64String([IO.File]::ReadAllText([GitHub]::GetTokenFile())), $session_pass)
                )
            )
        } catch {
            throw $_
        }
        return $sectoken
    }
    static [PsObject] GetUserInfo([string]$UserName) {
        if ([string]::IsNullOrWhiteSpace([GitHub]::userName)) { [GitHub]::createSession() }
        $response = Invoke-RestMethod -Uri "https://api.github.com/user/$UserName" -WebSession ([GitHub]::webSession) -Method Get -Verbose:$false
        return $response
    }
    static [PsObject] GetGist([uri]$Uri) {
        $l = [GistFile]::Create($Uri)
        return [GitHub]::GetGist($l.Owner, $l.Id)
    }
    static [PsObject] GetGist([string]$UserName, [string]$GistId) {
        $t = [GitHub]::GetToken()
        if ($null -eq ([GitHub]::webSession)) {
            [GitHub]::webSession = $(if ($null -eq $t) {
                    [GitHub]::createSession($UserName)
                } else {
                    [GitHub]::createSession($UserName, $t)
                }
            )
        }
        if (!((Test-Connection github.com -Count 1).status -eq "Success")) {
            throw [System.Net.NetworkInformation.PingException]::new("PingException, PLease check your connection!");
        }
        if ([string]::IsNullOrWhiteSpace($GistId) -or $GistId -eq '*') {
            return Get-Gists -UserName $UserName -SecureToken $t
        }
        return Invoke-RestMethod -Uri "https://api.github.com/gists/$GistId" -WebSession ([GitHub]::webSession) -Method Get -Verbose:$false
    }
    Static [string] GetGistContent([string]$FileName, [uri]$GistUri) {
        return [GitHub]::GetGist($GistUri).files.$FileName.content
    }
    static [PsObject] CreateGist([string]$description, [array]$files) {
        $url = 'https://api.github.com/gists'
        $body = @{
            description = $description
            files       = @{}
        }
        foreach ($file in $files) {
            $body.files[$file.Name] = @{
                content = $file.Content
            }
        }
        $response = Invoke-RestMethod -Uri $url -WebSession ([GitHub]::webSession) -Method Post -Body ($body | ConvertTo-Json) -Verbose:$false
        return $response
    }
    static [PsObject] UpdateGist([GistFile]$gist, [string]$NewContent) {
        return ''
    }
    static [string] GetTokenFile() {
        if (![IO.File]::Exists([GitHub]::TokenFile)) {
            [GitHub]::TokenFile = [IO.Path]::Combine([GitHub]::Get_dataPath('Github', 'clicache'), "token");
        }
        return [GitHub]::TokenFile
    }
    static [PsObject] GetUserRepositories() {
        if ($null -eq [GitHub]::webSession) { [Github]::createSession() }
        $response = Invoke-RestMethod -Uri 'https://api.github.com/user/repos' -WebSession ([GitHub]::webSession) -Method Get -Verbose:$false
        return $response
    }
    static [psobject] ParseLink([string]$text, [bool]$throwOnFailure) {
        [ValidateNotNullOrEmpty()][string]$text = $text
        $uri = $text -as 'Uri'; if ($uri -isnot [Uri] -and $throwOnFailure) {
            throw [System.InvalidOperationException]::New("Could not create uri from text '$text'.")
        }; $Scheme = $uri.Scheme
        if ([regex]::IsMatch($text, '^(\/[a-zA-Z0-9_-]+)+|([a-zA-Z]:\\(((?![<>:"\/\\|?*]).)+\\?)*((?![<>:"\/\\|?*]).)+)$')) {
            if ($text.ToCharArray().Where({ $_ -in [IO.Path]::InvalidPathChars }).Count -eq 0) {
                $Scheme = 'file'
            } else {
                Write-Debug "'$text' has invalidPathChars in it !" -Debug
            }
        }
        $IsValid = $Scheme -in @('file', 'https')
        $IsGistUrl = [Regex]::IsMatch($text, 'https?://gist\.github\.com/\w+/[0-9a-f]+')
        $OutptObject = [pscustomobject]@{
            FullName = $text
            Scheme   = [PSCustomObject]@{
                Name      = $Scheme
                IsValid   = $IsValid
                IsGistUrl = $IsGistUrl
            }
        }
        return $OutptObject
    }
    static [string] Get_Host_Os() {
        # Should return one of these: [Enum]::GetNames([System.PlatformID])
        return $(if ($(Get-Variable IsWindows -Value)) { "Windows" }elseif ($(Get-Variable IsLinux -Value)) { "Linux" }elseif ($(Get-Variable IsMacOS -Value)) { "macOS" }else { "UNKNOWN" })
    }
    static [IO.DirectoryInfo] Get_dataPath([string]$appName, [string]$SubdirName) {
        $_Host_OS = [GitHub]::Get_Host_Os()
        $dataPath = if ($_Host_OS -eq 'Windows') {
            [System.IO.DirectoryInfo]::new([IO.Path]::Combine($Env:HOME, "AppData", "Roaming", $appName, $SubdirName))
        } elseif ($_Host_OS -in ('Linux', 'MacOs')) {
            [System.IO.DirectoryInfo]::new([IO.Path]::Combine((($env:PSModulePath -split [IO.Path]::PathSeparator)[0] | Split-Path | Split-Path), $appName, $SubdirName))
        } elseif ($_Host_OS -eq 'Unknown') {
            try {
                [System.IO.DirectoryInfo]::new([IO.Path]::Combine((($env:PSModulePath -split [IO.Path]::PathSeparator)[0] | Split-Path | Split-Path), $appName, $SubdirName))
            } catch {
                Write-Warning "Could not resolve chat data path"
                Write-Warning "HostOS = '$_Host_OS'. Could not resolve data path."
                [System.IO.Directory]::CreateTempSubdirectory(($SubdirName + 'Data-'))
            }
        } else {
            throw [InvalidOperationException]::new('Could not resolve data path. Get_Host_OS FAILED!')
        }
        if (!$dataPath.Exists) { [GitHub]::Create_Dir($dataPath) }
        return $dataPath
    }
    static [void] Create_Dir([string]$Path) {
        [GitHub]::Create_Dir([System.IO.DirectoryInfo]::new($Path))
    }
    static [void] Create_Dir([System.IO.DirectoryInfo]$Path) {
        [ValidateNotNullOrEmpty()][System.IO.DirectoryInfo]$Path = $Path
        $nF = @(); $p = $Path; while (!$p.Exists) { $nF += $p; $p = $p.Parent }
        [Array]::Reverse($nF); $nF | ForEach-Object { $_.Create(); Write-Verbose "Created $_" }
    }
    static [bool] ValidateBase64String([string]$base64) {
        return $(try { [void][Convert]::FromBase64String($base64); $true } catch { $false })
    }
    static [bool] IsConnected() {
        if (![bool]("System.Net.NetworkInformation.Ping" -as 'type')) { Add-Type -AssemblyName System.Net.NetworkInformation };
        $cs = $null; $re = @{ true = @{ m = "Success"; c = "Green" }; false = @{ m = "Failed"; c = "Red" } }
        Write-Host "[Github] Testing Connection ... " -ForegroundColor Blue -NoNewline
        try {
            [System.Net.NetworkInformation.PingReply]$PingReply = [System.Net.NetworkInformation.Ping]::new().Send("github.com");
            $cs = $PingReply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success
        } catch [System.Net.Sockets.SocketException], [System.Net.NetworkInformation.PingException] {
            $cs = $false
        } catch {
            $cs = $false;
            Write-Error $_
        }
        $re = $re[$cs.ToString()]
        Write-Host $re.m -ForegroundColor $re.c
        return $cs
    }
}
class GistFile {
    [string]$Name # with extention
    [string]$language
    [string]$type
    [string]$Owner
    [string]$raw_url
    [bool]$IsPublic
    [bool]$truncated
    [string]$Id
    [int]$size
    [GistFile[]]$files
    hidden [string]$content
    static [string]$UserName
    static [PsObject]$ChildItems
    GistFile([string]$filename) {
        $this.Name = $filename
    }
    GistFile([PsObject]$GistInfo) {
        $this.language = $GistInfo.language
        $this.IsPublic = $GistInfo.IsPublic
        $this.raw_url = $GistInfo.raw_url
        $this.type = $GistInfo.type
        $this.Name = $GistInfo.filename
        $this.size = $GistInfo.size
        $this.Id = $GistInfo.Id
        $this.Owner = $GistInfo.Owner
        if ([string]::IsNullOrWhiteSpace($this.Owner)) {
            if (![string]::IsNullOrWhiteSpace([GistFile]::UserName)) {
                $this.Owner = [GistFile]::UserName
            } else {
                Write-Warning "Gist Owner was not set!"
            }
        }
        if ($null -eq ([GistFile]::ChildItems) -and ![string]::IsNullOrWhiteSpace($this.Id)) {
            [GistFile]::ChildItems = [GitHub]::GetGist($this.Owner, $this.Id).files
        }
        if ($null -ne [GistFile]::ChildItems) {
            $_files = $null; [string[]]$filenames = [GistFile]::ChildItems | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
            try {
                $_files = [GistFile[]]$filenames.Foreach({
                        $_Item = [GistFile]::ChildItems."$_"
                        $_Gist = [GistFile]::new($_Item.filename)
                        $_Gist.language = $_Item.language
                        $_Gist.Ispublic = $this.IsPublic
                        $_Gist.raw_url = $_Item.raw_url
                        $_Gist.type = $_Item.type
                        $_Gist.size = $_Item.size
                        $_Gist.content = $_Item.content
                        $_Gist.Owner = $this.Owner; $_Gist.Id = $this.Id
                        $_Gist
                    }
                )
            } finally {
                [GistFile]::ChildItems = $null
                $this.files = $_files
                if ([string]::IsNullOrWhiteSpace($this.Name)) {
                    $this.Name = $filenames[0]
                }
            }
        }
    }
    static [GistFile] Create([uri]$GistUri) {
        $res = $null; $ogs = $GistUri.OriginalString
        $IsRawUri = $ogs.Contains('/raw/') -and $ogs.Contains('gist.githubusercontent.com')
        $seg = $GistUri.Segments
        $res = $(if ($IsRawUri) {
                $_name = $seg[-1]
                $rtri = 'https://gist.github.com/{0}{1}' -f $seg[1], $seg[2]
                $rtri = $rtri.Remove($rtri.Length - 1)
                $info = [GitHub]::GetGist([uri]::new($rtri))
                $file = $info.files."$_name"
                [PsCustomObject]@{
                    language = $file.language
                    IsPublic = $info.IsPublic
                    raw_url  = $file.raw_url
                    Owner    = $info.owner.login
                    type     = $file.type
                    filename = $_name
                    size     = $file.size
                    Id       = $seg[2].Replace('/', '')
                }
            } else {
                # $info = [GitHub]::GetGist($GistUri)
                [PsCustomObject]@{
                    language = ''
                    IsPublic = $null
                    raw_url  = ''
                    Owner    = $seg[1].Split('/')[0]
                    type     = ''
                    filename = ''
                    size     = ''
                    Id       = $seg[-1]
                }
            }
        )
        if (![string]::IsNullOrWhiteSpace($res.Owner)) {
            [GistFile]::UserName = $res.Owner
        }
        return [GistFile]::New($res)
    }
    [string] ShowFileInfo() {
        return "File: $($this.Name)"
    }
}

class Gist {
    [uri] $Uri
    [string] $Id
    [string] $Owner
    [string] $Description
    [bool] $IsPublic
    [GistFile[]] $Files = @()

    Gist() {}
    Gist([string]$Name) {
        $this.AddFile([GistFile]::new($Name))
    }
    [psobject] Post() {
        $gisfiles = @()
        $this.Files.Foreach({
                $gisfiles += @{
                    $_.Name = @{
                        content = $_.Content
                    }
                }
            }
        )
        $data = @{
            files       = $gisfiles
            description = $this.Description
            public      = $this.IsPublic
        } | ConvertTo-Json

        Write-Verbose ($data | Out-String)
        Write-Verbose "[PROCESS] Posting to https://api.github.com/gists"
        $invokeParams = @{
            Method      = 'Post'
            Uri         = "https://api.github.com/gists"
            WebSession  = [GitHub]::webSession
            Body        = $data
            ContentType = 'application/json'
        }
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $r = Invoke-RestMethod @invokeParams
        $r = $r | Select-Object @{Name = "Url"; Expression = { $_.html_url } }, Description, Public, @{Name = "Created"; Expression = { $_.created_at -as [datetime] } }
        return $r
    }
    [void] AddFile([GistFile]$file) {
        $this.Files += $file
    }
    [string] ShowInfo() {
        $info = "Gist ID: $($this.Id)"
        $info += "`nDescription: $($this.Description)"
        $info += "`nFiles:"
        foreach ($file in $this.Files.Values) {
            $info += "`n  - $($file.ShowFileInfo())"
        }
        return $info
    }
}

#endregion GitHub

class FileMonitor {
    static [bool] $FileClosed = $true
    static [bool] $FileLocked = $false
    static [System.ConsoleKeyInfo[]] $Keys = @()
    static [ValidateNotNull()][IO.FileInfo] $FileTowatch
    static [ValidateNotNull()][string] $LogvariableName = $(if ([string]::IsNullOrWhiteSpace([FileMonitor]::LogvariableName)) {
            $n = ('fileMonitor_log_' + [guid]::NewGuid().Guid).Replace('-', '_');
            Set-Variable -Name $n -Scope Global -Value ([string[]]@()); $n
        } else {
            [FileMonitor]::LogvariableName
        }
    )
    static [System.IO.FileSystemWatcher] MonitorFile([string]$File) {
        return [FileMonitor]::monitorFile($File, { Write-Host "[+] File monitor Completed" -ForegroundColor Green })
    }
    static [System.IO.FileSystemWatcher] MonitorFile([string]$File, [scriptblock]$Action) {
        [ValidateNotNull()][IO.FileInfo]$File = [IO.FileInfo][CryptoBase]::GetUnResolvedPath($File)
        if (![IO.File]::Exists($File.FullName)) {
            throw "The file does not exist"
        }
        [FileMonitor]::FileTowatch = $File
        $watcher = [System.IO.FileSystemWatcher]::new();
        $Watcher = New-Object IO.FileSystemWatcher ([IO.Path]::GetDirectoryName($File.FullName)), $File.Name -Property @{
            IncludeSubdirectories = $false
            EnableRaisingEvents   = $true
        }
        $watcher.Filter = $File.Name
        $watcher.NotifyFilter = [System.IO.NotifyFilters]::LastWrite;
        $onChange = Register-ObjectEvent $Watcher Changed -Action {
            [FileMonitor]::FileLocked = $true
        }
        $OnClosed = Register-ObjectEvent $Watcher Disposed -Action {
            [FileMonitor]::FileClosed = $true
        }
        # [Console]::Write("Monitoring changes to $File"); [Console]::WriteLine("Press 'crl^q' to stop")
        do {
            try {
                [FileMonitor]::FileLocked = [FileMonitor]::IsFileLocked($File.FullName)
            } catch [System.IO.IOException] {
                [FileMonitor]::FileLocked = $(if ($_.Exception.Message.Contains('is being used by another process')) {
                        $true
                    } else {
                        throw 'An error occured while checking the file'
                    }
                )
            } finally {
                [System.Threading.Thread]::Sleep(100)
            }
        } until ([FileMonitor]::FileClosed -and ![FileMonitor]::FileLocked -and ![FileMonitor]::IsFileOpenInVim($File.FullName))
        Invoke-Command -ScriptBlock $Action
        Unregister-Event -SubscriptionId $onChange.Id; $onChange.Dispose();
        Unregister-Event -SubscriptionId $OnClosed.Id; $OnClosed.Dispose(); $Watcher.Dispose();
        return $watcher
    }
    static [PsObject] MonitorFileAsync([string]$filePath) {
        # .EXAMPLE
        # $flt = [FileMonitor]::MonitorFileAsync($filePath)
        # $flt.Thread.CloseInputStream();
        # $flt.Thread.StopJobAsync();
        # Stop-Job -Name $flt.Name -Verbose -PassThru | Remove-Job -Force -Verbose
        # $flt.Thread.Dispose()MOnitorFile
        # while ((Get-Job -Name $flt.Name).State -ne "Completed") {
        #     # DO other STUFF here ...
        # }
        $threadscript = [scriptblock]::Create("[FileMonitor]::MonitorFile('$filePath')")
        $fLT_Name = "kLThread-$([guid]::NewGuid().Guid)"
        return [PSCustomObject]@{
            Name   = $fLT_Name
            Thread = Start-ThreadJob -ScriptBlock $threadscript -Name $fLT_Name
        }
    }
    static [string] GetLogSummary() {
        return [FileMonitor]::GetLogSummary([FileMonitor]::LogvariableName)
    }
    static [string] GetLogSummary([string]$LogvariableName) {
        [ValidateNotNullOrWhiteSpace()][string]$LogvariableName = $LogvariableName
        $l = Get-Variable -Name $LogvariableName -Scope Global -ValueOnly;
        $summ = ''; $rgx = "\[.*\] The file '.*' is open in nvim \(PID: \d+\)"
        if ($null -eq $l) { return '' }; $ct = $l.Where({ $_ -notmatch $rgx })
        $LogSessions = @();
        $LogSessions += $(if ($ct.count -gt 1) {
                (($l.ForEach({ if ($_ -notmatch $rgx) { $_ + '|' } else { $_ } })) -join "`n").Split('|')
            } else {
                [string]::Join("`n", $l)
            }
        )
        foreach ($item in $LogSessions) {
            $s = ''; $lines = $item.Split("`n")
            0 .. $lines.Count | ForEach-Object { if ($_ -eq 0) { $s += "$($lines[0])`n" } elseif ($lines[$_] -match $rgx -or $lines[$_ + 1] -match $rgx) { $s += '.' } else { $s += "`n$($lines[$_ - 1])" } }
            $summ += [string]::Join("`n", $s.Split("`n").ForEach({ if ($_ -like "......*") { '⋮' } else { $_ } })).Trim()
            $summ += "`n"
        }
        return $summ.Trim()
    }
    static [bool] IsFileOpenInVim([IO.FileInfo]$file) {
        $res = $null; $logvar = Get-Variable -Name ([FileMonitor]::LogvariableName) -Scope Global;
        $fileName = Split-Path -Path $File.FullName -Leaf;
        $res = $false; $_log_msg = @(); $processes = Get-Process -Name "nvim*", "vim*" -ErrorAction SilentlyContinue
        foreach ($process in $processes) {
            if ($process.CommandLine -like "*$fileName*") {
                $_log_msg = "[{0}] The file '{1}' is open in {2} (PID: {3})" -f [DateTime]::Now.ToString(), $fileName, $process.ProcessName, $process.Id
                $res = $true; continue
            }
        }
        $_log_msg = $_log_msg -join [Environment]::NewLine
        if ([string]::IsNullOrEmpty($_log_msg)) {
            $res = $false; $_log_msg = "[{0}] The file '{1}' is not open in vim" -f [DateTime]::Now.ToString(), $fileName
        }
        $logvar.Value += $_log_msg
        Set-Variable -Name ([FileMonitor]::LogvariableName) -Scope Global -Value $logvar.Value | Out-Null
        return $res
    }
    static [bool] IsFileLocked([string]$filePath) {
        $res = $true; $logvar = Get-Variable -Name ([FileMonitor]::LogvariableName) -Scope Global; $filePath = Resolve-Path -Path $filePath -ErrorAction SilentlyContinue
        try {
            # (lsof -t "$filePath" | wc -w) -gt 0
            [System.IO.FileStream]$stream = [IO.File]::Open($filePath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
            if ($stream) { $stream.Close(); $stream.Dispose() }
            $res = $false
        } finally {
            if ($res) { $logvar.Value += "[$([DateTime]::Now.ToString())] File is already locked by another process." }
            Set-Variable -Name ([FileMonitor]::LogvariableName) -Scope Global -Value $logvar.Value | Out-Null
        }
        return $res
    }
}

class SecretStore {
    [string]$Name
    [uri]$Url
    static hidden [ValidateNotNullOrWhiteSpace()][string]$DataPath

    SecretStore([string]$Name) {
        $this.Name = $Name
        if ([string]::IsNullOrWhiteSpace([SecretStore]::DataPath)) {
            [SecretStore]::DataPath = [IO.Path]::Combine([cryptobase]::Get_dataPath('ArgonCage', 'Data'), 'secrets')
        }
        $this.psobject.Properties.Add([psscriptproperty]::new('File', {
                    return [IO.FileInfo]::new([IO.Path]::Combine([SecretStore]::DataPath, $this.Name))
                }, {
                    param($value)
                    if ($value -is [IO.FileInfo]) {
                        [SecretStore]::DataPath = $value.Directory.FullName
                        $this.Name = $value.Name
                    } else {
                        throw "Invalid value assigned to File property"
                    }
                }
            )
        )
        $this.psobject.Properties.Add([psscriptproperty]::new('Size', {
                    if ([IO.File]::Exists($this.File.FullName)) {
                        $this.File = Get-Item $this.File.FullName
                        return $this.File.Length
                    }
                    return 0
                }, { throw "Cannot set Size property" }
            )
        )
    }
}

#region    FipsHMACSHA256
# .SYNOPSIS
#     A PowerShell class to provide a FIPS compliant alternative to the built-in [System.Security.Cryptography.HMACSHA256]
# .DESCRIPTION
#     FIPS (Federal Information Processing Standard) is a set of guidelines that specify the security requirements for cryptographic algorithms and protocols used in the United States government.
#     A FIPS compliant algorithm is one that has been reviewed and approved by the National Institute of Standards and Technology (NIST) to meet certain security standards.
#     The HMAC is a type of message authentication code that uses a secret key to verify the authenticity and integrity of a message.
#     It is based on a hash function, such as SHA-256, which is a cryptographic function that produces a fixed-size output (called a hash or message digest) from a variable-size input.
#     The built-in HMACSHA256 class in .NET Framework implements the HMAC using the SHA-256 hash function.
#     However, in older versions the HMACSHA256 class may not be FIPS compliant.
# .EXAMPLE
#     $br = [System.Text.Encoding]::UTF8.GetBytes("Hello world!")
#     $hc = [FipsHmacSha256]::new()
#     $hc.ComputeHash($br)
class FipsHmacSha256 : System.Security.Cryptography.HMAC {
    static hidden $rng
    static [System.Security.Cryptography.HMACSHA256] $HMAC
    static [ValidateNotNullOrEmpty()] [byte[]] $key

    FipsHmacSha256() {
        $this._Init();
    }
    FipsHmacSha256([Byte[]]$key) {
        [FipsHmacSha256]::Key = $key;
        $this._Init();
    }

    [string] ComputeHash([byte[]] $data) {
        if ($null -eq [FipsHmacSha256]::HMAC) {
            [FipsHmacSha256]::HMAC = [System.Security.Cryptography.HMACSHA256]::new([FipsHmacSha256]::key)
        }
        $hashBytes = [FipsHmacSha256]::HMAC.ComputeHash($data)
        $hash = [BitConverter]::ToString($hashBytes) -replace '-'
        return $hash
    }
    hidden [void] _Init() {
        if ($null -eq [FipsHmacSha256].RNG) {
            [FipsHmacSha256].psobject.Properties.Add([psscriptproperty]::new('RNG',
                    { return [System.Security.Cryptography.RNGCryptoServiceProvider]::new() }
                )
            )
        }
        $flags = [Reflection.BindingFlags]'Instance, NonPublic'
        [Reflection.FieldInfo]$m_hashName = [System.Security.Cryptography.HMAC].GetField('m_hashName', $flags)
        [Reflection.FieldInfo]$m_hash1 = [System.Security.Cryptography.HMAC].GetField('m_hash1', $flags)
        [Reflection.FieldInfo]$m_hash2 = [System.Security.Cryptography.HMAC].GetField('m_hash2', $flags)
        if ($null -ne $m_hashName) {
            $m_hashName.SetValue($this, 'SHA256')
        }
        if ($null -ne $m_hash1) {
            $m_hash1.SetValue($this, [System.Security.Cryptography.SHA256CryptoServiceProvider]::new())
        }
        if ($null -ne $m_hash2) {
            $m_hash2.SetValue($this, [System.Security.Cryptography.SHA256CryptoServiceProvider]::new())
        }
        if ($null -eq [FipsHmacSha256]::key) {
            $randomBytes = [Byte[]]::new(64); [FipsHmacSha256].RNG.GetBytes($randomBytes)
            [FipsHmacSha256]::Key = $randomBytes
            # Write-Verbose "Hexkey = $([BitConverter]::ToString([FipsHmacSha256]::Key).Tolower() -replace '-')" -verbose
        }
        $this.HashSizeValue = 256
    }
}
#endregion FipsHMACSHA256

#region    OTPKIT
class OTPKIT {
    [string] $key = ""

    static [string] CreateHOTP([string]$SECRET, [int]$Phone) {
        return [OTPKIT]::CreateHOTP($phone, [OTPKIT]::GetOtp($SECRET))
    }

    static [string] CreateHOTP([int]$phone, [string]$otp) {
        return [OTPKIT]::CreateHOTP($phone, $otp, 5)
    }
    static [string] CreateHOTP([int]$phone, [string]$otp, [int]$expiresAfter) {
        $ttl = $expiresAfter * 60 * 1000
        $expires = (Get-Date).AddMilliseconds($ttl).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        $bytes = [byte[]]::new(16)
        [System.Security.Cryptography.RNGCryptoServiceProvider]::new().GetBytes($bytes)
        $salt = [BitConverter]::ToString($bytes) -replace '-'
        $data = "$phone.$otp.$expires.$salt"
        Write-Host "data: " -NoNewline -ForegroundColor Green; Write-Host "$data" -ForegroundColor Blue
        $hashBase = [FipsHmacSha256]::new().ComputeHash([System.Text.Encoding]::ASCII.GetBytes($data))
        $hash = "$hashBase.$expires.$salt"
        # Import the Twilio module
        Import-Module -Name Twilio
        $phoneNumber = "+1234567890"
        $message = "Hello, this is a test message."
        [OTPKIT]::Send_TWILIO_SMS($phoneNumber, $message)
        return $hash
    }
    static [bool] Send_TWILIO_SMS ([string]$PhoneNumber, [string]$Message) {
        # Function to send SMS using Twilio
        # Twilio account SID and auth token
        $accountSid = "YOUR_TWILIO_ACCOUNT_SID"
        $authToken = "YOUR_TWILIO_AUTH_TOKEN"

        # Twilio phone number
        $twilioPhoneNumber = "YOUR_TWILIO_PHONE_NUMBER"

        # Create a new Twilio client
        $twilio = New-TwilioRestClient -AccountSid $accountSid -AuthToken $authToken

        # Send the SMS message
        $twilio.SendMessage($twilioPhoneNumber, $PhoneNumber, $Message)
        return $?
    }
    static [bool] VerifyHOTP([string]$otp, [int]$phone, [string]$hash) {
        if (-not $hash -match "\.") {
            return $false
        }

        $hashValue, $expires, $salt = $hash -split "\."

        $now = (Get-Date).Ticks / 10000
        if ($now -gt [double]$expires) {
            return $false
        }
        $data = "$phone.$otp.$expires.$salt"
        Write-Host "data: " -NoNewline -ForegroundColor Green; Write-Host "$data" -ForegroundColor Blue
        $newCalculatedHash = [FipsHmacSha256]::new().ComputeHash([System.Text.Encoding]::ASCII.GetBytes($data))

        if ($newCalculatedHash -eq $hashValue) {
            return $true
        }
        return $false
    }

    static [string] ParseOtpUrl([string]$otpURL) {
        # $otpURL can be decrypted text
        if (-not [System.Uri]::IsWellFormedUriString("$otpURL", "Absolute") -or $otpURL -notmatch "^otpauth://") { Write-Host "The decrypted text is not a valid OTP URL" "Error" ; $script:FileBrowser.Dispose() ; exit 1 }
        $parseOtpUrl = [scriptblock]::Create("[System.Web.HttpUtility]::ParseQueryString(([uri]::new('$otpURL')).Query)").Invoke()
        $otpType = $([uri]$otpURL).Host
        if ($otpType -eq "hotp") { Write-Warning "TOTP is only supported" }
        if ($otpType -eq "totp" ) { $otpType = "$otpType=" }
        $otpPeriod = if (-not [string]::IsNullOrEmpty($parseOtpUrl["period"])) { $parseOtpUrl["period"] } else { 30 }
        $otpDigits = if (-not [string]::IsNullOrEmpty($parseOtpUrl["digits"])) { $parseOtpUrl["digits"] } else { 6 }
        $otpSecret = $parseOtpUrl["secret"]
        return GetOtp "$otpSecret" "$otpDigits" "$otpPeriod"
    }

    static [string] GetOtp([string]$SECRET) {
        return [OTPKIT]::GetOtp($SECRET, 4, "5")
    }
    static [string] GetOtp([string]$SECRET, [int]$LENGTH, [string]$WINDOW) {
        $hmac = New-Object -TypeName System.Security.Cryptography.HMACSHA1
        $hmac.key = $([OTPKIT]::ConvertBase32ToHex($SECRET.ToUpper())) -replace '^0x', '' -split "(?<=\G\w{2})(?=\w{2})" | ForEach-Object { [Convert]::ToByte( $_, 16 ) }
        $timeSpan = $(New-TimeSpan -Start (Get-Date -Year 1970 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0) -End (Get-Date).ToUniversalTime()).TotalSeconds
        $rndHash = $hmac.ComputeHash([byte[]][BitConverter]::GetBytes([Convert]::ToInt64([Math]::Floor($timeSpan / $WINDOW))))
        $toffset = $rndhash[($rndHash.Length - 1)] -band 0xf
        $fullOTP = ($rndhash[$toffset] -band 0x7f) * [math]::pow(2, 24)
        $fullOTP += ($rndHash[$toffset + 1] -band 0xff) * [math]::pow(2, 16)
        $fullOTP += ($rndHash[$toffset + 2] -band 0xff) * [math]::pow(2, 8)
        $fullOTP += ($rndHash[$toffset + 3] -band 0xff)

        $modNumber = [math]::pow(10, $LENGTH)
        $otp = $fullOTP % $modNumber
        $otp = $otp.ToString("0" * $LENGTH)
        return $otp
    }
    static [string] ConvertBase32ToHex([string]$base32) {
        $base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        $bits = "";
        $hex = "";

        for ($i = 0; $i -lt $base32.Length; $i++) {
            $val = $base32chars.IndexOf($base32.Chars($i));
            $binary = [Convert]::ToString($val, 2)
            $str = $binary.ToString();
            $len = 5
            $pad = '0'
            if (($len + 1) -ge $str.Length) {
                while (($len - 1) -ge $str.Length) {
                    $str = ($pad + $str)
                }
            }
            $bits += $str
        }

        for ($i = 0; $i + 4 -le $bits.Length; $i += 4) {
            $chunk = $bits.Substring($i, 4)
            # Write-Host $chunk
            $intChunk = [Convert]::ToInt32($chunk, 2)
            $hexChunk = '{0:x}' -f $([int]$intChunk)
            # Write-Host $hexChunk
            $hex = $hex + $hexChunk
        }
        return $hex;
    }
}
#endregion OTPKIT

#region    VaultStuff
# A managed credential object. Makes it easy to protect, convert, save and stuff ..
class CredManaged {
    [string]$target
    [CredType]hidden $type = [CredType]1;
    [bool]hidden $IsProtected = $false;
    [ValidateNotNullOrEmpty()][string]$UserName = $(whoami);
    [ValidateNotNullOrEmpty()][securestring]$Password = [securestring]::new();
    [ValidateNotNullOrEmpty()][string]hidden $Domain = [System.Environment]::UserDomainName;
    [ValidateSet('User', 'Machine')][ValidateNotNullOrEmpty()][string]hidden $Scope = 'User';

    CredManaged() {}
    CredManaged([string]$target, [string]$username, [SecureString]$password) {
        ($this.target, $this.username, $this.password) = ($target, $username, $password)
    }
    CredManaged([string]$target, [string]$username, [SecureString]$password, [CredType]$type) {
        ($this.target, $this.username, $this.password, $this.type) = ($target, $username, $password, $type)
    }
    CredManaged([PSCredential]$PSCredential) {
        ($this.UserName, $this.Password) = ($PSCredential.UserName, $PSCredential.Password)
    }
    CredManaged([string]$target, [PSCredential]$PSCredential) {
        ($this.target, $this.UserName, $this.Password) = ($target, $PSCredential.UserName, $PSCredential.Password)
    }
    [void]Protect() {
        $_scope_ = [EncryptionScope]$this.Scope
        $_Props_ = @($this | Get-Member -Force | Where-Object { $_.MemberType -eq 'Property' -and $_.Name -ne 'Scope' } | Select-Object -ExpandProperty Name)
        foreach ($n in $_Props_) {
            $OBJ = $this.$n
            if ($n.Equals('Password')) {
                $this.$n = [xconvert]::ToSecurestring([Base85]::Encode([xconvert]::ToProtected([xconvert]::Tostring($OBJ), $_scope_)))
            } else {
                $this.$n = [xconvert]::ToProtected($OBJ, $_scope_)
            }
        }
        Invoke-Command -InputObject $this.IsProtected -NoNewScope -ScriptBlock $([ScriptBlock]::Create({
                    $this.psobject.Properties.Add([psscriptproperty]::new('IsProtected', { return $true }))
                }
            )
        )
    }
    [void]UnProtect() {
        $_scope_ = [EncryptionScope]$this.Scope
        $_Props_ = @($this | Get-Member -Force | Where-Object { $_.MemberType -eq 'Property' -and $_.Name -ne 'Scope' } | Select-Object -ExpandProperty Name)
        foreach ($n in $_Props_) {
            $OBJ = $this.$n
            if ($n.Equals('Password')) {
                $this.$n = [xconvert]::ToSecurestring([xconvert]::ToUnProtected([encodingBase]::GetString([Base85]::Decode([xconvert]::Tostring($OBJ))), $_scope_));
            } else {
                $this.$n = [xconvert]::ToUnProtected($OBJ, $_scope_);
            }
        }
        Invoke-Command -InputObject $this.IsProtected -NoNewScope -ScriptBlock $([ScriptBlock]::Create({
                    $this.psobject.Properties.Add([psscriptproperty]::new('IsProtected', { return $false }))
                }
            )
        )
    }
    [void]SaveToVault() {
        $CredMan = [CredentialManager]::new();
        [void]$CredMan.SaveCredential($this.target, $this.UserName, $this.Password);
    }
    [string]ToString() {
        $str = $this.UserName
        if ($str.Length -gt 9) { $str = $str.Substring(0, 6) + '...' }
        return $str
    }
}
class NativeCredential {
    [System.Int32]$AttributeCount
    [UInt32]$CredentialBlobSize
    [IntPtr]$CredentialBlob
    [IntPtr]$TargetAlias
    [System.Int32]$Type
    [IntPtr]$TargetName
    [IntPtr]$Attributes
    [IntPtr]$UserName
    [UInt32]$Persist
    [IntPtr]$Comment

    NativeCredential([CredManaged]$Cr3dential) {
        $this._init_();
        $this.CredentialBlobSize = [UInt32](($Cr3dential.password.Length + 1) * 2)
        $this.TargetName = [System.Runtime.InteropServices.Marshal]::StringToCoTaskMemUni($Cr3dential.target)
        $this.CredentialBlob = [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($Cr3dential.password)
        $this.UserName = [System.Runtime.InteropServices.Marshal]::StringToCoTaskMemUni($Cr3dential.username)
    }
    NativeCredential([string]$target, [string]$username, [securestring]$password) {
        $this._init_();
        $this.CredentialBlobSize = [UInt32](($password.Length + 1) * 2);
        $this.TargetName = [System.Runtime.InteropServices.Marshal]::StringToCoTaskMemUni($target);
        $this.CredentialBlob = [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($password);
        $this.UserName = [System.Runtime.InteropServices.Marshal]::StringToCoTaskMemUni($username);
    }
    hidden _init_() {
        $this.AttributeCount = 0
        $this.Comment = [IntPtr]::Zero
        $this.Attributes = [IntPtr]::Zero
        $this.TargetAlias = [IntPtr]::Zero
        $this.Type = [CredType]::Generic.value__
        $this.Persist = [UInt32] [CredentialPersistence]::LocalComputer
    }
}
# Windows credential manager
class CredentialManager {
    static $LastErrorCode
    CredentialManager() { $this::Init() }
    [object] static hidden Advapi32() {
        return (New-Object -TypeName CredentialManager.Advapi32)
    }
    static [void] SaveCredential([string]$title, [SecureString]$SecureString) {
        $UserName = [System.Environment]::GetEnvironmentVariable('UserName');
        [CredentialManager]::SaveCredential([CredManaged]::new($title, $UserName, $SecureString));
    }
    static [void] SaveCredential([string]$title, [string]$UserName, [SecureString]$SecureString) {
        [CredentialManager]::SaveCredential([CredManaged]::new($title, $UserName, $SecureString));
    }
    static [void] SaveCredential([CredManaged]$Object) {
        if ($null -eq [CredentialManager].CONSTANTS) { [CredentialManager]::Init() }
        # Create the native credential object.
        $NativeCredential = New-Object -TypeName CredentialManager.Advapi32+NativeCredential;
        foreach ($prop in ([NativeCredential]::new($Object).PsObject.properties)) {
            $NativeCredential."$($prop.Name)" = $prop.Value
        }
        # Save Generic credential to the Windows Credential Vault.
        $result = [CredentialManager]::Advapi32()::CredWrite([ref]$NativeCredential, 0)
        [CredentialManager]::LastErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error();
        if (!$result) {
            throw [Exception]::new("Error saving credential: 0x" + "{0}" -f [CredentialManager]::LastErrorCode)
        }
        # Clean up memory allocated for the native credential object.
        [System.Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($NativeCredential.TargetName)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($NativeCredential.CredentialBlob)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($NativeCredential.UserName)
    }
    static [bool] Remove([string]$target, [CredType]$type) {
        if ($null -eq [CredentialManager].CONSTANTS) { [CredentialManager]::Init() }
        $Isdeleted = [CredentialManager]::Advapi32()::CredDelete($target, $type, 0);
        [CredentialManager]::LastErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error();
        if (!$Isdeleted) {
            if ([CredentialManager]::LastErrorCode -eq [CredentialManager].CONSTANTS.ERROR_NOT_FOUND) {
                throw [CredentialNotFoundException]::new("DeleteCred failed with the error code $([CredentialManager]::LastErrorCode) (credential not found).");
            } else {
                throw [Exception]::new("DeleteCred failed with the error code $([CredentialManager]::LastErrorCode).");
            }
        }
        return $Isdeleted
    }
    [CredManaged] static GetCredential([string]$target) {
        #uses the default $(whoami)
        return [CredentialManager]::GetCredential($target, (Get-Item Env:\USERNAME).Value);
    }
    [CredManaged] static GetCredential([string]$target, [string]$username) {
        return [CredentialManager]::GetCredential($target, [CredType]::Generic, $username);
    }
    # Method for retrieving a saved credential from the Windows Credential Vault.
    [CredManaged] static GetCredential([string]$target, [CredType]$type, [string]$username) {
        if ($null -eq [CredentialManager].CONSTANTS) { [CredentialManager]::Init() }
        $NativeCredential = New-Object -TypeName CredentialManager.Advapi32+NativeCredential;
        foreach ($prop in ([NativeCredential]::new($target, $username, [securestring]::new()).PsObject.properties)) {
            $NativeCredential."$($prop.Name)" = $prop.Value
        }
        # Declare variables
        $AdvAPI32 = [CredentialManager]::Advapi32()
        $outCredential = [IntPtr]::Zero # To hold the retrieved native credential object.
        # Try to retrieve the credential from the Windows Credential Vault.
        $result = $AdvAPI32::CredRead($target, $type.value__, 0, [ref]$outCredential)
        [CredentialManager]::LastErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error();
        if (!$result) {
            $errorCode = [CredentialManager]::LastErrorCode
            if ($errorCode -eq [CredentialManager].CONSTANTS.ERROR_NOT_FOUND) {
                $(Get-Variable host).value.UI.WriteErrorLine("`nERROR_NOT_FOUND: Credential '$target' not found in Windows Credential Vault. Returning Empty Object ...`n");
                return [CredManaged]::new();
            } else {
                throw [Exception]::new("Error reading '{0}' in Windows Credential Vault. ErrorCode: 0x{1}" -f $target, $errorCode)
            }
        }
        # Convert the retrieved native credential object to a managed Credential object & Get the Credential from the mem location
        $NativeCredential = [System.Runtime.InteropServices.Marshal]::PtrToStructure($outCredential, [Type]"CredentialManager.Advapi32+NativeCredential") -as 'CredentialManager.Advapi32+NativeCredential'
        [System.GC]::Collect();
        $target = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($NativeCredential.TargetName)
        $password = [Runtime.InteropServices.Marshal]::PtrToStringUni($NativeCredential.CredentialBlob)
        $targetuser = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($NativeCredential.UserName)
        $credential = [CredManaged]::new($target, $targetuser, [xconvert]::ToSecurestring($password));
        # Clean up memory allocated for the native credential object.
        [void]$AdvAPI32::CredFree($outCredential); [CredentialManager]::LastErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error();
        # Return the managed Credential object.
        return $credential
    }
    [System.Collections.ObjectModel.Collection[CredManaged]] static RetreiveAll() {
        $Credentials = [System.Collections.ObjectModel.Collection[CredManaged]]::new();
        # CredEnumerate is slow af so, I ditched it.
        $credList = [CredentialManager]::get_StoredCreds();
        foreach ($cred in $credList) {
            Write-Verbose "CredentialManager.GetCredential($($cred.Target))";
            $Credentials.Add([CredManaged]([CredentialManager]::GetCredential($cred.Target, $cred.Type, $cred.User)));
        }
        return $Credentials
    }
    [Psobject[]] static hidden get_StoredCreds() {
        # until I know the existance of a [wrapper module](https://learn.microsoft.com/en-us/powershell/utility-modules/crescendo/overview?view=ps-modules), I'll stick to this Hack.
        $cmdkey = (Get-Command cmdkey -ErrorAction SilentlyContinue).Source
        if ([string]::IsNullOrEmpty($cmdkey)) { throw [System.Exception]::new('get_StoredCreds() Failed.') }
        $outputLines = (&$cmdkey /list) -split "`n"
        [CredentialManager]::LastErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error();
        if ($outputLines) {
        } else {
            throw $error[0].Exception.Message
        }
        $target = $type = $user = $perst = $null
        $credList = $(foreach ($line in $outputLines) {
                if ($line -match "^\s*Target:\s*(.+)$") {
                    $target = $matches[1]
                } elseif ($line -match "^\s*Type:\s*(.+)$") {
                    $type = $matches[1]
                } elseif ($line -match "^\s*User:\s*(.+)$") {
                    $user = $matches[1]
                } elseif ($line -match "^\s*Local machine persistence$") {
                    $perst = "LocalComputer"
                } elseif ($line -match "^\s*Enterprise persistence$") {
                    $perst = 'Enterprise'
                }
                if ($target -and $type -and $user -and ![string]::IsNullOrEmpty($perst)) {
                    [PSCustomObject]@{
                        Target      = [string]$target
                        Type        = [CredType]$type
                        User        = [string]$user
                        Persistence = [CredentialPersistence]$perst
                    }
                    $target = $type = $user = $perst = $null
                }
            }
        ) | Select-Object @{l = 'Target'; e = { $_.target.replace('LegacyGeneric:target=', '').replace('WindowsLive:target=', '') } }, Type, User, Persistence | Where-Object { $_.target -ne 'virtualapp/didlogical' };
        return $credList
    }
    static hidden [void] Init() {
        $Host_OS = $(if ($(Get-Variable PSVersionTable -Value).PSVersion.Major -le 5 -or $(Get-Variable IsWindows -Value)) { "Windows" }elseif ($(Get-Variable IsLinux -Value)) { "Linux" }elseif ($(Get-Variable IsMacOS -Value)) { "macOS" }else { "UNKNOWN" });
        if ($Host_OS -ne "Windows") {
            throw "Error: '$Host_OS' is Unsupported. CredentialManager class works on windows only."
        }
        $CONSTANTS = [psobject]::new()
        $CONSTANTS.psobject.Properties.Add([psscriptproperty]::new('ERROR_SUCCESS', { return 0 }))
        $CONSTANTS.psobject.Properties.Add([psscriptproperty]::new('ERROR_NOT_FOUND', { return 1168 }))
        $CONSTANTS.psobject.Properties.Add([psscriptproperty]::new('ERROR_INVALID_FLAGS', { return 1004 }))
        $CONSTANTS.psobject.Properties.Add([psscriptproperty]::new('CRED_PERSIST_LOCAL_MACHINE', { return 2 }))
        $CONSTANTS.psobject.Properties.Add([psscriptproperty]::new('CRED_MAX_USERNAME_LENGTH', { return 514 }))
        $CONSTANTS.psobject.Properties.Add([psscriptproperty]::new('CRED_MAX_CREDENTIAL_BLOB_SIZE', { return 512 }))
        $CONSTANTS.psobject.Properties.Add([psscriptproperty]::new('CRED_MAX_GENERIC_TARGET_LENGTH', { return 32767 }))
        [CredentialManager].psobject.Properties.Add([psscriptproperty]::new('CONSTANTS', { return $CONSTANTS }))
        # Import native functions from Advapi32.dll
        # No other choice but to use Add-Type. ie: https://stackoverflow.com/questions/64405866/invoke-runtime-interopservices-dllimportattribute
        # So CredentialManager.Advapi32+functionName it is!
        if (![bool]('CredentialManager.Advapi32' -as 'type')) { Add-Type -Namespace CredentialManager -Name Advapi32 -MemberDefinition ([xconvert]::ToDeCompressed('H4sIAAAAAAAEALVUS2/aQBC+91eMOIFqWQT6kIo4UB4VKkQohuYQ5bDYA1lpvUt31zSk6n/vrB+AMW1a2vhge+f5ffONDQCwSZaCh4AyiaGvMZrvNggfIOHSwvdXkF+fUKKmsC5ceTBQMeNyxoz5pnREtlZh66O2fMVDZpHM7cL8hRu+FHiU8cYrSpZT3hYpw0eLMkIX+86DKXvkMQHswvv9YfhIx3rheQ1XzWazkQL+kd5Pic1QG25slVuAxnAlM24TFTIxZeEDl5gxG0qLeqO5SSkdNbgLrE5CO2E7ldh69vjMZeQH+DVBaTkTHvQfmA7QUmr+5i8kD1WEjftjlCYtleLMMg/w8ogU9EiwtekUpr1c7tY5KsXlGuZMr9Fes7ji6as4piZ784BGP+cxwoQZe6u5pcl3Sm1JOKdbwJ8qxQpN9/ZgZyzGNIMwoVK77AWDLDo7VHKO5cmfZQA9S/nLxGJfJUfIx9LOrD54zfkh9ARnFdfCoE6n87KKXjPLt3jQFS4XNmd7RtjccypsLsUNjYzk9cdukdUmQL3lIRqfwl1944/Gk+F8PB3+egEO+D8KtSztQdG7FHGyPv9F0hL9sqS566ykAyHG8UZpW6/1oi3b8HbLj4SopR+23s2UA9OFmiNwgyy6rf1GYo822LopDbVWmvwkMul+0JzUpl8O/bu0hKVSAoqy9buxvC92z6YcPEhte7Et3XKbw6SR6GwxcqvhAW1iQTPcj5pOjc7f03QS4wvwTOtmRDWuqqufEKHDMae6IFbtFqzcB3AJmZFGrF2G16VmcKuTdS3wD6Z7pu85lAMU+MzMn4Wb1fi3RWp0fgKYas6b9AcAAA==')) }
        if (Get-Service vaultsvc -ErrorAction SilentlyContinue) { Start-Service vaultsvc -ErrorAction Stop }
    }
}

# .DESCRIPTION
#     Hashicorp VaultClient helper class for interacting with a Vault server by the Vault API.
#     To use this class, you will need to have access to a running instance of Hashicorp Vault.
#     You can download it from from the Hashicorp website at https://www.hashicorp.com/products/vault/.
# .EXAMPLE
#     $vaucl = [VaultClient]::new('<VAULT_ADDRESS>', '<VAULT_TOKEN>', '<VAULT_PROTOCOL>')
#     $vault = $vaucl.GetVaultServer()
#     $secrets = $vaucl.GetVaultSecretList('<VAULT_PATH>')
#     $vaucl.SetVaultSecret('<VAULT_PATH>', @{key = 'value'})
class VaultClient {
    # Properties
    [string] $Address # This is the URL or IP address of your Vault server, including the port number if applicable. You can find this value in the api_addr field of the vault.hcl configuration file, or you can use the vault status command to display the current address of the Vault server.
    [string] $Token # This is a token that is used to authenticate with the Vault server. You can generate a new token using the vault token create command, or you can use the vault status command to display the current token of the Vault server.
    [string] $Protocol # This is the protocol that will be used to communicate with the Vault server. The most common value is https, but you can also use http if you have configured your Vault server to use an insecure connection. You can find this value in the api_addr field of the vault.hcl configuration file, or you can use the vault status command to display the current protocol of the Vault server.
    [string] $Url = [string]::Empty
    hidden [PSCustomObject] $ClientObj = $null
    static hidden $releases # ie: [Microsoft.PowerShell.Commands.HtmlWebResponseObject]

    # Constructor for the VaultClient class
    VaultClient([string]$address, [string]$token, [string]$protocol) {
        $this.Address = $address
        $this.Token = $token
        $this.Protocol = $protocol
        # Set the Vault URL
        $this.Url = "{0}://{1}/v1/" -f $protocol, $address
        # Generate the vaultClient object
        $this.GenerateVaultClient($token)
    }
    # Download and Install the latest Vault
    static [void] Install() {
        [console]::Write("Check Latest Version ...")
        [VaultClient]::releases = Invoke-WebRequest "https://releases.hashicorp.com/vault/" -Verbose:$false
        [string]$latestver = $([VaultClient]::releases.Links | ForEach-Object { $_.outerText.split('-')[0].split('_')[1] -as 'version' } | Sort-Object -Descending)[0].tostring()
        [VaultClient]::Install($latestver)
    }
    static [void] Install([string]$version) {
        [console]::WriteLine(" Found vault version: $version")
        if ($null -eq [VaultClient]::releases) { [VaultClient]::releases = Invoke-WebRequest "https://releases.hashicorp.com/vault/" -Verbose:$false }
        [string]$latest_dl = $(Invoke-WebRequest ("https://releases.hashicorp.com" + ([VaultClient]::releases.Links | Where-Object { $_.href -like "*/$version/*" } | Select-Object -ExpandProperty href)) -Verbose:$false).Links.href | Where-Object { $_ -like "*windows_386*" }
        $p = Get-Variable progressPreference -ValueOnly; $progressPreference = "SilentlyContinue"
        $Outfile = [IO.FileInfo]::new([CryptoBase]::GetUnResolvedPath("vault_$version.zip"));
        try {
            $should_download = $true
            if ($Outfile.Exists()) {
                #TODO: Check version of the file, if the version is lower, then $should_download = $true
            }
            if ($should_download) {
                $Outfile = [NetworkManager]::DownloadFile([uri]::new($latest_dl), $Outfile.FullName)
            }
            if ($Outfile.Exists()) {
                Expand-Archive -Path $Outfile.FullName -DestinationPath "C:\Program Files\Vault\"
            }
            [void][System.Environment]::SetEnvironmentVariable("PATH", $env:PATH + ";C:\Program Files\Vault\", "Machine")
        } catch {
            throw $_
        } finally {
            Remove-Item $Outfile -Force -ErrorAction SilentlyContinue
            $progressPreference = $p
        }
        # refresh env: like Update-SessionEnvironment from choco~
    }
    # Method to generate the vaultClient object
    [void] GenerateVaultClient([string]$token) {
        # Set the Vault token
        $this.ClientObj = @{
            Token   = $token
            Headers = @{ 'X-Vault-Token' = $token }
            BaseUri = $this.Url
        }
    }

    # Method to get a Vault server
    [PSCustomObject] GetVaultServer() {
        # Create a custom object with the vaultClient object
        $vault = New-Object -TypeName PSObject -Property $this.ClientObj
        # Return the custom object
        return $vault
    }

    # Method to get a Vault secret
    [Hashtable] GetVaultSecret([string]$path) {
        # Get the server
        $vault = $this.GetVaultServer()
        # Get the secret at the specified path
        $uri = $vault.BaseUri + $path
        $secret = Invoke-WebRequest -Uri $uri -Headers $vault.Headers | Select-Object -ExpandProperty Content | ConvertFrom-Json | Select-Object -ExpandProperty data
        # Return the secret
        return $secret
    }

    # Method to get a list of Vault secrets
    [string[]] GetVaultSecretList([string]$path) {
        return $this.GetVaultSecretList($path, $null)
    }
    # Method to get a list of Vault secrets
    [string[]] GetVaultSecretList([string]$path, [PSCustomObject]$vault = $null) {
        # Get the server
        if (!$vault) { $vault = $this.GetVaultServer() }
        # Get the list of secrets
        $uri = $vault.BaseUri + $path
        $secrets = Invoke-WebRequest -Uri $uri -Headers $vault.Headers -CustomMethod 'list' | Select-Object -ExpandProperty Content | ConvertFrom-Json | Select-Object -ExpandProperty data | Select-Object -ExpandProperty keys | ForEach-Object {
            if ($_ -like '*/') {
                $this.GetVaultSecretList($("$path/$_").Trim("/"), $vault)
            } else {
                "$path/$_"
            }
        }
        # Return the list of secrets
        return $secrets
    }

    # Method to set a Vault secret
    [void] SetVaultSecret([string]$path, [Hashtable]$secret) {
        $vault = $this.GetVaultServer()
        # Set the secret at the specified path
        $uri = $vault.BaseUri + $path
        $data = @{data = $secret } | ConvertTo-Json
        Invoke-WebRequest -Uri $uri -Headers $vault.Headers -Method 'POST' -Body $data | Select-Object -ExpandProperty Content | ConvertFrom-Json | Select-Object -ExpandProperty data
    }
    # Method to remove a Vault secret
    [void] RemoveVaultSecret([string]$path) {
        $vault = $this.GetVaultServer()
        # Remove the secret at the specified path
        $uri = $vault.BaseUri + $path
        Invoke-WebRequest -Uri $uri -Headers $vault.Headers -Method 'DELETE'
    }

    # Method to get a Vault group
    [Hashtable] GetVaultGroup([string]$name) {
        $vault = $this.GetVaultServer()
        # Get the group with the specified name
        $uri = $vault.BaseUri + "identity/group/name/$name"
        $group = Invoke-WebRequest -Uri $uri -Headers $vault.Headers | Select-Object -ExpandProperty Content | ConvertFrom-Json | Select-Object -ExpandProperty data

        # Return the group
        return $group
    }

    # Method to set a Vault group
    [void] SetVaultGroup([Hashtable]$group) {
        $vault = $this.GetVaultServer()
        # Set the group
        $uri = $vault.BaseUri + "identity/group"
        $data = $group | ConvertTo-Json
        Invoke-WebRequest -Uri $uri -Headers $vault.Headers -Method 'POST' -Body $data
    }

    # Method to remove a Vault group
    [void] RemoveVaultGroup([string]$name) {
        $vault = $this.GetVaultServer()
        # Remove the group with the specified name
        $uri = $vault.BaseUri + "identity/group/name/$name"
        Invoke-WebRequest -Uri $uri -Headers $vault.Headers -Method 'DELETE'
    }

    # Method to get a Vault policy
    [string] GetVaultPolicy([string]$name) {
        $vault = $this.GetVaultServer()
        # Get the policy with the specified name
        $uri = $vault.BaseUri + "sys/policy/$name"
        $policy = Invoke-WebRequest -Uri $uri -Headers $vault.Headers | Select-Object -ExpandProperty Content | ConvertFrom-Json | Select-Object -ExpandProperty data | Select-Object -ExpandProperty rules

        # Return the policy
        return $policy
    }

    # Method to set a Vault policy
    [void] SetVaultPolicy([string]$name, [string]$rules) {
        $vault = $this.GetVaultServer()
        # Set the policy with the specified name
        $uri = $vault.BaseUri + "sys/policy/$name"
        $data = @{rules = $rules } | ConvertTo-Json
        Invoke-WebRequest -Uri $uri -Headers $vault.Headers -Method 'POST' -Body $data
    }

    # Method to remove a Vault policy
    [void] RemoveVaultPolicy([string]$name) {
        $vault = $this.GetVaultServer()
        # Remove the policy with the specified name
        $uri = $vault.BaseUri + "sys/policy/$name"
        Invoke-WebRequest -Uri $uri -Headers $vault.Headers -Method 'DELETE'
    }

    # Method to get a list of Vault policies
    [string[]] GetVaultPolicyList() {
        $vault = $this.GetVaultServer()
        # Get the list of policies
        $uri = $vault.BaseUri + "sys/policy"
        $policies = Invoke-WebRequest -Uri $uri -Headers $vault.Headers | Select-Object -ExpandProperty Content | ConvertFrom-Json | Select-Object -ExpandProperty data | Select-Object -ExpandProperty keys

        # Return the list of policies
        return $policies
    }
}
#endregion vaultStuff

#region    securecodes~Expiration
Class Expiration {
    [Datetime]$Date
    [Timespan]$TimeSpan
    [String]$TimeStamp
    [ExpType]$Type

    Expiration() {
        $this.TimeSpan = [Timespan]::FromMilliseconds([DateTime]::Now.Millisecond)
        $this.Date = [datetime]::Now + $this.TimeSpan
        $this.setExpType($this.TimeSpan);
        $this.setTimeStamp($this.TimeSpan);
    }
    Expiration([int]$Years) {
        # ($Months, $Years) = if ($Years -eq 1) { (12, 0) }else { (0, $Years) };
        # $CrDate = [datetime]::Now;
        # $Months = [int]($CrDate.Month + $Months); if ($Months -gt 12) { $Months -= 12 };
        $this.TimeSpan = [Timespan]::new((365 * $years), 0, 0, 0);
        $this.Date = [datetime]::Now + $this.TimeSpan
        $this.setExpType($this.TimeSpan);
        $this.setTimeStamp($this.TimeSpan);
    }
    Expiration([int]$Years, [int]$Months) {
        $this.TimeSpan = [Timespan]::new((365 * $years + $Months * 30), 0, 0, 0);
        $this.Date = [datetime]::Now + $this.TimeSpan
        $this.setExpType($this.TimeSpan);
        $this.setTimeStamp($this.TimeSpan);
    }
    Expiration([datetime]$date) {
        $this.Date = $date
        $this.TimeSpan = $date - [datetime]::Now;
        $this.setExpType($this.TimeSpan);
        $this.setTimeStamp($this.TimeSpan);
    }
    Expiration([string]$dateString) {
        $this.Date = [xconvert]::ToDateTime($dateString);
        $this.TimeSpan = $this.Date - [datetime]::Now;
        $this.setExpType($this.TimeSpan);
        $this.setTimeStamp($this.TimeSpan);
    }
    Expiration([System.TimeSpan]$TimeSpan) {
        $this.TimeSpan = $TimeSpan;
        $this.Date = [datetime]::Now + $this.TimeSpan
        $this.setExpType($this.TimeSpan);
        $this.setTimeStamp($this.TimeSpan);
    }
    Expiration([int]$hours, [int]$minutes, [int]$seconds) {
        $this.TimeSpan = [Timespan]::new($hours, $minutes, $seconds);
        $this.setExpType($this.TimeSpan);
        $this.setTimeStamp($this.TimeSpan);
    }
    Expiration([int]$days, [int]$hours, [int]$minutes, [int]$seconds) {
        $this.TimeSpan = [Timespan]::new($days, $hours, $minutes, $seconds)
        $this.Date = [datetime]::Now + $this.TimeSpan
        $this.setExpType($this.TimeSpan);
        $this.setTimeStamp($this.TimeSpan);
    }
    [void]setTimeStamp([System.TimeSpan]$TimeSpan) {
        if ($null -eq $this.Date) {
            $this.TimeStamp = [DateTime]::Now.Add([Timespan]::FromMilliseconds($TimeSpan.TotalMilliseconds)).ToString("yyyyMMddHHmmssffff");
        } else {
            $this.TimeStamp = $this.Date.ToString("yyyyMMddHHmmssffff")
        }
    }
    [void]hidden setExpType([Timespan]$TimeSpan) {
        $this.Type = switch ($true) {
            ($TimeSpan.Days -ge 365) { [ExpType]::Years; break }
            ($TimeSpan.Days -ge 30) { [ExpType]::Months; break }
            ($TimeSpan.Days -ge 1) { [ExpType]::Days; break }
            ($TimeSpan.Hours -ge 1) { [ExpType]::Hours; break }
            ($TimeSpan.Minutes -ge 1) { [ExpType]::Minutes; break }
            ($TimeSpan.Seconds -ge 1) { [ExpType]::Seconds; break }
            Default { [ExpType]::Milliseconds; break }
        }
    }
    [int]GetDays () {
        return $this.TimeSpan.Days
    }
    [int]GetMonths () {
        return [int]($this.TimeSpan.Days / 30)
    }
    [int]GetYears () {
        return [int]($this.TimeSpan.Days / 365)
    }
    [string]ToString() {
        if ($null -eq $this.Date) { return [string]::Empty }
        if ($($this.Date - [datetime]::Now) -ge [timespan]::new(0)) {
            return $this.Date.ToString();
        } else {
            return 'Expired'
        }
    }
}
#endregion securecodes~Expiration

#region    Custom_EncClasses_&_Helpers

#region    BitwiseTools
# .SYNOPSIS
#     BitwUtil class heps design encryption algorithms that use bitwise operations and non-linear transformations.
#     Its also used in the construction of the ChaCha20 cipher.
Class BitwUtil {
    static [Byte[]]Prepend([Byte[]]$Bytes, [byte[]]$BytesToPrepend) {
        $tmp = New-Object byte[] $($bytes.Length + $bytesToPrepend.Length);
        #$tmp = [Byte[]] (, 0xFF * ($bytes.Length + $bytesToPrepend.Length));
        $bytesToPrepend.CopyTo($tmp, 0);
        $bytes.CopyTo($tmp, $bytesToPrepend.Length);
        return $tmp;
    }
    static [byte[][]]Shift([byte[]]$Bytes, [int]$size) {
        $left = New-Object byte[] $size;
        $right = New-Object byte[] $($bytes.Length - $size);
        [Array]::Copy($bytes, 0, $left, 0, $left.Length);
        [Array]::Copy($bytes, $left.Length, $right, 0, $right.Length);
        return ($left, $right);
    }
    static [Int32] RotateLeft([Int32]$val, [Int32]$amount) {
        return (($val -shl $amount) -bor ($val -shr (32 - $amount)))
    }
    static [Int64] RotateLeft([Int64]$val, [Int64]$amount) {
        return (($val -shl $amount) -bor ($val -shr (32 - $amount)))
    }
    static [void] QuaterRound([ref]$a, [ref]$b, [ref]$c, [ref]$d) {
        $a.Value = $a.Value + $b.Value; $d.Value = [BitwUtil]::RotateLeft($d.Value -xor $a.Value, 16);
        $c.Value = $c.Value + $d.Value; $b.Value = [BitwUtil]::RotateLeft($b.Value -xor $c.Value, 12);
        $a.Value = $a.Value + $b.Value; $d.Value = [BitwUtil]::RotateLeft($d.Value -xor $a.Value, 8);
        $c.Value = $c.Value + $d.Value; $b.Value = [BitwUtil]::RotateLeft($b.Value -xor $c.Value, 7);
    }
    static [int32[]] QuaterRound([int32]$a, [int32]$b, [int32]$c, [int32]$d) {
        # /!\ WARNING /!\ Incomplete & Not Tested
        [int32]$dVal = [BitConverter]::ToInt32($d, 0)
        [int32]$bVal = [BitConverter]::ToInt32($b, 0)
        $a = $a + $b
        $dVal = $dVal -xor $a
        $dVal = $dVal -shl 16
        $d = [BitConverter]::GetBytes($dVal)
        $c = $c + $d
        $bVal = $bVal -xor $c
        $bVal = $bVal -shl 12
        $b = [BitConverter]::GetBytes($bVal)
        $a = $a + $b
        $dVal = $dVal -xor $a
        $dVal = $dVal -shl 8
        $d = [BitConverter]::GetBytes($dVal)
        $c = $c + $d
        $bVal = $bVal -xor $c
        $bVal = $bVal -shl 7
        $b = [BitConverter]::GetBytes($bVal)
        return [int32[]]@([int32][BitConverter]::ToInt32($a, 0), [int32][BitConverter]::ToInt32($b, 0), [int32][BitConverter]::ToInt32($c, 0), [int32][BitConverter]::ToInt32($d, 0))
    }
    # MixColumns: performs operations on columns of an array
    static [byte[, ]] MixColumns([byte[, ]]$state) {
        [byte[]] $tmp = New-Object byte[] 4
        for ($i = 0; $i -lt 4; $i++) {
            $tmp[0] = [Byte] ($state[0, $i] * 2 + $state[1, $i] * 3)
            $tmp[1] = [Byte] ($state[1, $i] * 2 + $state[2, $i] * 3)
            $tmp[2] = [Byte] ($state[2, $i] * 2 + $state[3, $i] * 3)
            $tmp[3] = [Byte] ($state[3, $i] * 2 + $state[0, $i] * 3)
            for ($j = 0; $j -lt 4; $j++) {
                $state[$j, $i] = $tmp[$j]
            }
        }
        return $state
    }
    # ShiftRows: Performs bitwise operations to shift elements in rows of the $state array
    static [int32[]] ShiftRows([int32[]]$state) {
        $temp = $state[1]
        $state[1] = $state[5]
        $state[5] = $state[9]
        $state[9] = $state[13]
        $state[13] = $temp

        $temp = $state[2]
        $state[2] = $state[10]
        $state[10] = $temp
        $temp = $state[6]
        $state[6] = $state[14]
        $state[14] = $temp

        $temp = $state[15]
        $state[15] = $state[11]
        $state[11] = $state[7]
        $state[7] = $state[3]
        $state[3] = $temp

        return $state
    }
    # KeyExpansion: generates an expanded key based on the original key
    static [int32[]] KeyExpansion([int32[]]$key, [int32]$rounds) {
        $expandedKey = New-Object int32[] $rounds*16
        $temp = New-Object int32[] 4
        $i = 0
        while ($i -lt $rounds * 16) {
            $expandedKey[$i] = $key[$i % 4]
            if (($i % 4) -eq 3) {
                $temp = [BitwUtil]::KeyExpansionCore($temp, ($i / 4))
                for ($j = 0; $j -lt 4; $j++) {
                    $expandedKey[$i + $j] = $expandedKey[$i + $j - 4] -xor $temp[$j]
                }
                $i += 4
            }
            $i++
        }
        return $expandedKey
    }

    static hidden [int32[]] KeyExpansionCore([int32[]]$temp, [int32]$round) {
        $temp[0] = [int32]([BitConverter]::ToInt32($temp, 0) -shl 8 -xor $temp[0] -xor ($round -shl 24))
        $temp[1] = [int32]([BitConverter]::ToInt32($temp, 4) -shl 8 -xor $temp[1])
        $temp[2] = [int32]([BitConverter]::ToInt32($temp, 8) -shl 8 -xor $temp[2])
        $temp[3] = [int32]([BitConverter]::ToInt32($temp, 12) -shl 8 -xor $temp[3] -xor $round)
        return $temp
    }
    # SubBytes: Performs a substitution operation on each byte of an array
    static [byte[]] SubBytes([byte[]]$state, [byte[]]$sBox) {
        # Note: $sBox is an array of 256 values representing the substitution box.
        # You'll need to initialize it with appropriate values for the specific encryption algorithm you're using.
        for ($i = 0; $i -lt $state.Length; $i++) {
            $state[$i] = $sBox[$state[$i]]
        }
        return $state
    }
    # AddRoundKey: performs bitwise operations to add elements from two arrays
    static [byte[]] AddRoundKey([byte[]]$state, [byte[]]$roundKey) {
        for ($i = 0; $i -lt $state.Length; $i++) {
            $state[$i] = $state[$i] -bxor $roundKey[$i]
        }
        return $state
    }
    static [Int64] Reduce([Double]$nput) {
        [Double]$max = 9223372036854775807
        $result = $nput
        while ($result -ge $max) {
            $result = [double]($result / 2)
        }
        return $result
    }
    static [Int64[]] Reduce([Int64[]]$arr) {
        [Int64]$u = 0; # The overflow from each calculation of the reduction process
        [Int64[]]$h = $arr
        $u = $u + [BitwUtil]::Reduce($h[0]);
        $h[0] = $u -band 0xffffffc;
        $u = $u -shr 26;
        $u = $u + [BitwUtil]::Reduce($h[1]);
        $h[1] = $u -band 0xffffffc;
        $u = $u -shr 26;
        $u = $u + [BitwUtil]::Reduce($h[2]);
        $h[2] = $u -band 0xffffffc;
        $u = $u -shr 26;
        $u = $u + [BitwUtil]::Reduce($h[3]);
        $h[3] = $u -band 0xffffffc;
        $u = $u -shr 26;
        $u = $u + [BitwUtil]::Reduce($h[4]);
        $h[4] = $u -band 0xffffffc;
        $u = $u -shr 26;
        $h[0] = [BitwUtil]::Reduce($h[0]) + $u * 5;
        $u = $u -shr 2;
        # Write-Debug "ReduceOverflow: $u" -Debug
        return $h
    }
    [byte[]]ToLittleEndian([byte[]]$value) {
        if (![System.BitConverter]::IsLittleEndian) { [array]::Reverse($value) }
        return $value
    }
    # TODO: write InvMixColumns method: performs inverse operations on columns of an array
    # TODO: write InvShiftRows method: performs inverse bitwise operations to shift elements in rows of an array
    # TODO: write InvSubBytes method: performs an inverse substitution operation on each byte of an array
    # TODO: write InvAddRoundKey method: performs inverse bitwise operations to add elements from two arrays.
}
#endregion BitwiseTools

#region    Shuffl3r
# .SYNOPSIS
#     Shuffles bytes and nonce into a jumbled byte[] mess that can be split using a password.
#     Can be used to Combine the encrypted data with the initialization vector (IV) and other data.
# .DESCRIPTION
#     Everyone is appending the IV to encrypted bytes, such that when decrypting, $CryptoProvider.IV = $encyptedBytes[0..15];
#     They say its safe since IV is basically random and changes every encryption. but this small loophole can allow an advanced attacker to use some tools to find that IV at the end.
#     This class aim to prevent that; or at least make it nearly impossible.
#     By using an int[] of indices as a lookup table to rearrange the $nonce and $bytes.
#     The int[] array is derrivated from the password that the user provides.
# .EXAMPLE
#     $_bytes = [System.text.Encoding]::UTF8.GetBytes('** _H4ck_z3_W0rld_ **');
#     $Nonce1 = [CryptoBase]::GetRandomEntropy();
#     $Nonce2 = [CryptoBase]::GetRandomEntropy();
#     $Passwd = [xconvert]::ToSecurestring('OKay_&~rVJ+T?NpJ(8TqL');
#     $shuffld = [Shuffl3r]::Combine([Shuffl3r]::Combine($_bytes, $Nonce2, $Passwd), $Nonce1, $Passwd);
#     ($b,$n1) = [Shuffl3r]::Split($shuffld, $Passwd, $Nonce1.Length);
#     ($b,$n2) = [Shuffl3r]::Split($b, $Passwd, $Nonce2.Length);
#     [System.text.Encoding]::UTF8.GetString($b) -eq '** _H4ck_z3_W0rld_ **' # should be $true
class Shuffl3r {
    static [Byte[]] Combine([Byte[]]$Bytes, [Byte[]]$Nonce, [securestring]$Passwod) {
        return [Shuffl3r]::Combine($bytes, $Nonce, [xconvert]::ToString($Passwod))
    }
    static [Byte[]] Combine([Byte[]]$Bytes, [Byte[]]$Nonce, [string]$Passw0d) {
        # if ($Bytes.Length -lt 16) { throw [InvalidArgumentException]::New('Bytes', 'Input bytes.length should be > 16. ie: $minLength = 17, since the common $nonce length is 16') }
        if ($bytes.Length -lt ($Nonce.Length + 1)) {
            Write-Debug "Bytes.Length = $($Bytes.Length) but Nonce.Length = $($Nonce.Length)" -Debug
            throw [System.ArgumentOutOfRangeException]::new("Nonce", 'Make sure $Bytes.length > $Nonce.Length')
        }
        if ([string]::IsNullOrWhiteSpace($Passw0d)) { throw [System.ArgumentNullException]::new('$Passw0d') }
        [int[]]$Indices = [int[]]::new($Nonce.Length);
        Set-Variable -Name Indices -Scope local -Visibility Public -Option ReadOnly -Value ([Shuffl3r]::GenerateIndices($Nonce.Length, $Passw0d, $bytes.Length));
        [Byte[]]$combined = [Byte[]]::new($bytes.Length + $Nonce.Length);
        for ([int]$i = 0; $i -lt $Indices.Length; $i++) {
            $combined[$Indices[$i]] = $Nonce[$i]
        }
        $i = 0; $ir = (0..($combined.Length - 1)) | Where-Object { $_ -NotIn $Indices };
        foreach ($j in $ir) { $combined[$j] = $bytes[$i]; $i++ }
        return $combined
    }
    static [array] Split([Byte[]]$ShuffledBytes, [securestring]$Passwod, [int]$NonceLength) {
        return [Shuffl3r]::Split($ShuffledBytes, [xconvert]::ToString($Passwod), [int]$NonceLength);
    }
    static [array] Split([Byte[]]$ShuffledBytes, [string]$Passw0d, [int]$NonceLength) {
        if ($null -eq $ShuffledBytes) { throw [System.ArgumentNullException]::new('$ShuffledBytes') }
        if ([string]::IsNullOrWhiteSpace($Passw0d)) { throw [System.ArgumentNullException]::new('$Passw0d') }
        [int[]]$Indices = [int[]]::new([int]$NonceLength);
        Set-Variable -Name Indices -Scope local -Visibility Private -Option ReadOnly -Value ([Shuffl3r]::GenerateIndices($NonceLength, $Passw0d, ($ShuffledBytes.Length - $NonceLength)));
        $Nonce = [Byte[]]::new($NonceLength);
        $bytes = [Byte[]]$((0..($ShuffledBytes.Length - 1)) | Where-Object { $_ -NotIn $Indices } | Select-Object *, @{l = 'bytes'; e = { $ShuffledBytes[$_] } }).bytes
        for ($i = 0; $i -lt $NonceLength; $i++) { $Nonce[$i] = $ShuffledBytes[$Indices[$i]] };
        return ($bytes, $Nonce)
    }
    static hidden [int[]] GenerateIndices([int]$Count, [string]$randomString, [int]$HighestIndex) {
        if ($HighestIndex -lt 3 -or $Count -ge $HighestIndex) { throw [System.ArgumentOutOfRangeException]::new('$HighestIndex >= 3 is required; and $Count should be less than $HighestIndex') }
        if ([string]::IsNullOrWhiteSpace($randomString)) { throw [System.ArgumentNullException]::new('$randomString') }
        [Byte[]]$hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes([string]$randomString))
        [int[]]$indices = [int[]]::new($Count)
        for ($i = 0; $i -lt $Count; $i++) {
            [int]$nextIndex = [Convert]::ToInt32($hash[$i] % $HighestIndex)
            while ($indices -contains $nextIndex) {
                $nextIndex = ($nextIndex + 1) % $HighestIndex
            }
            $indices[$i] = $nextIndex
        }
        return $indices
    }
}
#endregion Shuffl3r

#region    AesGCM
# .SYNOPSIS
#     A custom AesCGM class, with nerdy Options like compression, iterrations, protection ...
# .DESCRIPTION
#     Both AesCng and AesGcm are secure encryption algorithms, but AesGcm is generally considered to be more secure than AesCng in most scenarios.
#     AesGcm is an authenticated encryption mode that provides both confidentiality and integrity protection. It uses a Galois/Counter Mode (GCM) to encrypt the data, and includes an authentication tag that protects against tampering with or forging the ciphertext.
#     AesCng, on the other hand, only provides confidentiality protection and does not include an authentication tag. This means that an attacker who can modify the ciphertext may be able to undetectably alter the decrypted plaintext.
#     Therefore, it is recommended to use AesGcm whenever possible, as it provides stronger security guarantees compared to AesCng.
# .EXAMPLE
#     $bytes = [xconvert]::BytesFromObject('Text_Message1'); $Password = [xconvert]::ToSecurestring('X-aP0jJ_:No=08TfdQ'); $salt = [CryptoBase]::GetRandomEntropy();
#     $enc = [AesGCM]::Encrypt($bytes, $Password, $salt)
#     $dec = [AesGCM]::Decrypt($enc, $Password, $salt)
#     echo ([System.Text.Encoding]::UTF8.GetString($dec).Trim()) # should be: Text_Message1
# .EXAMPLE
#     $bytes = [System.Text.Encoding]::UTF8.GetBytes("S3crEt message...")
#     $enc = [Aesgcm]::Encrypt($bytes, (Read-Host -AsSecureString -Prompt "Encryption Password"), 4) # encrypt 4 times!
#     $secmessage = [convert]::ToBase64String($enc)
#
#     # On recieving PC:
#     $dec = [AesGcm]::Decrypt([convert]::FromBase64String($secmessage), (Read-Host -AsSecureString -Prompt "Decryption Password"), 4)
#     echo ([System.Text.Encoding]::UTF8.GetString($dec)) # should be: S3crEt message...
# .NOTES
#  Todo: Find a working/cross-platform way to protect bytes (Like DPAPI for windows but better) then
#  add static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [byte[]]$associatedData, [bool]$Protect, [string]$Compression, [int]$iterations)
class AesGCM : CryptoBase {
    # static hidden [byte[]]$_salt = [convert]::FromBase64String("hsKgmva9wZoDxLeREB1udw==");
    static hidden [EncryptionScope] $Scope = [EncryptionScope]::User
    static [byte[]] Encrypt([byte[]]$bytes) {
        return [AesGCM]::Encrypt($bytes, [AesGCM]::GetPassword());
    }
    static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password) {
        [byte[]]$_salt = [AesGCM]::GetDerivedBytes($Password)
        return [AesGCM]::Encrypt($bytes, $Password, $_salt);
    }
    static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt) {
        return [AesGCM]::Encrypt($bytes, $Password, $Salt, $null, $null, 1);
    }
    static [string] Encrypt([string]$text, [SecureString]$Password, [int]$iterations) {
        return [convert]::ToBase64String([AesGCM]::Encrypt([System.Text.Encoding]::UTF8.GetBytes("$text"), $Password, $iterations));
    }
    static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [int]$iterations) {
        [byte[]]$_salt = [AesGCM]::GetDerivedBytes($Password)
        return [AesGCM]::Encrypt($bytes, $Password, $_salt, $null, $null, $iterations);
    }
    static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [int]$iterations) {
        return [AesGCM]::Encrypt($bytes, $Password, $Salt, $null, $null, $iterations);
    }
    static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [int]$iterations, [string]$Compression) {
        [byte[]]$_salt = [AesGCM]::GetDerivedBytes($Password)
        return [AesGCM]::Encrypt($bytes, $Password, $_salt, $null, $Compression, $iterations);
    }
    static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [byte[]]$associatedData, [int]$iterations) {
        return [AesGCM]::Encrypt($bytes, $Password, $Salt, $associatedData, $null, $iterations);
    }
    static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [byte[]]$associatedData) {
        return [AesGCM]::Encrypt($bytes, $Password, $Salt, $associatedData, $null, 1);
    }
    static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [byte[]]$associatedData, [string]$Compression, [int]$iterations) {
        [int]$IV_SIZE = 0; Set-Variable -Name IV_SIZE -Scope Local -Visibility Private -Option Private -Value 12
        [int]$TAG_SIZE = 0; Set-Variable -Name TAG_SIZE -Scope Local -Visibility Private -Option Private -Value 16
        [string]$Key = $null; Set-Variable -Name Key -Scope Local -Visibility Private -Option Private -Value $([convert]::ToBase64String([System.Security.Cryptography.Rfc2898DeriveBytes]::new([xconvert]::ToString($Password), $Salt, 10000, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes(32)));
        [System.IntPtr]$th = [System.IntPtr]::new(0); if ([string]::IsNullOrWhiteSpace([AesGCM]::caller)) { [AesGCM]::caller = '[AesGCM]' }
        Set-Variable -Name th -Scope Local -Visibility Private -Option Private -Value $([System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($TAG_SIZE));
        try {
            $_bytes = $bytes;
            $aes = $null; Set-Variable -Name aes -Scope Local -Visibility Private -Option Private -Value $([ScriptBlock]::Create("[Security.Cryptography.AesGcm]::new([convert]::FromBase64String('$Key'))").Invoke());
            for ($i = 1; $i -lt $iterations + 1; $i++) {
                # Write-Host "$([AesGCM]::caller) [+] Encryption [$i/$iterations] ... Done" -ForegroundColor Yellow
                # if ($Protect) { $_bytes = [xconvert]::ToProtected($_bytes, $Salt, [EncryptionScope]::User) }
                # Generate a random IV for each iteration:
                [byte[]]$IV = $null; Set-Variable -Name IV -Scope Local -Visibility Private -Option Private -Value ([System.Security.Cryptography.Rfc2898DeriveBytes]::new([xconvert]::ToString($password), $salt, 1, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes($IV_SIZE));
                $tag = [byte[]]::new($TAG_SIZE);
                $Encrypted = [byte[]]::new($_bytes.Length);
                [void]$aes.Encrypt($IV, $_bytes, $Encrypted, $tag, $associatedData);
                $_bytes = [Shuffl3r]::Combine([Shuffl3r]::Combine($Encrypted, $IV, $Password), $tag, $Password);
            }
        } catch {
            throw $_
        } finally {
            [void][System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocAnsi($th);
            Remove-Variable IV_SIZE, TAG_SIZE, th -ErrorAction SilentlyContinue
        }
        if (![string]::IsNullOrWhiteSpace($Compression)) {
            $_bytes = [xconvert]::ToCompressed($_bytes, $Compression);
        }
        return $_bytes
    }
    static [void] Encrypt([IO.FileInfo]$File) {
        [AesGCM]::Encrypt($File, [AesGCM]::GetPassword());
    }
    static [void] Encrypt([IO.FileInfo]$File, [securestring]$Password) {
        [AesGCM]::Encrypt($File, $Password, $null);
    }
    static [void] Encrypt([IO.FileInfo]$File, [securestring]$Password, [string]$OutPath) {
        [AesGCM]::Encrypt($File, $password, $OutPath, 1, $null);
    }
    static [void] Encrypt([IO.FileInfo]$File, [securestring]$Password, [string]$OutPath, [int]$iterations) {
        [AesGCM]::Encrypt($File, $password, $OutPath, $iterations, $null);
    }
    static [void] Encrypt([IO.FileInfo]$File, [securestring]$Password, [string]$OutPath, [int]$iterations, [string]$Compression) {
        [ValidateNotNullOrEmpty()][IO.FileInfo]$File = [AesGCM]::GetResolvedPath($File.FullName); if ([string]::IsNullOrWhiteSpace($OutPath)) { $OutPath = $File.FullName }
        [ValidateNotNullOrEmpty()][string]$OutPath = [AesGCM]::GetUnResolvedPath($OutPath);
        if (![string]::IsNullOrWhiteSpace($Compression)) { [AesGCM]::ValidateCompression($Compression) }
        $streamReader = [System.IO.FileStream]::new($File.FullName, [System.IO.FileMode]::Open)
        $ba = [byte[]]::New($streamReader.Length);
        [void]$streamReader.Read($ba, 0, [int]$streamReader.Length);
        [void]$streamReader.Close();
        Write-Verbose "$([AesGCM]::caller) Begin file encryption:"
        Write-Verbose "[-]  File    : $File"
        Write-Verbose "[-]  OutFile : $OutPath"
        [byte[]]$_salt = [AesGCM]::GetDerivedBytes($Password);
        $encryptdbytes = [AesGCM]::Encrypt($ba, $Password, $_salt, $null, $Compression, $iterations)
        $streamWriter = [System.IO.FileStream]::new($OutPath, [System.IO.FileMode]::OpenOrCreate);
        [void]$streamWriter.Write($encryptdbytes, 0, $encryptdbytes.Length);
        [void]$streamWriter.Close()
        [void]$streamReader.Dispose()
        [void]$streamWriter.Dispose()
    }
    static [byte[]] Decrypt([byte[]]$bytes) {
        return [AesGCM]::Decrypt($bytes, [AesGCM]::GetPassword());
    }
    static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password) {
        [byte[]]$_salt = [AesGCM]::GetDerivedBytes($Password)
        return [AesGCM]::Decrypt($bytes, $Password, $_salt);
    }
    static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt) {
        return [AesGCM]::Decrypt($bytes, $Password, $Salt, $null, $null, 1);
    }
    static [string] Decrypt([string]$text, [SecureString]$Password, [int]$iterations) {
        return [System.Text.Encoding]::UTF8.GetString([AesGCM]::Decrypt([convert]::FromBase64String($text), $Password, $iterations));
    }
    static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [int]$iterations) {
        [byte[]]$_salt = [AesGCM]::GetDerivedBytes($Password)
        return [AesGCM]::Decrypt($bytes, $Password, $_salt, $null, $null, $iterations);
    }
    static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [int]$iterations) {
        return [AesGCM]::Decrypt($bytes, $Password, $Salt, $null, $null, 1);
    }
    static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [int]$iterations, [string]$Compression) {
        [byte[]]$_salt = [AesGCM]::GetDerivedBytes($Password)
        return [AesGCM]::Decrypt($bytes, $Password, $_salt, $null, $Compression, $iterations);
    }
    static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [byte[]]$associatedData, [int]$iterations) {
        return [AesGCM]::Decrypt($bytes, $Password, $Salt, $associatedData, $null, $iterations);
    }
    static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [byte[]]$associatedData) {
        return [AesGCM]::Decrypt($bytes, $Password, $Salt, $associatedData, $null, 1);
    }
    static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [byte[]]$associatedData, [string]$Compression, [int]$iterations) {
        [int]$IV_SIZE = 0; Set-Variable -Name IV_SIZE -Scope Local -Visibility Private -Option Private -Value 12
        [int]$TAG_SIZE = 0; Set-Variable -Name TAG_SIZE -Scope Local -Visibility Private -Option Private -Value 16
        [string]$Key = $null; Set-Variable -Name Key -Scope Local -Visibility Private -Option Private -Value $([convert]::ToBase64String([System.Security.Cryptography.Rfc2898DeriveBytes]::new([xconvert]::ToString($Password), $Salt, 10000, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes(32)));
        [System.IntPtr]$th = [System.IntPtr]::new(0); if ([string]::IsNullOrWhiteSpace([AesGCM]::caller)) { [AesGCM]::caller = '[AesGCM]' }
        Set-Variable -Name th -Scope Local -Visibility Private -Option Private -Value $([System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($TAG_SIZE));
        try {
            $_bytes = if (![string]::IsNullOrWhiteSpace($Compression)) { [xconvert]::ToDecompressed($bytes, $Compression) } else { $bytes }
            $aes = [ScriptBlock]::Create("[Security.Cryptography.AesGcm]::new([convert]::FromBase64String('$Key'))").Invoke()
            for ($i = 1; $i -lt $iterations + 1; $i++) {
                # Write-Host "$([AesGCM]::caller) [+] Decryption [$i/$iterations] ... Done" -ForegroundColor Yellow
                # if ($UnProtect) { $_bytes = [xconvert]::ToUnProtected($_bytes, $Salt, [EncryptionScope]::User) }
                # Split the real encrypted bytes from nonce & tags then decrypt them:
                ($b, $n1) = [Shuffl3r]::Split($_bytes, $Password, $TAG_SIZE);
                ($b, $n2) = [Shuffl3r]::Split($b, $Password, $IV_SIZE);
                $Decrypted = [byte[]]::new($b.Length);
                $aes.Decrypt($n2, $b, $n1, $Decrypted, $associatedData);
                $_bytes = $Decrypted;
            }
        } catch {
            if ($_.FullyQualifiedErrorId -eq "AuthenticationTagMismatchException") {
                Write-Host "$([AesGCM]::caller) Wrong password" -ForegroundColor Yellow
            }
            throw $_
        } finally {
            [void][System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocAnsi($th);
            Remove-Variable IV_SIZE, TAG_SIZE, th -ErrorAction SilentlyContinue
        }
        return $_bytes
    }
    static [void] Decrypt([IO.FileInfo]$File) {
        [AesGCM]::Decrypt($File, [AesGCM]::GetPassword());
    }
    static [void] Decrypt([IO.FileInfo]$File, [securestring]$password) {
        [AesGCM]::Decrypt($File, $password, $null);
    }
    static [void] Decrypt([IO.FileInfo]$File, [securestring]$Password, [string]$OutPath) {
        [AesGCM]::Decrypt($File, $password, $OutPath, 1, $null);
    }
    static [void] Decrypt([IO.FileInfo]$File, [securestring]$Password, [string]$OutPath, [int]$iterations) {
        [AesGCM]::Decrypt($File, $password, $OutPath, $iterations, $null);
    }
    static [void] Decrypt([IO.FileInfo]$File, [securestring]$Password, [string]$OutPath, [int]$iterations, [string]$Compression) {
        [ValidateNotNullOrEmpty()][IO.FileInfo]$File = [AesGCM]::GetResolvedPath($File.FullName); if ([string]::IsNullOrWhiteSpace($OutPath)) { $OutPath = $File.FullName }
        [ValidateNotNullOrEmpty()][string]$OutPath = [AesGCM]::GetUnResolvedPath($OutPath);
        if (![string]::IsNullOrWhiteSpace($Compression)) { [AesGCM]::ValidateCompression($Compression) }
        $streamReader = [System.IO.FileStream]::new($File.FullName, [System.IO.FileMode]::Open)
        $ba = [byte[]]::New($streamReader.Length);
        [void]$streamReader.Read($ba, 0, [int]$streamReader.Length);
        [void]$streamReader.Close();
        Write-Verbose "$([AesGCM]::caller) Begin file decryption:"
        Write-Verbose "[-]  File    : $File"
        Write-Verbose "[-]  OutFile : $OutPath"
        [byte[]]$_salt = [AesGCM]::GetDerivedBytes($Password);
        $decryptdbytes = [AesGCM]::Decrypt($ba, $Password, $_salt, $null, $Compression, $iterations)
        $streamWriter = [System.IO.FileStream]::new($OutPath, [System.IO.FileMode]::OpenOrCreate);
        [void]$streamWriter.Write($decryptdbytes, 0, $decryptdbytes.Length);
        [void]$streamWriter.Close()
        [void]$streamReader.Dispose()
        [void]$streamWriter.Dispose()
    }
}
#endregion AesGCM

#region    AesCng
# .SYNOPSIS
#     A custom System.Security.Cryptography.AesCng class, for more control on hashing, compression & other stuff.
# .DESCRIPTION
#     A symmetric-key encryption algorithm that is used to protect a variety of sensitive data, including financial transactions and government communications.
#     It is considered to be very secure, and has been adopted as a standard by many governments and organizations around the world.
#
#     Just as [System.Security.Cryptography.AesCng], by default this class CBC ciphermode, PKCS7 padding, and 256b key & SHA1 to hash (since it has been proven to be more secure than MD5).
#     Plus there is the option to stack encryptions by iteration. (But beware when you iterate much it produces larger output)
class AesCng : CryptoBase {
    static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password) {
        return [AesCng]::Encrypt($Bytes, $Password, [Convert]::FromBase64String('bz07LmY5XiNkXW1WQjxdXw=='));
    }
    static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt) {
        return [AesCng]::Encrypt($Bytes, $Password, $Salt, 'Gzip', $false);
    }
    static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [bool]$Protect) {
        return [AesCng]::Encrypt($Bytes, $Password, [Convert]::FromBase64String('bz07LmY5XiNkXW1WQjxdXw=='), 'Gzip', $Protect);
    }
    static [byte[]] Encrypt([byte[]]$Bytes, [securestring]$Password, [int]$iterations) {
        return [AesCng]::Encrypt($Bytes, $Password, [Convert]::FromBase64String('bz07LmY5XiNkXW1WQjxdXw=='), $iterations)
    }
    static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [bool]$Protect) {
        return [AesCng]::Encrypt($Bytes, $Password, $Salt, 'Gzip', $Protect);
    }
    static [byte[]] Encrypt([byte[]]$Bytes, [securestring]$Password, [byte[]]$Salt, [int]$iterations) {
        if ($null -eq $Bytes) { throw [System.ArgumentNullException]::new('bytes', 'Bytes Value cannot be null.') }
        $_bytes = $Bytes; if ([string]::IsNullOrWhiteSpace([AesGCM]::caller)) { [AesCng]::caller = '[AesCng]' }
        for ($i = 1; $i -lt $iterations + 1; $i++) {
            Write-Host "$([AesCng]::caller) [+] Encryption [$i/$iterations] ...$(
                $_bytes = [AesCng]::Encrypt($_bytes, $Password, $Salt)
            ) Done." -ForegroundColor Yellow
        };
        return $_bytes;
    }
    static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [string]$Compression) {
        return [AesCng]::Encrypt($Bytes, $Password, [Convert]::FromBase64String('bz07LmY5XiNkXW1WQjxdXw=='), $Compression, $false);
    }
    static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [string]$Compression) {
        return [AesCng]::Encrypt($Bytes, $Password, $Salt, $Compression, $false);
    }
    static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [string]$Compression, [bool]$Protect) {
        [int]$KeySize = 256; $CryptoProvider = $null; $EncrBytes = $null
        if ($Compression -notin ([Enum]::GetNames('Compression' -as 'Type'))) { Throw [System.InvalidCastException]::new("The name '$Compression' is not a valid [Compression]`$typeName.") }
        Set-Variable -Name CryptoProvider -Scope Local -Visibility Private -Option Private -Value ([System.Security.Cryptography.AesCryptoServiceProvider]::new());
        $CryptoProvider.KeySize = [int]$KeySize;
        $CryptoProvider.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7;
        $CryptoProvider.Mode = [System.Security.Cryptography.CipherMode]::CBC;
        $CryptoProvider.Key = [System.Security.Cryptography.Rfc2898DeriveBytes]::new([xconvert]::ToString($Password), $Salt, 10000, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes($KeySize / 8);
        $CryptoProvider.IV = [System.Security.Cryptography.Rfc2898DeriveBytes]::new([xconvert]::Tostring($password), $salt, 1, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes(16);
        Set-Variable -Name EncrBytes -Scope Local -Visibility Private -Option Private -Value $([Shuffl3r]::Combine($CryptoProvider.CreateEncryptor().TransformFinalBlock($Bytes, 0, $Bytes.Length), $CryptoProvider.IV, $Password));
        if ($Protect) { $EncrBytes = [xconvert]::ToProtected($EncrBytes, $Salt, [EncryptionScope]::User) }
        Set-Variable -Name EncrBytes -Scope Local -Visibility Private -Option Private -Value $([xconvert]::ToCompressed($EncrBytes, $Compression));
        $CryptoProvider.Clear(); $CryptoProvider.Dispose()
        return $EncrBytes
    }
    static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password) {
        return [AesCng]::Decrypt($bytes, $Password, 'Gzip');
    }
    static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt) {
        return [AesCng]::Decrypt($bytes, $Password, $Salt, 'GZip', $false);
    }
    static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [bool]$UnProtect) {
        return [AesCng]::Decrypt($bytes, $Password, [Convert]::FromBase64String('bz07LmY5XiNkXW1WQjxdXw=='), 'GZip', $UnProtect);
    }
    static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [int]$iterations) {
        return [AesCng]::Decrypt($Bytes, $Password, [Convert]::FromBase64String('bz07LmY5XiNkXW1WQjxdXw=='), $iterations);
    }
    static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [bool]$UnProtect) {
        return [AesCng]::Decrypt($bytes, $Password, $Salt, 'GZip', $UnProtect);
    }
    static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$salt, [int]$iterations) {
        if ($null -eq $bytes) { throw [System.ArgumentNullException]::new('bytes', 'Bytes Value cannot be null.') }
        $_bytes = $bytes; if ([string]::IsNullOrWhiteSpace([AesCng]::caller)) { [AesCng]::caller = '[AesCng]' }
        for ($i = 1; $i -lt $iterations + 1; $i++) {
            Write-Host "$([AesCng]::caller) [+] Decryption [$i/$iterations] ...$(
                $_bytes = [AesCng]::Decrypt($_bytes, $Password, $salt)
            ) Done" -ForegroundColor Yellow
        };
        return $_bytes
    }
    static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [string]$Compression) {
        return [AesCng]::Decrypt($bytes, $Password, [Convert]::FromBase64String('bz07LmY5XiNkXW1WQjxdXw=='), $Compression, $false);
    }
    static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [string]$Compression) {
        return [AesCng]::Decrypt($bytes, $Password, $Salt, $Compression, $false);
    }
    static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [string]$Compression, [bool]$UnProtect) {
        [int]$KeySize = 256; $CryptoProvider = $null; $DEcrBytes = $null; $_Bytes = $null
        $_Bytes = [xconvert]::ToDeCompressed($bytes, $Compression);
        if ($UnProtect) { $_Bytes = [xconvert]::ToUnProtected($_Bytes, $Salt, [EncryptionScope]::User) }
        Set-Variable -Name CryptoProvider -Scope Local -Visibility Private -Option Private -Value ([System.Security.Cryptography.AesCryptoServiceProvider]::new());
        $CryptoProvider.KeySize = $KeySize;
        $CryptoProvider.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7;
        $CryptoProvider.Mode = [System.Security.Cryptography.CipherMode]::CBC;
        $CryptoProvider.Key = [System.Security.Cryptography.Rfc2898DeriveBytes]::new([xconvert]::ToString($Password), $Salt, 10000, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes($KeySize / 8);
        ($_Bytes, $CryptoProvider.IV) = [Shuffl3r]::Split($_Bytes, $Password, 16);
        Set-Variable -Name DEcrBytes -Scope Local -Visibility Private -Option Private -Value $($CryptoProvider.CreateDecryptor().TransformFinalBlock($_Bytes, 0, $_Bytes.Length))
        $CryptoProvider.Clear(); $CryptoProvider.Dispose();
        return $DEcrBytes
    }
}
#endregion AesCng

#region    AesCtr
# .SYNOPSIS
#   A custom implementation of AES-ctr.
# .DESCRIPTION
#   [System.Security.Cryptography.CipherMode]::CTR is not available in PowerShell.
#   This class implements the CTR mode manually by XOR-ing with a sequence of counter blocks generated from the given nonce (IV) and block count.
# .NOTES
#    I found out that, in practice it is recommended to use a more secure encryption mode, such as `[System.Security.Cryptography.CipherMode]::GCM` instead of a manual implementing the CTR mode.
#    So I gave it up and I dont use/recommend this class. what a waste!
class AesCtr : CryptoBase {
    static hidden [byte[]]$counter

    static [Byte[]] Encrypt([Byte[]]$Bytes, [byte[]]$Key, [byte[]]$IV) {
        $aes = [System.Security.Cryptography.AesCryptoServiceProvider]::new()
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Key = $Key
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        [AesCtr]::counter = [Byte[]]::new($aes.BlockSize / 8)
        [Array]::Copy($IV, 0, [AesCtr]::counter, 0, $IV.Length)
        [BitConverter]::GetBytes([AesCtr]::counter).CopyTo([AesCtr]::counter, [AesCtr]::counter.Length - 8)
        [Byte[]]$CipherBytes = [Byte[]]::new($Bytes.Length)
        for ($i = 0; $i -lt $Bytes.Length; $i += $aes.BlockSize / 8) {
            [Byte[]]$counterBlock = $aes.CreateEncryptor().TransformFinalBlock([AesCtr]::counter, 0, [AesCtr]::counter.Length);
            [Array]::Copy($counterBlock, 0, $CipherBytes, $i, [Math]::Min($counterBlock.Length, $Bytes.Length - $i));
            [AesCtr]::counter++
            [BitConverter]::GetBytes([AesCtr]::counter).CopyTo([AesCtr]::counter, [AesCtr]::counter.Length - 8);
        }
        for ($i = 0; $i -lt $Bytes.Length; $i++) {
            $CipherBytes[$i] = $CipherBytes[$i] -bxor $Bytes[$i]
        }
        return $CipherBytes
    }
    static [Byte[]] Decrypt([Byte[]]$Bytes, [byte[]]$Key, [byte[]]$IV) {
        $aes = [System.Security.Cryptography.AesCryptoServiceProvider]::new()
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Key = $Key
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        [AesCtr]::counter = [Byte[]]::new($aes.BlockSize / 8)
        [Array]::Copy($IV, 0, [AesCtr]::counter, 0, $IV.Length)
        [BitConverter]::GetBytes([AesCtr]::counter).CopyTo([AesCtr]::counter, [AesCtr]::counter.Length - 8)
        [Byte[]]$decrypted = [Byte[]]::new($Bytes.Length)
        for ($i = 0; $i -lt $Bytes.Length; $i += $aes.BlockSize / 8) {
            [Byte[]]$counterBlock = $aes.CreateEncryptor().TransformFinalBlock([AesCtr]::counter, 0, [AesCtr]::counter.Length)
            [Array]::Copy($counterBlock, 0, $decrypted, $i, [Math]::Min($counterBlock.Length, $Bytes.Length - $i))
            [AesCtr]::counter++
            [BitConverter]::GetBytes([AesCtr]::counter).CopyTo([AesCtr]::counter, [AesCtr]::counter.Length - 8)
        }
        for ($i = 0; $i -lt $decrypted.Length; $i++) {
            $decrypted[$i] = $Bytes[$i] -bxor $decrypted[$i]
        }
        return $decrypted
    }
}
#endregion AesCtr

#region    RSA
# .SYNOPSIS
#     Powershell class implementation of RSA (Rivest-Shamir-Adleman) algorithm.
# .DESCRIPTION
#     A public-key cryptosystem that is widely used for secure data transmission. It is based on the mathematical concept of factoring large composite numbers into their prime factors. The security of the RSA algorithm is based on the difficulty of factoring large composite numbers, which makes it computationally infeasible for an attacker to determine the private key from the public key.
# .EXAMPLE
#     Test-MyTestFunction -Verbose
#     Explanation of the function or its result. You can include multiple examples with additional .EXAMPLE lines
class RSA : CryptoBase {
    # Simply Encrypts the specified data using the public key.
    static [byte[]] Encrypt([byte[]]$data, [string]$publicKeyXml) {
        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
        $rsa.FromXmlString($publicKeyXml)
        return $rsa.Encrypt($data, $true)
    }

    # Decrypts the specified data using the private key.
    static [byte[]] Decrypt([byte[]]$data, [string]$privateKeyXml) {
        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
        $rsa.FromXmlString($privateKeyXml)
        return $rsa.Decrypt($data, $true)
    }

    # The data is encrypted using AES in combination with the password and salt.
    # The encrypted data is then encrypted using RSA.
    static [byte[]] Encrypt([byte[]]$data, [string]$PublicKeyXml, [securestring]$password, [byte[]]$salt) {
        # Generate the AES key and initialization vector from the password and salt
        $aesKey = [System.Security.Cryptography.Rfc2898DeriveBytes]::new([xconvert]::Tostring($password), $salt, 1000).GetBytes(32);
        $aesIV = [System.Security.Cryptography.Rfc2898DeriveBytes]::new([xconvert]::Tostring($password), $salt, 1000).GetBytes(16);

        # Encrypt the data using AES
        $aes = [System.Security.Cryptography.AesCryptoServiceProvider]::new(); ($aes.Key, $aes.IV) = ($aesKey, $aesIV);
        $encryptedData = $aes.CreateEncryptor().TransformFinalBlock($data, 0, $data.Length)

        # Encrypt the AES key and initialization vector using RSA
        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
        $rsa.FromXmlString($PublicKeyXml)
        $encryptedKey = $rsa.Encrypt($aesKey, $true)
        $encryptedIV = $rsa.Encrypt($aesIV, $true)

        # Concatenate the encrypted key, encrypted IV, and encrypted data
        # and return the result as a byte array
        return [byte[]]([System.Linq.Enumerable]::Concat($encryptedKey, $encryptedIV, $encryptedData));
    }

    # Decrypts the specified data using the private key.
    # The data is first decrypted using RSA to obtain the AES key and initialization vector.
    # The data is then decrypted using AES.
    static [byte[]] Decrypt([byte[]]$data, [string]$privateKeyXml, [securestring]$password) {
        # Extract the encrypted key, encrypted IV, and encrypted data from the input data
        $encryptedKey = $data[0..255]
        $encryptedIV = $data[256..271]
        $encryptedData = $data[272..$data.Length]

        # Decrypt the AES key and initialization vector using RSA
        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
        # todo: Use the $PASSWORD to decrypt the private key so it can be used
        $rsa.FromXmlString($privateKeyXml)
        $aesKey = $rsa.Decrypt($encryptedKey, $true)
        $aesIV = $rsa.Decrypt($encryptedIV, $true)

        # Decrypt the data using AES
        $aes = [System.Security.Cryptography.AesCryptoServiceProvider]::new()
        $aes.Key = $aesKey
        $aes.IV = $aesIV
        return $aes.CreateDecryptor().TransformFinalBlock($encryptedData, 0, $encryptedData.Length)
    }
    # Exports the key pair to a file or string. # This can be useful if you want to save the key pair to a file or string for later use.
    # If a file path is specified, the key pair will be saved to the file.
    # If no file path is specified, the key pair will be returned as a string.
    static [void] ExportKeyPair([xml]$publicKeyXml, [string]$privateKeyXml, [string]$filePath = "") {
        $keyPair = @{
            "PublicKey"  = $publicKeyXml
            "PrivateKey" = $privateKeyXml
        }

        if ([string]::IsNullOrWhiteSpace($filePath)) {
            throw 'Invalid FilePath'
        } else {
            # Save the key pair to the specified file
            $keyPair | ConvertTo-Json | Out-File -FilePath $filePath
        }
    }
    static [psobject] LoadKeyPair([string]$filePath = "" ) {
        if ([string]::IsNullOrWhiteSpace($filePath)) {
            throw [System.ArgumentNullException]::new('filePath')
        }
        return [RSA]::LoadKeyPair((Get-Content $filePath | ConvertFrom-Json))
    }
    static [psobject] LoadKeyPair([string]$filePath = "", [string]$keyPairString = "") {
        return $keyPairString | ConvertFrom-Json
    }

    # Generates a new RSA key pair and returns the public and private key XML strings.
    [string] GenerateKeyPair() {
        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
        ($publicKey, $privateKey) = ($rsa.ToXmlString($false), $rsa.ToXmlString($true))
        return $publicKey, $privateKey
    }
}
#endregion RSA

#region    X509
class X509 : CryptoBase {
    static [System.Security.Cryptography.X509Certificates.X509Certificate2]CreateCertificate([string]$Subject, [string]$KeyUsage) {
        $upn = if ([bool](Get-Command git -ErrorAction SilentlyContinue)) { git config user.email } else { 'work@contoso.com' }
        return [X509]::CreateCertificate($Subject, $KeyUsage, $upn)
    }
    static [System.Security.Cryptography.X509Certificates.X509Certificate2]CreateCertificate([string]$Subject, [string]$KeyUsage, [string]$upn) {
        $pin = [xconvert]::ToSecurestring([CryptoBase]::GetRandomSTR('01233456789', 3, 4, 4))
        $Extentions = @("2.5.29.17={text}upn=$upn")
        return [X509]::CreateCertificate($Subject, 2048, 60, "Cert:\CurrentUser\My", $Pin, 'ExportableEncrypted', 'Protect', $KeyUsage, $Extentions, $true)
    }
    static [System.Security.Cryptography.X509Certificates.X509Certificate2]CreateCertificate([string]$Subject, [string]$KeyUsage, [string[]]$Extentions) {
        $pin = [xconvert]::ToSecurestring([CryptoBase]::GetRandomSTR('01233456789', 3, 4, 4))
        return [X509]::CreateCertificate($Subject, 2048, 60, "Cert:\CurrentUser\My", $Pin, 'ExportableEncrypted', 'Protect', $KeyUsage, $Extentions, $true)
    }
    static [System.Security.Cryptography.X509Certificates.X509Certificate2]CreateCertificate([string]$Subject, [string]$upn, [securestring]$pin, [string]$KeyUsage) {
        $Extentions = @("2.5.29.17={text}upn=$upn")
        return [X509]::CreateCertificate($Subject, 2048, 60, "Cert:\CurrentUser\My", $Pin, 'ExportableEncrypted', 'Protect', $KeyUsage, $Extentions, $true)
    }
    static [System.Security.Cryptography.X509Certificates.X509Certificate2]CreateCertificate([string]$Subject, [int]$keySizeInBits = 2048, [int]$ValidForInDays = 365, [string]$StoreLocation, [securestring]$Pin, [string]$KeyExportPolicy, [string]$KeyProtection, [string]$KeyUsage, [string[]]$Extentions, [bool]$IsCritical) {
        if (!($KeyExportPolicy -as [KeyExportPolicy] -is 'KeyExportPolicy')) { throw [InvalidArgumentException]::New('[Microsoft.CertificateServices.Commands.KeyExportPolicy]$KeyExportPolicy') }
        if (!($KeyProtection -as [KeyProtection] -is 'KeyProtection')) { throw [InvalidArgumentException]::New('[Microsoft.CertificateServices.Commands.KeyProtection]$KeyProtection') }
        if (!($keyUsage -as [KeyUsage] -is 'KeyUsage')) { throw [InvalidArgumentException]::New('[System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]$KeyUsage') }
        if (![bool]("Microsoft.CertificateServices.Commands.KeyExportPolicy" -as [Type])) {
            Write-Verbose "[+] Load all necessary assemblies." # By Creating a dumy cert then remove it. This loads all necessary assemblies to create certificates; It worked for me!
            $DummyName = 'dummy-' + [Guid]::NewGuid().Guid; $DummyCert = New-SelfSignedCertificate -Type Custom -Subject "CN=$DummyName" -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2", "2.5.29.17={text}upn=dummy@contoso.com") -KeyExportPolicy NonExportable -KeyUsage None -KeyAlgorithm RSA -KeyLength 2048 -CertStoreLocation "Cert:\CurrentUser\My";
            $DummyCert.Dispose(); Get-ChildItem "Cert:\CurrentUser\My" | Where-Object { $_.subject -eq "CN=$DummyName" } | Remove-Item
        }
        $key = [System.Security.Cryptography.RSA]::Create($keySizeInBits)
        # Create a regular expression to match the DN (distinguishedName) format. ie: CN=CommonName,OU=OrganizationalUnit,O=Organization,L=Locality,S=State,C=Country
        $dnFormat = "^CN=.*,OU=.*,O=.*,L=.*,S=.*,C=.*"; # Ex: $subjN = "CN=My Cert Subject,OU=IT,O=MyCompany,L=MyCity,S=MyState,C=MyCountry"
        if ($subject -notmatch $dnFormat) {
            $Ip_Info = $(& ([scriptblock]::Create($((Invoke-RestMethod -Verbose:$false -Method Get https://api.github.com/gists/d1985ebe22fe07cc191c9458b3a2bdbc).files.'IpInfo.ps1'.content) + ';[Ipinfo]::getInfo()')))
            $subject = "CN=$subject,OU=,O=,L=,S=,C=";
            $subject = $subject -replace "O=,", "O=Contoso,";
            $subject = $subject -replace "OU=,", "OU=$keyUsage,";
            $subject = $subject -replace "C=", "C=$($Ip_Info.country_name)";
            $subject = $subject -replace "L=,", "L=$($Ip_Info.location.geoname_id),";
            $subject = $subject -replace "S=,", "S=$($Ip_Info.city),"
        }
        # Set the OID (Object Identifier) for the subjectName object
        $subjectName = [System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new($Subject); $subjectName.Oid = [System.Security.Cryptography.Oid]::new("1.2.840.10045.3.1.7");
        $certRequest = [system.security.cryptography.x509certificates.certificaterequest]::new($subjectName, $key, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1);
        # Create an X509KeyUsageFlags object
        $X509KeyUsageFlags = [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::None
        $X509KeyUsageFlags = $X509KeyUsageFlags -bor ([System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::$KeyUsage);
        $notBefore = [System.DateTimeOffset]::Now.AddDays(-1); $notAfter = [System.DateTimeOffset]::Now.AddDays($ValidForInDays)
        $certRequest.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509Extension][System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new($X509KeyUsageFlags, $IsCritical))
        foreach ($ext in $Extentions) {
            if ([X509]::IsValidExtension($ext)) {
                $oid, $val = $ext.Split("=")
                $extensionOid = [System.Security.Cryptography.Oid]::new($oid)
                $extsnrawData = [byte[]][System.Text.Encoding]::ASCII.GetBytes($val)
                $certRequest.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509Extension]::new($extensionOid, $extsnrawData, $IsCritical))
            } else {
                throw [InvalidArgumentException]::New("$ext")
            }
        }
        Write-Verbose "[+] Creating SelfSigned Certificate ..."
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]$certRequest.CreateSelfSigned($notBefore, $notAfter);
        # Create an X509KeyStorageFlags object and set the KeyProtection value
        $x509ContentType, $x509KeyStorageFlags = switch ([string]::Join(':', $KeyExportPolicy, $KeyUsage, $KeyProtection)) {
            'NonExportable:None:None' { ('Cert', 'UserKeySet'); break }
            'NonExportable:DataEncipherment:Protect' { ('SerializedCertPfx', 'UserProtected'); break }
            'ExportableEncrypted:DataEncipherment:Protect' { ('Pkcs12', 'Exportable'); break }
            'ExportableEncrypted:DataEncipherment:ProtectHigh' { ('Pkcs12', 'UserProtected'); break }
            'ExportableEncrypted:KeyEncipherment:Protect' { ('Pkcs12', 'Exportable'); break }
            'ExportableEncrypted:CertSign:Protect' { ('SerializedStore', 'EphemeralKeySet'); break }
            'Exportable:DataEncipherment:None' { ('Pkcs12', 'Exportable'); break }
            'Exportable:DataEncipherment:Protect' { ('Pkcs12', 'UserProtected'); break }
            'Exportable:DataEncipherment:ProtectHigh' { ('Pkcs12', 'EphemeralKeySet'); break }
            'Exportable:KeyEncipherment:Protect' { ('SerializedCertPfx', 'Exportable'); break }
            'Exportable:KeyEncipherment:ProtectHigh' { ('SerializedCertPfx', 'UserProtected'); break }
            'Exportable:KeyAgreement:ProtectFingerPrint' { ('Pkcs7', 'MachineKeySet'); break }
            'ExportableEncrypted:DecipherOnly:ProtectFingerPrint' { ('Authenticode', 'PersistKeySet'); break }
            'NonExportable:CRLSign:None' { ('SerializedStore', 'UserKeySet'); break }
            'NonExportable:NonRepudiation:Protect' { ('Pkcs7', 'UserProtected'); break }
            'ExportableEncrypted:DigitalSignature:ProtectHigh' { ('SerializedStore', 'EphemeralKeySet'); break }
            'Exportable:EncipherOnly:ProtectFingerPrint' { ('Pkcs7', 'UserProtected'); break }
            'Default' { ('Unknown', 'DefaultKeySet') }
        }
        $x509ContentType = [System.Security.Cryptography.X509Certificates.X509ContentType]::$x509ContentType
        $x509KeyStorageFlags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::$x509KeyStorageFlags
        # if ($null -eq $Pin) { [securestring]$Pin = Read-Host -Prompt "New Certificate PIN" -AsSecureString }
        [byte[]]$certData = $cert.Export($x509ContentType, $Pin);
        # Import the certificate from the byte array and return the imported certificate
        [void]$cert.Import($certData, $Pin, $x509KeyStorageFlags);
        # Add the certificate to the personal store
        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new([System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)
        [void]$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        [void]$store.Add($cert)
        [void]$store.Close()
        Write-Verbose "[+] Created $StoreLocation\$($cert.Thumbprint)"
        return $cert
    }
    static [byte[]] Encrypt([byte[]]$PlainBytes, [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert) {
        $encryptor = $Cert.GetRSAPublicKey().CreateEncryptor()
        $cipherBytes = $encryptor.TransformFinalBlock($PlainBytes, 0, $PlainBytes.Length)
        return $cipherBytes
    }
    static [byte[]] Encrypt([byte[]]$PlainBytes, [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert, [System.Security.Cryptography.RSAEncryptionPadding]$KeyPadding) {
        $encryptor = $Cert.GetRSAPublicKey().CreateEncryptor($KeyPadding)
        $cipherBytes = $encryptor.TransformFinalBlock($PlainBytes, 0, $PlainBytes.Length)
        return $cipherBytes
    }
    static [byte[]] Decrypt([byte[]]$CipherBytes, [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert) {
        $decryptor = $Cert.GetRSAPrivateKey().CreateDecryptor()
        $plainBytes = $decryptor.TransformFinalBlock($CipherBytes, 0, $CipherBytes.Length)
        return $plainBytes
    }
    static [byte[]] Decrypt([byte[]]$CipherBytes, [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert, [System.Security.Cryptography.RSAEncryptionPadding]$KeyPadding) {
        $decryptor = $Cert.GetRSAPrivateKey().CreateDecryptor($KeyPadding)
        $plainBytes = $decryptor.TransformFinalBlock($CipherBytes, 0, $CipherBytes.Length)
        return $plainBytes
    }
    static [bool]IsValidExtension([string] $extension) {
        # Regular expression to match the format of an extension string: "oid={text}value"
        $extensionFormat = "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}={text}.*"
        return $extension -match $extensionFormat
    }
    static [System.Security.Cryptography.RSAEncryptionPadding]GetRSAPadding () {
        return $(& ([ScriptBlock]::Create("[System.Security.Cryptography.RSAEncryptionPadding]::$([Enum]::GetNames([RSAPadding]) | Get-Random)")))
    }
    static [System.Security.Cryptography.RSAEncryptionPadding]GetRSAPadding([string]$Padding) {
        if (!(($Padding -as 'RSAPadding') -is [RSAPadding])) {
            throw "Value Not in Validateset."
        }
        return $(& ([ScriptBlock]::Create("[System.Security.Cryptography.RSAEncryptionPadding]::$Padding")))
    }
    static [System.Security.Cryptography.RSAEncryptionPadding]GetRSAPadding([System.Security.Cryptography.RSAEncryptionPadding]$Padding) {
        [System.Security.Cryptography.RSAEncryptionPadding[]]$validPaddings = [Enum]::GetNames([RSAPadding]) | ForEach-Object { & ([ScriptBlock]::Create("[System.Security.Cryptography.RSAEncryptionPadding]::$_")) }
        if ($Padding -notin $validPaddings) {
            throw "Value Not in Validateset."
        }
        return $Padding
    }
    static [System.Security.Cryptography.X509Certificates.X509Certificate2] Import([string]$FilePath, [securestring]$Password) {
        return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($FilePath, $Password);
    }

    static [void] Export([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert, [string]$FilePath, [string]$Passw0rd) {
        $Cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $Passw0rd) | Set-Content -Path $FilePath -Encoding byte
    }
}
# static [void]Import() {}
# static [string]Export([System.Security.Cryptography.X509Certificates.X509Certificate2]$cert, [X509ContentType]$contentType) {
#     # Ex:
#     if ($contentType -eq 'PEM') {
#         $InsertLineBreaks = 1
#         $oMachineCert = Get-Item Cert:\LocalMachine\My\1C0381278083E3CB026E46A7FF09FC4B79543D
#         $oPem = New-Object System.Text.StringBuilder
#         $oPem.AppendLine("-----BEGIN CERTIFICATE-----")
#         $oPem.AppendLine([System.Convert]::ToBase64String($oMachineCert.RawData, $InsertLineBreaks))
#         $oPem.AppendLine("-----END CERTIFICATE-----")
#         $oPem.ToString() | Out-File D:\Temp\my.pem

#         # Or load a certificate from a file and convert it to pem format
#         $InsertLineBreaks = 1
#         $sMyCert = "D:\temp\myCert.der"
#         $oMyCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($sMyCert)
#         $oPem = New-Object System.Text.StringBuilder
#         $oPem.AppendLine("-----BEGIN CERTIFICATE-----")
#         $oPem.AppendLine([System.Convert]::ToBase64String($oMyCert.RawData, $InsertLineBreaks))
#         $oPem.AppendLine("-----END CERTIFICATE-----")
#         $oPem.ToString() | Out-File D:\Temp\my.pem
#     }
#     # $cert.Issuer = Get-CimInstance -ClassName Win32_UserAccount -Verbose:$false | Where-Object { $_.Name -eq $(whoami) } | Select-Object -ExpandProperty FullName
#     # X509Certificate2 pfxGeneratedCert = new X509Certificate2(generatedCert.Export(X509ContentType.Pfx));
#     # has to be turned into pfx or Windows at least throws a security credentials not found during sslStream.connectAsClient or HttpClient request...
#     # return pfxGeneratedCert;
#     return ''
# }
#endregion X509

#region    ecc
# .SYNOPSIS
#     Elliptic Curve Cryptography
# .DESCRIPTION
#     Asymmetric-key encryption algorithms that are known for their strong security and efficient use of resources. They are widely used in a variety of applications, including secure communication, file encryption, and password storage.
# .EXAMPLE
#     $ecc = new ECC($publicKeyXml, $privateKeyXml)
#     $encryptedData = $ecc.Encrypt($data, $password, $salt)
#     $decryptedData = $ecc.Decrypt($encryptedData, $password, $salt)
class ECC : CryptoBase {
    $publicKeyXml = [string]::Empty
    $privateKeyXml = [string]::Empty

    # Constructor
    ECC([string]$publicKeyXml, [string]$privateKeyXml) {
        $this.publicKeyXml = $publicKeyXml
        $this.privateKeyXml = $privateKeyXml
    }
    # Encrypts the specified data using the public key.
    # The data is encrypted using AES in combination with the password and salt.
    # Normally I could use System.Security.Cryptography.ECCryptoServiceProvider but for Compatibility reasons
    # I use ECDsaCng class, which provides similar functionality.
    # The encrypted data is then encrypted using ECC.
    # Encrypts the specified data using the public key.
    # The data is encrypted using AES in combination with the password and salt.
    # The encrypted data is then encrypted using ECC.
    [byte[]] Encrypt([byte[]]$data, [securestring]$password, [byte[]]$salt) {
        # Generate the AES key and initialization vector from the password and salt
        $aesKey = [System.Security.Cryptography.Rfc2898DeriveBytes]::new([xconvert]::Tostring($password), $salt, 1000).GetBytes(32);
        $aesIV = [System.Security.Cryptography.Rfc2898DeriveBytes]::new([xconvert]::Tostring($password), $salt, 1000).GetBytes(16);
        # Encrypt the data using AES
        $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
        $aes.Key = $aesKey
        $aes.IV = $aesIV
        $encryptedData = $aes.CreateEncryptor().TransformFinalBlock($data, 0, $data.Length)

        # Encrypt the AES key and initialization vector using ECC
        $ecc = New-Object System.Security.Cryptography.ECDsaCng
        $ecc.FromXmlString($this.publicKeyXml)
        $encryptedKey = $ecc.Encrypt($aesKey, $true)
        $encryptedIV = $ecc.Encrypt($aesIV, $true)

        # Concatenate the encrypted key, encrypted IV, and encrypted data
        # and return the result as a byte array
        return [byte[]]([System.Linq.Enumerable]::Concat($encryptedKey, $encryptedIV, $encryptedData))
        # or:
        # $bytes = New-Object System.Collections.Generic.List[Byte]
        # $bytes.AddRange($encryptedKey)
        # $bytes.AddRange($encryptedIV)
        # $bytes.AddRange($encryptedData)
        # return [byte[]]$Bytes
    }
    # Decrypts the specified data using the private key.
    # The data is first decrypted using ECC to obtain the AES key and initialization vector.
    # The data is then decrypted using AES.
    [byte[]] Decrypt([byte[]]$data, [securestring]$password) {
        # Extract the encrypted key, encrypted IV, and encrypted data from the input data
        $encryptedKey = $data[0..255]
        $encryptedIV = $data[256..271]
        $encryptedData = $data[272..$data.Length]

        # Decrypt the AES key and initialization vector using ECC
        $ecc = [System.Security.Cryptography.ECDsaCng]::new();
        $ecc.FromXmlString($this.privateKeyXml)
        $aesKey = $ecc.Decrypt($encryptedKey, $true)
        $aesIV = $ecc.Decrypt($encryptedIV, $true)

        # Decrypt the data using AES
        $aes = [System.Security.Cryptography.AesCryptoServiceProvider]::new();
        $aes.Key = $aesKey
        $aes.IV = $aesIV
        return $aes.CreateDecryptor().TransformFinalBlock($encryptedData, 0, $encryptedData.Length)
    }
    # Generates a new ECC key pair and returns the public and private keys as XML strings.
    [string] GenerateKeyPair() {
        $ecc = [System.Security.Cryptography.ECDsaCng]::new(256)
        ($publicKey, $privateKey) = ($ecc.ToXmlString($false), $ecc.ToXmlString($true))
        return $publicKey, $privateKey
    }
    # Exports the ECC key pair to a file or string.
    # If a file path is specified, the keys are saved to the file.
    # If a string is specified, the keys are returned as a string.
    # Usage:
    # $ECC.ExportKeyPair("C:\keys.xml")
    [string] ExportKeyPair([string]$file = $null) {
        # Create the key pair XML string
        $keyPairXml = "
            <keyPair>
                <publicKey>$($this.publicKeyXml)</publicKey>
                <privateKey>$($this.privateKeyXml)</privateKey>
            </keyPair>
        "
        # Save the key pair XML to a file or return it as a string
        if ($null -ne $file) {
            $keyPairXml | Out-File -Encoding UTF8 $file
            return $null
        } else {
            return $keyPairXml
        }
    }
    # Imports the ECC key pair from a file or string.
    # If a file path is specified, the keys are loaded from the file.
    # If a string is specified, the keys are loaded from the string.
    [void] ImportKeyPair([string]$filePath = $null, [string]$keyPairXml = $null) {
        # Load the key pair XML from a file or string
        if (![string]::IsNullOrWhiteSpace($filePath)) {
            if ([IO.File]::Exists($filePath)) {
                $keyPairXml = Get-Content -Raw -Encoding UTF8 $filePath
            } else {
                throw [System.IO.FileNotFoundException]::new('Unable to find the specified file.', "$filePath")
            }
        } else {
            throw [System.ArgumentNullException]::new('filePath')
        }
        # Extract the public and private key XML strings from the key pair XML
        $publicKey = ([xml]$keyPairXml).keyPair.publicKey
        $privateKey = ([xml]$keyPairXml).keyPair.privateKey

        # Set the public and private key XML strings in the ECC object
        $this.publicKeyXml = $publicKey
        $this.privateKeyXml = $privateKey
    }
}
#endregion ecc

#region    MD5
class MD5 : CryptoBase {
    MD5() {}
    static [byte[]] Encrypt([byte[]]$data, [string]$hash) {
        $md5 = [System.Security.Cryptography.MD5CryptoServiceProvider]::new()
        $encoderShouldEmitUTF8Identifier = $false
        $encoder = [System.Text.UTF8Encoding]::new($encoderShouldEmitUTF8Identifier)
        $keys = [byte[]]$md5.ComputeHash($encoder.GetBytes($hash));
        return [TripleDES]::Encrypt($data, $keys, $hash.Length);
    }
    static [byte[]] Decrypt([byte[]]$data, [string]$hash) {
        $md5 = [System.Security.Cryptography.MD5CryptoServiceProvider]::new()
        $encoderShouldEmitUTF8Identifier = $false
        $encoder = [System.Text.UTF8Encoding]::new($encoderShouldEmitUTF8Identifier)
        $keys = [byte[]]$md5.ComputeHash($encoder.GetBytes($hash));
        return [TripleDES]::Decrypt($data, $keys, $hash.Length);
    }
}
#endregion MD5


#region    TripleDES
# .SYNOPSIS
#     Triple Des implementation in Powershell
# .EXAMPLE
#     $t = [TripleDES]::new(3004)
#     $e = $t.Encrypt(30) # i.e: 30 times
#     [convert]::ToBase64String($e) > enc.txt
#
#     # On the same PC
#     $n = [TripleDES]::new([convert]::FromBase64String($(Get-Content ./enc.txt)))
#     $d = $n.Decrypt(30)
#     echo (Bytes_To_Object($d)) # should be 3004
# .EXAMPLE
#    # Use static methods
class TripleDES : CryptoBase {
    [ValidateNotNullOrEmpty()][cPsObject]$Object;
    [ValidateNotNullOrEmpty()][SecureString]$Password;
    static hidden [byte[]] $Salt = [System.Text.Encoding]::UTF7.GetBytes('@Q:j9=`M?EV/h>9_M/esau>A)Y6h>/v^q\ZVMPH\Vu5/E"P_GN`#t6Wnf;ah~[dik.fkj7vpoSqqN]-u`tSS5o26?\u).6YF-9e_5-KQ%kf)A{P4a9/67J8v]:[%i8PW');

    TripleDES([Object]$object) {
        $this.Object = [cPsObject]::new($object)
        $this.Password = [xconvert]::ToSecurestring([System.Text.Encoding]::UTF7.GetString([System.Security.Cryptography.Rfc2898DeriveBytes]::new([CryptoBase]::GetUniqueMachineId(), [TripleDES]::Salt, 1000, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes(24)));
    }
    [byte[]]Encrypt() {
        return $this.Encrypt(1);
    }
    [byte[]]Encrypt([int]$iterations) {
        if ($null -eq $this.Object.Bytes) { throw ([System.ArgumentNullException]::new('Object.Bytes')) }
        if ($null -eq $this.Password) { throw ([System.ArgumentNullException]::new('Password')) }
        $this.Object.Psobject.properties.add([psscriptproperty]::new('Bytes', [scriptblock]::Create("[Convert]::FromBase64String('$([convert]::ToBase64String([TripleDES]::Encrypt($this.Object.Bytes, [System.Security.Cryptography.Rfc2898DeriveBytes]::new([xconvert]::Tostring($this.Password), [TripleDES]::Salt, 1000, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes(24), $null, $iterations)))')")));
        return $this.Object.Bytes
    }
    [byte[]]Decrypt() {
        return $this.Decrypt(1);
    }
    [byte[]]Decrypt([int]$iterations) {
        if ($null -eq $this.Object.Bytes) { throw ([System.ArgumentNullException]::new('Object.Bytes')) }
        if ($null -eq $this.Password) { throw ([System.ArgumentNullException]::new('Password')) }
        $this.Object.Psobject.properties.add([psscriptproperty]::new('Bytes', [scriptblock]::Create("[Convert]::FromBase64String('$([convert]::ToBase64String([TripleDES]::Decrypt($this.Object.Bytes, [System.Security.Cryptography.Rfc2898DeriveBytes]::new([xconvert]::Tostring($this.Password), [TripleDES]::Salt, 1000, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes(24), $null, $iterations)))')")));
        return $this.Object.Bytes
    }
    static [byte[]] Encrypt([Byte[]]$data, [Byte[]]$Key) {
        return [TripleDES]::Encrypt($data, $Key, $null, 1)
    }
    static [byte[]] Encrypt([Byte[]]$data, [Byte[]]$Key, [Byte[]]$IV) {
        return [TripleDES]::Encrypt($data, $Key, $IV, 1)
    }
    static [byte[]] Encrypt([Byte[]]$data, [Byte[]]$Key, [Byte[]]$IV, [int]$iterations) {
        for ($i = 1; $i -le $iterations; $i++) { $data = [TripleDES]::Get_ED($data, $Key, $IV, $true) }
        return $data
    }
    static [byte[]] Encrypt ([byte]$data, [securestring]$Password) {
        return [TripleDES]::Encrypt($data, $Password, 1);
    }
    static [byte[]] Encrypt ([byte]$data, [string]$Passw0rd, [int]$iterations) {
        return [TripleDES]::Encrypt($data, [System.Security.Cryptography.Rfc2898DeriveBytes]::new($Passw0rd, [TripleDES]::Salt, 1000, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes(24), $null, $iterations);
    }
    static [byte[]] Encrypt ([byte]$data, [securestring]$Password, [int]$iterations) {
        return [TripleDES]::Encrypt($data, [xconvert]::Tostring($Password), $iterations)
    }
    static [byte[]] Decrypt([Byte[]]$data, [Byte[]]$Key) {
        return [TripleDES]::Decrypt($data, $Key, $null, 1);
    }
    static [byte[]] Decrypt([Byte[]]$data, [Byte[]]$Key, [Byte[]]$IV) {
        return [TripleDES]::Decrypt($data, $Key, $IV, 1);
    }
    static [byte[]] Decrypt([Byte[]]$data, [Byte[]]$Key, [Byte[]]$IV, [int]$iterations) {
        for ($i = 1; $i -le $iterations; $i++) { $data = [TripleDES]::Get_ED($data, $Key, $IV, $false) }
        return $data
    }
    static [byte[]] Decrypt ([byte]$data, [securestring]$Password) {
        return [TripleDES]::Decrypt($data, $Password, 1)
    }
    static [byte[]] Decrypt ([byte]$data, [string]$Passw0rd, [int]$iterations) {
        return [TripleDES]::Decrypt($data, [System.Security.Cryptography.Rfc2898DeriveBytes]::new($Passw0rd, [TripleDES]::Salt, 1000, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes(24), $null, $iterations);
    }
    static [byte[]] Decrypt ([byte]$data, [securestring]$Password, [int]$iterations) {
        return [TripleDES]::Decrypt($data, [xconvert]::Tostring($Password), $iterations)
    }
    static hidden [byte[]] Get_ED([Byte[]]$data, [Byte[]]$Key, [Byte[]]$IV, [bool]$Encrypt) {
        $result = [byte[]]::new(0); $ms = [System.IO.MemoryStream]::new(); $cs = $null
        try {
            $tdes = [System.Security.Cryptography.TripleDESCryptoServiceProvider]::new()
            if ($null -eq $Key) { throw ([System.ArgumentNullException]::new('Key')) }else { $tdes.Key = $Key }
            if ($null -eq $IV) { $p4 = [CryptoBase]::GetUniqueMachineId(); $tdes.IV = [System.Security.Cryptography.Rfc2898DeriveBytes]::new($p4, [TripleDES]::Salt, [int]([int[]][char[]]$p4 | Measure-Object -Sum).Sum, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes(8) }else { $tdes.IV = $IV }
            $CryptoTransform = [System.Security.Cryptography.ICryptoTransform]$(if ($Encrypt) { $tdes.CreateEncryptor() }else { $tdes.CreateDecryptor() })
            $cs = [System.Security.Cryptography.CryptoStream]::new($ms, $CryptoTransform, [System.Security.Cryptography.CryptoStreamMode]::Write)
            [void]$cs.Write($data, 0, $data.Length)
            [void]$cs.FlushFinalBlock()
            $ms.Position = 0
            $result = [Byte[]]::new($ms.Length)
            [void]$ms.Read($result, 0, $ms.Length)
        } catch [System.Security.Cryptography.CryptographicException] {
            if ($_.exception.message -notlike "*data is not a complete block*") { throw $_.exception }
        } finally {
            Invoke-Command -ScriptBlock { $tdes.Clear(); $cs.Close(); $ms.Dispose() } -ErrorAction SilentlyContinue
        }
        return $result
    }
}
#endregion TripleDES

#region    XOR
# .SYNOPSIS
#     Custom Xor implementation in Powershell
# .EXAMPLE
#     $x = [XOR]::new("hello world!")
#     $e = $x.Encrypt(5) # i.e: 5 times
#     [convert]::ToBase64String($e) > xenc.txt
#
#     # On the same PC
#     $n = [XoR]::new([convert]::FromBase64String($(Get-Content ./xenc.txt)))
#     $d = $n.Decrypt(5)
#     echo (Bytes_To_Object($d)) # should be hello world!
# .EXAMPLE
#    # Use static methods
class XOR : CryptoBase {
    [ValidateNotNullOrEmpty()][cPsObject]$Object;
    [ValidateNotNullOrEmpty()][SecureString]$Password;
    static hidden [byte[]] $Salt = [System.Text.Encoding]::UTF7.GetBytes('\SBOv!^L?XuCFlJ%*[6(pUVp5GeR^|U=NH3FaK#XECOaM}ExV)3_bkd:eG;Z,tWZRMg;.A!,:-k6D!CP>74G+TW7?(\6;Li]lA**2P(a2XxL}<.*oJY7bOx+lD>%DVVa');
    XOR([Object]$object) {
        $this.Object = [cPsObject]::new($object)
        $this.Password = [xconvert]::ToSecurestring([System.Text.Encoding]::UTF7.GetString([System.Security.Cryptography.Rfc2898DeriveBytes]::new([CryptoBase]::GetUniqueMachineId(), [XOR]::Salt, 1000, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes(256 / 8)))
    }
    [byte[]]Encrypt() {
        return $this.Encrypt(1)
    }
    [byte[]]Encrypt([int]$iterations) {
        if ($null -eq $this.Object.Bytes) { throw ([System.ArgumentNullException]::new('Object.Bytes')) }
        if ($null -eq $this.Password) { throw ([System.ArgumentNullException]::new('key')) }
        $this.Object.Psobject.properties.add([psscriptproperty]::new('Bytes', [scriptblock]::Create("[Convert]::FromBase64String('$([convert]::ToBase64String([byte[]][XOR]::Encrypt($this.Object.Bytes, $this.Password, $iterations)))')")))
        return $this.Object.Bytes
    }
    static [byte[]] Encrypt([byte[]]$Bytes, [String]$Passw0rd) {
        return [XOR]::Encrypt($bytes, [xconvert]::ToSecurestring([System.Text.Encoding]::UTF7.GetString([System.Security.Cryptography.Rfc2898DeriveBytes]::new($Passw0rd, [XOR]::Salt, 1000, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes(256 / 8))), 1)
    }
    static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$password) {
        return [XOR]::Encrypt($bytes, $password, 1)
    }
    static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$password, [int]$iterations) {
        $xorkey = [xconvert]::BytesFromObject([xconvert]::ToString($password));
        # [system.Text.Encoding]::UTF8.GetBytes()
        return [XOR]::Encrypt($bytes, $xorkey, $iterations)
    }
    static [byte[]] Encrypt([byte[]]$Bytes, [byte[]]$xorkey, [int]$iterations) {
        if ($null -eq $xorkey) {
            throw ([System.ArgumentNullException]::new('xorkey'))
        }
        $_bytes = $bytes;
        for ($i = 1; $i -lt $iterations + 1; $i++) {
            $_bytes = [XOR]::Get_ED($_bytes, $xorkey);
        }; if ($_bytes.Equals($bytes)) { $_bytes = $null }
        return $_bytes
    }
    [byte[]]Decrypt() {
        return $this.Decrypt(1)
    }
    [byte[]]Decrypt([int]$iterations) {
        if ($null -eq $this.Object.Bytes) { throw ([System.ArgumentNullException]::new('Object.Bytes')) }
        if ($null -eq $this.Password) { throw ([System.ArgumentNullException]::new('Password')) }
        $this.Object.Psobject.properties.add([psscriptproperty]::new('Bytes', [scriptblock]::Create("[Convert]::FromBase64String('$([convert]::ToBase64String([byte[]][XOR]::Decrypt($this.Object.Bytes, $this.Password, $iterations)))')")));
        return $this.Object.Bytes
    }
    #!Not Recommended!
    static [byte[]] Decrypt([byte[]]$Bytes, [String]$Passw0rd) {
        return [XOR]::Decrypt($bytes, [xconvert]::ToSecurestring([System.Text.Encoding]::UTF7.GetString([System.Security.Cryptography.Rfc2898DeriveBytes]::new($Passw0rd, [XOR]::Salt, 1000, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes(256 / 8))), 1);
    }
    static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$password) {
        return [XOR]::Decrypt($bytes, $password, 1);
    }
    static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$password, [int]$iterations) {
        $xorkey = [xconvert]::BytesFromObject([xconvert]::ToString($password))
        # [system.Text.Encoding]::UTF8.GetBytes()
        return [XOR]::Decrypt($bytes, $xorkey, $iterations);
    }
    static [byte[]] Decrypt([byte[]]$Bytes, [byte[]]$xorkey, [int]$iterations) {
        if ($null -eq $xorkey) {
            throw ([System.ArgumentNullException]::new('xorkey'))
        }
        $_bytes = $bytes; for ($i = 1; $i -lt $iterations + 1; $i++) {
            $_bytes = [XOR]::Get_ED($_bytes, $xorkey)
        };
        return $_bytes;
    }
    static hidden [byte[]] Get_ED([byte[]]$Bytes, [byte[]]$key) {
        return $(for ($i = 0; $i -lt $bytes.length) {
                for ($j = 0; $j -lt $key.length; $j++) {
                    $bytes[$i] -bxor $key[$j]
                    $i++
                    if ($i -ge $bytes.Length) {
                        $j = $key.length
                    }
                }
            }
        )
    }
}
#endregion XOR

#region    RC4
# .SYNOPSIS
#     PowerShell class implementation of the RC4 algorithm
# .DESCRIPTION
#     "Ron's Code 4" or "Rivest Cipher 4," depending on the source.
#     A symmetric key stream cipher that was developed by Ron Rivest of RSA Security in 1987.
#     It was widely used in the 1990s and early 2000s, but has since been replaced by more secure algorithms in many applications due to vulnerabilities.
# .NOTES
#     RC4 is an old and insecure encryption algorithm.
#     It is recommended to use a more modern and secure algorithm, such as AES or ChaCha20.
#     But if you insist on using this, Just Use really strong passwords.
#     I mean shit like: Wwi@4c5w&@hOtf}Mm_t%&[BXq>5*0:Fm}6L'poyi!8LoZD\!HXPPPvMRas<CWl$yk${vlW9(f:S@w/E
# .EXAMPLE
#     $dat = Bytes_From_Object("Hello World")
#     $enc = [rc4]::Encrypt($dat, (Read-Host -AsSecureString -Prompt 'Password'))
#     $dec = [rc4]::Decrypt($enc, (Read-Host -AsSecureString -Prompt 'Password'))
#     Bytes_To_Object($dec)
class RC4 : CryptoBase {
    static [Byte[]] Encrypt([Byte[]]$data, [Byte[]]$passwd) {
        $a = $i = $j = $k = $tmp = [Int]0
        $key = [Int[]]::new(256)
        $box = [Int[]]::new(256)
        $cipher = [Byte[]]::new($data.Length)
        for ($i = 0; $i -lt 256; $i++) {
            $key[$i] = $passwd[$i % $passwd.Length];
            $box[$i] = $i;
        }
        for ($j = $i = 0; $i -lt 256; $i++) {
            $j = ($j + $box[$i] + $key[$i]) % 256;
            $tmp = $box[$i];
            $box[$i] = $box[$j];
            $box[$j] = $tmp;
        }
        for ($a = $j = $i = 0; $i -lt $data.Length; $i++) {
            $a++;
            $a %= 256;
            $j += $box[$a];
            $j %= 256;
            $tmp = $box[$a];
            $box[$a] = $box[$j];
            $box[$j] = $tmp;
            $k = $box[(($box[$a] + $box[$j]) % 256)];
            $cipher[$i] = [Byte]($data[$i] -bxor $k);
        }
        return $cipher;
    }
    static [Byte[]] Decrypt([Byte[]]$data, [Byte[]]$passwd) {
        return [RC4]::Encrypt($data, $passwd);
        # The Decrypt method simply calls the Encrypt method with the same arguments.
        # This is because the RC4 algorithm is symmetric, meaning that the same key is used for both encryption and decryption.
        # Therefore, the encryption and decryption processes are identical.
    }
}
#endregion RC4

#region    CHACHA20
# .SYNOPSIS
#     An implementation of the ChaCha20 encryption algorithm in PowerShell.
# .DESCRIPTION
#     Its derived from the Salsa20 stream cipher algorithm, with several changes like integrity checking to improve its security and performance.
#     ChaCha20 operates on a 256-bit key, a 64-bit nonce, and a 20-round pseudo-random number generator to generate keystream data.
#     The algorithm is highly efficient, making it well-suited for use in a wide range of applications, including encryption, digital signatures, and key derivation.
# .NOTES
#     Encryption is a subtle and complex area and it's easy to make mistakes that can leave you vulnerable to attack.
#     While this implementation is functional, its not 100% tested. In a enterprise env practice, you should use a well-vetted implementation, like one from a reputable library.
#     You should also consider additional measures like key management, which are crucial for the security of the encryption and use a secure method for generating the key and nonce, such as using the System.Security.Cryptography.RNGCryptoServiceProvider class.
# .LINK
#     https://github.com/alainQtec/CipherTron/blob/main/Private/CipherTron.Core/CipherTron.Core.psm1
# .EXAMPLE
#     $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider; $key = New-Object Byte[] 32; $rng.GetBytes($key); $IV = New-Object Byte[] 16; $rng.GetBytes($IV)
#     $bytes = [Text.Encoding]::UTF8.GetBytes("my secret message")
#     $enc = [chacha20]::Encrypt($bytes, $key, $IV)
#     $dec = [chacha20]::Decrypt($enc, $key, $IV)
#     echo ([Text.Encoding]::UTF8.GetString($dec)) # should be: my secret message
# .EXAMPLE
#     $enc = [Chacha20]::Encrypt($bytes, (Read-Host -AsSecureString -Prompt "Passwd"), 5)
#     $dec = [chacha20]::Decrypt($enc, (Read-Host -AsSecureString -Prompt "Passwd"), 5)
#     echo ([Text.Encoding]::UTF8.GetString($dec))
Class ChaCha20 : CryptoBase {
    static hidden [Int32]$blockSize = 64
    static hidden [Byte[]]$SIGMA = [Byte[]]@(83, 72, 65, 67, 72, 65, 50, 48, 87, 65, 86, 69)
    static hidden [byte[]]$Salt = [convert]::FromBase64String('plqnkknbuujsklslyscgkycobvflyqwrttalqqjidosyjrodkiuxcokwjrftfyyttipfvtwodwrnvsre')

    static [byte[]] Encrypt([byte[]]$Bytes, [securestring]$Password) {
        return [Chacha20]::Encrypt($Bytes, $Password, [ChaCha20]::Salt)
    }
    static [Byte[]] Encrypt([Byte[]]$bytes, [Byte[]]$key, [Byte[]]$nonce) {
        # Write-Debug "Nptb64: $([convert]::ToBase64String($bytes))" -Debug
        [byte[]]$hash = [System.Security.Cryptography.SHA256CryptoServiceProvider]::new().ComputeHash($bytes)
        [byte[]]$bytes = $bytes + $hash # Used for integrity check ie: We append a cryptographic hash (e.g., SHA-256) before encryption, and then check the hash of the decrypted plainBytes against the original hash after decryption.
        [Byte[]]$EncrBytes = [Byte[]]::new($bytes.Length)
        [Byte[]]$block = [Byte[]]::new([ChaCha20]::blockSize)
        [Int32]$bytesIndex = 0
        [Int32]$EncrnIndex = 0
        [Int32]$blockCounter = 0
        while ($bytesIndex -lt $bytes.Length) {
            $block = [ChaCha20]::GenerateBlock($blockCounter, $key, $nonce)
            [Int32]$bytesToCopy = [Math]::Min($bytes.Length - $bytesIndex, [ChaCha20]::blockSize)
            for ([Int32]$i = 0; $i -lt $bytesToCopy; $i++) {
                $EncrBytes[$EncrnIndex + $i] = $bytes[$bytesIndex + $i] -bxor $block[$i]
            }
            $bytesIndex += $bytesToCopy
            $EncrnIndex += $bytesToCopy
            $blockCounter++
        }
        # Write-Debug "Encb64: $([convert]::ToBase64String($EncrBytes))" -Debug
        return $EncrBytes
    }
    static [byte[]] Encrypt([byte[]]$Bytes, [securestring]$Password, [byte[]]$Salt) {
        return [Chacha20]::Encrypt($Bytes, $Password, $Salt, 1)
    }
    static [byte[]] Encrypt([byte[]]$Bytes, [securestring]$Password, [int]$iterations) {
        return [Chacha20]::Encrypt($Bytes, $Password, [ChaCha20]::Salt, $iterations)
    }
    static [byte[]] Encrypt([byte[]]$Bytes, [securestring]$Password, [byte[]]$Salt, [int]$iterations) {
        [byte[]]$Key = $null; Set-Variable -Name Key -Scope Local -Visibility Private -Option Private -Value ([System.Security.Cryptography.Rfc2898DeriveBytes]::new([xconvert]::ToString($Password), $Salt, 10000, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes(32));
        $_bytes = $bytes; if ([string]::IsNullOrWhiteSpace([ChaCha20]::caller)) { [ChaCha20]::caller = '[ChaCha20]' }
        for ($i = 1; $i -lt $iterations + 1; $i++) {
            Write-Host "$([ChaCha20]::caller) [+] Encryption [$i/$iterations] ...$(
                # Generate a random IV for each iteration:
                [byte[]]$IV = $null; Set-Variable -Name IV -Scope Local -Visibility Private -Option Private -Value ([System.Security.Cryptography.Rfc2898DeriveBytes]::new([xconvert]::Tostring($password), $salt, 1, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes(16));
                $_bytes = [Shuffl3r]::Combine([Chacha20]::Encrypt($_bytes, $Key, $IV), $IV, $Password)
            ) Done" -ForegroundColor Yellow
        }
        return $_bytes
    }
    static [byte[]] Decrypt([byte[]]$Bytes, [securestring]$Password) {
        return [ChaCha20]::Decrypt($Bytes, $Password, [ChaCha20]::Salt)
    }
    static [byte[]] Decrypt([byte[]]$bytes, [byte[]]$key, [byte[]]$nonce) {
        [byte[]]$decrBytes = [byte[]]::new($bytes.Length);
        [Int32]$bytesIndex = 0
        [Int32]$decrnIndex = 0
        while ($bytesIndex -lt $bytes.Length) {
            [Int32]$blockCounter = $bytesIndex / [ChaCha20]::blockSize
            [Int32]$bytesToCopy = [Math]::Min($bytes.Length - $bytesIndex, [ChaCha20]::blockSize)
            [Byte[]]$block = [ChaCha20]::GenerateBlock($blockCounter, $key, $nonce)
            for ($i = 0; $i -lt $bytesToCopy; $i++) {
                $decrBytes[$decrnIndex + $i] = $bytes[$bytesIndex + $i] -bxor $block[$i]
            }
            $bytesIndex += [ChaCha20]::blockSize
            $decrnIndex += $bytesToCopy
        }
        $hash = $decrBytes | Select-Object -Last 32
        $decr = $decrBytes | Select-Object -First ($decrBytes.Length - 32)
        if ([convert]::ToBase64String([System.Security.Cryptography.SHA256CryptoServiceProvider]::new().ComputeHash($decr)) -ne [convert]::ToBase64String($hash)) {
            throw [IntegrityCheckFailedException]"Integrity check failed"
        }
        # Write-Debug "Decb64: $([convert]::ToBase64String($decr))" -Debug
        return $decr
    }
    static [byte[]] Decrypt([byte[]]$Bytes, [securestring]$Password, [byte[]]$Salt) {
        return [ChaCha20]::Decrypt($Bytes, $Password, $Salt, 1)
    }
    static [byte[]] Decrypt([byte[]]$Bytes, [securestring]$Password, [int]$iterations) {
        return [ChaCha20]::Decrypt($Bytes, $Password, [ChaCha20]::Salt, $iterations)
    }
    static [byte[]] Decrypt([byte[]]$Bytes, [securestring]$Password, [byte[]]$Salt, [int]$iterations) {
        [byte[]]$Key = $null; Set-Variable -Name Key -Scope Local -Visibility Private -Option Private -Value ([System.Security.Cryptography.Rfc2898DeriveBytes]::new([xconvert]::ToString($Password), $Salt, 10000, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes(32));
        $_bytes = $bytes; if ([string]::IsNullOrWhiteSpace([ChaCha20]::caller)) { [ChaCha20]::caller = '[ChaCha20]' }
        for ($i = 1; $i -lt $iterations + 1; $i++) {
            Write-Host "$([ChaCha20]::caller) [+] Decryption [$i/$iterations] ...$(
                $bytes = $null; $IV = $null
                ($bytes, $IV) = [Shuffl3r]::Split($_bytes, $Password, 16);
                $_bytes = [Chacha20]::Decrypt($bytes, $Key, $IV)
            ) Done" -ForegroundColor Yellow
        }
        return $_bytes
    }
    static hidden [Byte[]] GenerateBlock([Int32]$blockCounter, [Byte[]]$key, [Byte[]]$nonce) {
        [Int32[]]$state = [Int32[]]@(
            0x61707865, 0x3320646E, 0x79622D32, 0x6B206574, # constant
            0, 0, 0, 0, # block counter
            [BitConverter]::ToInt32($key[0..3], 0), [BitConverter]::ToInt32($key[4..7], 0), [BitConverter]::ToInt32($key[8..11], 0), [BitConverter]::ToInt32($key[12..15], 0), # key
            [BitConverter]::ToInt32($key[16..19], 0), [BitConverter]::ToInt32($key[20..23], 0), [BitConverter]::ToInt32($key[24..27], 0), [BitConverter]::ToInt32($key[28..31], 0),
            0, 0, # nonce
            0, 0
        )
        $state[12] = $blockCounter
        $state[14] = [BitConverter]::ToInt32($nonce[0..3], 0)
        $state[15] = [BitConverter]::ToInt32($nonce[4..7], 0)

        for ([Int32]$i = 0; $i -lt 10; $i++) {
            [BitwUtil]::QuaterRound([ref]$state[0], [ref]$state[4], [ref]$state[8], [ref]$state[12])
            [BitwUtil]::QuaterRound([ref]$state[1], [ref]$state[5], [ref]$state[9], [ref]$state[13])
            [BitwUtil]::QuaterRound([ref]$state[2], [ref]$state[6], [ref]$state[10], [ref]$state[14])
            [BitwUtil]::QuaterRound([ref]$state[3], [ref]$state[7], [ref]$state[11], [ref]$state[15])
            [BitwUtil]::QuaterRound([ref]$state[0], [ref]$state[5], [ref]$state[10], [ref]$state[15])
            [BitwUtil]::QuaterRound([ref]$state[1], [ref]$state[6], [ref]$state[11], [ref]$state[12])
            [BitwUtil]::QuaterRound([ref]$state[2], [ref]$state[7], [ref]$state[8], [ref]$state[13])
            [BitwUtil]::QuaterRound([ref]$state[3], [ref]$state[4], [ref]$state[9], [ref]$state[14])
        }
        [Byte[]]$result = [Byte[]]::new($state.Length * 4)
        for ([Int32]$i = 0; $i -lt $state.Length; $i++) {
            # Copy the bytes from the $i-th int in $state to the correct position in $result
            [Array]::Copy([BitConverter]::GetBytes($state[$i]), 0, $result, $i * 4, 4)
        }
        return $result
    }
}
#endregion CHACHA20

#region    Poly1305
# .DESCRIPTION
#     Using Poly1305 for integrity checking is a better option than using SHA-256 in terms of security.
#     Poly1305 is a faster and more secure message authentication code (MAC) algorithm compared to SHA-256.
# .NOTES
#     This Class would be amazing but it not functional; ...yet. Yeal its total bs :)
class Poly1305 : CryptoBase {
    [Byte[]]$Key

    Poly1305([Byte[]]$key) {
        if ($key.Length -ne 32) {
            throw [System.ArgumentException]"Invalid key size. Key must be 32 bytes."
        }
        $this.Key = $key
    }
    [byte[]] ComputeHash([Byte[]]$nput) {
        # Constants
        $block = $null
        $blockSize = 16
        $blockLength = $blockSize * 4
        $r = New-Object 'UInt64[]' 16
        $h = New-Object 'UInt64[]' 17

        # Initialize r array
        for ($i = 0; $i -lt 16; $i++) {
            if (($i * 8) + 7 -lt $this.Key.Length) {
                $r[$i] = [BitConverter]::ToUInt64($this.Key, ($i * 8))
            } else {
                $r[$i] = 0
            }
        }
        for ($i = 0; $i -lt 17; $i++) {
            $h[$i] = 0
        }
        # Process input bytes
        for ($offset = 0; $offset -lt $nput.Length; $offset += $blockLength) {
            $block = New-Object 'Byte[]' $blockLength
            [Array]::Copy($nput, $offset, $block, 0, [Math]::Min($blockLength, $nput.Length - $offset))
            ($h, $r, $block) = $this.Poly1305_Block($h, $r, $block)
        }

        # Finalize
        [UInt64]$s = 0
        for ($i = 0; $i -lt 16; $i++) {
            $s = ($s + $h[$i]) -band 0xffffffff
            if ($i -eq 15) {
                break
            }
            $s = ($s -shr 26) -band 0xffffffff
        }
        $mac = [BitConverter]::GetBytes($s)
        [Array]::Reverse($mac)
        for ($i = 1; $i -lt 16; $i++) {
            [UInt64]$c = $h[$i] + 16 - $mac[$i - 1]
            $mac = $mac + [BitConverter]::GetBytes($c)
            [Array]::Reverse($mac[($mac.Length - 8)..($mac.Length - 1)])
        }
        return $mac[0..15]
    }
    [array] Poly1305_Block([UInt64[]]$h, [UInt64[]]$r, [UInt64[]]$m) {
        [UInt64[]]$h = [bitwUtil]::Reduce($h)
        [UInt64[]]$r = [bitwUtil]::Reduce($r)
        [UInt64[]]$m = [bitwUtil]::Reduce($m)
        [UInt64] $s = 0
        [UInt64] $d0 = 0
        [UInt64] $d1 = 0
        for ($i = 0; $i -lt 16; $i++) {
            $d0 = ($m[$i] + $h[$i]) -band 0xffffffff
            $d1 = ($d0 * $r[0]) -band 0xffffffff
            $d0 = ($d0 + ((($d1 * $r[1]) -band 0xffffffff) -shl 16)) -band 0xffffffff
            $d0 = ($d0 % 130) -band 0xffffffff
            $s = ($s + $d0) -band 0xffffffff
            if ($i -eq 15) {
                break
            }
            $s = ($s * 5) -band 0xffffffff
            $s = ($s + 0x800000000000) -band 0xffffffff
            $s = ($s % 130) -band 0xffffffff
        }
        $h[0] = $s -band 0xffffffff
        for ($i = 1; $i -lt 17; $i++) {
            $s = ($s -shr 26) -band 0xffffffff
            $h[$i] = ($h[$i] + $s) -band 0xffffffff
        }
        return ($h, $r, $m)
    }
}
#endregion Poly1305

#endregion Custom_EncClasses_&_Helpers

#region    FileCrypter
# .SYNOPSIS
#     Simple file encryption & some script obfuscation
# .NOTES
#     - Requires powershell core
#     - Obfuscation method was inspired by: https://netsec.expert/posts/write-a-crypter-in-any-language
#       I modified the functions from netsec blog and tried my best to avoid using Invoke-Expression in any possible way, since its like a red flag for Anti viruses. I Instead used "& ([scriptblock]::Create(...."
Class FileCryptr {
    static hidden [System.Object] $CommonFileExtensions;
    static hidden [ValidateNotNullOrEmpty()][string] $_salt;
    static hidden [ValidateNotNullOrEmpty()][securestring] $Password;
    static hidden [ValidateNotNullOrEmpty()][Compression] $Compression;
    FileCryptr() {
        [FileCryptr]::_salt = 'bz07LmY5XiNkXW1WQjxdXw=='
        [FileCryptr]::Compression = [Compression]::Gzip
        [FileCryptr]::CommonFileExtensions = New-Object System.Management.Automation.PSStyle+FileInfoFormatting+FileExtensionDictionary
    }
    static [void] Encrypt([string]$FilePath) {
        [FileCryptr]::Encrypt($FilePath, 1)
    }
    static [void] Encrypt([string]$FilePath, [string]$Outfile) {
        [FileCryptr]::Encrypt($FilePath, 1, $Outfile)
    }
    static [void] Encrypt([string]$FilePath, [int]$iterations) {
        [FileCryptr]::Encrypt($FilePath, $iterations, $FilePath)
    }
    static [void] Encrypt([string]$FilePath, [int]$iterations, [string]$Outfile) {
        [FileCryptr]::Password = [xconvert]::ToSecurestring(
            [System.Text.Encoding]::UTF8.GetString(
                [System.Security.Cryptography.Rfc2898DeriveBytes]::new(
                    [CryptoBase]::GetUniqueMachineId(),
                    [convert]::FromBase64String([FileCryptr]::_salt),
                    1000,
                    [System.Security.Cryptography.HashAlgorithmName]::SHA1
                ).GetBytes(256 / 8)
            )
        )
        [FileCryptr]::Encrypt($FilePath, [FileCryptr]::Password, $iterations, $Outfile)
    }
    static [void] Encrypt([string]$FilePath, [securestring]$passwr0d, [int]$iterations) {
        [FileCryptr]::Encrypt($FilePath, $passwr0d, $iterations, $FilePath)
    }
    static [void] Encrypt([string]$FilePath, [securestring]$passwr0d, [int]$iterations, [string]$Outfile) {
        [byte[]]$clearData = [System.IO.File]::ReadAllBytes($FilePath);
        $Outfile = [CryptoBase]::GetUnResolvedPath($Outfile); if (![IO.File]::Exists($Outfile)) { New-Item -Path $Outfile -ItemType File }
        $encryptedBytes = [AesGCM]::Encrypt($clearData, $passwr0d, [convert]::FromBase64String([FileCryptr]::_salt), $iterations)
        [System.IO.File]::WriteAllBytes($Outfile, $encryptedBytes)
    }
    static [void] Decrypt([string]$FilePath) {
        [FileCryptr]::Decrypt($FilePath, 1)
    }
    static [void] Decrypt([string]$FilePath, [string]$Outfile) {
        [FileCryptr]::Decrypt($FilePath, 1, $Outfile)
    }
    static [void] Decrypt([string]$FilePath, [int]$iterations) {
        [FileCryptr]::Decrypt($FilePath, $iterations, $FilePath)
    }
    static [void] Decrypt([string]$FilePath, [int]$iterations, [string]$Outfile) {
        [FileCryptr]::Password = [xconvert]::ToSecurestring(
            [System.Text.Encoding]::UTF8.GetString(
                [System.Security.Cryptography.Rfc2898DeriveBytes]::new(
                    [CryptoBase]::GetUniqueMachineId(), [convert]::FromBase64String([FileCryptr]::_salt),
                    1000, [System.Security.Cryptography.HashAlgorithmName]::SHA1
                ).GetBytes(256 / 8)
            )
        )
        [FileCryptr]::Decrypt($FilePath, [FileCryptr]::Password, $iterations, $Outfile)
    }
    static [void] Decrypt([string]$FilePath, [securestring]$passwr0d, [int]$iterations) {
        [FileCryptr]::Decrypt($FilePath, $passwr0d, $iterations, $FilePath)
    }
    static [void] Decrypt([string]$FilePath, [securestring]$passwr0d, [int]$iterations, [string]$Outfile) {
        [byte[]]$encryptedData = [System.IO.File]::ReadAllBytes($FilePath);
        $Outfile = [CryptoBase]::GetUnResolvedPath($Outfile); if (![IO.File]::Exists($Outfile)) { New-Item -Path $Outfile -ItemType File }
        $decryptedBytes = [AesGCM]::Decrypt($encryptedData, $passwr0d, [convert]::FromBase64String([FileCryptr]::_salt), $iterations)
        [System.IO.File]::WriteAllBytes($Outfile, $decryptedBytes)
    }
    static [string] GetStub([string]$filePath) {
        [int]$keySize = 256;
        [byte[]]$salt = [convert]::FromBase64String([FileCryptr]::_salt);
        [string]$b64k = [convert]::ToBase64String(
            [System.Security.Cryptography.Rfc2898DeriveBytes]::new(
                [FileCryptr]::RNdvar(), $salt, 10000,
                [System.Security.Cryptography.HashAlgorithmName]::SHA1
            ).GetBytes($keySize / 8)
        );
        return [FileCryptr]::GetStub($filePath, $b64k);
    }
    static [string] RNdvar() {
        return [FileCryptr]::RNdvar(15)
    }
    static [string] RNdvar([string]$Length) {
        return [Guid]::NewGuid().Guid.subString($Length).replace('-', [string]::Join('', (0..9 | Get-Random -Count 1)))
    }
    static [string] GetStub([string]$filePath, [string]$base64key) {
        return [FileCryptr]::GetStub($filePath, $base64key, [FileCryptr]::_salt)
    }
    static hidden [string] GetStub([string]$filePath, [string]$base64key, [string]$salt) {
        Write-Verbose "[+] Reading file: '$($filePath)' ..."
        $filePath = [CryptoBase]::GetUnResolvedPath($filePath)
        if (![IO.File]::Exists($filePath)) { throw [System.IO.FileNotFoundException]::new("Unable to find the file: $filePath") }
        $codebytes = [System.Text.Encoding]::UTF8.GetBytes([System.IO.File]::ReadAllText($filePath, [System.Text.Encoding]::UTF8));
        $Comprssnm = [FileCryptr]::Compression.ToString()
        $EncrBytes = $null
        Write-Verbose "[+] Encrypting ...$(
            $Passw = [SecureString][xconvert]::TosecureString($base64key)
            $bSalt = [byte[]][Convert]::FromBase64String($salt); [int]$KeySize = 256; $CryptoProvider = $null;
            if ($Comprssnm -notin ([Enum]::GetNames('Compression' -as 'Type'))) { Throw [System.InvalidCastException]::new("The name '$Comprssnm' is not a valid [Compression]`$typeName.") };
            Set-Variable -Name CryptoProvider -Scope Local -Visibility Private -Option Private -Value ([System.Security.Cryptography.AesCryptoServiceProvider]::new());
            $CryptoProvider.KeySize = [int]$KeySize;
            $CryptoProvider.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7;
            $CryptoProvider.Mode = [System.Security.Cryptography.CipherMode]::CBC;
            $CryptoProvider.Key = [System.Security.Cryptography.Rfc2898DeriveBytes]::new([xconvert]::ToString($Passw), $bSalt, 10000, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes($KeySize / 8);
            $CryptoProvider.IV = [System.Security.Cryptography.Rfc2898DeriveBytes]::new([xconvert]::Tostring($passw), $bsalt, 1, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes(16);
            Set-Variable -Name EncrBytes -Scope Local -Visibility Private -Option Private -Value $($CryptoProvider.IV + $CryptoProvider.CreateEncryptor().TransformFinalBlock($codebytes, 0, $codebytes.Length));
            Set-Variable -Name EncrBytes -Scope Local -Visibility Private -Option Private -Value $([xconvert]::ToCompressed($EncrBytes, $Comprssnm));
            $CryptoProvider.Clear(); $CryptoProvider.Dispose()
        ) Done."
        $base64encString = [convert]::ToBase64String($EncrBytes)
        $base64encbArray = $base64encString.ToCharArray(); [array]::Reverse($base64encbArray);
        $base64encrevstr = -join $base64encbArray
        [string]$xorPassword = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes([CryptoBase]::GeneratePassword(30, $true, $false, $true, $true)))
        [byte[]]$Passwdbytes = [System.Text.Encoding]::UTF8.GetBytes($xorPassword); $xkey64 = [convert]::ToBase64String($Passwdbytes)
        $base64XOREncPayload = [Convert]::ToBase64String([xor]::Encrypt([System.Text.Encoding]::UTF8.GetBytes($base64encrevstr), $Passwdbytes, 1))
        Write-Verbose "[+] Finalizing Code Layer ..."
        $s = [string]::Empty
        $l = @(); $n = "`r`n"
        $l += '${9} = [int][System.Text.Encoding]::UTF8.GetString([convert]::FromBase64String("MjU2"))' + $n
        $l += '${7} = [System.Convert]::FromBase64String("LkNyZWF0ZURlY3J5cHRvcigpLlRyYW5zZm9ybUZpbmFsQmxvY2s=")' + $n
        $l += '${2} = [System.Convert]::FromBase64String("{25}")' + $n
        $l += '${3} = [System.Convert]::FromBase64String("{0}")' + $n
        $l += '${4} = [byte[]]$(for (${6} = 0; ${6} -lt ${3}.length) {' + $n
        $l += '        for (${5} = 0; ${5} -lt ${2}.length; ${5}++) {' + $n
        $l += '            ${3}[${6}] -bxor ${2}[${5}]' + $n
        $l += '            ${6}++' + $n
        $l += '            if (${6} -ge ${3}.Length) {' + $n
        $l += '                ${5} = ${2}.length' + $n
        $l += '            }' + $n
        $l += '        }' + $n
        $l += '    }' + $n
        $l += ')' + $n
        $s += $l -join ''; $l = @()
        $l += '[array]::Reverse(${4});' + $n
        $l += '${19} = -join [char[]]${4};' + $n
        $l += '${20} = $null; ${11} = $null; ${12} = $null' + $n
        $l += '${10} = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGVjb21wcmVzcw=="));' + $n
        $l += '${21} = & ([scriptblock]::Create("$([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W1N5c3RlbS5JTy5NZW1vcnlTdHJlYW1dOjpuZXc=")))([System.Convert]::FromBase64String(`"${19}`"))"));' + $n
        $l += '${13} = & ([scriptblock]::Create([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0lPLkNvbXByZXNzaW9uLkNvbXByZXNzaW9uTW9kZV0="))));' + $n
        $l += '${14} = switch ("{23}") {' + $n
        $l += '    "Gzip" { New-Object ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3lzdGVtLklPLkNvbXByZXNzaW9uLkd6aXBTdHJlYW0="))) ${21}, (${13}::${10}) }' + $n
        $l += '    "Deflate" { New-Object ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3lzdGVtLklPLkNvbXByZXNzaW9uLkRlZmxhdGVTdHJlYW0="))) ${21}, (${13}::${10}) }' + $n
        $l += '    "ZLib" { New-Object (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3lzdGVtLklPLkNvbXByZXNzaW9uLlpMaWJTdHJlYW0=")))) ${21}, (${13}::${10}) }' + $n
        $l += '    Default { throw ([System.Text.Encoding]::UTF8.GetString([convert]::FromBase64String("RmFpbGVkIHRvIERlQ29tcHJlc3MgQnl0ZXMuIENvdWxkIE5vdCByZXNvbHZlIENvbXByZXNzaW9uIQ=="))) }' + $n
        $l += '}' + $n
        $s += $l -join ''; $l = @()
        $l += '${15} = & ([scriptblock]::Create([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W1N5c3RlbS5JTy5NZW1vcnlTdHJlYW1dOjpOZXcoKQ=="))))' + $n
        $l += '[void]${14}.CopyTo(${15}); ${14}.Close(); ${14}.Dispose(); ${21}.Close();' + $n
        $l += '[byte[]]${12} = ${15}.ToArray(); ${15}.Close();' + $n
        $l += 'Set-Variable -Name {20} -Scope Local -Visibility Private -Option Private -Value (& ([scriptblock]::Create([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W1N5c3RlbS5TZWN1cml0eS5DcnlwdG9ncmFwaHkuQWVzQ3J5cHRvU2VydmljZVByb3ZpZGVyXTo6bmV3KCk=")))));' + $n
        $l += '${18} = & ([scriptblock]::Create([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W1N5c3RlbS5TZWN1cml0eS5DcnlwdG9ncmFwaHkuQ2lwaGVyTW9kZV06OkNCQw=="))))' + $n
        $l += '${17} = & ([scriptblock]::Create([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W1N5c3RlbS5TZWN1cml0eS5DcnlwdG9ncmFwaHkuUGFkZGluZ01vZGVdOjpQS0NTNw=="))))' + $n
        $l += '${16} = & ([scriptblock]::Create([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W1N5c3RlbS5TZWN1cml0eS5DcnlwdG9ncmFwaHkuSGFzaEFsZ29yaXRobU5hbWVdOjpTSEEx"))))' + $n
        $l += '${8} = & ([scriptblock]::Create([System.Text.Encoding]::UTF8.GetString([convert]::FromBase64String("W1N5c3RlbS5TZWN1cml0eS5DcnlwdG9ncmFwaHkuUmZjMjg5OERlcml2ZUJ5dGVzXTo6bmV3")) + "(`"{1}`", [Convert]::FromBase64String(`"{24}`"), 10000, `"${16}`")"))' + $n
        $l += '${20}.KeySize = ${9};' + $n
        $l += '${20}.Padding = ${17}' + $n
        $l += '${20}.Mode = ${18}' + $n
        $l += '${20}.Key = ${8}.GetBytes(${9} / 8)' + $n
        $l += '${20}.IV = ${12}[0..15];' + $n
        $l += 'Set-Variable -Name {11} -Scope Local -Visibility Private -Option Private -Value $(${20}.CreateDecryptor().TransformFinalBlock(${12}, 16, ${12}.Length - 16))' + $n
        $l += '${20}.Clear(); ${20}.Dispose();' + $n
        $l += '${7} = [System.Text.Encoding]::UTF8.GetString(${11});' + $n
        if ([IO.FileInfo]::new($filePath).Extension -in ('.ps1', '.psm1', '.cmd', '.bat', '.sh')) {
            # Why only these Extension? Well I mainly wrote this crypter to hide scripts from WDefender.
            $l += '& ([scriptblock]::Create("${7}"));' + $n
        } else {
            $l += 'echo ${7}' + $n
        }
        $s += $l -join ''
        $s = $s.Replace("{0}", $base64XOREncPayload)
        $s = $s.Replace("{1}", $base64key)
        $s = $s.Replace("{25}", $xkey64)
        $s = $s.Replace("{23}", $Comprssnm)
        $s = $s.Replace("{24}", $salt)
        2..21 | ForEach-Object { $s = $s.Replace("{$_}", [FileCryptr]::RNdvar()) }
        return $s
    }
    static [string] Obfuscate([string]$filePath) {
        return [FileCryptr]::Obfuscate($filePath, $filePath)
    }
    static [string] Obfuscate([string]$filePath, [string]$OutputFile) {
        if (![FileCryptr]::IsTextFile($filePath)) {
            throw [Exception]::new("Error: $filePath is not a text file.")
        }
        $stub = [FileCryptr]::GetStub($filePath)
        $OutputFile = [CryptoBase]::GetUnResolvedPath($OutputFile)
        return (Set-Content -Path $OutputFile -Value $stub -Encoding UTF8 -PassThru)
    }
    static [string] Deobfuscate([string]$base64EncodedString) {
        throw 'Idk! Just run the damn file; (and hope its not a virus).'
    }
    static [bool] IsTextFile([string]$filePath) {
        @(# Default file extensions to speed up the detection process.
            ".txt", ".log", ".ini", ".env", ".cfg", ".conf", ".cnf",
            ".properties", ".props", ".prop", ".rtf", ".csv", ".jsx",
            ".tsv", ".ssv", ".dsv", ".csv", ".tab", ".vcf",
            ".js", ".json", ".py", ".pl", ".pm", ".t", ".php",
            ".php3", ".php4", ".php5", ".phtml", ".inc", ".phps",
            ".asp", ".aspx", ".asax", ".ascx", ".ashx", ".asmx",
            ".css", ".html", ".htm", ".shtml", ".xhtml", ".md",
            ".markdown", ".mdown", ".mkd", ".rst", ".xml", ".yml",
            ".ps1", ".psm1", ".psd1", ".pssc", ".cdxml", ".clixml",
            ".xaml", ".toml", ".resx", ".restext", ".unity", ".sln", ".csproj",
            ".vbproj", ".vcxproj", ".vcxproj.filters", ".proj", ".projitems",
            ".shproj", ".scc", ".suo", ".sln", ".cs", ".vb", ".vc", ".vcx",
            ".cxx", ".cpp", ".h", ".hpp", ".hh", ".hxx", ".inc", ".inl",
            ".ipp", ".tcc", ".tpp", ".cc", ".c", ".mm", ".m", ".s",
            ".sx", ".S", ".rs", ".rlib", ".def", ".odl", ".idl",
            ".odl", ".hdl", ".vhd", ".vhdl", ".ucf", ".qsf",
            ".tcl", ".tk", ".itk", ".tkm", ".blt", ".tcl"
        ) | ForEach-Object { [FileCryptr]::CommonFileExtensions.Add($_, '') }
        if ([FileCryptr]::CommonFileExtensions.ContainsKey([IO.Path]::GetExtension($filePath))) {
            return $true;
        }
        try {
            $null = [IO.File]::ReadAllText($filePath);
            return $true;
        } catch [Exception] {
            return $false;
        }
    }
}
#endregion FileCrypter

#region    Custom_Cryptography_Wrappers
class k3y {
    [ValidateNotNullOrEmpty()][CredManaged]$User;
    [ValidateNotNullOrEmpty()][Expiration]$Expiration;
    [ValidateNotNullOrEmpty()][securestring]hidden $UID;
    [ValidateNotNullOrEmpty()][int]hidden $_PID = [System.Environment]::ProcessId;
    [ValidateNotNullOrEmpty()][keyStoreMode]hidden $Storage = [KeyStoreMode]::Securestring;
    [ValidateNotNullOrEmpty()][version]hidden $version = [version]::new("1.0.0.1");
    [ValidateNotNullOrEmpty()][byte[]] static hidden $Salt = [System.Text.Encoding]::UTF7.GetBytes('hR#ho"rK6FMu mdZFXp}JMY\?NC]9(.:6;>oB5U>.GkYC-JD;@;XRgXBgsEi|%MqU>_+w/RpUJ}Kt.>vWr[WZ;[e8GM@P@YKuT947Z-]ho>E2"c6H%_L2A:O5:E)6Fv^uVE; aN\4t\|(*;rPRndSOS(7& xXLRKX)VL\/+ZB4q.iY { %Ko^<!sW9n@r8ihj*=T $+Cca-Nvv#JnaZh'); #this is the default salt, change it if you want.

    k3y([string]$Passw0rd) {
        $Password = [xconvert]::TosecureString($Passw0rd);
        $this.User = [CredManaged]::new([pscredential]::new($(whoami), $Password));
        $this.Expiration = [expiration]::new(0, 1);
        $this.SetUID(); $this.PsObject.Methods.Remove('SetUID');
    }
    k3y([securestring]$Password) {
        $this.User = [CredManaged]::new([pscredential]::new($(whoami), $Password));
        $this.Expiration = [expiration]::new(0, 1);
        $this.SetUID(); $this.PsObject.Methods.Remove('SetUID');
    }
    k3y([CredManaged]$User, [Datetime]$Expiration) {
        $this.User = $User
        $this.Expiration = [expiration]::new($Expiration);
        $this.SetUID(); $this.PsObject.Methods.Remove('SetUID');
    }
    k3y([securestring]$Password, [Datetime]$Expiration) {
        $this.User = [CredManaged]::new([pscredential]::new($(whoami), $Password));
        $this.Expiration = [Expiration]::new($Expiration);
        $this.SetUID(); $this.PsObject.Methods.Remove('SetUID');
    }
    k3y([securestring]$Password, [byte[]]$salt, [Datetime]$Expiration) {
        $this.User = [CredManaged]::new([pscredential]::new($(whoami), $Password));
        [k3y]::Salt = $salt; $this.Expiration = [Expiration]::new($Expiration);
        $this.SetUID(); $this.PsObject.Methods.Remove('SetUID');
    }
    k3y([pscredential]$User, [Datetime]$Expiration) {
        ($this.User, $this.Expiration) = ([CredManaged]::new($User), [Expiration]::new($Expiration));
        $this.SetUID(); $this.PsObject.Methods.Remove('SetUID');
    }
    k3y([string]$UserName, [securestring]$Password) {
        $this.User = [CredManaged]::new([pscredential]::new($UserName, $Password));
        $this.SetUID(); $this.PsObject.Methods.Remove('SetUID');
    }
    k3y([string]$UserName, [securestring]$Password, [Datetime]$Expiration) {
        ($this.User, $this.Expiration) = ([CredManaged]::new([pscredential]::new($UserName, $Password)), [Expiration]::new($Expiration));
        $this.SetUID(); $this.PsObject.Methods.Remove('SetUID');
    }
    [void]hidden SetUID() {
        $assocdataProps = ($this | Get-Member -Force | Where-Object { $_.MemberType -eq "Property" -and $_.Name -notin ('UID', 'Salt') }) | Select-Object -ExpandProperty Name
        $s = [string]::Empty
        $s += '"' + ($assocdataProps -join '","') + '"' + "`n"; $vals = $assocdataProps | ForEach-Object { $this.$_.Tostring() }; $fs = '"{' + ((0 .. ($vals.Count - 1)) -join '}","{') + '}"';
        $s += $fs -f $vals; $O = ConvertFrom-Csv $s; $O.User = $this.User
        $op = ($o.User | Get-Member -Force | Where-Object { $_.MemberType -eq "Property" }) | Select-Object -ExpandProperty Name
        $st = ("[PSCustomObject]@{`n " + $($op | ForEach-Object { "$_ = '$($O.User.$_)'`n" }) + '}').Replace(" Password = 'System.Security.SecureString'", " password = '$([xconvert]::Tostring($O.User.password))'")
        $O.User = [convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($st)); $s = $(ConvertTo-Csv $O).Split('"Expiration","Storage","User","version","_PID"', [System.StringSplitOptions]::TrimEntries);
        $dt = [System.Text.Encoding]::UTF8.GetBytes($s)
        $ps = $null; Set-Variable -Name ps -Scope Local -Visibility Private -Option Private -Value $(
            [xconvert]::ToSecurestring(
                [convert]::ToBase64String(
                    [System.Security.Cryptography.Rfc2898DeriveBytes]::new([xconvert]::ToString($this.User.Password), [k3y]::Salt, 10000, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes(256 / 8)
                )
            )
        );
        Write-Verbose "[+] Res-password $([xconvert]::Tostring($ps))"
        Write-Verbose "[+] Res-password Length: $([convert]::FromBase64String([xconvert]::Tostring($ps)).Length)"
        & ([scriptblock]::Create("`$this.psobject.Properties.Add([psscriptproperty]::new('UID', { ConvertTo-SecureString -AsPlainText -String '$([convert]::ToBase64String([Shuffl3r]::Combine([AesGcm]::Encrypt($dt, $ps, [k3y]::Salt), [convert]::FromBase64String([xconvert]::Tostring($ps)), [CryptoBase]::GetUniqueMachineId())))' -Force }))"));
    }
    [psobject] GetInfo([string]$passw0rd) {
        return $this.GetInfo([xconvert]::TosecureString($passw0rd))
    }
    [psobject] GetInfo([securestring]$password) {
        return $this.GetInfo([xconvert]::ToString($this.UID), $password, [k3y]::Salt)
    }
    [psobject] GetInfo([string]$UID, [securestring]$password, [byte[]]$salt) {
        return [System.Text.Encoding]::UTF8.GetString([AesGcm]::Decrypt([System.Convert]::FromBase64String($UID), $this.ResolvePassword($Password), $salt)) | ConvertFrom-Csv
    }
    [bool] IsValid() { return $this.IsValid($false) }
    [bool] IsValid([bool]$ThrowOnFailure) {
        # Verifies if The password has already been set.
        $IsValid = $false; [bool]$SetValu3Exception = $false; [securestring]$kUID = $this.UID; $InnerException = [System.Exception]::new()
        try {
            $this.UID = [securestring]::new()
        } catch [System.Management.Automation.SetValueException] {
            $SetValu3Exception = $true
        } catch {
            $InnerException = $_.Exception
        } finally {
            if ($SetValu3Exception) {
                $IsValid = $true
            } else {
                $this.UID = $kUID
            }
        }
        if ($ThrowOnFailure -and !$IsValid) {
            throw [System.InvalidOperationException]::new("The key Hasn't been used!`nEncrypt Something with this K3Y at least once or Manually Call SetK3YUID method.", $InnerException)
        }
        return $IsValid
    }
    # [securestring] hidden ResolvePassword([securestring]$Password) {
    #     if (!$this.IsHashed()) {
    #         $hashSTR = [string]::Empty; Set-Variable -Name hashSTR -Scope local -Visibility Private -Option Private -Value $([string][xconvert]::ToHexString([HKDF2]::GetToken($password)));
    #         & ([scriptblock]::Create("`$this.User.psobject.Properties.Add([psscriptproperty]::new('Password', { ConvertTo-SecureString -AsPlainText -String '$hashSTR' -Force }))"));
    #     }
    #     $SecHash = $this.User.Password;
    #     return [ArgonCage]::Resolve($Password, $SecHash)
    # }
    [bool]IsHashed() {
        return $this.IsHashed($false);
    }
    static [bool] IsHashed([K3Y]$k3y) {
        $ThrowOnFailure = $false
        return [K3Y]::IsHashed($k3y, $ThrowOnFailure);
    }
    [bool]IsHashed([bool]$ThrowOnFailure) {
        return [K3Y]::IsHashed($this, $ThrowOnFailure);
    }
    static [bool] IsHashed([K3Y]$k3y, [bool]$ThrowOnFailure) {
        # Verifies if The password (the one only you know) has already been hashed
        [bool]$SetValu3Exception = $false; [securestring]$p = $k3y.User.Password; $InnerException = [System.Exception]::new()
        [bool]$IsHashed = [regex]::IsMatch([string][xconvert]::ToString($k3y.User.Password), "^[A-Fa-f0-9]{72}$");
        try {
            $k3y.User.Password = [securestring]::new() # This will not work if the hash has been set
        } catch [System.Management.Automation.SetValueException] {
            $SetValu3Exception = $true
        } catch {
            $InnerException = $_.Exception
        } finally {
            $IsHashed = $IsHashed -and $SetValu3Exception
        }
        if (!$SetValu3Exception) {
            $k3y.User.Password = $p
        }
        if ($ThrowOnFailure -and !$IsHashed) {
            throw [System.InvalidOperationException]::new('Operation is not valid due to the current state of the object. No password Hash found.', $InnerException)
        }
        return $IsHashed
    }
    [void]Export([string]$FilePath) {
        $this.Export($FilePath, $false);
    }
    [void]Export([string]$FilePath, [bool]$encrypt) {
        $ThrowOnFailure = $true; [void]$this.IsValid($ThrowOnFailure)
        $FilePath = [CryptoBase]::GetUnResolvedPath($FilePath)
        if (![IO.File]::Exists($FilePath)) { New-Item -Path $FilePath -ItemType File | Out-Null }
        Set-Content -Path $FilePath -Value ($this.Tostring()) -Encoding UTF8 -NoNewline;
        if ($encrypt) { Write-Verbose "[i] Export encrypted key to $FilePath"; [Filecryptr]::Encrypt($FilePath) };
    }
    static [K3Y] Create([System.IO.FileInfo]$File) {
        $tmp = [IO.Path]::GetTempFileName()
        [Filecryptr]::Decrypt($File.FullName, $tmp)
        $_id = Get-Content $tmp; Remove-Item $tmp
        return [K3Y]::Create($_id)
    }
    static [K3Y] Create([string]$uid) {
        ($idb, $pb) = [Shuffl3r]::Split([convert]::FromBase64String($uid), [CryptoBase]::GetUniqueMachineId(), 32)
        $dec = [AesGcm]::Decrypt($idb, [xconvert]::Tosecurestring([convert]::ToBase64String($pb)), [k3y]::Salt)
        $Obj = ConvertFrom-Csv $('"Expiration","Storage","User","version","_PID"' + "`n" + ([System.Text.Encoding]::UTF8.GetString($dec).Trim()))
        $Obj.User = & ([scriptblock]::Create([System.Text.Encoding]::UTF8.GetString([convert]::FromBase64String($Obj.User)))); $Obj.user.password = [xconvert]::ToSecurestring($Obj.user.password)
        $Obj.User = & { $usr = [credmanaged]::new(); $usr.psobject.properties.name | ForEach-Object { $usr.$_ = $Obj.User.$_ }; $usr }
        Write-Verbose "[i] Create new k3y object ..."
        $K3Y = [K3Y]::new($Obj.User, [xconvert]::ToDateTime($Obj.Expiration))
        $K3Y._PID = $Obj._PID; $K3Y.version = [version]$Obj.version; $K3Y.Storage = [keyStoreMode]$Obj.Storage
        return $K3Y
    }

    [K3Y]Import([string]$uid) {
        $K3Y = $null; Set-Variable -Name K3Y -Scope Local -Visibility Private -Option Private -Value ([K3Y]::Create($uid));
        try {
            $this | Get-Member -Force | Where-Object { $_.Membertype -eq 'property' } | ForEach-Object { $this.$($_.Name) = $K3Y.$($_.Name) };
        } catch [System.Management.Automation.SetValueException] {
            throw [System.InvalidOperationException]::New('You can only Import One Key.')
        }
        $Key_UID = [string]::Empty; $hashSTR = [string]::Empty; Set-Variable -Name hashSTR -Scope local -Visibility Private -Option Private -Value $([string][xconvert]::ToString($this.User.Password));
        if ([regex]::IsMatch($hashSTR, "^[A-Fa-f0-9]{72}$")) {
            & ([scriptblock]::Create("`$this.User.psobject.Properties.Add([psscriptproperty]::new('Password', { ConvertTo-SecureString -AsPlainText -String '$hashSTR' -Force }))"))
        }
        Set-Variable -Name Key_UID -Scope local -Visibility Private -Option Private -Value $([string][xconvert]::Tostring($K3Y.UID))
        & ([scriptblock]::Create("`$this.psobject.Properties.Add([psscriptproperty]::new('UID', { ConvertTo-SecureString -AsPlainText -String '$Key_UID' -Force }))"));
        return $K3Y
    }
    [void]SetPassword([securestring]$password) {}
    [void]SaveToVault() {
        $_Hash = [xconvert]::ToString($this.User.Password);
        if ([string]::IsNullOrWhiteSpace($_Hash)) {
            throw 'Please set a Password first.'
        }
        $RName = 'PNKey' + $_Hash
        $_Cred = New-Object -TypeName CredManaged -ArgumentList ($RName, $this.User.UserName, [xconvert]::Tostring($this))
        Write-Verbose "[i] Saving $RName To Vault .."
        # Note: Make sure file size does not exceed the limit allowed and cannot be saved.
        $_Cred.SaveToVault()
    }
    [string]Tostring() {
        return [xconvert]::Tostring($this.UID)
    }
}
#region    _The_K3Y
# The K3Y 'UID' [ see .SetK3YUID() method ] is a fancy way of storing the version, user/owner credentials, Compression alg~tm used and Other Info
# about the most recent use and the person who used it; so it can be analyzed later to verify some rules before being used again. This enables the creation of complex expiring encryptions.
# It does not store or use the actual password; instead, it employs its own 'KDF' and retains a 'SHA1' hash string as securestring objects. idk if this is the most secure way to use but it should work.

# [byte[]]Encrypt([byte[]]$BytesToEncrypt, [securestring]$Password, [byte[]]$salt, [string]$Compression, [Datetime]$Expiration, [CryptoAlgorithm]$Algorithm) {
#     $Password = [securestring]$this.ResolvePassword($Password); $this.SetK3YUID($Password, $Expiration, $Compression, $this._PID)
#     # $CryptoServiceProvider = [CustomCryptoServiceProvider]::new($bytesToEncrypt, $Password, $salt, [CryptoAlgorithm]$Algorithm)
#     # $encryptor = $CryptoServiceProvider.CreateEncryptor(); $result = $encryptor.encrypt();
#     return [AesGCM]::Encrypt($bytesToEncrypt, $Password, $salt);
# }

# [byte[]]Decrypt([byte[]]$BytesToDecrypt, [securestring]$Password, [byte[]]$salt) {
#     $Password = [securestring]$this.ResolvePassword($Password); # (Get The real Password)
#     ($IsValid, $Compression) = [k3Y]::AnalyseK3YUID($this, $Password, $false)[0, 2];
#     if (-not $IsValid) { throw [System.Management.Automation.PSInvalidOperationException]::new("The Operation is not valid due to Expired K3Y.") };
#     if ($Compression.Equals('')) { throw [System.Management.Automation.PSInvalidOperationException]::new("The Operation is not valid due to Invalid Compression.", [System.ArgumentNullException]::new('Compression')) };
#     # todo: Chose the algorithm
#     # if alg -eq RSA then we RSA+AES hybrid
#     return [AesGCM]::Decrypt($bytesToDecrypt, $Password, $salt);
#     # $Compression
# }

class KeyManager {
    KeyManager() {}
}
#endregion _The_K3Y

#region Custom_Encryptor
# .DESCRIPTION
#     A custom encryptor to make it easy to combine several algorithms.
# .EXAMPLE
#     $encryptor = [Encryptor]::new($bytesToEncrypt, [securestring]$Password, [byte]$salt, [CryptoAlgorithm]$Algorithm);
#     $encrypted = $encryptor.encrypt();
class Encryptor {
    Encryptor([byte[]]$BytesToEncrypt, [securestring]$Password, [byte[]]$salt, [CryptoAlgorithm]$Algorithm) {
        $this.bytes = $bytesToEncrypt
        $this.Password = $Password
        $this.salt = $salt
        $this.setAlgorithm($Algorithm)
    }
    Encryptor([byte[]]$bytesToEncrypt, [K3Y]$key) {
        $this.bytes = $bytesToEncrypt
        # Dynamicaly create methods using [PsScriptMethod] : https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.psscriptmethod
        # $key.PSObject.Methods.Add(
        #     [psscriptmethod]::new(
        #         'MethodName', {
        #             param()
        #             return 'stuff'
        #         }
        #     )
        # )
    }
    [void]setAlgorithm([string]$Algorithm) {}
    [void]setAlgorithm([CryptoAlgorithm]$Algorithm) {}
    [byte[]] Encrypt() {
        $Encrypted = $null
        switch ([string]$this.Algorithm) {
            'AesGCM' {
                # {aes aesgcm} encrypt using: $this.bytes; $this.Password; $this.salt; $this.Algorithm
                $Encrypted = 'bytes encrypted Using aes aesgcm'
            }
            'ChaCha20' {
                $Encrypted = 'bytes encrypted Using ChaCha20 + SHA256'
            }
            'RsaAesHMAC' {
                # {aes + rsa} encrypt using: $this.bytes; $this.Password; $this.salt; $this.Algorithm
                #
                # Generate a random AES key and initialization vector
                # $aesKey = New-Object Byte[] 32
                # [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($aesKey)
                # $aesIV = New-Object Byte[] 16
                # [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($aesIV)

                # # Create an RSA key for encryption and decryption
                # $rsa = New-Object Security.Cryptography.RSACryptoServiceProvider
                # $rsaPublicKey = $rsa.ExportParameters(false)
                # $rsaPrivateKey = $rsa.ExportParameters(true)

                # # Encrypt the AES key using RSA encryption
                # $encryptedAesKey = $rsa.Encrypt($aesKey, $false)

                # # Create a HMACSHA256 object and compute the HMAC of the original data
                # $hmac = New-Object System.Security.Cryptography.HMACSHA256
                # $hmac.Key = $aesKey
                # $dataHMAC = $hmac.ComputeHash($bytes)

                # # Encrypt the data using AES encryption
                # $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
                # $aes.Key = $aesKey
                # $aes.IV = $aesIV
                # $encryptor = $aes.CreateEncryptor()
                # $encryptedBytes = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length)

                # # Combine the encrypted data, HMAC, and encrypted AES key into a single encrypted payload
                # $encryptedPayload = [Byte[]]::new($encryptedBytes.Length + $dataHMAC.Length + $encryptedAesKey.Length)
                # $encryptedBytes.CopyTo($encryptedPayload, 0)
                # $dataHMAC.CopyTo($encryptedPayload, $encryptedBytes.Length)
                # $encryptedAesKey.CopyTo($encryptedPayload, $encryptedBytes.Length + $dataHMAC.Length)
                # return $encryptedPayload
                $Encrypted = 'bytes encrypted Using RsaAesHMAC'
            }
            'RsaECDSA' {
                # RSA-ECDSA:  RSA and ECDSA (Elliptic Curve Digital Signature Algorithm) are public-key cryptography algorithms that are often used together. RSA can be used for encrypting data, while ECDSA can be used for digital signatures, providing both confidentiality and authenticity for the data.
                # {RSA + ECDSA} encrypt using: $this.bytes; $this.Password; $this.salt; $this.Algorithm
                # Create an RSA key for encryption and decryption
                # $rsa = New-Object Security.Cryptography.RSACryptoServiceProvider
                # $rsaPublicKey = $rsa.ExportParameters(false)
                # $rsaPrivateKey = $rsa.ExportParameters(true)

                # # Create an ECDSA key for signing and verifying
                # $ecdsa = New-Object Security.Cryptography.ECDsaCng
                # $ecdsaPublicKey = $ecdsa.Key.Export(Security.Cryptography.CngKeyBlobFormat::GenericPublicBlob)
                # $ecdsaPrivateKey = $ecdsa.Key.Export(Security.Cryptography.CngKeyBlobFormat::GenericPrivateBlob)

                # # Encrypt the data using RSA encryption
                # $encryptedBytes = $rsa.Encrypt($bytes, $false)

                # # Sign the encrypted data using ECDSA
                # $signature = $ecdsa.SignData($encryptedBytes)

                # # Combine the encrypted data and signature into a single encrypted payload
                # $encryptedPayload = [Byte[]]::new($encryptedBytes.Length + $signature.Length)
                # $encryptedBytes.CopyTo($encryptedPayload, 0)
                # $signature.CopyTo($encryptedPayload, $encryptedBytes.Length)

                $Encrypted = 'bytes encrypted Using RSA-ECDSA'
            }
            'RsaOAEP' {
                # Generate a new RSA key pair
                # $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
                # $publicKey = $rsa.ExportParameters(False)
                # $privateKey = $rsa.ExportParameters(True)
                # # Encrypt the data using RSA-OAEP
                # $rsaEncryptor = New-Object System.Security.Cryptography.RSAPKCS1KeyExchangeFormatter($publicKey)
                # $encryptedBytes = $rsaEncryptor.Encrypt([System.Text.Encoding]::UTF8.GetBytes("secret data"), "OAEP")
                $Encrypted = 'bytes encrypted Using RsaOAEP'
            }
            Default {
                throw "Please Provide a valid algorithm"
            }
        }
        return $Encrypted
    }
}
# .DESCRIPTION
#     A custom decryptor.
# .EXAMPLE
#     $decryptor = [Decryptor]::new($bytesToDecrypt, [securestring]$Password, [byte]$salt, [CryptoAlgorithm]$Algorithm);
#     $decrypted = $Decryptor.encrypt();
class Decryptor {
    Decryptor([byte[]]$BytesToDecrypt, [securestring]$Password, [byte[]]$salt, [CryptoAlgorithm]$Algorithm) {
        $this.bytes = $bytesToDecrypt
        $this.Password = $Password
        $this.salt = $salt
        $this.setAlgorithm($Algorithm)
    }
    [void]setAlgorithm([string]$Algorithm) {}
    [void]setAlgorithm([CryptoAlgorithm]$Algorithm) {}
    [byte[]]Decrypt() {
        $Decrypted = $null
        switch ([string]$this.Algorithm) {
            'AesGCM' {
                # {aesgcm} decrypt using: $this.bytes; $this.Password; $this.salt; $this.Algorithm
                $Decrypted = 'bytes decrypted Using aesgcm'
            }
            'ChaCha20' {
                $Decrypted = 'bytes decrypted Using ChaCha20 + SHA256'
            }
            'RsaAesHMAC' {
                # {aes + rsa} decrypt using: $this.bytes; $this.Password; $this.salt; $this.Algorithm
                #
                # # Split the encrypted payload into its three components: encrypted data, HMAC, and encrypted AES key
                # $encryptedBytes = $encryptedPayload[0..($encryptedBytes.Length - 1)]
                # $dataHMAC = $encryptedPayload[$encryptedBytes.Length..($encryptedBytes.Length + $dataHMAC.Length - 1)]
                # $encryptedAesKey = $encryptedPayload[($encryptedBytes.Length + $dataHMAC.Length)..($encryptedPayload.Length - 1)]

                # # Decrypt the AES key using RSA decryption
                # $aesKey = $rsa.Decrypt($encryptedAesKey, $false)

                # # Verify the HMAC of the encrypted data
                # $hmac = New-Object System.Security.Cryptography.HMACSHA256
                # $hmac.Key = $aesKey
                # $computedHMAC = $hmac.ComputeHash($encryptedBytes)
                # if ($computedHMAC -ne $dataHMAC)
                # {
                #     throw "HMAC verification failed"
                # }

                # # Decrypt the data using AES encryption
                # $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
                # $aes.Key = $aesKey
                # $aes.IV = $aesIV
                # $decryptor = $aes.CreateDecryptor()
                # $decryptedBytes = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length)
                # return $decryptedBytes
                $Decrypted = 'bytes decrypted Using aes + rsa'
            }
            'RsaECDSA' {
                # {RSA + ECDSA} decrypt using: $this.bytes; $this.Password; $this.salt; $this.Algorithm
                # Decryption process:
                # # Split the encrypted payload into its two components: encrypted data and signature
                # $encryptedBytes = $encryptedPayload[0..($encryptedBytes.Length - 1)]
                # $signature = $encryptedPayload[$encryptedBytes.Length..($encryptedPayload.Length - 1)]

                # # Verify the signature of the encrypted data using ECDSA
                # if (!$ecdsa.VerifyData($encryptedBytes, $signature))
                # {
                #     throw "Signature verification failed"
                # }

                # # Decrypt the data using RSA decryption
                # $decryptedBytes = $rsa.Decrypt($encryptedBytes, $false)

                # # Return the decrypted data
                # return $decryptedBytes
                $Decrypted = 'bytes decrypted Using RsaECDSA'
            }
            'RsaOAEP' {
                # # Decrypt the data using RSA-OAEP
                # $rsaDecryptor = New-Object System.Security.Cryptography.RSACryptoServiceProvider
                # $rsaDecryptor.ImportParameters($privateKey)
                # $decryptedBytes = $rsaDecryptor.Decrypt($encryptedBytes, "OAEP")
                # $decryptedMessage = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
                $Decrypted = 'Bytes decrypted with RSA-OAEP'
                # Write-Output "Decrypted message: $decryptedMessage"
            }
            Default {
                throw "Please Provide a valid CryptoAlgorithm"
            }
        }
        return $Decrypted
    }
}
#endregion Custom_Cryptography_Wrappers

#endregion Helpers

#region    MainClass
# .SYNOPSIS
#   CipherTron Core class (A fancy chatbot, expert on cryptography stuff)
# .DESCRIPTION
#   This is a chatbot like app to use all classes in this file to do what you tell it (cryptography stuff)
#   The bot has 2 modes
#   When there's internet, the bot Gets gpt responses from OpenAI's GPT-3 API
#   When no internet it Uses offline presets from $bot.Presets and try do offline stuff with them.
# .EXAMPLE
#   $bot = [CipherTron]::new()
#   $bot.Chat()
#
#   $bot.ChatLog.ToString()
# .NOTES
#  Todo: Each user will use his own Azure OpenAI key
#    ie: https://4sysops.com/archives/use-powershell-to-deploy-and-access-gpt-4o-via-azure-openai-service/
class CipherTron : CryptoBase {
    [ValidateNotNullOrEmpty()][RecordTbl] $Config
    [ValidateNotNullOrEmpty()][version] $Version
    [ValidateNotNullOrEmpty()][chatPresets] $Presets
    static [ValidateNotNullOrEmpty()][ChatSession] $ChatSession
    static hidden [ValidateNotNull()][SessionTmp] $Tmp
    static hidden [ValidateNotNullOrEmpty()][uri] $ConfigUri
    static hidden [bool] $useverbose = [bool]$((Get-Variable verbosePreference -ValueOnly) -eq "continue")
    static [System.Collections.ObjectModel.Collection[Byte[]]] $banners = @()

    CipherTron() {
        $this.Version = [CipherTron]::GetVersion()
        [CipherTron]::ChatSession = [ChatSession]::new(); $this.SetTMPvariables(); $this.SaveConfigs(); $this.ImportConfigs()
        $this.PsObject.properties.add([psscriptproperty]::new('ConfigPath', [scriptblock]::Create({ return $this.Config.File })))
        $this.PsObject.properties.add([psscriptproperty]::new('DataPath', [scriptblock]::Create({ return [CipherTron]::Get_dataPath() })))
        $this.PsObject.properties.add([psscriptproperty]::new('User', [scriptblock]::Create({ return [CipherTron]::ChatSession.User })))
        $this.PsObject.properties.add([psscriptproperty]::new('ChatUid', [scriptblock]::Create({ return [CipherTron]::ChatSession.ChatUid.ToString() })))
        $this.PsObject.properties.add([psscriptproperty]::new('ChatLog', [scriptblock]::Create({ return [CipherTron]::ChatSession.ChatLog })))
        $this.PsObject.properties.add([psscriptproperty]::new('Sessions', [scriptblock]::Create({ return @(Get-ChildItem ([ChatSessionManager]::GetSessionFolder()) -Filter "*.chat" | ForEach-Object { [ChatSession]::New($_.FullName) }) })))
        $this.PsObject.properties.add([psscriptproperty]::new('IsOffline', [scriptblock]::Create({ [NetworkManager]::caller = '[CipherTron]'; return ![NetworkManager]::TestConnection('github.com') })))
    }

    [void] Chat() {
        try {
            $(Get-Variable executionContext).Value.Host.UI.RawUI.WindowTitle = "Ciphertron";
            $this.ShowMenu()
            # $authenticated = $false
            # while (-not $authenticated) {
            #     $username = $this.Presets.Prompt("Please enter your username:")
            #     $password = $this.Presets.Prompt("Please enter your password:", $true)
            #     $authenticated = $this.Login($username, $password)

            #     if (-not $authenticated) {
            #         [void][cli]::Write("Invalid username or password. Please try again.", [System.ConsoleColor]::Red, $false, $false)
            #     }
            # }
            if ([CipherTron]::ChatSession.ChatLog.Messages.Count -le 1) {
                $this.SetStage();
            } else {
                $finish_reason = $this::Tmp.vars.finish_reason
                # Do chat resume stuff here. (re-send previous failed queries ...)
                Write-Debug "Resuming Chat ... Finish_reason: $finish_reason" -Debug
                if ([CipherTron]::ChatSession.ChatLog.count.Equals(1)) { [CipherTron]::ChatSession.ChatLog.clear(); $this.SetStage() }
                switch -Wildcard ($finish_reason) {
                    'No_Internet' {
                        if (!$this.IsOffline) { [void][cli]::Write("Internet is back!") }
                    }
                    'Failed_HttpRequest' {  }
                    'Empty_API_key' {
                        $this.SetAPIkey();
                        Write-Debug 'Finished Resume -SetApiKey' -Debug
                        break
                    }
                    "Ctrl+*" {
                        Write-Debug 'Finished Resume Ctrl+' -Debug
                        break
                    }
                    Default {
                        Write-Debug 'Finished Resume ???' -Debug
                    }
                }
            }
            $this::Tmp.vars.set("ChatIsOngoing", $true)
            while ($this::Tmp.vars.ChatIsOngoing) { $this.ReadInput(); $this.GetResponse(); $this.RecordChat() }
        } catch {
            $this::Tmp.vars.Set("ExitCode", 1)
            [void][cli]::Write("     $_", [System.ConsoleColor]::Red, $false, $false)
        } finally {
            if ($this::Tmp.vars.finish_reason -in $this.Config.ERROR_NAMES) {
                $this::Tmp.vars.Set("ExitCode", 1)
            } else {
                $this::Tmp.vars.Set("ExitCode", 0)
            }
        }
    }
    [void] RegisterUser() {
        # TODO: FINSISH this .. I'm tir3d!
        # store the encrypted(user+ hashedPassword) s in a file. ie:
        # user1:HashedPassword1 -encrypt-> 3dsf#s3s#$3!@dd*34d@dssxb
        # user2:HashedPassword2 -encrypt-> dds#$3!@dssd*sf#s343dfdsf
    }
    [bool] Login([string]$UserName, [securestring]$Password) {
        # This method authenticates the user by verifying the supplied username and password.
        # Todo: replace this with a working authentication mechanism.
        [ValidateNotNullOrEmpty()][string]$username = $username
        [ValidateNotNullOrEmpty()][securestring]$password = $password
        $valid_username = "example_user"
        $valid_password = "example_password"
        if ($username -eq $valid_username -and $password -eq $valid_password) {
            return $true
        } else {
            return $false
        }
    }
    static [void] LoadUsers([string]$UserFile) {
        [ValidateNotNullOrEmpty()][string]$UserFile = $UserFile
        # Reads the user file and loads the usernames and hashed passwords into a hashtable.
        if (Test-Path $UserFile) {
            $lines = Get-Content $UserFile
            foreach ($line in $lines) {
                $parts = $line.Split(":")
                $username = $parts[0]
                $password = $parts[1]
                [CipherTron]::Tmp.vars.Users[$username] = $password
            }
        }
    }
    static [void] RegisterUser([string]$username, [securestring]$password) {
        [ValidateNotNullOrEmpty()][string]$username = $username
        [ValidateNotNullOrEmpty()][securestring]$password = $password
        # Registers a new user with the specified username and password.
        # Hashes the password and stores it in the user file.
        $UserFile = ''
        $hashedPassword = $password | ConvertFrom-SecureString
        $line = "{0}:{1}" -f $username, $hashedPassword
        Add-Content $UserFile $line
        [CipherTron]::Tmp.vars.Users[$username] = $hashedPassword
    }
    hidden [void] ReadInput() {
        $npt = [string]::Empty; $OgctrInput = [System.Console]::TreatControlCAsInput
        [void][Console]::WriteLine(); if (![console]::KeyAvailable) { [System.Console]::TreatControlCAsInput = $true } #Treat Ctrl key as normal Input
        while ([string]::IsNullOrWhiteSpace($npt) -and [CipherTron]::Tmp.vars.ChatIsOngoing) {
            [void][cli]::Write($this.Config.emojis.user, [string]::Empty, 1, 100, [ConsoleColor]::Green, $false, $false);
            $key = [System.Console]::ReadKey($false)
            if (($key.modifiers -band [consolemodifiers]::Control) -and ($key.key -eq 'q' -or $key.key -eq 'c')) {
                Write-Debug "$(Get-Date -f 'yyyyMMdd HH:mm:ss') Closed by user exit command`n" -Debug
                [CipherTron]::Tmp.vars.Set('Finish_reason', "Ctrl+$($key.key)")
                [System.Console]::TreatControlCAsInput = $OgctrInput
                [CipherTron]::Tmp.vars.Set('ChatIsOngoing', $false)
                $npt = [string]::Empty
            } else {
                [console]::CancelKeyPress
                $npt = [string]$key.KeyChar + [System.Console]::ReadLine()
            }
        }
        [System.Console]::TreatControlCAsInput = $OgctrInput
        [CipherTron]::Tmp.vars.Set('Query', $npt);
    }
    hidden [void] RecordChat() {
        $RecdOfflnAns = $this::Tmp.vars.Response.Equals($this.Config.OfflineNoAns) -and $this.Config.LogOfflineErr
        $NonEmptyChat = !([string]::IsNullOrEmpty($this::Tmp.vars.Query) -and [string]::IsNullOrEmpty($this::Tmp.vars.Response))
        $ShouldRecord = $RecdOfflnAns -or $NonEmptyChat
        if ($ShouldRecord) { [CipherTron]::ChatSession.ChatLog.Add([ChatObject]::new($this::Tmp.vars.Query, $this::Tmp.vars.Response)) }
        $this::Tmp.vars.Set('Query', ''); $this::Tmp.vars.Set('Response', '')
    }
    hidden [void] GetResponse() {
        $r = [string]::Empty
        if ([CipherTron]::Tmp.vars.ChatIsOngoing -and ![string]::IsNullOrWhiteSpace([CipherTron]::Tmp.vars.Query)) {
            $r = $this.GetResponse([CipherTron]::Tmp.vars.Query); $animate = $r.Length -lt 1000
            if (![string]::IsNullOrWhiteSpace($r)) {
                [void][cli]::Write($r, $animate)
            }
        }
        [CipherTron]::Tmp.vars.Set('Response', $r)
    }
    [string] GetResponse([string]$npt) {
        [ValidateNotNullOrEmpty()][string]$npt = $npt; $rsp = [string]::Empty; $npt = $npt.Tolower()
        $_ln = $this.IsOffline -or [CipherTron]::Tmp.vars.OfflineMode
        $rsp = if ($_ln) {
            $this.GetOfflineResponse($npt)
        } else {
            $this.GetResponse($npt, [gptOptions]::new())
        }
        [CipherTron]::Tmp.vars.Set('OfflineMode', $($rsp -eq $this.Config.OfflineNoAns -or (!$_ln -and [CipherTron]::Tmp.vars.ChatIsOngoing -and [CipherTron]::Tmp.vars.Finish_reason -in ('No_Internet', 'Empty_API_key'))))
        return $rsp
    }
    [string] GetResponse([string]$npt, [gptOptions]$options) {
        [ValidateNotNullOrEmpty()][string]$npt = $npt;
        [ValidateNotNullOrEmpty()][gptOptions]$options = $options; $OpenAIKey = $this.GetAPIkey()
        if ($null -eq $OpenAIKey) {
            if (![CipherTron]::IsInteractive()) { throw 'Please run SetAPIkey() first. Get yours at: https://platform.openai.com/account/api-keys' }
            $this.SetAPIkey(); if ([CipherTron]::Tmp.vars.Finish_reason -eq 'Empty_API_key' -or [CipherTron]::Tmp.vars.OfflineMode) {
                return $this.GetOfflineResponse($npt)
            }
        }
        $prompt = [string]::Empty
        if ([CipherTron]::ChatSession.ChatLog.Messages.Count -gt 0) {
            $prompt = [System.Text.StringBuilder]::new();
            [void]$prompt.AppendLine([CipherTron]::ChatSession.ChatLog.ToString())
            [void]$prompt.AppendLine()
            [void]$prompt.Append($this::Tmp.vars.StopSigns.Sendr)
            [void]$prompt.Append($npt)
            $prompt = $prompt.ToString()
        } else {
            Write-Debug "[SetStage] Getting first Gpt response ..." -Debug
            #ie: this should run only once by setStage() method.
            $prompt = $npt
        }
        Write-Debug @"
$prompt
"@ -Debug
        $body = [Ordered]@{
            model             = $options.model
            prompt            = $prompt
            temperature       = $options.temperature
            max_tokens        = $options.max_tokens
            top_p             = $options.top_p
            frequency_penalty = $options.frequency_penalty
            presence_penalty  = $options.presence_penalty
            stop              = $options.stop
        }
        $body = $body | ConvertTo-Json -Depth 5
        $Rest_Result = $null; $GptResponse = [string]::Empty
        Add-Type -AssemblyName System.Net.Http
        try {
            Write-Debug "Getting Gpt response ..." -Debug
            $http_Client = New-Object System.Net.Http.HttpClient; $http_Client.Timeout = [System.TimeSpan]::new(0, 0, 15); # Set MaxTimout to 15 seconds. The OpenAI API documentation recommends setting a timeout of at least 10 seconds for all API requests.
            $httpRequest = New-Object System.Net.Http.HttpRequestMessage(('Post' -as 'System.Net.Http.HttpMethod'), "https://api.openai.com/v1/completions");
            $httpRequest.Content = New-Object System.Net.Http.StringContent($body, [System.Text.Encoding]::UTF8, "application/json");
            $httpRequest.Headers.Authorization = "Bearer $([xconvert]::Tostring($OpenAIKey))";
            $Rest_Result = ConvertFrom-Json $($http_Client.SendAsync($httpRequest).GetAwaiter().GetResult().Content.ReadAsStringAsync().GetAwaiter().GetResult());
            if ([CipherTron]::Tmp.vars.OfflineMode) { [CipherTron]::Tmp.vars.Set('OfflineMode', $false) }
        } catch [System.Net.Sockets.SocketException] {
            if (![CipherTron]::Tmp.vars.OfflineMode) { [void][cli]::Write("$($_.exception.message)`n", [System.ConsoleColor]::Red) }
            [CipherTron]::Tmp.vars.Set('Finish_reason', 'No_Internet'); [CipherTron]::Tmp.vars.Set('ChatIsOngoing', $false)
        } catch {
            if (![CipherTron]::Tmp.vars.OfflineMode) { [void][cli]::Write("$($_.exception.message)`n", [System.ConsoleColor]::Red) }
            [CipherTron]::Tmp.vars.Set('Finish_reason', 'Failed_HttpRequest'); [CipherTron]::Tmp.vars.Set('ChatIsOngoing', $false);
        } finally {
            if ($null -ne $Rest_Result.choices) {
                [CipherTron]::Tmp.vars.ResponseCount = $Rest_Result.choices.Count
                if ([CipherTron]::Tmp.vars.ResponseCount -gt 0) {
                    Write-Verbose "Got $([CipherTron]::Tmp.vars.ResponseCount) answer(s). Finish_Reason: $($Rest_Result.choices.finish_reason)"
                    $GptResponse = $Rest_Result.choices.text
                }
                [CipherTron]::Tmp.vars.Set('Finish_reason', $Rest_Result.choices.finish_reason)
            }
            if ($null -ne $Rest_Result.error) {
                [void][cli]::Write("$($Rest_Result.error.type.toUpper()). ", [System.ConsoleColor]::Red);
                [void][cli]::Write("$($Rest_Result.error.message)`n", [System.ConsoleColor]::Yellow, $false, $false);
                [CipherTron]::Tmp.vars.Set('Finish_reason', 'Failed_HttpRequest')
                [CipherTron]::Tmp.vars.Set('ChatIsOngoing', $false)
            }
        }
        return $GptResponse
    }
    hidden [string] GetOfflineResponse([string]$query) {
        [ValidateNotNullOrEmpty()][string]$query = $query; if ($null -eq $this::Tmp.vars.Keys) { $this.SetTMPvariables() }; [string]$resp = '';
        if ([CipherTron]::ChatSession.ChatLog.Messages.Count -eq 0 -and $this::Tmp.vars.Query -eq $this.Config.First_Query) { return $this.Config.OfflineHello }
        $resp = $this.Config.OfflineNoAns; trap { $resp = "Error! $_`n$resp" }
        Write-Debug "Checking through presets ..." -Debug
        $botcmd = $this.presets.ToArray() | Where-Object { $_.Keys -eq $query -or $_.values.aliases.aliasnames -contains $query }
        if ($null -ne $botcmd) {
            if (-not $botcmd.Count.Equals(1)) { throw [System.InvalidOperationException]::New('Something Went Wrong! Please fix Overllaping bot_cmd aliases.') }
            return $botcmd.values[0].Command.Invoke()
        }
        Write-Debug "Query not found in presets ... checking using Get-Command ..." -Debug
        $c = Get-Command $query -ErrorAction SilentlyContinue # $Error[0] = $null idk
        if ([bool]$c) {
            $CommandName = $c.ResolvedCommandName
            $Description = $c | Format-List * -Force | Out-String
            [void][cli]::Write("Do you mean $CommandName ?`n")
            [void][cli]::Write($Description, [System.ConsoleColor]::Green, $false, $false);
            [void][cli]::Write("Run Command?", $false)
            $answer = (Get-Variable host).Value.UI.PromptForChoice(
                '', 'Run the command or send a gpt Query.',
                [System.Management.Automation.Host.ChoiceDescription[]](
                    [System.Management.Automation.Host.ChoiceDescription]::new('&y', "(y)es Run $($c.Name)."),
                    [System.Management.Automation.Host.ChoiceDescription]::new('&n', '(n)o  Use Internet to get the answer.')
                ),
                0
            )
            if ($answer -eq 0) {
                [void][cli]::Write("Running the command ...`n", [System.ConsoleColor]::Green, $true);
                $resp = & $c
            } elseif ($answer -eq 1) {
                [void][cli]::Write("Ok, so this was a normal gpt query.`n", [System.ConsoleColor]::Blue, $true);
            } else {
                [void][cli]::Write("Ok, I aint do shit about it.`n", [System.ConsoleColor]::DarkYellow, $true);
            }
        }
        return $resp
    }
    static [void] ToggleOffline() { [CipherTron]::Tmp.vars.Set('OfflineMode', ![CipherTron]::Tmp.vars.OfflineMode) }
    static hidden [string] GetdalleImage([string]$Description) {
        return [CipherTron]::GetdalleImage($Description, 256)
    }
    static hidden [string] GetdalleImage([string]$Description, [int]$Size, [bool]$Raw) {
        if ($Size -notin @('256', '512', '1024')) {
            throw 'Unsupported size'
        }
        $targetSize = switch ($Size) {
            256 { '256x256' }
            512 { '512x512' }
            1024 { '1024x1024' }
        }
        $body = [ordered]@{
            prompt = $Description
            size   = $targetSize
        } | ConvertTo-Json

        $result = Invoke_OpenAIAPI -Uri 'https://api.openai.com/v1/images/generations' -Body $body -Method Post

        if ($Raw) {
            # The raw response will be returned. Otherwise, the image will be saved to a temporary file and the path to that file will be returned
            return $result
        } else {
            $DestinationPath = [IO.Path]::GetTempFileName() -replace ".tmp", ".png"
            Invoke-RestMethod $result.data.url -OutFile $DestinationPath
            $DestinationPath
        }
        return ''
    }
    static [void] SavetoImage() {
        if ([CipherTron]::IsInteractive()) {
            # Prompt for text to save:
            $info = Read-Host -AsSecureString
            [CipherTron]::SavetoImage([xconvert]::Tostring($info))
        } else {
            throw [InvalidOperationException]::new('SavetoImage() failed. Please run in Interactive mode')
        }
    }
    static [void] SavetoImage([string]$info) {
        [ValidateNotNullOrEmpty()][string]$info = $info
        $ImagePath = [CipherTron]::GetdalleImage("a cryptography assistant robot")
        Write-Debug "Doing some steganography magic on $ImagePath" -Debug
        # Todo: Complete this SavetoImage([string]$info) Method.
        throw 'Method Not ready Yet!'
    }
    hidden [void] SetStage() {
        [bool]$IsComplete = $false
        if ([CipherTron]::ChatSession.ChatLog.Messages.Count -gt 0) {
            throw [System.InvalidOperationException]::new('Please Clear chatLog first.')
        }
        if ([string]::IsNullOrEmpty($this.Config.ChatDescrptn)) {
            throw [System.InvalidOperationException]::new('Please run setConfigs() first.')
        }
        [CipherTron]::ChatSession.ChatLog.Intro = $this.Config.ChatDescrptn
        $c = [System.Text.StringBuilder]::new();
        [CipherTron]::Tmp.vars.Set('Query', $this.Config.First_Query)
        [void]$c.AppendLine("$($this.Config.ChatDescrptn)");
        [void]$c.Append([CipherTron]::Tmp.vars.StopSigns.Sendr);
        [void]$c.AppendLine([CipherTron]::Tmp.vars.Query);
        [void]$c.AppendLine([CipherTron]::Tmp.vars.StopSigns.Recvr);
        $BotIntro = $this.GetResponse($c.ToString())
        if (![string]::IsNullOrWhiteSpace($BotIntro)) {
            [void][cli]::Write($BotIntro)
            $IsComplete = $true
        }
        [CipherTron]::Tmp.vars.Set('Response', $BotIntro); $this.RecordChat()
        [CipherTron]::Tmp.vars.Set('SetStage_Complete', $IsComplete);
    }
    [void] EndSession() {
        # Todo: Should work like exit but Instead you go back to a menu showing availble sessions
        # cleanup cache:
        # $this.DeleteConfigs()
    }
    [void] SaveSession() {
        [CipherTron]::ChatSession.Save()
    }
    [void] LoadSession([string]$Uid) {
        if ([string]::IsNullOrWhiteSpace($uid)) { throw [InvalidArgumentException]::new('Uid') }
        $snFile = [IO.FileInfo]::new([IO.Path]::Combine([ChatSessionManager]::GetSessionFolder(), "$Uid.chat"))
        if (!$snFile.Exists) { throw [System.InvalidOperationException]::new("Failed to load chatsession with Id: '$Uid'", [System.IO.FileNotFoundException]::new('Unable to find the specified file.', $snFile.BaseName)) }
        [CipherTron]::ChatSession = [ChatSession]::new($snFile)
    }
    [void] SetConfigs() { $this.SetConfigs([string]::Empty, $false) }
    [void] SetConfigs([string]$ConfigFile) { $this.SetConfigs($ConfigFile, $true) }
    [void] SetConfigs([bool]$throwOnFailure) { $this.SetConfigs([string]::Empty, $throwOnFailure) }
    [void] SetConfigs([string]$ConfigFile, [bool]$throwOnFailure) {
        [AesGCM]::caller = "[$($this.GetType().Name)]"
        if ($null -eq $this.Config) { $this.Config = [RecordTbl]::new($this.Get_default_Config()) }
        if (![string]::IsNullOrWhiteSpace($ConfigFile)) { $this.Config.File = [CipherTron]::GetUnResolvedPath($ConfigFile) }
        if (![IO.File]::Exists($this.Config.File)) {
            if ($throwOnFailure -and ![bool]$((Get-Variable WhatIfPreference).Value.IsPresent)) {
                throw [System.IO.FileNotFoundException]::new("Unable to find file '$($this.Config.File)'")
            }; [void](New-Item -ItemType File -Path $this.Config.File)
        }
        if ($null -eq $this.Presets) { $this.Presets = [chatPresets]::new() }
        $Commands = $this.Get_default_Commands()
        $Commands.keys | ForEach-Object {
            $this.Presets.Add([PresetCommand]::new("$_", $Commands[$_][0]))
            [string]$CommandName = $_; [string[]]$aliasNames = $Commands[$_][1]
            if ($null -eq $aliasNames) { Write-Verbose "[ciphertron] SetConfigs: Skipped Load_Alias_Names('$CommandName', `$aliases). Reason: `$null -eq `$aliases"; Continue }
            if ($null -eq $this.presets.$CommandName) {
                Write-Verbose "[ciphertron] SetConfigs: Skipped Load_Alias_Names('`$CommandName', `$aliases). Reason: No CipherTron Command named '$CommandName'."
            } else {
                $this.presets.$CommandName.aliases = [System.Management.Automation.AliasAttribute]::new($aliasNames)
            }
        }
        [cli]::preffix = $this.Config.emojis.Bot
        [cli]::textValidator = [scriptblock]::Create({ param($npt) if ([CipherTron]::Tmp.vars.ChatIsOngoing -and ([string]::IsNullOrWhiteSpace($npt))) { throw [System.ArgumentNullException]::new('InputText!') } })
        Set-PSReadLineKeyHandler -Key 'Ctrl+g' -BriefDescription OpenAICli -LongDescription "Calls Open AI on the current buffer" -ScriptBlock $([scriptblock]::Create("param(`$key, `$arg) (`$line, `$cursor) = (`$null,`$null); [CipherTron]::Complete([ref]`$line, [ref]`$cursor);"))
    }
    [void] SetTMPvariables() {
        # Sets default variables and stores them in $this::Tmp.vars
        # Makes it way easier to clean & manage variables without worying about scopes and not dealing with global variables.
        if ($null -eq [CipherTron]::Tmp) { [CipherTron]::Tmp = [SessionTmp]::new() }
        if ($null -eq $this.Config) { $this.SetConfigs() }
        [CipherTron]::Tmp.vars.Set(@{
                Query             = ''
                Users             = @{}
                Host_Os           = [CipherTron]::Get_Host_Os()
                Response          = ''
                ExitCode          = 0
                StopSigns         = [gptOptions]::new().GetStopSign()
                ApiKey_Path       = $this.Get_ApiKey_Path("OpenAIKey.enc")
                Quick_Exit        = $this.Config.Quick_Exit  #ie: if true, then no Questions asked, Just closes the damn thing.
                OfflineMode       = $this.IsOffline
                ResponseCount     = 0
                Finish_reason     = ''
                OgWindowTitle     = $(Get-Variable executionContext).Value.Host.UI.RawUI.WindowTitle
                ChatIsOngoing     = $false
                CurrentsessionId  = ''
                WhatIf_IsPresent  = [bool]$((Get-Variable WhatIfPreference).Value.IsPresent)
                SetStage_Complete = $false
            }
        )
    }
    [securestring] GetAPIkey([securestring]$Password) {
        $TokenFile = [CipherTron]::Tmp.vars.ApiKey_Path; $sectoken = $null; $_c = [AesGCM]::caller; [AesGCM]::caller = '[CipherTron]'
        if ([string]::IsNullOrWhiteSpace((Get-Content $TokenFile -ErrorAction Ignore))) {
            $this.SetAPIkey()
        } elseif ([CipherTron]::IsBase64String([IO.File]::ReadAllText($TokenFile))) {
            Write-Host "[CipherTron] Encrypted token found in file: $TokenFile" -ForegroundColor DarkGreen
        } else {
            throw [System.Exception]::New("Unable to read token file!")
        }
        try {
            $sectoken = [xconvert]::ToSecurestring([system.Text.Encoding]::UTF8.GetString([AesGCM]::Decrypt([Convert]::FromBase64String([IO.File]::ReadAllText($TokenFile)), $Password)))
        } catch {
            throw $_
        } finally {
            [AesGCM]::caller = $_c
        }
        return $sectoken
    }
    [void] SetAPIkey() {
        if ($null -eq $this::Tmp.vars.Keys) { $this.SetTMPvariables() }
        $ApiKey = $null; $rc = 0; $prompt = "Enter your OpenAI API key: "
        $ogxc = [CipherTron]::Tmp.vars.ExitCode;
        [CipherTron]::Tmp.vars.Set('ExitCode', 1)
        do {
            if ($rc -gt 0) { [void][cli]::Write($this.Config.NoApiKeyHelp + "`n", [System.ConsoleColor]::Green, $false, $true); $prompt = "Paste your OpenAI API key: " }
            [void][cli]::Write($prompt); Set-Variable -Name ApiKey -Scope local -Visibility Private -Option Private -Value ((Get-Variable host).Value.UI.ReadLineAsSecureString());
            $rc ++
        } while ([string]::IsNullOrWhiteSpace([xconvert]::ToString($ApiKey)) -and $rc -lt 2)
        [CipherTron]::Tmp.vars.Set('OfflineMode', $true)
        if ([string]::IsNullOrWhiteSpace([xconvert]::ToString($ApiKey))) {
            [CipherTron]::Tmp.vars.Set('Finish_reason', 'Empty_API_key')
            if ($this.Config.ThrowNoApiKey) {
                throw [System.InvalidOperationException]::new('Operation canceled due to empty API key')
            }
        }
        if ([CipherTron]::IsInteractive()) {
            # Ask the user to save API key or not:
            [void][cli]::Write('++  '); [void][cli]::Write('Encrypt and Save the API key', [System.ConsoleColor]::Green, $true, $false); [void][cli]::Write("  ++`n", $false);
            $answer = (Get-Variable host).Value.UI.PromptForChoice(
                '', '       Encrypt and save OpenAi API key on local drive?',
                [System.Management.Automation.Host.ChoiceDescription[]](
                    [System.Management.Automation.Host.ChoiceDescription]::new('&y', '(y)es,'),
                    [System.Management.Automation.Host.ChoiceDescription]::new('&n', '(n)o')
                ),
                0
            )
            if ($answer -eq 0) {
                $Pass = $null; Set-Variable -Name pass -Scope Local -Visibility Private -Option Private -Value $(if ([CryptoBase]::EncryptionScope.ToString() -eq "User") { Read-Host -Prompt "$([RecordTbl]::caller) Paste/write a Password to encrypt apikey" -AsSecureString }else { [xconvert]::ToSecurestring([AesGCM]::GetUniqueMachineId()) })
                $this.SaveApiKey($ApiKey, [CipherTron]::Tmp.vars.ApiKey_Path, $Pass)
                [CipherTron]::Tmp.vars.Set('OfflineMode', $false)
            } elseif ($answer -eq 1) {
                [void][cli]::Write("API key not saved`n.", [System.ConsoleColor]::DarkYellow, $true);
            } else {
                [void][cli]::Write("Invalid answer.`n", [System.ConsoleColor]::Red, $true);
            }
        } else {
            # save without asking :)
            $this.SaveApiKey($ApiKey, [CipherTron]::Tmp.vars.ApiKey_Path, [xconvert]::ToSecurestring([AesGCM]::GetUniqueMachineId()))
        }
        [CipherTron]::Tmp.vars.Set('ExitCode', $ogxc)
    }
    [void] SaveApiKey([securestring]$ApiKey, [string]$FilePath, [securestring]$password) {
        if (![IO.File]::Exists("$FilePath")) {
            Throw [FileNotFoundException]::new("Please set a valid ApiKey_Path first", $FilePath)
        }
        #--todo: use hash hkdf
        [void][cli]::Write("Saving API key to $([IO.Fileinfo]::New($FilePath).FullName) ...", [System.ConsoleColor]::Green, $false, $false);
        [IO.File]::WriteAllText($FilePath, [convert]::ToBase64String([AesGCM]::Encrypt([System.Text.Encoding]::UTF8.GetBytes([xconvert]::ToString($ApiKey)), $password)), [System.Text.Encoding]::UTF8)
        [void][cli]::Write('API key saved in'); [void][cli]::Write(" $FilePath", [System.ConsoleColor]::Green, $false, $false);
    }
    [string] Get_ApiKey_Path([string]$fileName) {
        $DataPath = $this.Config.Bot_data_Path; if (![IO.Directory]::Exists($DataPath)) { [CipherTron]::Create_Dir($DataPath) }
        return [IO.Path]::Combine($DataPath, "$fileName")
    }
    [void] EditConfig() {
        if ($null -eq $this.Config) {
            throw 'Start Ciphertron first'
        }; [AesGCM]::caller = '[ciphertron]'
        $config_file = $this.Config.File
        if (![IO.File]::Exists($config_file)) {
            New-Item -Type File -Path $config_file
            #Export current config to the file
        }
        Write-Verbose "Editing $config_file ..."
        code $config_file
    }
    [void] SaveConfigs() {
        [RecordTbl]::caller = "[$($this.GetType().Name)]"; $this.Config.Save()
    }
    [void] SyncConfigs() {
        # Imports remote configs into current ones, then uploads the updated version to github gist
        # Compare REMOTE's lastWritetime with [IO.File]::GetLastWriteTime($this.File)
        $this.ImportConfig($this.Config.Remote); $this.SaveConfigs()
    }
    [void] ImportConfigs() {
        [RecordTbl]::caller = "[$($this.GetType().Name)]"; [void]$this.Config.Import($this.Config.File)
    }
    [void] ImportConfigs([uri]$raw_uri) {
        # $e = "GIST_CUD = {0}" -f ([AesGCM]::Decrypt("AfXkvWiCce7hAIvWyGeU4TNQyD6XLV8kFYyk87X4zqqhyzb7DNuWcj2lHb+2mRFdN/1aGUHEv601M56Iwo/SKhkWLus=", $(Read-Host -Prompt "pass" -AsSecureString), 1)); $e >> ./.env
        [RecordTbl]::caller = "[$($this.GetType().Name)]"; $this.Config.Import($raw_uri)
    }
    [bool] DeleteConfigs() {
        return [bool]$(
            try {
                $configFiles = ([GitHub]::GetTokenFile() | Split-Path | Get-ChildItem -File -Recurse).FullName, $this.Config.File, ($this.Config.Bot_data_Path | Get-ChildItem -File -Recurse).FullName
                $configFiles.Foreach({ Remove-Item -Path $_ -Force -Verbose });
                $true
            } catch { $false }
        )
    }
    [hashtable] Get_default_Config() {
        $default_Config = @{
            Remote        = ''
            FileName      = 'Config.enc' # Config is stored locally but it's contents will always be encrypted.
            File          = ''
            GistUri       = 'https://gist.github.com/alainQtec/0710a1d4a833c3b618136e5ea98ca0b2' # replace with yours
            emojis        = @{ #ie: Use emojis as preffix to indicate messsage source.
                Bot  = '{0} : ' -f ([System.Text.UTF8Encoding]::UTF8.GetString([byte[]](240, 159, 150, 173, 32)))
                user = '{0} : ' -f ([CipherTron]::ChatSession.User.preferences.Avatar_Emoji)
            }
            GPt_Options   = @{
                model             = 'text-davinci-003'
                temperature       = 1.0
                max_tokens        = 256
                top_p             = 1.0
                frequency_penalty = 0.0
                presence_penalty  = 0.0
            }
            Quick_Exit    = [CipherTron]::ChatSession.User.preferences.Quick_Exit
            ERROR_NAMES   = ('No_Internet', 'Failed_HttpRequest', 'Empty_API_key') # If exit reason is in one of these, the bot will appologise and close.
            First_Query   = "Hi, can you introduce yourself in one sentense?"
            OfflineHello  = "Hello; I am $([CipherTron]::ChatSession.ChatLog.Recvr), your cryptography helper.`n"
            OfflineNoAns  = "I'm sorry, I can't understand what you mean; Please Connect internet and try again.`n"
            NoApiKeyHelp  = 'Get your OpenAI API key here: https://platform.openai.com/account/api-keys'
            LogOfflineErr = $false # If true then chatlogs will include results like OfflineNoAns.
            ThrowNoApiKey = $false # If false then Chat() will go in offlineMode when no api key is provided, otherwise it will throw an error and exit.
            ChatDescrptn  = "The following is a conversation of $([CipherTron]::ChatSession.ChatLog.Sendr) with an A.I cryptography assistant named $([CipherTron]::ChatSession.ChatLog.Recvr). The assistant is a helpful, creative, clever security expert and extremely experienced in cryptography and PowerShell Scripting.`n"
            UsageHelp     = "Usage:`nHere's an example of how to use this bot:`n   `$bot = [CipherTron]::new()`n   `$bot.Chat()`n`nAnd make sure you have Internet."
            Bot_data_Path = [CipherTron]::Get_dataPath()
            LastWriteTime = [datetime]::Now
        }
        $default_Config.UsageHelp += "`n`nPreset Commands:`n"; $commands = $this.Get_default_Commands()
        $default_Config.UsageHelp += $($commands.Keys.ForEach({ [PSCustomObject]@{ Command = $_; Aliases = $commands[$_][1]; Description = $commands[$_][2] } }) | Out-String).Replace("{", '(').Replace("}", ')')
        $default_Config.File = [CipherTron]::GetUnResolvedPath([IO.Path]::Combine((Split-Path -Path ([CipherTron]::Get_dataPath())), $default_Config.FileName))
        $l = [GistFile]::Create([uri]::New($default_Config.GistUri)); [GitHub]::UserName = $l.UserName
        Write-Host "[CipherTron] Get Remote gist uri for config ..." -ForegroundColor Blue
        $default_Config.Remote = [uri]::new([GitHub]::GetGist($l.Owner, $l.Id).files."$($default_Config.FileName)".raw_url)
        Write-Host "[CipherTron] Get Remote gist uri Complete" -ForegroundColor Blue
        return $default_Config
    }
    [System.Collections.Specialized.OrderedDictionary] Get_default_Commands() {
        return [Ordered]@{
            cls           = { [System.Console]::Clear() }, ('clear'), 'Clears screen'
            exit          = { $this._Exit($true) }, ('close', 'bye'), 'Closes the chat session'
            help          = { [void][cli]::write($this.Config.UsageHelp) }, ('view usage', '--help'), 'View this help message'
            hash          = { $this.User.Hash() }, ('create hash', 'hash this'), 'Hash a string'
            sign          = { $this.User.Sign() }, ('sign this', 'Create a new signature'), 'Hash a string'
            encrypt       = { $this.User.Encrypt() }, ('encrypt this', 'encipher'), 'Encrypt stuff with multiple algorithms'
            decrypt       = { $this.User.Decrypt() }, ('decrypt this', 'decipher'), 'Decrypt stuff with multiple algorithms'
            EditConfig    = { $this.EditConfig() }, ('edit config', 'settings'), 'View and edit bot config file'
            SetConfigs    = { $this.SetConfigs($false) }, ('resfresh config', 'Load config'), 'Set/save config file'
            ToggleOffline = { [CipherTron]::ToggleOffline() }, ('Offline Mode', 'toggle Offline'), 'Change chatmode to offline'
            SavetoImage   = { [CipherTron]::SavetoImage() }, ('Save to Image', 'hide in Image'), 'Used for steganography stuff'
            NewPassword   = { [CipherTron]::NewPassword() }, ('new password', 'new-password'), 'Generate new password'
            generateKey   = { [KeyManager]::generateKey() }, ('create key', 'new key'), ''
            importKey     = { [KeyManager]::importKey() }, ('import key', 'use key'), ''
            deleteKey     = { [KeyManager]::deleteKey() }, ('delete key', 'delkey'), ''
            rotateKeys    = { [KeyManager]::rotateKeys() }, ('rotate key', 'rtkey'), ''
            exportKey     = { [KeyManager]::exportKey() }, ('export key', 'xpkey'), ''
            validateKey   = { [KeyManager]::validateKey() }, ('validate key', 'check key'), ''
            startSession  = { $this.Chat() }, ('start session', 'new chat'), 'Creates a new chat session'
            endSession    = { $this.endSession() }, ('end session', 'end chat'), 'Ends a chat session'
            saveSession   = { $this.saveSession() }, ('save session', 'save chat'), 'Saves current chat session'
            loadSession   = { $this.loadSession() }, ('load session', 'import chat'), 'Loads existing chat session'
        }
    }
    static [string] NewPassword() {
        #Todo: there should be like a small chat here to help the user generate the password
        return [CryptoBase]::GeneratePassword()
    }
    static [string] Get_dataPath() {
        return [CipherTron]::Get_dataPath('CipherTron', ([ChatLog]::new().Recvr + '_Chat').Trim()).FullName
    }
    static hidden [void] Complete([ref]$line, [ref]$cursor) {
        # Used for a code completion Shortcut
        [Microsoft.PowerShell.PSConsoleReadLine]::GetBufferState($line, $cursor);
        # Warning: Not ready yet: the fact that a new bot has to be created every time is not cool ie: It will prompt for apikeys & stuff etc ...
        $bot = [CipherTron]::new(); if ($null -eq $bot::Tmp.vars.OpenAIKey) {
            # TODO: Add A GUI to set api key
            throw 'Please Set the api key first and try again'
        }
        $output = $bot.GetResponse($line, [gptOptions]::new('text-davinci-003', 256));
        $output = $output -replace "`r", ''
        if ($output -eq $bot.Config.OfflineNoAns) {
            Write-Error $output
        } elseif (![string]::IsNullOrWhiteSpace($output)) {
            [Microsoft.PowerShell.PSConsoleReadLine]::Insert("@'")
            [Microsoft.PowerShell.PSConsoleReadLine]::AddLine()
            foreach ($str in $output) {
                if (![string]::IsNullOrEmpty($str)) {
                    [Microsoft.PowerShell.PSConsoleReadLine]::Insert("$str")
                    [Microsoft.PowerShell.PSConsoleReadLine]::AddLine()
                }
            }
            [Microsoft.PowerShell.PSConsoleReadLine]::Insert("'@")
        }
    }
    static hidden [void] WriteBanner() {
        $bc = [CipherTron]::banners.Count
        if ($null -eq [CipherTron]::banners -or ($bc -eq 0)) {
            [void][CipherTron]::banners.Add([base85]::Decode([xconvert]::ToDeCompressed('H4sIAAAAAAAAA61YV1sqyxJ95/v8EQgIiEgYRGQIImkrGbqJEhQkqMSB/3+qqnsGMGw9597HZoaaCqtWrerZ1DftsurQunpIm6/Ks399PDH9/TkPpII7OMZqs2nBNuCl/q1ZHvWXT0z/8dv744np8/Ox5382sXc/fjqbFudxps20aq/ttNpnU/+LhdXWE0c3MeYWOF6OT0y8nh13a05+7qHneOz12o7dBv6tJXitskiDsVDlW1d+m4u/BPeDCY11/YPqbFoK3rNWLtcGb5Xb2TS86PGbYrOAsUb1XNScwd1j6vVmJ3KBwaGxt9k07TrXj5ErCC7j5+XqygmpMZ/B01UCclEb2bK5buiR/9vKyuB+gpZ+jGmzaeQpiv4MSlfDyWQ2TQXGjD14L05M+dhio86myijOanVuheNbbzZVAxM8Wh4GkdhBMQrqm++ZSsmq7+dr/NQUc6EEPDw8zj1CKZdzAQSWOL+A19UMRDu/5eXL5ulve+RnYCa3fc5vrLVe7Hlug+8lfWAC/LVBfi0jcLCz46E/6yS+3oR/v/U+/JstnO6tTI3edZ9xAcFjG26f8PV1fld2rOG4HvDrSSEG3x6n4Ns+l45y1sdcAFD+GzA3CC0/mvCv7fzqdu7sDANmgJ4S9jEeaPu/tggOUN/Ay3Zoo9LNg2izXs+S7SYoPLa0jeyyK0vmO3ydUrMycrHGyrZErEaPBK9EtGz2VMLKpsGVVRJhm/5FcIfp5DV3Pc7OKumA7BuAFm97LH2RLkCi6wOldC6qryvMBcRDwGWJ90ae3GfrZCyKtekLY01zHrsyEoJc9ML4ch9hMCTbAheWsn+gTPffzp01stDiftcL481NSPJXyZuljn90lrw3XwXyRe2KTyolO98O7MJHLBCaCeC17ErdMCFfH8hipB1OeXRogOOo+w/21RYyVVgLY6V+fNceXzeDmIuMcs/rluKjZBFIDVv0q6cS5UpTpVK2Zmr0AVrc94KZ3FQvmq8MYg1Ap7LGPJOTuSpcj/8GzLhf5B7arArgCMUJltipsvEH4P71pfF62ChVD4OziKN60e2D+50i+HM6YHzruRG5aAn3a/2OFf3xCoINd9Md/d/KH0oNElJd5OKm0SvCy2oVcxGxOVl1591I95VSiK1Xj7fAp33ARcmeQpymvghOA2g9FanNgMag/MHOUNFujytblR+QwUWFt9sx63Wyc21DpcA2o2I4lhB8+j5ADvDdg6dHpeSh6mkKj0CBSi9K35aFpuBiA+ALgHXFvP+2jBYSyyuZnAcppyme1n1qDDsoLgYnJpZeplEkw6NOBYs1AE8hOmXs5e5SWvQn54w9RtzYCAtI9rpvUE5UbzPwN6uzhDsjgGnJjhNEsMQxMppi1GMcAYcFvsJp5q4nJDCLl+ecs2BdGjvkUxgmKdeQcAqlGp4S5fBA/W57YsJJCpksXA5Zy3vTQEaNy+BgnGLbq9Wspv2BV6pLtpg2LQeEzkJWF0BrELkDB/ylNYEDRzmYCJjTrHWXbmGpIDUBe5a6Ehh8YiFOo7aHpysr5oKe6z/sj+BPDga9kr+mI+S52KLBafAptIRvgUVtVAM5aBr/lYA1tiHyaUAYwzoAA1Vg7KqWgOAdGCFnyMFbyeCHrakm30XjHg3jdS218s/FADom0P+DaCxVnKuBPs2AMc8gF5v4AU4BmIDydE89IkMtwXjp/QoDQUWXbOnQAhrTysWzIJCympnrCTFms6CUeMSYnlp9k0kAONJJCGRhi2Weuoud8laq5t6jC1smm+pCIbWOe/v4BseXYndZOL9/8EZe07nEps5lTgslK2BKCRhyDagfPW+JI4BQe8zlFhfUBdbc7RTAETl1ICvZIYZAZz+bQSjtyr6R0TkaGPYKwmc8OlBQ08J4UnyX3zVKBr04+OEs+eH5V0eiFOSnCbU9TjMAyl5Ukm/HnmEx1Db0yO2MBwoRVDnxawjuGWhRcV0gOu8vs3X1xWM5kh4odXTtglm7FpQCfdz45T6CqgxZAAh2AsNPdY1QKN3+sExs5PSNTOL6cwwO+faDZyRIoY0UPRDs6XrDlXiWtSP8uZgPSM492n8RJuBwSv4Y2O3oulNXA2tB2RBtE4XU674YGE18r0OQ4oCw1csXasITE1DkxLZfX9CfpjgiwyPltEhGGbV5FYSEweGodlEuDhQqsIjCw6xZfK2gsSEE97ISymeZMDua7/HT7HE6K6TBHS6yCeBxOr5ubGizwiafiguGxlEN68D6/kA0ohLZ7UhIkTEg0AYzdNUAKVCTm52Y3Gg73QnvcaFCsSI+NyUHE786ciUIqkJ5inGe8zYgsaMlBjcTUEaon5igdpfxfbEOOG+dT0UqudOq6wjqumgEcVCBidJilIvXBPkLLJIdknARfQPGWjLZMB263YvuRqocj1bB1ahPKBb0q0sL9dmst5njjWrDA1AN+dTvm+ilzIxoUrKaP2qmaaaoEF7fI4Rb+XaEpHIFWPE3twYaOtSprM5rcQiugX1je/7cZsDwbuTghNS8r3YmU4ObJgIPptm7JmCip6ZJKqdvxmXsXIo05DcMXkoLiWOMNdQSwANX7uSit9/NUBNrIlc47Uj0yOBw2WKDTplbCkPwx3+/5OEbN5c05N86wASMPC9+8WmPlg/ABKzMuRE8LuGNCqlWXLI1AS1QZapPqlbfeFbb449ENxZwSeWlTV0qH5yeSOgkDmJD4g78oiY1OtYzFHxJgXsXCQmOTtJj+DiVQhuGxYmp/bBueoXU1p9LQGEBCw1ftHOEd3SZRkRmHMCRdiaJj3Yc7NS6kAQ4QqSQPGzclXhad1xF8DjW0bkOh8LSuj+zoG/rrkjbcjtV80sdHOOItA3BHesLLCBWDAsktibWPK+WMX/j/UoIT12twyGAUrsuHUhmoxCNbUvG9F5LySstHAI40k6/0BcAD+iXyBZSlwCpqG7tuhqgSyBMrE9V99sT5iKsI38Sg0BAlHdg6Jdr+/A+4kvcDJDyxi0EtFQeN0TwtuAbgQnYIEvIHYA/pXpjcJVyLF0bcr27YF1I50osYDx8p0Cb6bIZgKI1JkhEbQ/tl/oy+xQ7rmxTkFgtdW8FqLeJtdA3fA7Wl48wj86zxrJV/j44WRsnbYh4aQXdvUPhCyb8t++0eh/sEZ//ffABeUF3uILFBnQ8o53gUHSjJMd97sMVkWCtwT4alOxRgQvwTGxfn65kjoL7Tl/gug66vQXKuwCdkSot2TZ314Tit32GolvTbn94WbkPnt+kq3nU7VzccCELgHtzj1gCDoL77nYNeam1FhMQlG4QacoiSBfFyJe5+KF2X5QyJkXzNL07MWHCYGqqCxvTlFIeNxyf2BBRVB/8GzkE+KmEG2J+RVtGdRg226nNFmcfsEQaXEaTsaZwPFkxF3bjvs62L9XPN40/BvfZBHJie3z91BcXhgu/ssOJDLXxO0acdyMNIPRpmCYKqqHaiQn1kEOsPFgMSTkwM5BjokAq2gu4H3DTVSb8exGliYHbcpc6Xs+Frga+v2j+Nriv78H/ctSvGfTlOAr0i/klrNXF1QVKBhQMsBNERjH6N6J8KW5qm09mhrIYltHU9JRqA/pi4E2axcUtWtcv8P7Dhf7vgPmDjD9sUtSGuBDdk9ij2iGnCXVC2g/lxBtRHNIvKF2pkw1l+eva/LTqdv4B3LwMnMIZAAA=')));
            [void][CipherTron]::banners.Add([base85]::Decode([xconvert]::ToDeCompressed('H4sIAAAAAAAAA41UTW+DMAy9I+VHIKrCpB526aH70Na12mWTKFvVbWpXJqAtGaxFHfv/SyABJyTA0bGfYz8/Gx9GfuRNH93o+c/1V/gwmq+pGXr725ujaO4qEwQjw7O3T2c3na/90s/NuAe68JIUWr+Uu4mm5iZChjY7b6SrTVJFla4Mf5hd/rBwC1/XmAW+/8XkbRUICJ4ihFzMJkfXu3B3Si5sx04lppChRtPPhrn5/fo1Pidtua9MygULT3j5wb5A0/Bz/0a0fsiklWCBqbexzEVc0ukMPnOpAP1kaXPIAN0qZqdG83oKr0YXNDvNnTcH/RFW6FjSBfybUJObYimxILLNFg51gadmUCta4kqXIuqnC+cus9o1J3AB/APnVHPVqthygwgXrVx1q4Y1oueKeN+z5lApU1aeFm/I6B4G7wZsGBu0yEVzA1uvDdheevjU6LiHqlq54I320Fyx7GJ4qSqwcNL5yEsEMzOb3wsuI5ErOgzJK6ALL+GCnxfxM+bXoMH+pch4CSfLk6hJdTg8JLBNcPgUjcpoKv/hP5EAUEL/BgAA')));
            #You can create more using: https://github.com/LachlanArthur/Braille-ASCII-Art
        }
        $bn = [CipherTron]::banners[(Get-Random (0..($bc - 1)))]
        [System.Text.Encoding]::UTF8.GetString($bn) | Write-Host -ForegroundColor Green
        [void][cli]::Write("            Making Cryptography Easy and Fun", [System.ConsoleColor]::Green, $true, $false)
        [void][System.Console]::WriteLine()
    }
    hidden [void] ShowMenu() {
        if ($null -eq [CipherTron]::ConfigUri) {
            if ($null -eq $this.Config) { $this.SetConfigs() }
            [CipherTron]::ConfigUri = $this.Config.Remote
        }
        if (![IO.File]::Exists($this.Config.File)) {
            if ([CipherTron]::useverbose) { "[+] Get your latest configs .." | Write-Host -ForegroundColor Magenta }
            [NetworkManager]::DownloadFile([CipherTron]::ConfigUri, $this.Config.File)
        }
        [CipherTron]::WriteBanner()
        # code for menu goes here ...
    }
    static hidden [bool] IsInteractive() {
        return ([Environment]::UserInteractive -and [Environment]::GetCommandLineArgs().Where({ $_ -like '-NonI*' }).Count -eq 0)
    }
    static [version] GetVersion() {
        # Returns the current version of the chatbot.
        return [version]::New($script:localizedData.ModuleVersion)
    }
    hidden [void] _Exit() {
        $this._Exit($false);
    }
    hidden [void] _Exit([bool]$cleanUp) {
        $ExitMsg = if ($this::Tmp.vars.ExitCode -gt 0) { "Sorry, an error Occured, Ending chat session ...`n     " } else { "Okay, see you nextime." };
        # save stuff, Restore stuff
        [System.Console]::Out.NewLine; [void]$this.SaveSession()
        $(Get-Variable executionContext).Value.Host.UI.RawUI.WindowTitle = $this::Tmp.vars.OgWindowTitle
        $this::Tmp.vars.Set('Query', 'exit'); [CipherTron]::ChatSession.ChatLog.SetMessage($this::Tmp.vars.Query);
        if ($this::Tmp.vars.Quick_Exit) {
            $this::Tmp.vars.Set('Response', [cli]::Write($ExitMsg)); return
        }
        $cResp = 'Do you mean Close chat?'
        [void][cli]::Write('++  '); [void][cli]::Write('Close this chat session', [System.ConsoleColor]::Green, $true, $false); [void][cli]::Write("  ++`n", $false);
        [void][cli]::Write("    $cResp`n"); [CipherTron]::ChatSession.ChatLog.SetResponse($cResp);
        $answer = (Get-Variable host).Value.UI.PromptForChoice(
            '', $this::Tmp.vars.Response,
            [System.Management.Automation.Host.ChoiceDescription[]](
                [System.Management.Automation.Host.ChoiceDescription]::new('&y', '(y)es,'),
                [System.Management.Automation.Host.ChoiceDescription]::new('&n', '(n)o')
            ),
            0
        )
        Write-Debug "Checking answers ..."
        if ($answer -eq 0) {
            $this::Tmp.vars.Set('Query', 'yes')
            $this.RecordChat(); [CipherTron]::ChatSession.ChatLog.SetResponse([cli]::Write($ExitMsg));
            $this::Tmp.vars.Set('ChatIsOngoing', $false)
            $this::Tmp.vars.Set('ExitCode', 0)
        } else {
            $this.RecordChat();
            [CipherTron]::ChatSession.ChatLog.SetMessage('no');
            [CipherTron]::ChatSession.ChatLog.SetResponse([cli]::Write("Okay; then I'm here to help If you need anything."));
            $this::Tmp.vars.Set('ChatIsOngoing', $true)
        }
        $this::Tmp.vars.Set('Query', ''); $this::Tmp.vars.Set('Response', '')
        if ($cleanUp) { $this::Tmp.Clear() }
        return
    }
}
# A class to represent the ongoing conversation between the chatbot and the user.
# It stores send message and recieved response plus any contextual information that may be relevant.
class ChatObject : System.Runtime.Serialization.ISerializable {
    static hidden [ValidateNotNullOrEmpty()][string]$SenderName
    static hidden [ValidateNotNullOrEmpty()][string]$RecieverName
    ChatObject() {
        $this.Set_Message('');
        $this.Set_Response('')
    }
    ChatObject([string]$Message, [string]$Response) {
        $this.Set_Message($Message);
        $this.Set_Response($Response)
    }
    ChatObject ([System.Runtime.Serialization.SerializationInfo]$Info, [System.Runtime.Serialization.StreamingContext]$Context) {
        $this.Set_Message($Info.GetValue('Message', [string]));
        $this.Set_Response($Info.GetValue('Response', [string]));
    }
    [void] GetObjectData ([System.Runtime.Serialization.SerializationInfo]$Info, [System.Runtime.Serialization.StreamingContext]$Context) {
        $Info.AddValue('SenderName', [ChatObject]::SenderName)
        $Info.AddValue('RecieverName', [ChatObject]::RecieverName)
    }
    static [System.Collections.Generic.List[ChatObject]] Create ([string]$InputText) {
        return [ChatObject]::Create($InputText, [ChatObject]::SenderName, [ChatObject]::RecieverName)
    }
    #  Turns a multiline stringified chat to usable chat list objects
    # .EXAMPLE
    #  View usage examples on github: https://gist.github.com/alainQtec/9de9507c362f16adddb408b3b113e857
    static [System.Collections.Generic.List[ChatObject]] Create ([string]$InputText, [string]$Sender_Name, [string]$Reciever_Name) {
        if ([string]::IsNullOrWhiteSpace($InputText)) { throw [System.ArgumentNullException]::new('InputText', [InvalidPasswordException]::New('Please input a valid ChatString')) }
        if ([string]::IsNullOrWhiteSpace($Sender_Name)) { throw [InvalidArgumentException]::new('Please first set sender_Name') }
        if ([string]::IsNullOrWhiteSpace($Reciever_Name)) { throw [InvalidArgumentException]::new('Please first set Reciever_Name') }
        $InpTxt = $InputText.Trim().Split("`n"); $cc = [ChatObject]::new();
        $Output = [System.Collections.Generic.List[ChatObject]]::new();
        $SendrN = $Sender_Name
        $RecvrN = $Reciever_Name
        $Smatch = [scriptblock]::Create({ param([string]$line) $p = '^{0}\s+:\s+(.*)$' -f "$SendrN"; return [regex]::Match($line, $p) } )
        $Rmatch = [scriptblock]::Create({ param([string]$line) $p = '^{0}\s+:\s+(.*)$' -f "$RecvrN"; return [regex]::Match($line, $p) } )
        $cStops = [gptOptions]::new().GetStopSign(); $SendrN = $cStops.Sendr ; $RecvrN = $cStops.Recvr
        # Try to get [Chat sequence] based on alternating _speaker ie: sender & Reciever.
        $_speaker = 'Unknown'; $lc = $InpTxt.Count
        for ($i = 0; $i -le $InpTxt.Count; $i++) {
            $_S = $Smatch.Invoke($InpTxt[$i])
            $_R = $Rmatch.Invoke($InpTxt[$i])
            if ($_S.Success) {
                $_speaker = 'Sender'
                $_msg = $_S.Value.Substring($SendrN.Length)
                $_msg = if ([string]::IsNullOrEmpty($_msg)) { ' ' }else { $_msg }
                $cc.Set_Message("`n$_msg", $true)
            } elseif ($_R.Success) {
                $_speaker = 'Reciever'
                $_msg = $_R.Value.Substring($RecvrN.Length)
                $_msg = if ([string]::IsNullOrEmpty($_msg)) { ' ' }else { $_msg }
                $cc.Set_Response("`n$_msg", $true)
            } elseif ($_speaker -eq 'Sender') {
                $cc.Set_Message("`n$($InpTxt[$i])", $true)
            } elseif ($_speaker -eq 'Reciever') {
                $cc.Set_Response("`n$($InpTxt[$i])", $true)
            } else {
                $lc--
                # Write-Debug "[Chat Sequence] Skipped Line $i" -Debug
            }
            # Write-Debug "speaker: $_speaker" -Debug
            if (($i -ge $lc) -or $Smatch.Invoke($InpTxt[$i + 1]).Success -or $Rmatch.Invoke($InpTxt[$i + 1]).Success) {
                $cc.Trim(); [void]$Output.Add([PSObject]$cc); $cc = [ChatObject]::new()
            }
        }
        # Try to align:
        $i = 0; $cc = [ChatObject]::new()
        $C = $Output; $rp = $cc::Get_Reciever(); $sp = $cc::Get_Sender()
        $Output = [System.Collections.Generic.List[ChatObject]]::new()
        do {
            switch ($true) {
                (![string]::IsNullOrEmpty($C[$i].$sp)) {
                    do {
                        $cc.Set_Message("`n$($C[$i].$sp)", $true);
                        $cc.Set_Response("`n$($C[$i].$rp)", $true)
                        $i++
                    } until ($i -ge $C.Count -or ![string]::IsNullOrEmpty($C[$i].$sp))
                    $cc.Trim(); [void]$Output.Add($cc); $cc = [ChatObject]::new()
                }
                (![string]::IsNullOrEmpty($C[$i].$rp)) {
                    do {
                        $cc.Set_Message("`n$($C[$i].$sp)", $true);
                        $cc.Set_Response("`n$($C[$i].$rp)", $true)
                        $i++
                    } until ($i -ge $C.Count -or ![string]::IsNullOrEmpty($C[$i].$rp))
                    $cc.Trim(); [void]$Output.Add($cc); $cc = [ChatObject]::new()
                }
                Default {
                    $i++ #; Write-Debug "[Chat Align] Skipped Line $i" -Debug
                }
            }
        } while ($i -le $C.Count)
        return $Output;
    }
    [void] Set_Message([string]$text) {
        $this.Set_Message($text, $false);
    }
    [void] Set_Message([string]$text, [bool]$append) {
        $sn = $this::Get_Sender(); if ($append) { $text = $this.$sn + $text }
        $this.PsObject.properties.add([psscriptproperty]::new($sn, [scriptblock]::Create("return @'`n$text`n'@"), { throw 'this is a read Only property' }))
    }
    [void] Set_Response([string]$text) {
        $this.Set_Response($text, $false);
    }
    [void] Set_Response([string]$text, [bool]$append) {
        $rn = $this::Get_Reciever(); if ($append) { $text = $this.$rn + $text }
        $this.PsObject.properties.add([psscriptproperty]::new($rn, [scriptblock]::Create("return @'`n$text`n'@"), { throw 'this is a read Only property' }))
    }
    [void] Trim() {
        $sn = $this::Get_Sender(); $st = ($this.$sn).Trim(); $this.Set_Message($st);
        $rn = $this::Get_Reciever(); $rt = ($this.$rn).Trim(); $this.Set_Response($rt);
    }
    static hidden [string] Get_Sender() {
        $sn = [ChatObject]::SenderName;
        if ([string]::IsNullOrWhiteSpace($sn)) { $sn = 'Human'; [ChatObject]::SenderName = $sn }
        return $sn
    }
    static hidden [string] Get_Reciever() {
        $rn = [ChatObject]::RecieverName;
        if ([string]::IsNullOrWhiteSpace($rn)) { $rn = 'CipherTron'; [ChatObject]::RecieverName = $rn }
        return $rn
    }
}
class ChatLog : System.Runtime.Serialization.ISerializable {
    hidden [ValidateNotNull()][int]$Length = 0
    hidden [ValidateNotNull()][string]$Intro = ''
    hidden [ValidateNotNull()][datetime]$StartTime
    [ValidateNotNull()][ChatObject[]]$Messages = @()
    ChatLog() {
        $this.Length = $this.ToString().Length
        [gptOptions]::new().stop.Replace(':', '')
        $this.Set_Sendr(); $this.Set_Recvr()
    }
    ChatLog([ChatObject[]]$ChatObjects) {
        $this.Add($ChatObjects)
        $this.Set_Sendr(); $this.Set_Recvr()
    }
    ChatLog([System.Runtime.Serialization.SerializationInfo]$Info, [System.Runtime.Serialization.StreamingContext]$Context) {
        $this.Length = $Info.GetValue('Length', [int])
        $this.Intro = $Info.GetValue('Intro', [string])
        $this.StartTime = $Info.GetValue('StartTime', [datetime])
        $this.Messages = $Info.GetValue('Messages', [ChatObject[]])
    }
    [void] GetObjectData([System.Runtime.Serialization.SerializationInfo] $Info, [System.Runtime.Serialization.StreamingContext]$Context) {
        $Info.AddValue('Length', $this.Length)
        $Info.AddValue('Intro', $this.Intro)
        $Info.AddValue('StartTime', $this.StartTime)
        $Info.AddValue('Messages', $this.Messages)
    }
    [void] Add([string]$ChatString) {
        $ChatObjects = [System.Collections.Generic.List[ChatObject]][ChatObject]::Create($ChatString);
        $ChatObjects | ForEach-Object { $this.Add($_) };
    }
    [void] Add([ChatObject[]]$ChatObjects) {
        $ChatObjects | ForEach-Object {
            if ($null -eq $_) { Continue }
            if ($null -ne $_.SentMsg -and ![ChatObject]::SenderName.Equals('SentMsg')) {
                $this.Messages += [ChatObject]::new($_.SentMsg, $_.Response)
            } else {
                $this.Messages += $_
            }
        };
        $this.Length = $this.ToString().Length
    }
    [void] SetMessage([string]$Msg) {
        $this.SetMessage($Msg, -1)
    }
    [void] SetMessage([string]$Msg, [int]$index) {
        if ($null -eq $this.Messages[$index]) {
            if ($this.Messages.Count -eq 0) {
                $this.Messages += [ChatObject]::new('', '')
            } else {
                $this.Messages[$index] = [ChatObject]::new('', '')
            }
        }
        $this.Messages[$index].Set_Message($Msg)
        $this.Length = $this.ToString().Length
    }
    [void] SetResponse([string]$Msg) {
        $this.SetResponse($Msg, -1)
    }
    [void] SetResponse([string]$Msg, [int]$index) {
        if ($null -eq $this.Messages[$index]) {
            if ($this.Messages.Count -eq 0) {
                $this.Messages += [ChatObject]::new('', '')
            } else {
                $this.Messages[$index] = [ChatObject]::new('', '')
            }
        }
        $this.Messages[$index].Set_Response($Msg)
        $this.Length = $this.ToString().Length
    }
    hidden [void] Set_Sendr() {
        $this.Set_Sendr([gptOptions]::new().stop.Replace(':', '')[0].Trim())
    }
    hidden [void] Set_Sendr([string]$Name) {
        $this.PsObject.properties.add([psscriptproperty]::new('Sendr', [scriptblock]::Create("return '$Name'"), { throw 'Sendr is a read Only property' }))
        [ChatObject]::SenderName = $Name
    }
    hidden [void] Set_Recvr() {
        $this.Set_Recvr([gptOptions]::new().stop.Replace(':', '')[1].Trim())
    }
    hidden [void] Set_Recvr([string]$Name) {
        $this.PsObject.properties.add([psscriptproperty]::new('Recvr', [scriptblock]::Create("return '$Name'"), { throw 'Recvr is a read Only property' }))
        [ChatObject]::RecieverName = $Name
    }
    [void] Clear() {
        $this.Messages = @()
        Write-Debug "Chatlog was Cleared" -Debug
    }
    [string] ToString() {
        $Chat = [System.Text.StringBuilder]::new();
        $Chat_String = $($this.Messages | Format-List | Out-String).Trim()
        [void]$Chat.AppendLine($this.Intro);
        [void]$Chat.AppendLine($Chat_String);
        $Chat_String = $Chat.ToString().Trim();
        return $Chat_String
    }
}
class SessionTmp {
    [ValidateNotNull()][RecordTbl]$vars
    [ValidateNotNull()][System.Collections.Generic.List[string]]$Paths
    SessionTmp() {
        $this.vars = [RecordTbl]::new()
        $this.Paths = [System.Collections.Generic.List[string]]::new()
    }
    [void] Clear() {
        $this.vars = [RecordTbl]::new()
        $this.Paths | ForEach-Object { Remove-Item "$_" -ErrorAction SilentlyContinue }; $this.Paths = [System.Collections.Generic.List[string]]::new()
    }
}
class chatPresets {
    chatPresets() {
        $this.PsObject.properties.add([psscriptproperty]::new('Count', [scriptblock]::Create({ ($this | Get-Member -Type *Property).count })))
        $this.PsObject.properties.add([psscriptproperty]::new('Keys', [scriptblock]::Create({ ($this | Get-Member -Type *Property).Name })))
    }
    chatPresets([PresetCommand[]]$Commands) {
        [ValidateNotNullOrEmpty()][PresetCommand[]]$Commands = $Commands; $this.Add($Commands)
        $this.PsObject.properties.add([psscriptproperty]::new('Count', [scriptblock]::Create({ ($this | Get-Member -Type *Property).count })))
        $this.PsObject.properties.add([psscriptproperty]::new('Keys', [scriptblock]::Create({ ($this | Get-Member -Type *Property).Name })))
    }
    [void] Add([PresetCommand[]]$Commands) {
        $cms = $this.Keys
        foreach ($Command in $Commands) {
            if (!$cms.Contains($Command.Name)) { $this | Add-Member -MemberType NoteProperty -Name $Command.Name -Value $Command }
        }
    }
    [bool] Contains([PresetCommand]$Command) {
        return $this.Keys.Contains($Command.Name)
    }
    [array] ToArray() {
        $array = @(); $props = $this | Get-Member -MemberType NoteProperty
        if ($null -eq $props) { return @() }
        $props.name | ForEach-Object { $array += @{ $_ = $this.$_ } }
        return $array
    }
    [string] ToJson() {
        return [string]($this | Select-Object -ExcludeProperty count, Keys | ConvertTo-Json)
    }
    [string] ToString() {
        $r = $this.ToArray(); $s = ''
        $shortnr = [scriptblock]::Create({
                param([string]$str, [int]$MaxLength)
                while ($str.Length -gt $MaxLength) {
                    $str = $str.Substring(0, [Math]::Floor(($str.Length * 4 / 5)))
                }
                return $str
            }
        )
        if ($r.Count -gt 1) {
            $b = $r[0]; $e = $r[-1]
            $0 = $shortnr.Invoke("{'$($b.Keys)' = '$($b.values.ToString())'}", 40)
            $1 = $shortnr.Invoke("{'$($e.Keys)' = '$($e.values.ToString())'}", 40)
            $s = "@($0 ... $1)"
        } elseif ($r.count -eq 1) {
            $0 = $shortnr.Invoke("{'$($r[0].Keys)' = '$($r[0].values.ToString())'}", 40)
            $s = "@($0)"
        } else {
            $s = '@()'
        }
        return $s
    }
}

class PSObjectHelper {
    static [string[]] ListProperties([System.Object]$Obj) {
        return [PSObjectHelper]::ListProperties($Obj, '')
    }
    static [string[]] ListProperties([System.Object]$Obj, [string]$Prefix = '') {
        $Properties = @()
        $Obj.PSObject.Properties | ForEach-Object {
            $PropertyName = $_.Name
            $FullPropertyName = if ([string]::IsNullOrEmpty($Prefix)) {
                $PropertyName
            } else {
                "$Prefix,$PropertyName"
            }
            $PropertyValue = $_.Value
            $propertyType = $_.TypeNameOfValue
            # $BaseType = $($propertyType -as 'type').BaseType.FullName
            if ($propertyType -is [System.ValueType]) {
                Write-Verbose "vt <= $propertyType"
                $Properties += $FullPropertyName
            } elseif ($propertyType -is [System.Object]) {
                Write-Verbose "ob <= $propertyType"
                $Properties += [PSObjectHelper]::ListProperties($PropertyValue, $FullPropertyName)
            }
        }
        return $Properties
    }
}

class ChatSessionManager {
    [ValidateNotNull()][int]$MaxSessions = 100
    [ValidateNotNullOrEmpty()][string]$ArchiveFolder
    ChatSessionManager() {
        $this.ArchiveFolder = [IO.Path]::Combine([CipherTron]::Get_dataPath(), 'ChatArchives')
        $SessionFolder = [ChatSessionManager]::GetSessionFolder()
        if (!(Test-Path $SessionFolder)) {
            New-Item -ItemType Directory -Path $SessionFolder
        }
    }
    static [string] GetSession([string]$sessionId) {
        [ValidateNotNullOrEmpty()][string]$sessionId = $sessionId
        return [IO.Path]::Combine([ChatSessionManager]::GetSessionFolder(), "$sessionId.chat")
    }
    static [string] GetSessions() {
        return ''
    }
    static [string] GetSessionFolder() {
        return [IO.Path]::Combine([CipherTron]::Get_dataPath(), [CipherTron]::Tmp.vars.CurrentsessionId)
    }
    static [ChatSession] CreateSession([string]$sessionId) {
        $Session = $null; $sessionFile = [ChatSessionManager]::GetSession($sessionId)
        if (Test-Path $sessionFile) { $Session = [ChatSession]::New($sessionFile) }
        return $Session
    }
    static [ChatSession] TryParse([string]$FilePath) {
        [ValidateNotNullOrEmpty()][string]$FilePath = $FilePath
        $lines = [IO.File]::ReadAllLines($FilePath, [system.text.encoding]::UTF8)
        ($usr, $id) = $lines[0].Split(':')
        $ofb = [xconvert]::Deserialize([convert]::FromBase64String([xconvert]::ToDeCompressed($lines[1])))
        if (!$ofb.User.name.Substring(0, 5).Equals($usr)) { throw 'User names do not match!' }
        $Out = [ChatSession]::new([User]::new($ofb.User.Name, $ofb.User.Password, $ofb.User.PublicKey, $ofb.User.privatekey), [ChatLog]::new([ChatObject[]]$ofb.chatlog.Messages))
        $Out.ChatUid = [guid]::new($id); $out.file = [IO.Fileinfo]::new($FilePath)
        return $Out
    }
    static [pscustomobject] ParseId ([string]$Id) {
        $r = [xconvert]::ToString([guid]::new($Id)).Split(':')
        return [pscustomobject]@{
            UserName     = $r[0]
            CreationDate = Get-Date -UnixTime $r[1]
        }
    }
    static [void] DeleteSession([string]$sessionId) {
        $sessionFile = [ChatSessionManager]::GetSession($sessionId)
        if (Test-Path $sessionFile) {
            Remove-Item -Path $sessionFile
        }
    }
}
class PresetCommand : System.Runtime.Serialization.ISerializable {
    [ValidateNotNullOrEmpty()][string]$Name
    [ValidateNotNullOrEmpty()][System.Management.Automation.ScriptBlock]$Command
    [ValidateNotNull()][System.Management.Automation.AliasAttribute]$aliases

    PresetCommand([string]$Name, [ScriptBlock]$Command) {
        $this.Name = $Name; $this.Command = $Command
        $this.aliases = [System.Management.Automation.AliasAttribute]::new()
    }
    PresetCommand([string]$Name, [ScriptBlock]$Command, [string[]]$aliases) {
        $al = [System.Management.Automation.AliasAttribute]::new($aliases)
        $this.Name = $Name; $this.Command = $Command; $this.aliases = $al
    }
    PresetCommand([string]$Name, [ScriptBlock]$Command, [System.Management.Automation.AliasAttribute]$aliases) {
        $this.Name = $Name; $this.Command = $Command; $this.aliases = $aliases
    }
    PresetCommand([System.Runtime.Serialization.SerializationInfo]$Info, [System.Runtime.Serialization.StreamingContext]$Context) {
        $this.Name = $Info.GetValue('Name', [string])
        $this.Command = $Info.GetValue('Command', [System.Management.Automation.ScriptBlock])
        $this.aliases = $Info.GetValue('aliases', [System.Management.Automation.AliasAttribute])
    }
    [void] GetObjectData([System.Runtime.Serialization.SerializationInfo] $Info, [System.Runtime.Serialization.StreamingContext]$Context) {
        $Info.AddValue('Name', $this.Name)
        $Info.AddValue('Command', $this.Command)
        $Info.AddValue('aliases', $this.aliases)
    }
}
# gptOptions: Wrapp options in a class to make sure the user don't screw up in the config.
class gptOptions {
    [ValidateSet(
        'Text-davinci-003', # Most capable GPT-3 model. It can do any task the other models can do, often with higher quality, longer output, and better instruction-following. It also supports inserting completions within the text.
        'Text-curie-001', # Very capable, but faster and lower cost than Davinci.
        'Text-babbage-001', # Capable of straightforward tasks, very fast, and lower cost.
        'text-ada-001' # Capable of very simple tasks, usually the fastest model in the GPT-3 series, and lowest cost
    )][string]$model = 'text-davinci-003'
    [ValidateRange(0, 2)][decimal]$temperature = 1.0
    [ValidateRange(1, 2048)][int]$max_tokens = 256
    [ValidateRange(0, 1)][decimal]$top_p = 1.0
    [ValidateRange(-2, 2)][decimal]$frequency_penalty = 0
    [ValidateRange(-2, 2)][decimal]$presence_penalty = 0
    [ValidateNotNull()][object]$stop
    gptOptions() {
        $this.SetStop()
        $this.PsObject.Methods.Add([psscriptmethod]::new('GetStopSign', [scriptblock]::Create({ return [gptOptions]::GetStopSign() })))
    }
    gptOptions([string]$model) {
        $this.SetStop(); $this.model = $model
        $this.PsObject.Methods.Add([psscriptmethod]::new('GetStopSign', [scriptblock]::Create({ return [gptOptions]::GetStopSign() })))
    }
    gptOptions([string]$model, [int]$max_tokens) {
        $this.SetStop(); $this.model = $model; $this.max_tokens = $max_tokens
        $this.PsObject.Methods.Add([psscriptmethod]::new('GetStopSign', [scriptblock]::Create({ return [gptOptions]::GetStopSign() })))
    }
    hidden [void] SetStop() { $this.SetStop([ChatObject]::Get_Sender(), [ChatObject]::Get_Reciever()) }
    hidden [void] SetStop([string]$SenderName, [string]$RecieverName) {
        ([ChatObject]::SenderName, [ChatObject]::RecieverName) = ($SenderName, $RecieverName); $this.stop = [gptOptions]::GetStopSign().ToArray()
    }
    static [StopSign] GetStopSign() {
        # creates StopSigns with same length for better aligned when stringified.
        # ie: Run the follow~n snip~t what I mean by aligned:
        # [gptOptions]::new().GetStopSign() | fl
        $SendrN = [ChatObject]::SenderName; $RecvrN = [ChatObject]::RecieverName
        $d = $RecvrN.Length - $SendrN.Length; ($SendrN, $RecvrN) = if ($d -gt 0) { ($SendrN + ' ' * $d + ' : '), ($RecvrN + ' : ') } else { $d = $SendrN.Length - $RecvrN.Length; ($SendrN + ' : '), ($RecvrN + ' ' * $d + ' : ') }
        return [StopSign]::new($SendrN, $RecvrN)
    }
}
# Tells gpt where to stop. ie: thus where the message ends in the simulated chat
class StopSign {
    [ValidateNotNullOrEmpty()][string]$Sendr
    [ValidateNotNullOrEmpty()][string]$Recvr
    StopSign([string]$Sendr, [string]$Recvr) {
        $this.Sendr = $Sendr
        $this.Recvr = $Recvr
    }
    [string[]] ToArray() {
        return  [string[]]($this.Sendr, $this.Recvr)
    }
}
# Custom cli writer class and stuff
# .EXAMPLE
# [cli]::Preffix = [CipherTron]::Tmp.emojis.bot
# [void][cli]::Write('animations and stuff', [ConsoleColor]::Magenta)
class cli {
    static hidden [ValidateNotNull()][string]$Preffix
    static hidden [ValidateNotNull()][scriptblock]$textValidator # ex: if $text does not match a regex throw 'erro~ ..'
    static [string] write([string]$text) {
        return [cli]::Write($text, 20, 1200)
    }
    static [string] Write([string]$text, [bool]$AddPreffix) {
        return [cli]::Write($text, 20, 1200, $AddPreffix)
    }
    static [string] Write([string]$text, [int]$Speed, [int]$Duration) {
        return [cli]::Write($text, 20, 1200, $true)
    }
    static [string] write([string]$text, [ConsoleColor]$color) {
        return [cli]::Write($text, $color, $true)
    }
    static [string] write([string]$text, [ConsoleColor]$color, [bool]$Animate) {
        return [cli]::Write($text, [cli]::Preffix, 20, 1200, $color, $Animate, $true)
    }
    static [string] write([string]$text, [int]$Speed, [int]$Duration, [bool]$AddPreffix) {
        return [cli]::Write($text, [cli]::Preffix, $Speed, $Duration, [ConsoleColor]::White, $true, $AddPreffix)
    }
    static [string] write([string]$text, [ConsoleColor]$color, [bool]$Animate, [bool]$AddPreffix) {
        return [cli]::Write($text, [cli]::Preffix, 20, 1200, $color, $Animate, $AddPreffix)
    }
    static [string] write([string]$text, [string]$Preffix, [System.ConsoleColor]$color) {
        return [cli]::Write($text, $Preffix, $color, $true)
    }
    static [string] write([string]$text, [string]$Preffix, [System.ConsoleColor]$color, [bool]$Animate) {
        return [cli]::Write($text, $Preffix, 20, 1200, $color, $Animate, $true)
    }
    static [string] write([string]$text, [string]$Preffix, [int]$Speed, [int]$Duration, [bool]$AddPreffix) {
        return [cli]::Write($text, $Preffix, $Speed, $Duration, [ConsoleColor]::White, $true, $AddPreffix)
    }
    static [string] write([string]$text, [string]$Preffix, [int]$Speed, [int]$Duration, [ConsoleColor]$color, [bool]$Animate, [bool]$AddPreffix) {
        return [cli]::Write($text, $Preffix, $Speed, $Duration, $color, $Animate, $AddPreffix, [cli]::textValidator)
    }
    static [string] write([string]$text, [string]$Preffix, [int]$Speed, [int]$Duration, [ConsoleColor]$color, [bool]$Animate, [bool]$AddPreffix, [scriptblock]$textValidator) {
        if ($null -ne $textValidator) {
            $textValidator.Invoke($text)
        }
        if ([string]::IsNullOrWhiteSpace($text)) {
            return $text
        }
        [int]$length = $text.Length; $delay = 0
        # Check if delay time is required:
        $delayIsRequired = if ($length -lt 50) { $false } else { $delay = $Duration - $length * $Speed; $delay -gt 0 }
        if ($AddPreffix -and ![string]::IsNullOrEmpty($Preffix)) {
            [void][cli]::Write($Preffix, [string]::Empty, 1, 100, [ConsoleColor]::Green, $false, $false);
        }
        $FgColr = [Console]::ForegroundColor
        [Console]::ForegroundColor = $color
        if ($Animate) {
            for ($i = 0; $i -lt $length; $i++) {
                [void][Console]::Write($text[$i]);
                Start-Sleep -Milliseconds $Speed;
            }
        } else {
            [void][Console]::Write($text);
        }
        if ($delayIsRequired) {
            Start-Sleep -Milliseconds $delay
        }
        [Console]::ForegroundColor = $FgColr
        return $text
    }
}

class ParamBase : System.Reflection.ParameterInfo {
    [bool]$IsDynamic
    [System.Object]$Value
    [System.Collections.ObjectModel.Collection[string]]$Aliases
    [System.Collections.ObjectModel.Collection[System.Attribute]]$Attributes
    [System.Collections.Generic.IEnumerable[System.Reflection.CustomAttributeData]]$CustomAttributes
    ParamBase([string]$Name) { [void]$this.Create($Name, [System.Management.Automation.SwitchParameter], $null) }
    ParamBase([string]$Name, [type]$Type) { [void]$this.Create($Name, $Type, $null) }
    ParamBase([string]$Name, [System.Object]$value) { [void]$this.Create($Name, ($value.PsObject.TypeNames[0] -as 'Type'), $value) }
    ParamBase([string]$Name, [type]$Type, [System.Object]$value) { [void]$this.create($Name, $Type, $value) }
    ParamBase([System.Management.Automation.ParameterMetadata]$ParameterMetadata, [System.Object]$value) { [void]$this.Create($ParameterMetadata, $value) }
    hidden [ParamBase] Create([string]$Name, [type]$Type, [System.Object]$value) { return $this.Create([System.Management.Automation.ParameterMetadata]::new($Name, $Type), $value) }
    hidden [ParamBase] Create([System.Management.Automation.ParameterMetadata]$ParameterMetadata, [System.Object]$value) {
        $Name = $ParameterMetadata.Name; if ([string]::IsNullOrWhiteSpace($ParameterMetadata.Name)) { throw [System.ArgumentNullException]::new('Name') }
        $PType = $ParameterMetadata.ParameterType; [ValidateNotNullOrEmpty()][type]$PType = $PType;
        if ($null -ne $value) {
            try {
                $this.Value = $value -as $PType;
            } catch {
                $InnrEx = [System.Exception]::new()
                $InnrEx = if ($null -ne $this.Value) { if ([Type]$this.Value.PsObject.TypeNames[0] -ne $PType) { [System.InvalidOperationException]::New('Operation is not valid due to ambigious parameter types') }else { $innrEx } } else { $innrEx }
                throw [System.Management.Automation.SetValueException]::new("Unable to set value for $($this.ToString()) parameter.", $InnrEx)
            }
        }; $this.Aliases = $ParameterMetadata.Aliases; $this.IsDynamic = $ParameterMetadata.IsDynamic; $this.Attributes = $ParameterMetadata.Attributes;
        $this.PsObject.properties.add([psscriptproperty]::new('Name', [scriptblock]::Create("return '$Name'"), { throw "'Name' is a ReadOnly property." }));
        $this.PsObject.properties.add([psscriptproperty]::new('IsSwitch', [scriptblock]::Create("return [bool]$([int]$ParameterMetadata.SwitchParameter)"), { throw "'IsSwitch' is a ReadOnly property." }));
        $this.PsObject.properties.add([psscriptproperty]::new('ParameterType', [scriptblock]::Create("return [Type]'$PType'"), { throw "'ParameterType' is a ReadOnly property." }));
        $this.PsObject.properties.add([psscriptproperty]::new('DefaultValue', [scriptblock]::Create('return $(switch ($this.ParameterType) { ([bool]) { $false } ([string]) { [string]::Empty } ([array]) { @() } ([hashtable]) { @{} } Default { $null } }) -as $this.ParameterType'), { throw "'DefaultValue' is a ReadOnly property." }));
        $this.PsObject.properties.add([psscriptproperty]::new('RawDefaultValue', [scriptblock]::Create('return $this.DefaultValue.ToString()'), { throw "'RawDefaultValue' is a ReadOnly property." }));
        $this.PsObject.properties.add([psscriptproperty]::new('HasDefaultValue', [scriptblock]::Create('return $($null -ne $this.DefaultValue)'), { throw "'HasDefaultValue' is a ReadOnly property." })); return $this
    }
    [string] ToString() { $nStr = if ($this.IsSwitch) { '[switch]' }else { '[Parameter()]' }; return ('{0}${1}' -f $nStr, $this.Name) }
}

class CommandLineParser {
    CommandLineParser() {}
    # The Parse method takes an array of command-line arguments and parses them according to the parameters specified using AddParameter.
    # returns a dictionary containing the parsed values.
    #
    # $stream = @('str', 'eam', 'mm'); $filter = @('ffffil', 'llll', 'tttr', 'rrr'); $excludestr = @('sss', 'ddd', 'ggg', 'hhh'); $dkey = [consolekey]::S
    # $cliArgs = '--format=gnu -f- -b20 --quoting-style=escape --rmt-command=/usr/lib/tar/rmt -DeleteKey [consolekey]$dkey -Exclude [string[]]$excludestr -Filter [string[]]$filter -Force -Include [string[]]$IncludeStr -Recurse -Stream [string[]]$stream -Confirm -WhatIf'.Split(' ')
    static [System.Collections.Generic.Dictionary[String, ParamBase]] Parse([string[]]$cliArgs, [System.Collections.Generic.Dictionary[String, ParamBase]]$ParamBaseDict) {
        [ValidateNotNullOrEmpty()]$cliArgs = $cliArgs; [ValidateNotNullOrEmpty()]$ParamBaseDict = $ParamBaseDict; $paramDict = [System.Collections.Generic.Dictionary[String, ParamBase]]::new()
        for ($i = 0; $i -lt $cliArgs.Count; $i++) {
            $arg = $cliArgs[$i]; ($name, $IsParam) = switch ($true) {
                $arg.StartsWith('--') { $arg.Substring(2), $true; break }
                $arg.StartsWith('-') { $arg.Substring(1), $true; break }
                Default { $arg; $false }
            }
            if ($IsParam) {
                $lgcp = $name.Contains('=')
                if ($lgcp) { $name = $name.Substring(0, $name.IndexOf('=')) }
                $bParam_Index = $ParamBaseDict.Keys.Where({ $_ -match $name })
                $IsKnownParam = $null -ne $bParam_Index; $Param = if ($IsKnownParam) { $ParamBaseDict[$name] } else { $null }
                $IsKnownParam = $null -ne $Param
                if ($IsKnownParam) {
                    if (!$lgcp) {
                        $i++; $argVal = $cliArgs[$i]
                        if ($Param.ParameterType.IsArray) {
                            $arr = [System.Collections.Generic.List[Object]]::new()
                            while ($i -lt $cliArgs.Count -and !$cliArgs[$i].StartsWith('-')) {
                                $arr.Add($argVal); $i++; $argVal = $cliArgs[$i]
                            }
                            $paramDict.Add($name, [ParamBase]::New($name, $Param.ParameterType, $($arr.ToArray() -as $Param.ParameterType)))
                        } else {
                            $paramDict.Add($name, [ParamBase]::New($name, $Param.ParameterType, $argVal))
                        }
                    } else {
                        $i++; $argVal = $name.Substring($name.IndexOf('=') + 1)
                        $paramDict.Add($name, [ParamBase]::New($name, $Param.ParameterType, $argVal))
                    }
                } else { Write-Warning "[CommandLineParser] : Unknown parameter: $name" }
            }
        }
        return $paramDict
    }
    static [System.Collections.Generic.Dictionary[String, ParamBase]] Parse([string[]]$cliArgs, [System.Collections.Generic.Dictionary[System.Management.Automation.ParameterMetadata, object]]$ParamBase) {
        $ParamBaseDict = [System.Collections.Generic.Dictionary[String, ParamBase]]::New(); $ParamBase.Keys | ForEach-Object { $ParamBaseDict.Add($_.Name, [ParamBase]::new($_.Name, $_.ParameterType, $ParamBase[$_])) }
        return [CommandLineParser]::Parse($cliArgs, $ParamBaseDict)
    }
    # A method to convert parameter names from their command-line format (using dashes) to their property name format (using PascalCase).
    static hidden [string] MungeName([string]$name) {
        return [string]::Join('', ($name.Split('-') | ForEach-Object { $_.Substring(0, 1).ToUpper() + $_.Substring(1) }))
    }
}
class RecordTbl : RecordBase {
    static hidden [string] $caller = '[RecordTbl]'
    hidden [uri] $Remote # usually a gist uri
    hidden [string] $File
    [datetime] $LastWriteTime = [datetime]::Now
    RecordTbl() {
        $this.PsObject.properties.add([psscriptproperty]::new('Count', [scriptblock]::Create({ ($this | Get-Member -Type *Property).count - 2 })))
        $this.PsObject.properties.add([psscriptproperty]::new('Keys', [scriptblock]::Create({ ($this | Get-Member -Type *Property).Name.Where({ $_ -notin ('Keys', 'Count') }) })))
    }
    RecordTbl([hashtable[]]$array) {
        $this.Add($array)
        $this.PsObject.properties.add([psscriptproperty]::new('Count', [scriptblock]::Create({ ($this | Get-Member -Type *Property).count - 2 })))
        $this.PsObject.properties.add([psscriptproperty]::new('Keys', [scriptblock]::Create({ ($this | Get-Member -Type *Property).Name.Where({ $_ -notin ('Keys', 'Count') }) })))
    }
    [void] Edit() {
        $this.Set([RecordTbl]::EditFile([IO.FileInfo]::new($this.File)))
        $this.Save()
    }
    [void] Import([uri]$raw_uri) {
        try {
            $pass = $null; if ([string]::IsNullOrWhiteSpace([AesGCM]::caller)) { [AesGCM]::caller = [RecordTbl]::caller }
            Set-Variable -Name pass -Scope Local -Visibility Private -Option Private -Value $(if ([CryptoBase]::EncryptionScope.ToString() -eq "User") { Read-Host -Prompt "$([RecordTbl]::caller) Paste/write a Password to decrypt configs" -AsSecureString }else { [xconvert]::ToSecurestring([AesGCM]::GetUniqueMachineId()) })
            $_ob = [xconvert]::Deserialize([xconvert]::ToDeCompressed([AesGCM]::Decrypt([base85]::Decode($(Invoke-WebRequest $raw_uri -Verbose:$false).Content), $pass)))
            $this.Set([hashtable[]]$_ob.Keys.ForEach({ @{ $_ = $_ob.$_ } }))
        } catch {
            throw $_.Exeption
        } finally {
            Remove-Variable Pass -Force -ErrorAction SilentlyContinue
        }
    }
    [void] Upload() {
        if ([string]::IsNullOrWhiteSpace($this.Remote)) { throw [InvalidArgumentException]::new('remote') }
        # $gisturi = 'https://gist.github.com/' + $this.Remote.Segments[2] + $this.Remote.Segments[2].replace('/', '')
        # [GitHub]::UpdateGist($gisturi, $content)
    }
}
class User : System.Runtime.Serialization.ISerializable {
    [string]$Name
    [ValidateNotNull()][RecordTbl]$preferences
    hidden [ValidateNotNull()][string]$PublicKey
    hidden [ValidateNotNull()][securestring]$Password
    hidden [ValidateNotNull()][string]$PrivateKeyHash

    User([string]$Name) {
        $this.Name = $Name
        $default_Preferences = @{
            Quick_Exit   = $false
            Avatar_Emoji = '🗿'
        }
        $this.preferences = [RecordTbl]::new($default_Preferences)
    }
    User([string]$name, [string]$passw0rd, [string]$publicKey, [securestring]$privateKey) {
        $this.Name = $name
        $this.Password = [xconvert]::TosecureString($passw0rd)
        $this.PublicKey = $publicKey
        $this.PrivateKeyHash = '' # = [xconvert]::ToString($privateKey)
        $default_Preferences = @{
            Quick_Exit   = $false
            Avatar_Emoji = '🗿'
        }
        $this.preferences = [RecordTbl]::new($default_Preferences)
    }
    User([System.Runtime.Serialization.SerializationInfo]$Info, [System.Runtime.Serialization.StreamingContext]$Context) {
        $this.Name = $Info.GetValue('Name', [string])
        $this.Password = $Info.GetValue('Password', [securestring])
        $this.PublicKey = $Info.GetValue('PublicKey', [string])
        $this.preferences = $Info.GetValue('preferences', [RecordTbl])
        $this.PrivateKeyHash = $Info.GetValue('PrivateKeyHash', [string])
    }
    [void] GetObjectData([System.Runtime.Serialization.SerializationInfo]$Info, [System.Runtime.Serialization.StreamingContext]$Context) {
        $Info.AddValue('Name', $this.Name)
        $Info.AddValue('preferences', $this.preferences)
        $Info.AddValue('PublicKey', $this.PublicKey)
        $Info.AddValue('Password', $this.Password)
        $Info.AddValue('PrivateKeyHash', $this.PrivateKeyHash)
    }
    [void] Hash() {
        #TODO: Write this interactive hashing process:
        # 1. The user initiates the interactive hashing process by typing a command into the console or chat bot. For example, they might type "hash" or "interactive hash".
        # 2. The chat bot responds with a prompt asking the user to input the message they wish to hash.
        # 3. The user types in the message they want to hash and presses enter.
        # 4. The chat bot then asks the user to select a hashing algorithm. It could provide a list of available algorithms, or allow the user to input the name of the algorithm they want to use.
        # 5. Once the user has selected an algorithm, the chat bot performs the hash on the message and displays the resulting hash to the user.
        # 6. The chat bot may give the user the option to save the hash to a file or clipboard.
        # 7. If the user wants to hash another message, they can repeat the process by typing the command again.
        throw 'hash Method not ready Yet!'
    }
    [string] Sign() {
        #TODO: Write this interactive digital signature process:
        # Using New-DigitalSignature
        # 1. Generate a public-private key pair:
        #    - Generate a private key that will be kept secret and only used by the owner of the key pair.
        #    - Generate a public key that can be shared with anyone who needs to verify the digital signature.
        # 2. Create the message that needs to be signed.
        # 3. Hash the message using a secure hash function like SHA-256.
        # 4. Use the private key to encrypt the hash, creating a digital signature.
        # 5. Send the message and the digital signature to the recipient.
        #
        # The recipient will use the public key to decrypt the digital signature and obtain the hash value.
        # The recipient will hash the message again using the same hash function.
        # The recipient will compare the two hash values:
        #    - If they match, the message has not been altered since it was signed, and the digital signature is considered valid.
        #    - If they do not match, the message has been altered, and the digital signature is considered invalid.
        throw 'sign Method not ready Yet!'
    }
    [string] Sign([string]$text, [string]$privateKey) {
        # Signs the given input using the specified private key and returns the signature
        return ''
    }
    # Method to verify data signature using the user's public key
    [bool] Verify([string]$text, [string]$signature, [string]$publicKey) {
        # TODO: Implement signature verification logic using user's public key
        # Verifies the given input with the specified signature using the specified public key and returns true if the verification is successful, false otherwise
        return $false
    }
    [string] NewPassword() {
        #TODO: Write this interactive password generation process:
        # using: New-Password -AsPlainText
        # 1. Prompt the user for the desired length of the password
        # 2. Generate a random password string of the desired length, using a combination of uppercase letters, lowercase letters, numbers, and special characters
        # 3. Display the generated password to the user
        # 4. Ask the user if they want to use the generated password or generate another one
        # 5. If the user wants to generate another password, repeat the process from step 1, otherwise exit the function
        return $(New-Password -AsPlainText)
    }
    # Method to encrypt data using the user's public key
    [void] Encrypt() {
        #TODO: Write this interactive encryption Process:
        # 1. The user inputs the plaintext to be encrypted via the console.
        # 2. The chat bot prompts the user to choose an encryption algorithm, such as AES or RSA, and asks for any required encryption parameters, such as key size or passphrase.
        [cli]::Write('Please answer all questions marked *');
        # 3. The chat bot encrypts the plaintext using the chosen algorithm and parameters.
        # 4. The chat bot displays the encrypted data to the user in a way that is easy to copy and paste or save.
        # 5. Optionally, the chat bot may ask the user if they want to save the encrypted data to a file or clipboard.
        # $encryptor = [Encryptor]::new($bytesToEncrypt, [securestring]$Password, [byte]$salt, [CryptoAlgorithm]$Algorithm);
        # $encrypted = $encryptor.encrypt();
        throw 'Encrypt Method not ready Yet!'
    }
    # Method to decrypt data using the user's private key
    [void] Decrypt() {
        #TODO: Write this interactive decryption Process:
        # 1. The user inputs the encrypted data.
        # 2. The chatbot prompts the user for the secret key/password used to encrypt the data.
        # 3. The chatbot uses the same decryption algorithm (e.g. AES-256-CBC) and secret key to decrypt the data.
        # 4. The decrypted data is displayed to the user.
        # $decryptor = [Decryptor]::new($bytesToDecrypt, [securestring]$Password, [byte]$salt, [CryptoAlgorithm]$Algorithm);
        # $decrypted = $Decryptor.encrypt()
        throw 'Decrypt Method not ready Yet!'
    }
    [string] ToString() {
        return $this.Name
    }
}
class ChatSession : System.Runtime.Serialization.ISerializable {
    [ValidateNotNullOrEmpty()][User]$User
    [ValidateNotNullOrEmpty()][guid]$ChatUid
    [ValidateNotNull()][ChatLog]$ChatLog
    hidden [ValidateNotNull()][System.IO.FileInfo]$File

    ChatSession() {
        $this.User = [User]::new([Environment]::UserName);
        $this.ChatLog = [ChatLog]::new()
        $this.ChatUid = $this.GetChatUid()
        $this.File = [System.IO.FileInfo]::new([IO.Path]::Combine([CipherTron]::Get_dataPath(), $this.ChatUid.ToString() + '.chat'))
    }
    ChatSession([string]$FilePath) {
        $sn = [ChatSessionManager]::TryParse($FilePath)
        $this.User = $sn.User;
        $this.ChatUid = $sn.ChatUid
        $this.ChatLog = $sn.ChatLog
        $this.File = $sn.File
    }
    ChatSession([User]$user, [ChatLog]$ChatLog) {
        $this.User = $user; $this.ChatLog = $ChatLog
        $this.ChatUid = $this.GetChatUid()
        $this.File = [System.IO.FileInfo]::new([IO.Path]::Combine([CipherTron]::Get_dataPath(), $this.ChatUid.ToString() + '.chat'))
    }
    ChatSession([System.Runtime.Serialization.SerializationInfo]$Info, [System.Runtime.Serialization.StreamingContext]$Context) {
        $this.User = $Info.GetValue('Length', [User])
        $this.ChatUid = $Info.GetValue('ChatUid', [guid])
        $this.ChatLog = $Info.GetValue('ChatLog', [ChatLog])
        $this.File = $Info.GetValue('File', [System.IO.FileInfo])
    }
    [void] GetObjectData([System.Runtime.Serialization.SerializationInfo]$Info, [System.Runtime.Serialization.StreamingContext]$Context) {
        $Info.AddValue('User', $this.User)
        $Info.AddValue('ChatUid', $this.ChatUid)
        $Info.AddValue('ChatLog', $this.ChatLog)
        $Info.AddValue('File', $this.File)
    }
    [string] GetSummary() {
        # Returns a summary of the session, including the user, start time, and number of messages.
        return "User: $($this.User.Name)`nStart Time: $($this.ChatLog.StartTime)`nNumber of Messages: $($this.ChatLog.Messages.Count)"
    }
    [string] GetChatUid() {
        $n = $this.User.Name
        return [guid][xconvert]::ToGuid(
            [System.Convert]::ToBase64String(
                [CryptoBase]::GetDerivedBytes(
                    [xconvert]::ToSecurestring(
                        $(if ($n.Length -gt 5) { $n.Substring(0, 5) } else { $n }) + ':' + (
                            [int]([Datetime]::Now.ToUniversalTime() - (Get-Date -Date '1970-01-01T00:00:00Z')).TotalSeconds
                        )
                    )
                )
            ).Substring(0, 16)
        )
    }
    [void] Save() {
        $Out = [System.Text.StringBuilder]::new();
        $Out.Append($this.User.Name); $Out.Append(':'); $Out.AppendLine([string]$this.ChatUid.Guid);
        # [system.Text.Encoding]::UTF8.GetBytes()
        $Out.Append([xconvert]::ToCompressed([convert]::ToBase64String([xconvert]::BytesFromObject([xconvert]::ToPSObject($this)))));
        $Out = $Out.Tostring()
        [IO.File]::WriteAllText($this.File.FullName , $Out, [system.text.encoding]::UTF8)
    }
}
#endregion MainClass

#region    Functions
function Start-Ciphertron {
    [CmdletBinding(SupportsShouldProcess = $true)]
    [Alias('CipherTron')]
    param ()

    begin {
        $bot = [CipherTron]::new()
    }

    process {
        if ($PSCmdlet.ShouldProcess('Starting Chat', '', '')) {
            $bot.Chat()
        }
    }

    end {}
}

function Edit-CiphertronConfig {
    <#
    .SYNOPSIS
        Edits the config file for CipherTron
    .DESCRIPTION
        A longer description of the function, its purpose, common use cases, etc.
    .NOTES
        Information or caveats about the function e.g. 'This function is not supported in Linux'
    .LINK
        Specify a URI to a help page, this will show when Get-Help -Online is used.
    .EXAMPLE
        In terminal tab 1:
            Ciphertron
            ... The chat starts. but you want to change some settings without restarting the chat.
            ... [Option 1] type 'EditConfig' in the chat (When this command ends the bot refresh configs on its own).
                [Option 2] You can use this function in another tab
        In terminal tab 2:
            Edit-CiphertronConfig
            ... Folow the on screen instruction, edit the settings and, go back to tab 1 and type 'refreshConfig' in the chat
                This gives same result as [Option 1]
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param ([string]$Config)

    begin {}

    process {
        if ($PSCmdlet.ShouldProcess("Editing $Config", '', '')) {
            [CipherTron]::EditConfig()
        }
    }

    end {}
}
function New-DigitalSignature {
    <#
    .SYNOPSIS
    Creates a digital signature.

    .DESCRIPTION
    Generates a digital signature for a file using a private key.

    .PARAMETER FilePath
    The path to the file to be signed.

    .PARAMETER PrivateKeyPath
    The path to the private key file to use for signing.

    .PARAMETER SignatureOutputPath
    The path where the generated signature will be saved.

    .NOTES
    The signature will be generated using the SHA256 hash algorithm and the RSA public-key cryptosystem.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string]$PrivateKeyPath,

        [Parameter(Mandatory = $true)]
        [string]$SignatureOutputPath
    )

    begin {}

    process {
        if ($PSCmdlet.ShouldProcess("Target", "Operation")) {
            Write-Verbose ""
        }
    }

    end {}
}
function New-K3Y {
    <#
    .SYNOPSIS
        Creates a new [K3Y] object
    .DESCRIPTION
        Creates a custom k3y object for encryption/decryption.
        The K3Y can only be used to Once, and its 'UID' [ see .SetK3YUID() method ] is a fancy way of storing the version, user/owner credentials, Compression alg~tm used and Other Info
        about the most recent use and the person who used it; so it can be analyzed later to verify some rules before being used again. this allows to create complex expiring encryptions.
    .EXAMPLE
        $K = New-K3Y (Get-Credential -UserName 'Alain Herve' -Message 'New-K3Y')
    .NOTES
        This is a private function, its not meant to be exported, or used alone
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = '')]
    [CmdletBinding(DefaultParameterSetName = 'default')]
    [OutputType([K3Y], [string])]
    param (
        # Parameter help description
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName = 'byPscredential')]
        [Alias('Owner')][ValidateNotNull()]
        [pscredential]$User,

        # Parameter help description
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName = 'default')]
        [string]$UserName,

        # Parameter help description
        [Parameter(Position = 1, Mandatory = $false, ParameterSetName = 'default')]
        [securestring]$Password,

        # Expiration date
        [Parameter(Position = 2, Mandatory = $false, ParameterSetName = 'default')]
        [Parameter(Position = 1, Mandatory = $false, ParameterSetName = 'byPscredential')]
        [datetime]$Expiration,

        # Convert to string (sharable)
        [Parameter(Mandatory = $false, ParameterSetName = '__AllParameterSets')]
        [switch]$AsString,

        [Parameter(Mandatory = $false, ParameterSetName = '__AllParameterSets')]
        [switch]$Protect
    )

    begin {
        $k3y = $null
        $params = $PSCmdlet.MyInvocation.BoundParameters
        $IsInteractive = [Environment]::UserInteractive -and [Environment]::GetCommandLineArgs().Where({ $_ -like '-NonI*' }).Count -eq 0
    }
    process {
        $k3y = $(if ($PSCmdlet.ParameterSetName -eq 'byPscredential') {
                if ($params.ContainsKey('User') -and $params.ContainsKey('Expiration')) {
                    [K3Y]::New($User, $Expiration);
                } else {
                    # It means: $params.ContainsKey('User') -and !$params.ContainsKey('Expiration')
                    [datetime]$ExpiresOn = if ($IsInteractive) {
                        [int]$days = Read-Host -Prompt "Expires In (replie num of days)"
                        [datetime]::Now + [Timespan]::new($days, 0, 0, 0);
                    } else {
                        [datetime]::Now + [Timespan]::new(30, 0, 0, 0); # ie: expires in 30days
                    }
                    [K3Y]::New($User, $ExpiresOn);
                }
            } elseif ($PSCmdlet.ParameterSetName -eq 'default') {
                if ($params.ContainsKey('UserName') -and $params.ContainsKey('Password') -and $params.ContainsKey('Expiration')) {
                    [K3Y]::New($UserName, $Password, $Expiration);
                } elseif ($params.ContainsKey('UserName') -and $params.ContainsKey('Password') -and !$params.ContainsKey('Expiration')) {
                    [K3Y]::New($UserName, $Password);
                } elseif ($params.ContainsKey('UserName') -and !$params.ContainsKey('Password') -and !$params.ContainsKey('Expiration')) {
                    $passwd = if ($IsInteractive) { Read-Host -AsSecureString -Prompt "Password" } else { [securestring]::new() }
                    [K3Y]::New($UserName, $passwd);
                } elseif (!$params.ContainsKey('UserName') -and $params.ContainsKey('Password') -and !$params.ContainsKey('Expiration')) {
                    $usrName = if ($IsInteractive) { Read-Host -Prompt "UserName" } else { [System.Environment]::GetEnvironmentVariable('UserName') }
                    [K3Y]::New($usrName, $Password);
                } elseif (!$params.ContainsKey('UserName') -and !$params.ContainsKey('Password') -and $params.ContainsKey('Expiration')) {
                    if ($IsInteractive) {
                        $usrName = Read-Host -Prompt "UserName"; $passwd = Read-Host -AsSecureString -Prompt "Password";
                        [K3Y]::New($usrName, $passwd);
                    } else {
                        [K3Y]::New($Expiration);
                    }
                } elseif (!$params.ContainsKey('UserName') -and $params.ContainsKey('Password') -and $params.ContainsKey('Expiration')) {
                    $usrName = if ($IsInteractive) { Read-Host -Prompt "UserName" } else { [System.Environment]::GetEnvironmentVariable('UserName') }
                    [K3Y]::New($usrName, $Password, $Expiration);
                } else {
                    [K3Y]::New();
                }
            } else {
                Write-Verbose "System.Management.Automation.ParameterBindingException: Could Not Resolve ParameterSetname."
                [K3Y]::New();
            }
        )
        if ($Protect.IsPresent) { $k3y.User.Protect() };
    }

    end {
        if ($AsString.IsPresent) {
            return [xconvert]::Tostring($k3y)
        }
        return $k3y
    }
}
#region     Encrpt-Decrp
function Get-EncryptionAlgorithm {
    <#
    .SYNOPSIS
        Used to set the encryption algorithm that will be used by other functions in the CipherTron module to encrypt and decrypt data.
    .DESCRIPTION
        A longer description of the function, its purpose, common use cases, etc.
    .NOTES
        Information or caveats about the function e.g. 'This function is not supported in Linux'
    .LINK
        https://github.com/alainQtec/CipherTron/blob/main/Public/Encrpt_Decrpt/Get-EncryptionAlgorithm.ps1
    .EXAMPLE
        Get-EncryptionAlgorithm -key "dsfjkmsjkfnsdkcnmdimsidfcsdcmsdlkxiddsdcmsdlcdlilsdldd "
        Explanation of the function or its result. You can include multiple examples with additional .EXAMPLE lines
    #>
    [CmdletBinding(DefaultParameterSetName = 'default')]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'default')]
        [string]$key,

        [Parameter(Mandatory = $true, ParameterSetName = 'k')]
        [K3Y]$k3y
    )

    begin {
        $algorthm = [String]::Empty
    }

    process {
        # Parse the Object to return the Name of encryption Algorithm
    }

    end {
        return $algorthm
    }
}

function Encrypt-Object {
    <#
    .SYNOPSIS
        Applies several paranoid encryptions to an Object or a file.
    .DESCRIPTION
        Encryption can be applied to any item that can be converted to a byte array.
        This function may currently encrypt Objects (i.e. "System.Object") and files.
        The function employs Rijndael AES-256, Rivest-Shamir-Adleman encryption (RSA), MD5 Triple D.E.S, and other algorithms.
        Yeah, It gets Pretty paranoid!

        There is an option to store your encryption key(s) in Windows Password vault so that the
        Decryptor Function (Decrypt-Object) can use them without need of your input again.
    .NOTES
        # Some Points to Consider When Using This function:

        1. If you don't feel safe when typing or sending sensitive info to the terminal/console or via RMM,
        Then its better to use some nerdy function that uses the best well known/tested/approved standard algorithms
        That way, you know your data is secure enough. This was the whole reason why I created this function.

        2. One of this script's flaws is that it is a script (a non-obfuscated, cleartext script!).
        If you or some hacker can't get the password but have the source code you can reverse engineer to findout why you are not getting clear output.
        Thus allowing to bruteforce untill you get cleartext. Although I doubt that AES-256-GCM can be brute forced if you used a strong Password.
        Even though that eventuality is unlikely, ensure that the source code (Modified Version of this Script or anything...) is never leaked in production.
        Perhaps compile it to an encrypted binary or something.

        3. Sometimes even your local password vault is not secure enough!
        i.e: Read: https://www.hackingarticles.in/credential-dumping-windows-credential-manager/
        So If you feel unsafe Retrieve your stuff from WindowsCredentialManager, Store them on a Goober or somethin
        Then clean your local vault, ie:
        if (-not [bool]("Windows.Security.Credentials.PasswordVault" -as 'type';)) { [Windows.Security.Credentials.PasswordVault, Windows.Security.Credentials, ContentType = WindowsRuntime] }

        $vault = [Windows.Security.Credentials.PasswordVault]::new()
        # Suppose you have stuff in your vault. ex:
        # $vault.Add([Windows.Security.Credentials.PasswordCredential]::new(';MySecretPlan';, $(whoami), "#Test`nThis is my secret Plan written in MarkDown..."))

        $VaultContent = $vault.RetrieveAll() | select resource, userName | % {$vault.Retrieve($_.Resource, $_.UserName)} | select UserName, Resource, @{l=';Content';; e={$_.Password}};
        $VaultContent | ConvertTo-Json | Set-Content -Path $PathtoMyGoober\MyLocalVault_Export.json -Encoding UTF8
        $(Get-Item $PathtoMyGoober\MyLocalVault_Export.json).Encrypt();
        $vault.RetrieveAll() | % { $vault.Remove($vault.Retrieve($_.Resource, $_.UserName)); Write-verbose "[i] Removed $($_.Resource)" }
    .LINK
        https://github.com/alainQtec/CipherTron/blob/main/Private/CipherTron.Core/CipherTron.Core.psm1
    .EXAMPLE
        $enc = Encrypt-Object -Object "Hello World!" -Password $([ArgonCage]::GetPassword()) -KeyOutFile .\PublicKee.txt
        $dec = Decrypt-Object -InputBytes $enc -Password $([ArgonCage]::GetPassword()) -PublicKey $(cat .\PublicKee.txt)
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Justification = 'Prefer verb usage')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingConvertSecurestringWithPlainText", '')]
    [CmdletBinding(ConfirmImpact = "Medium", DefaultParameterSetName = 'WithSecureKey')]
    [Alias('Encrypt')]
    [OutputType([byte[]])]
    param (
        # The Object you want to encrypt
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = '__AllParameterSets')]
        [Alias('InputObj')]
        $Object,

        # Use a strong password. It will be used Lock Your local Key (ConvertTo-SecureString -String "Message" -SecureKey [System.Security.SecureString]) before storing in vault.
        # Add this if you want 3rd layer of security. Useful when someone(Ex: Hacker) has somehow gained admin priviledges of your PC;
        # With a locked local Password vault it will require much more than just guessing The password, or any BruteForce tool.
        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = 'WithSecureKey')]
        [Alias('Password', 'Securestring')]
        [SecureString]$PrivateKey = [ArgonCage]::GetPassword(),

        [Parameter(Mandatory = $false, Position = 2, ParameterSetName = '__AllParameterSets')]
        [ValidateNotNullOrEmpty()]
        [string]$PublicKey,

        # Source or the Encryption Key. Full/Path of the keyfile you already have. It will be used to lock your keys. (ConvertTo-SecureString -String "Message" -Key [Byte[]])
        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = 'WithKey')]
        [ValidateNotNullOrEmpty()]
        [Byte[]]$Key,

        # Path OF the KeyFile (Containing You saved key base64String Key)
        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = 'WithKeyFile')]
        [ValidateNotNullOrEmpty()]
        [string]$KeyFile,

        # FilePath to store your keys. Saves keys as base64 in an enrypted file. Ex: some_random_Name.key (Not recomended)
        [Parameter(Mandatory = $false, Position = 3, ParameterSetName = '__AllParameterSets')]
        [ValidateNotNullOrEmpty()]
        [Alias('ExportFile')]
        [string]$KeyOutFile,

        # How long you want the encryption to last. Default to one month (!Caution Your data will be LOST Forever if you do not decrypt before the Expiration date!)
        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = 'WithVault')]
        [Parameter(Mandatory = $false, Position = 4, ParameterSetName = 'WithKey')]
        [Parameter(Mandatory = $false, Position = 3, ParameterSetName = 'WithPlainKey')]
        [Parameter(Mandatory = $false, Position = 3, ParameterSetName = 'WithSecureKey')]
        [ValidateNotNullOrEmpty()]
        [Alias('KeyExpiration')]
        [datetime]$Expiration = ([Datetime]::Now + [TimeSpan]::new(30, 0, 0, 0)),

        [Parameter(Mandatory = $false, Position = 4, ParameterSetName = 'WithSecureKey')]
        [Parameter(Mandatory = $false, Position = 4, ParameterSetName = 'WithPlainKey')]
        [Parameter(Mandatory = $false, Position = 4, ParameterSetName = 'WithVault')]
        [Parameter(Mandatory = $false, Position = 5, ParameterSetName = 'WithKey')]
        [ValidateNotNullOrEmpty()]
        [int]$Iterations = 2,

        [Parameter(Mandatory = $false, Position = 6, ParameterSetName = '__AllParameterSets')]
        [ValidateScript({
                if ([Enum]::GetNames([CryptoAlgorithm]).Contains($_)) {
                    return $true
                }
                throw 'Invalid CryptoAlgorithm'
            }
        )][Alias('CryptoAlgorithm')]
        [ValidateNotNullOrEmpty()]
        [string]$Algorithm
    )

    DynamicParam {
        $DynamicParams = [System.Management.Automation.RuntimeDefinedParameterDictionary]::new()
        [bool]$IsPossiblefileType = $false
        [bool]$IsArrayObject = $false
        [int]$P = 7 #(Position)
        try {
            if ($Object.count -gt 1) {
                $InputType = @()
                $IsArrayObject = $true
                foreach ($Obj in $Object) {
                    $InputType += $Obj.GetType()
                }
                $InputType = $InputType | Sort-Object -Unique
            } else {
                $InputType = $Object.GetType()
            }
        } catch { $InputType = [string]::Empty }
        $IsPossiblefileTypes = @('string', 'string[]', 'System.IO.FileInfo', 'System.IO.FileInfo[]', 'System.Object', 'System.Object[]')
        if ($IsArrayObject) {
            foreach ($type in $InputType) {
                $IsPossiblefileType = [bool]($type -in $IsPossiblefileTypes) -or $IsPossiblefileType
            }
        } else {
            $IsPossiblefileType = [bool]($InputType -in $IsPossiblefileTypes)
        }
        #region OutFile
        if ($IsPossiblefileType) {
            $attributeCollection = [System.Collections.ObjectModel.Collection[System.Attribute]]::new()
            $attributes = [System.Management.Automation.ParameterAttribute]::new(); $attHash = @{
                Position                        = $P
                ParameterSetName                = '__AllParameterSets'
                Mandatory                       = $False
                ValueFromPipeline               = $false
                ValueFromPipelineByPropertyName = $false
                ValueFromRemainingArguments     = $false
                HelpMessage                     = 'Use to specify Output File, if inputObject is a file.'
                DontShow                        = $False
            }; $attHash.Keys | ForEach-Object { $attributes.$_ = $attHash.$_ }
            $attributeCollection.Add($attributes);
            $attributeCollection.Add([System.Management.Automation.ValidateNotNullOrEmptyAttribute]::new())
            $attributeCollection.Add([System.Management.Automation.AliasAttribute]::new([System.String[]]('OutPutFile', 'DestinationFile')))
            $RuntimeParam = [System.Management.Automation.RuntimeDefinedParameter]::new("OutFile", [Object], $attributeCollection)
            $DynamicParams.Add("OutFile", $RuntimeParam)
            $P++
        }
        #endregion OutFile

        #region IgnoredArguments
        $attributeCollection = [System.Collections.ObjectModel.Collection[System.Attribute]]::new()
        $attributes = [System.Management.Automation.ParameterAttribute]::new(); $attHash = @{
            Position                        = $P
            ParameterSetName                = '__AllParameterSets'
            Mandatory                       = $False
            ValueFromPipeline               = $true
            ValueFromPipelineByPropertyName = $true
            ValueFromRemainingArguments     = $true
            HelpMessage                     = 'Allows splatting with arguments that do not apply. Do not use directly.'
            DontShow                        = $False
        }; $attHash.Keys | ForEach-Object { $attributes.$_ = $attHash.$_ }
        $attributeCollection.Add($attributes)
        $RuntimeParam = [System.Management.Automation.RuntimeDefinedParameter]::new("IgnoredArguments", [Object[]], $attributeCollection)
        $DynamicParams.Add("IgnoredArguments", $RuntimeParam)
        #endregion IgnoredArguments
        return $DynamicParams
    }

    begin {
        $eap = $ErrorActionPreference; $ErrorActionPreference = "SilentlyContinue"
        $PsCmdlet.MyInvocation.BoundParameters.GetEnumerator() | ForEach-Object { New-Variable -Name $_.Key -Value $_.Value -ea 'SilentlyContinue' }
        $PsW = [securestring]::new(); $nc = $null;
        $fxn = ('[' + $MyInvocation.MyCommand.Name + ']')
        $ExportsPNK = $PsCmdlet.MyInvocation.BoundParameters.ContainsKey('KeyOutFile') -and ![string]::IsNullOrEmpty($KeyOutFile)
        if ($PsCmdlet.ParameterSetName -ne 'WithKey' -and !$ExportsPNK) {
            throw 'Plese specify PublicKey "ExportFile/Outfile" Parameter.'
        }
        # Write-Invocation $MyInvocation
    }

    process {
        Write-Verbose "[+] $fxn $($PsCmdlet.ParameterSetName) ..."
        Set-Variable -Name PsW -Scope Local -Visibility Private -Option Private -Value $(switch ($PsCmdlet.ParameterSetName) {
                'WithKey' {  }
                'WithVault' {  }
                'WithSecureKey' { $PrivateKey }
                Default {
                    throw 'Error!'
                }
            }
        );
        Set-Variable -Name nc -Scope Local -Visibility Private -Option Private -Value $([CipherTron]::new($Object));
        if ($PsCmdlet.MyInvocation.BoundParameters.ContainsKey('Expiration')) { $nc.key.Expiration = [Expiration]::new($Expiration) }
        if ($PsCmdlet.MyInvocation.BoundParameters.ContainsKey('PublicKey')) {
            $nc.SetPNKey($PublicKey);
        } else {
            Write-Verbose "[+] Create PublicKey (K3Y) ...";
            $PNK = New-K3Y -UserName $nc.key.User.UserName -Password $PsW -Expiration $nc.key.Expiration.date -AsString -Protect
            $nc.SetPNKey($PNK);
        }
        $encryptor = [Encryptor]::new($bytesToEncrypt, [securestring]$Password, [byte[]]$salt, [CryptoAlgorithm]$Algorithm);
        $encrypted = $encryptor.encrypt($Iterations);
        $bytes = $encrypted
        if ($ExportsPNK) {
            Write-Verbose "[i] Export PublicKey (PNK) to $KeyOutFile ..."
            $nc.key.Export($KeyOutFile, $true);
        }
        $bytes = $(if ($bytes.Equals($nc.Object.Bytes)) { $null }else { $nc.Object.Bytes })
    }

    end {
        $ErrorActionPreference = $eap
        return $bytes
    }
}
function Decrypt-Object {
    <#
    .SYNOPSIS
        Decryts Objects or files.
    .DESCRIPTION
        A longer description of the function, its purpose, common use cases, etc.
    .NOTES
        Caveats about the function: 'This function is not fully supported in Linux'
    .LINK
        Specify a URI to a help page, this will show when Get-Help -Online is used.
    .EXAMPLE
        $msg = "My email: alain.1337dev@outlook.com"
        $enc = Encrypt-Object $msg -Password $([ArgonCage]::GetPassword()) -KeyOutFile .\PublicKee.txt
        $dec = Decrypt-Object $enc -Password $([ArgonCage]::GetPassword()) -PublicKey $(cat .\PublicKee.txt)
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Justification = 'Prefer verb usage')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingConvertSecurestringWithPlainText", '')]
    [CmdletBinding(ConfirmImpact = "Medium", DefaultParameterSetName = 'WithSecureKey')]
    [Alias('Decrypt')]
    [OutputType([byte[]])]
    param (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = '__AllParameterSets')]
        [ValidateNotNullOrEmpty()]
        [Alias('Bytes')]
        [byte[]]$InputBytes,

        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = 'WithSecureKey')]
        [ValidateNotNullOrEmpty()]
        [Alias('Password')]
        [SecureString]$PrivateKey = [ArgonCage]::GetPassword(),

        [Parameter(Mandatory = $true, Position = 2, ParameterSetName = '__AllParameterSets')]
        [ValidateNotNullOrEmpty()]
        [string]$PublicKey,

        # Source or the Encryption Key. Full/Path of the keyfile you already have. It will be used to lock your keys. (ConvertTo-SecureString -String "Message" -Key [Byte[]])
        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = 'WithKey')]
        [ValidateNotNullOrEmpty()]
        [Byte[]]$Key,

        # Path OF the KeyFile (Containing You saved key base64String Key)
        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = 'WithKeyFile')]
        [ValidateNotNullOrEmpty()]
        [string]$KeyFile,

        [Parameter(Mandatory = $false, Position = 4, ParameterSetName = '__AllParameterSets')]
        [ValidateNotNullOrEmpty()]
        [int]$Iterations = 2,

        [Parameter(Mandatory = $false, Position = 5, ParameterSetName = '__AllParameterSets')]
        [ValidateScript({
                if ([Enum]::GetNames([CryptoAlgorithm]).Contains($_)) {
                    return $true
                }
                throw 'Invalid CryptoAlgorithm'
            }
        )][Alias('CryptoAlgorithm')]
        [ValidateNotNullOrEmpty()]
        [string]$Algorithm
    )

    begin {
        $eap = $ErrorActionPreference; $ErrorActionPreference = "SilentlyContinue"
        $fxn = ('[' + $MyInvocation.MyCommand.Name + ']');
        # Write-Invocation $MyInvocation
    }

    process {
        Write-Verbose "[+] $fxn $($PsCmdlet.ParameterSetName) ..."
        $PsW = switch ($PsCmdlet.ParameterSetName) {
            'WithKey' {  }
            'WithVault' {  }
            'WithSecureKey' { $PrivateKey }
            Default {
                [CipherTron]::new()
            }
        }
        $salt = [byte[]]::new()
        $decryptor = [Decryptor]::new($InputBytes, [securestring]$PsW, [byte[]]$salt, [CryptoAlgorithm]$Algorithm);
        $decrypted = $Decryptor.encrypt($Iterations);
        $bytes = $decrypted
        if ($PsCmdlet.ParameterSetName -ne 'WithKey' -and $PsCmdlet.MyInvocation.BoundParameters.ContainsKey('KeyOutFile')) {
            if (![string]::IsNullOrEmpty($KeyOutFile)) {
                Write-Verbose "[i] Export PublicKey (PNK) to $KeyOutFile ..."
                $nc.key.Export($KeyOutFile, $true)
            }
        }
        $bytes = $(if ($bytes.Equals($nc.Object.Bytes)) { $null }else { $nc.Object.Bytes })
    }

    end {
        $ErrorActionPreference = $eap
        return $bytes
    }
}
function Protect-Data {
    <#
    .SYNOPSIS
        Protects Data so that it won't be decipherd unless by on that same PC
    .DESCRIPTION
        A longer description of the function, its purpose, common use cases, etc.
    .NOTES
        Information or caveats about the function e.g. 'This function is not fully supported in Linux'
    .LINK
        https://github.com/alainQtec/CipherTron/blob/main/Private/CipherTron.Core/CipherTron.Core.psm1
    .EXAMPLE
        [securestring]$sec = Protect-Data $(Read-Host -AsSecurestring -Prompt 'Secret msg')
    #>
    [CmdletBinding(ConfirmImpact = "Medium", DefaultParameterSetName = 'String', SupportsShouldProcess = $true)]
    [Alias('Protect')]
    [OutputType([Object[]])]
    param (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'String')]
        [ValidateNotNullOrEmpty()]
        [string]$MSG,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'SecureString')]
        [ValidateNotNullOrEmpty()]
        [securestring]$SecureMSG,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Bytes')]
        [ValidateNotNullOrEmpty()]
        [byte[]]$Bytes,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Xml')]
        [ValidateNotNullOrEmpty()]
        [Alias('XmlDoc')]
        [xml]$InputXml,

        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = '__AllParameterSets')]
        [ValidateSet('User', 'Machine')]
        [ValidateNotNullOrEmpty()]
        [Alias('ProtectionScope')]
        [string]$Scope = 'User',

        [Parameter(Mandatory = $false, Position = 2, ParameterSetName = '__AllParameterSets')]
        [ValidateNotNullOrEmpty()]
        [byte[]]$Entropy
    )

    begin {
        #Load The Assemblies
        if (!("System.Security.Cryptography.ProtectedData" -is 'Type')) { Add-Type -AssemblyName System.Security }
        [bool]$UseCustomEntropy = $null -ne $Entropy -and $PsCmdlet.MyInvocation.BoundParameters.ContainsKey('Entropy')
    }

    process {
        $ProtectedD = switch ($PsCmdlet.ParameterSetName) {
            'Xml' {
                if ($PSCmdlet.ShouldProcess("Xml", "Protect")) {
                    if ($UseCustomEntropy) {
                        # [system.Text.Encoding]::UTF8.GetBytes()
                        [xconvert]::ToProtected($([xconvert]::BytesFromObject([xconvert]::ToPSObject($InputXml))), $Entropy, [EncryptionScope]$Scope)
                    } else {
                        # [system.Text.Encoding]::UTF8.GetBytes()
                        [xconvert]::ToProtected($([xconvert]::BytesFromObject([xconvert]::ToPSObject($InputXml))), [EncryptionScope]$Scope)
                    }
                }
            }
            'string' {
                if ($PSCmdlet.ShouldProcess("String", "Protect")) {
                    if ($UseCustomEntropy) {
                        [xconvert]::ToProtected($Msg, $Entropy, [EncryptionScope]$Scope)
                    } else {
                        [xconvert]::ToProtected($Msg, [EncryptionScope]$Scope)
                    }
                }
            }
            'Bytes' {
                if ($PSCmdlet.ShouldProcess("Bytes", "Protect")) {
                    if ($UseCustomEntropy) {
                        [xconvert]::ToProtected($Bytes, $Entropy, [EncryptionScope]$Scope)
                    } else {
                        [xconvert]::ToProtected($Bytes, [EncryptionScope]$Scope)
                    }
                }
            }
            'SecureString' { throw 'Yeet!' }
            Default {
                throw 'Error!'
            }
        }
    }

    end {
        return $ProtectedD
    }
}
function UnProtect-Data {
    <#
    .SYNOPSIS
        Unprotects data
    .DESCRIPTION
        A longer description of the function, its purpose, common use cases, etc.
    .NOTES
        Information or caveats about the function e.g. 'This function is not fully supported in Linux'
    .LINK
        https://github.com/alainQtec/CipherTron/blob/main/Private/CipherTron.Core/CipherTron.Core.psm1
    .EXAMPLE
        UnProtect-Data $secretMsg
    #>
    [CmdletBinding(ConfirmImpact = "Medium", DefaultParameterSetName = 'string', SupportsShouldProcess = $true)]
    [Alias('UnProtect')]
    [OutputType([byte[]])]
    param (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'String')]
        [ValidateNotNullOrEmpty()]
        [string]$MSG,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'SecureString')]
        [ValidateNotNullOrEmpty()]
        [securestring]$SecureMSG,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Bytes')]
        [ValidateNotNullOrEmpty()]
        [Alias('Bytes')]
        [byte[]]$InputBytes,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Xml')]
        [ValidateNotNullOrEmpty()]
        [Alias('XmlDoc')]
        [xml]$InputXml,

        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = '__A llParameterSets')]
        [ValidateSet('User', 'Machine')]
        [ValidateNotNullOrEmpty()]
        [Alias('ProtectionScope')]
        [string]$Scope = 'User',

        [Parameter(Mandatory = $false, Position = 2, ParameterSetName = '__AllParameterSets')]
        [ValidateNotNullOrEmpty()]
        [byte[]]$Entropy
    )

    begin {
        #Load The Assemblies
        if (!("System.Security.Cryptography.ProtectedData" -is 'Type')) { Add-Type -AssemblyName System.Security }
        [bool]$UseCustomEntropy = $null -ne $Entropy -and $PsCmdlet.MyInvocation.BoundParameters.ContainsKey('Entropy')
    }

    process {
        $UnProtected = switch ($PsCmdlet.ParameterSetName) {
            'Xml' {
                if ($PSCmdlet.ShouldProcess("Xml", "Protect")) {
                    if ($UseCustomEntropy) {
                        [xconvert]::ToUnProtected($([xconvert]::BytesFromObject([xconvert]::ToPSObject($InputXml))), $Entropy, [EncryptionScope]$Scope)
                    } else {
                        [xconvert]::ToUnProtected($([xconvert]::BytesFromObject([xconvert]::ToPSObject($InputXml))), [EncryptionScope]$Scope)
                    }
                }
            }
            'string' {
                if ($PSCmdlet.ShouldProcess("String", "Protect")) {
                    if ($UseCustomEntropy) {
                        [xconvert]::ToUnProtected($Msg, $Entropy, [EncryptionScope]$Scope)
                    } else {
                        [xconvert]::ToUnProtected($Msg, [EncryptionScope]$Scope)
                    }
                }
            }
            'Bytes' {
                if ($PSCmdlet.ShouldProcess("Bytes", "Protect")) {
                    if ($UseCustomEntropy) {
                        [xconvert]::ToUnProtected($Bytes, $Entropy, [EncryptionScope]$Scope)
                    } else {
                        [xconvert]::ToUnProtected($Bytes, [EncryptionScope]$Scope)
                    }
                }
            }
            'SecureString' { throw 'Yeet!' }
            Default {
                throw 'Error!'
            }
        }
    }

    end {
        return $UnProtected
    }
}
#endregion  Encrpt-Decrp

#region    Local_Vault
function Get-SavedCredential {
    <#
    .SYNOPSIS
        Get SavedCredential
    .DESCRIPTION
        Gets Saved Credential from credential vault
    .NOTES
        This function is not supported on Linux
    .LINK
        https://github.com/alainQtec/CipherTron/blob/main/Private/CipherTron.Core/CipherTron.Core.ps1
    .EXAMPLE
        Get-SavedCredential 'My App'
        Explanation of the function or its result. You can include multiple examples with additional .EXAMPLE lines
    #>
    [CmdletBinding(DefaultParameterSetName = 'default')]
    [OutputType([CredManaged])]
    param (
        # Target /title /name of the saved credential
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName = '__AllParameterSets')]
        [Alias('Name', 'TargetName')][ValidateNotNullOrEmpty()]
        [string]$Target,

        # Username / Owner
        [Parameter(Position = 1, Mandatory = $false, ParameterSetName = 'default')]
        [Parameter(Position = 2, Mandatory = $false, ParameterSetName = 'byCrtyp')]
        [Alias('usrnm')][ValidateNotNullOrEmpty()]
        [string]$UserName,

        # Credential type.
        [Parameter(Position = 1, Mandatory = $false, ParameterSetName = 'byCrtyp')]
        [ValidateSet('Generic', 'DomainPassword', 'DomainCertificate', 'DomainVisiblePassword', 'GenericCertificate', 'DomainExtended', 'Maximum', 'MaximumEx')]
        [Alias('CredType')][ValidateNotNullOrEmpty()]
        [string]$Type = 'Generic'
    )

    begin {
        $CredentialManager = [CredentialManager]::new(); $Savd_Cred = $null
        $params = $PSCmdlet.MyInvocation.BoundParameters;
        $GetTargetName = [scriptblock]::Create({
                if ([Environment]::UserInteractive -and [Environment]::GetCommandLineArgs().Where({ $_ -like '-NonI*' }).Count -eq 0) {
                    $t = Read-Host -Prompt "TargetName"
                    if ([string]::IsNullOrWhiteSpace($t)) {
                        throw 'Null Or WhiteSpace targetName is not valid'
                    }
                    $t
                } else {
                    throw 'Please Input valid Name'
                }
            }
        )
    }

    process {
        $_Target = $(if ($params.ContainsKey('Target') -and [string]::IsNullOrWhiteSpace($Target)) {
                Invoke-Command -ScriptBlock $GetTargetName
            } elseif (!$params.ContainsKey('Target')) {
                Invoke-Command -ScriptBlock $GetTargetName
            } else {
                $Target
            }
        )
        $Savd_Cred = $(if ($PSCmdlet.ParameterSetName -eq 'default') {
                $CredentialManager.GetCredential($_Target, $UserName)
            } elseif ($PSCmdlet.ParameterSetName -eq 'byCrtyp') {
                if ($params.ContainsKey('type')) {
                    $CredentialManager.GetCredential($_Target, $Type, $UserName)
                } else {
                    $CredentialManager.GetCredential($_Target, $Type, $UserName)
                }
            }
        )
        if ([CredentialManager]::LastErrorCode.Equals([CredentialManager]::ERROR_NOT_FOUND)) {
            throw [CredentialNotFoundException]::new("$_Target not found.", [System.Exception]::new("Exception of type 'ERROR_NOT_FOUND' was thrown."))
        }
        if ([string]::IsNullOrWhiteSpace($Savd_Cred.target)) {
            Write-Warning "Could not resolve the target Name for: $_Target"
        }
    }

    end {
        return $Savd_Cred
    }
}
function Get-SavedCredentials {
    <#
    .SYNOPSIS
        Retreives All strored credentials from credential Manager
    .DESCRIPTION
        Retreives All strored credentials and returns an [System.Collections.ObjectModel.Collection[CredManaged]] object
    .NOTES
        This function is supported on windows only
    .LINK
        https://github.com/alainQtec/CipherTron/blob/main/Private/CipherTron.Core/CipherTron.Core.ps1
    .EXAMPLE
        Get-SavedCredentials
        Enumerates all SavedCredentials
    #>
    [CmdletBinding()]
    [outputType([System.Collections.ObjectModel.Collection[CredManaged]])]
    param ()

    begin {
        $Credentials = $null
        $CredentialManager = [CredentialManager]::new();
    }

    process {
        $Credentials = $CredentialManager.RetreiveAll();
    }
    end {
        return $Credentials;
    }
}
function Remove-Credential {
    <#
    .SYNOPSIS
        Deletes credential from Windows Credential Mandger
    .DESCRIPTION
        A longer description of the function, its purpose, common use cases, etc.
    .NOTES
        This function is supported on windows only
    .LINK
        https://github.com/alainQtec/CipherTron/blob/main/Private/CipherTron.Core/CipherTron.Core.psm1
    .EXAMPLE
        Remove-Credential -Verbose
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        # TargetName
        [Parameter(Mandatory = $true)][ValidateLength(1, 32767)]
        [ValidateScript({
                if (![string]::IsNullOrWhiteSpace($_)) {
                    return $true
                }
                throw 'Null or WhiteSpace Inputs are not allowed.'
            }
        )][Alias('Title')]
        [String]$Target,
        [Parameter(Mandatory = $false)]
        [ValidateSet('Generic', 'DomainPassword', 'DomainCertificate', 'DomainVisiblePassword', 'GenericCertificate', 'DomainExtended', 'Maximum', 'MaximumEx')]
        [String]$Type = "GENERIC"
    )

    begin {
        $CredentialManager = [CredentialManager]::new();
    }

    process {
        $CredType = [CredType]"$Type"
        if ($PSCmdlet.ShouldProcess("Removing Credential, target: $Target", '', '')) {
            $IsRemoved = $CredentialManager.Remove($Target, $CredType);
            if (-not $IsRemoved) {
                throw 'Remove-Credential Failed. ErrorCode: 0x' + [CredentialManager]::LastErrorCode
            }
        }
    }
}
function Save-Credential {
    <#
    .SYNOPSIS
        Saves credential to windows credential Manager
    .DESCRIPTION
        A longer description of the function, its purpose, common use cases, etc.
    .NOTES
        This function is supported on windows only
    .LINK
        https://github.com/alainQtec/CipherTron/blob/main/Private/CipherTron.Core/CipherTron.Core.ps1
    .EXAMPLE
        Save-Credential youtube.com/@memeL0rd memeL0rd $(Read-Host -AsSecureString -Prompt "memeLord's youtube password")
    #>
    [CmdletBinding(DefaultParameterSetName = 'uts')]
    param (
        # title aka TargetName of the credential you want to save
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = 'uts')]
        [ValidateScript({
                if (![string]::IsNullOrWhiteSpace($_)) {
                    return $true
                }
                throw 'Null or WhiteSpace targetName is not allowed.'
            }
        )][Alias('target')]
        [string]$Title,
        # UserName
        [Parameter(Position = 1, Mandatory = $false, ParameterSetName = 'uts')]
        [Alias('UserName')]
        [string]$User,

        # Securestring / Password
        [Parameter(Position = 2, Mandatory = $true, ParameterSetName = 'uts')]
        [ValidateNotNull()]
        [securestring]$SecureString,

        # ManagedCredential Object you want to save
        [Parameter(Mandatory = $true, ParameterSetName = 'MC')]
        [Alias('Credential')][ValidateNotNull()]
        [CredManaged]$Obj

    )

    process {
        if ($PSCmdlet.ParameterSetName -eq 'uts') {
            $CredentialManager = [CredentialManager]::new();
            if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('User')) {
                [void]$CredentialManager.SaveCredential($Title, $User, $SecureString);
            } else {
                [void]$CredentialManager.SaveCredential($Title, $SecureString);
            }
        } elseif ($PSCmdlet.ParameterSetName -eq 'MC') {
            $CredentialManager = [CredentialManager]::new();
            [void]$CredentialManager.SaveCredential($Obj);
        }
    }
}
function Show-SavedCredentials {
    <#
    .SYNOPSIS
        Retreives All strored credentials from credential Manager, but no securestrings. (Just showing)
    .DESCRIPTION
        Retreives All strored credentials and returns a PsObject[]
    .NOTES
        This function is supported on windows only
    .LINK
        https://github.com/alainQtec/CipherTron/blob/main/Private/CipherTron.Core/CipherTron.Core.ps1
    .EXAMPLE
        Show-SavedCredentials
    #>
    [CmdletBinding()]
    [outputType([PsObject[]])]
    [Alias('ShowCreds')]
    param ()

    end {
        return [CredentialManager]::get_StoredCreds();
    }
}
#endregion Local_Vault

#region    PasswordManagment
function New-Password {
    <#
    .SYNOPSIS
        Creates a password string
    .DESCRIPTION
        Creates a password containing minimum of 9 characters, 1 lowercase, 1 uppercase, 1 numeric, and 1 special character.
        Can not exceed 999 characters
    .LINK
        https://github.com/alainQtec/CipherTron/blob/main/Private/CipherTron.Core/CipherTron.Core.psm1
    .EXAMPLE
        New-Password
        Explanation of the function or its result. You can include multiple examples with additional .EXAMPLE lines
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'No system state is being changed')]
    [CmdletBinding(DefaultParameterSetName = 'asSecureString')]
    param (
        # Exact password Length. Note: The minimum length is 14 characters, Otherwise it nearly impossible to create a password under 14 characters. Youll'd be better off use a random text generator!
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName = '__AllParameterSets')]
        [Alias('l')][ValidateRange(14, 999)]
        [int]$Length = 19,

        [Parameter(Mandatory = $false, ParameterSetName = '__AllParameterSets')]
        [switch]$StartWithLetter,

        [Parameter(Mandatory = $false, ParameterSetName = '__AllParameterSets')]
        [switch]$NoSymbols,

        [Parameter(Mandatory = $false, ParameterSetName = '__AllParameterSets')]
        [switch]$UseAmbiguousCharacters,

        [Parameter(Mandatory = $false, ParameterSetName = '__AllParameterSets')]
        [switch]$UseExtendedAscii,

        [Parameter(Mandatory = $false, ParameterSetName = 'PlainText')]
        [switch]$AsPlainText
    )

    begin {
        $Pass = [string]::Empty
        # $params = $PSCmdlet.MyInvocation.BoundParameters
    }

    process {
        $Pass = [CryptoBase]::GeneratePassword($Length, $StartWithLetter, $NoSymbols, $UseAmbiguousCharacters, $UseExtendedAscii);
        if ($PSCmdlet.ParameterSetName -eq 'asSecureString') {
            $pass = [xconvert]::ToSecurestring($Pass)
        }
    }
    end {
        return $Pass
    }
}
#endregion PasswordManagment

#region    GithubGists
function Get-Gists {
    <#
    .SYNOPSIS
        Gets all gists for a user
    .DESCRIPTION
        A longer description of the function, its purpose, common use cases, etc.
    .LINK
        Specify a URI to a help page, this will show when Get-Help -Online is used.
    .EXAMPLE
        Get-Gists -UserName 'alainQtec' -SecureToken (Read-Host -Prompt "Github Api Token" -AsSecureString)
        Explanation of the function or its result. You can include multiple examples with additional .EXAMPLE lines
    #>
    [OutputType([Gist[]])]
    [CmdletBinding(DefaultParameterSetName = 'ClearT')]
    param (
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = '__AllParameterSets')]
        [Alias('UserName')]
        [string]$ownerID,

        [Parameter(Position = 1, Mandatory = $true, ParameterSetName = 'SecureT')]
        [ValidateNotNullOrEmpty()]
        [securestring]$SecureToken,

        [Parameter(Position = 1, Mandatory = $true, ParameterSetName = 'ClearT')]
        [ValidateNotNullOrEmpty()]
        [string]$GitHubToken
    )

    begin {
        $Gists = $null; [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'ClearT') {
            $SecureToken = [xconvert]::ToSecurestring($GitHubToken)
        }
        if ($null -eq [GitHub]::webSession) { [void][GitHub]::createSession($ownerID, $SecureToken) }
        $auth = Invoke-RestMethod -Method Get -Uri "https://api.github.com/user" -WebSession ([GitHub]::webSession)
        if ($auth) {
            $Gists = $(Invoke-RestMethod -Method Get -Uri "https://api.github.com/users/$ownerID/gists" -WebSession $([GitHub]::webSession)) | Select-Object -Property @(
                @{l = 'Id'; e = { $_.Id } }
                @{l = 'Uri'; e = { "https://gist.github.com/$($_.owner.login)/$($_.Id)" -as [uri] } }
                @{l = 'FLOB'; e = { $_.files } }
                @{l = 'IsPublic'; e = { $_.public } }
                @{l = 'Owner'; e = { $_.owner.login } }
                @{l = 'Description'; e = { $_.description } }
            ) | Select-Object *, @{l = 'Files'; e = {
                    $flob = [psobject[]]::new(0); $Names = $_.FLOB | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
                    foreach ($n in $Names) { if (($_.FLOB."$n".raw_url -as [uri]).Segments[2] -eq $_.Id + '/') { $flob += $_.FLOB."$n" } }
                    $flob
                }
            } -ExcludeProperty FLOB
            Write-Verbose "Found $($Gists.Count) gists"
            $Gists = foreach ($g in $Gists) {
                $_g = [Gist]::new()
                $_f = $g.Files | Select-Object *, @{l = 'Id'; e = { $g.Id } }, @{l = 'Owner'; e = { $g.Owner } }, @{l = 'IsPublic'; e = { $g.IsPublic } }
                $_f.Foreach({ $_g.AddFile([GistFile]::new($_)) });
                $_g.Description = $g.Description
                $_g.IsPublic = $g.IsPublic
                $_g.Owner = $g.Owner
                $_g.Uri = $g.Uri
                $_g.Id = $g.Id
                $_g
            }
        } else {
            throw $Error[0]
        }
    }

    end {
        return $Gists
    }
}
function Get-GistFiles {
    <#
    .SYNOPSIS
        Get gist Files
    .DESCRIPTION
        A longer description of the function, its purpose, common use cases, etc.
    .EXAMPLE
        $Name   = "P0t4t0_ex.ps1"
        $params = @{
            UserName    = '6r1mh04x'
            SecureToken = Read-Host -Prompt "Github Api Token" -AsSecureString
            GistId      = '995856aa97ac3120cd8d92d2a6eac212'
        }
        $rawUrl = (Get-GistFiles @$params).Where({ $_.Name -eq $Name }).raw_url

        Using this function to Fetch raw_url of a private gist
    #>
    [OutputType([GistFile[]])]
    [CmdletBinding(DefaultParameterSetName = 'ClearT')]
    param (
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = '__AllParameterSets')]
        [Alias('UserName')]
        [string]$ownerID,

        [Parameter(Position = 1, Mandatory = $true, ParameterSetName = 'SecureT')]
        [ValidateNotNullOrEmpty()]
        [securestring]$SecureToken,

        [Parameter(Position = 1, Mandatory = $true, ParameterSetName = 'ClearT')]
        [ValidateNotNullOrEmpty()]
        [string]$GitHubToken,

        [Parameter(Position = 2, Mandatory = $true, ParameterSetName = '__AllParameterSets')]
        [ValidateNotNullOrEmpty()]
        [string]$GistId
    )

    begin {
        $gistFiles = $null;
    }

    process {
        $gistFiles = if ($PSCmdlet.ParameterSetName -eq 'ClearT') {
            Get-Gists -UserName $ownerID -GitHubToken $GitHubToken
        } else {
            Get-Gists -UserName $ownerID -SecureToken $SecureToken
        }
        $gistFiles = $gistFiles.Files.Where({
                $_.Id -eq $GistId
            }
        )
    }

    end {
        return $gistFiles
    }
}
#endregion GithubGistss

#endregion Functions
