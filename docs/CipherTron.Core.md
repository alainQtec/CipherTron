This is mostly a bunch of classes

here are some of the main ones

## CredentialManager

**Usage examples**:

Here is an example of using the CredentialManager cmdlets

```Powershell
# Set the target name for the credentials. This is typically the name of the
# application or resource for which the credentials are used.
$targetName = "MyApp2"

# Set the credentials username and password.
$username = "John doe"
$password = ConvertTo-SecureString "A secret-string, token or password. Like-your-Api-key or something" -AsPlainText -Force

# Save the credential to the Windows Credential Vault.
Save-Credential -Title $targetName -User $username -SecureString $password

# Check if it got saved (optional).
Show-SavedCredentials

# Retrieve the saved credential from the Windows Credential Vault.
$retrieved = Get-SavedCredential $targetName

# Print the retrieved credential's username and password.
Write-Output "Username: $($retrieved.username)";
Write-Output "Password: $([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($retrieved.password)))";

# You can also remove the credential
Remove-Credential $targetName
```

To understand what classes run under the hood, here is the same example but using the CredentialManager class

```PowerShell
$CredentialManager = New-Object CredentialManager

# Set the target name for the credentials.
$targetName = "MyApp"

# Set the credentials username and password.
$username = "John doe"
$password = ConvertTo-SecureString "@-secret-message-or-password-Like-your-Api-key-or-something-@" -AsPlainText -Force

# Create a new Managed Credential instance.
$credential = New-Object -TypeName CredManaged -ArgumentList $targetName, $username, $password

# Save the credential to the Windows Credential Vault.
$credential.SaveToVault()

# Check if it got stored.
$CredentialManager::get_StoredCreds();

# Retrieve the saved credential from the Windows Credential Vault.
$retrieved = $CredentialManager.GetCredential($targetName);

# Print the retrieved credential's username and password.
Write-Output "Username: $($retrieved.username)";
Write-Output "Password: $([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($retrieved.password)))";

# then removing
$CredentialManager.Remove($targetName, [credtype]::Generic);

```