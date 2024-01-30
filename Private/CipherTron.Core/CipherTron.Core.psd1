@{
    ModuleVersion     = '1.1.0'
    RootModule        = 'CipherTron.Core.psm1'
    RequiredModules   = @('PSReadLine', 'Microsoft.PowerShell.Utility')
    FunctionsToExport = @(
        'Encrypt-Object'
        'Decrypt-Object'
        'Protect-Data'
        'UnProtect-Data'
        'New-Password'
        'New-Converter'
        'Save-Credential'
        'Start-Ciphertron'
        'Remove-Credential'
        'Get-SavedCredential'
        'Get-SavedCredentials'
        'Show-SavedCredentials'
        'Edit-CiphertronConfig'
    )
}