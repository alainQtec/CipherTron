@{
    ModuleName                      = 'CipherTron.Core'
    ModuleVersion                   = [System.Management.Automation.SemanticVersion]::new(0, 1, 2, 'beta')
    # Error messages
    Error_InvalidKeySize            = 'Invalid key size specified. The key size should be a multiple of 8 and greater than or equal to 128 bits.'
    Error_InvalidInput              = 'Invalid input specified. Please provide a valid input.'
    Error_EncryptionFailed          = 'Encryption failed. Please try again later.'
    Error_DecryptionFailed          = 'Decryption failed. Please try again later.'
    Error_DataProtectionFailed      = 'Data protection failed. Please try again later.'
    Error_DataUnprotectionFailed    = 'Data unprotection failed. Please try again later.'
    Error_SessionCreationFailed     = 'Failed to create a new session. Please try again later.'
    Error_SessionClosed             = 'The session has been closed.'
    Error_SendingMessageFailed      = 'Failed to send message. Please try again later.'
    Error_CredentialsNotFound       = 'No saved credentials were found.'
    Error_CredentialsSaveFailed     = 'Failed to save credentials. Please try again later.'
    Error_CredentialsDeleteFailed   = 'Failed to delete credentials. Please try again later.'

    # Warning messages
    Warning_PlaintextTooLong        = 'The plaintext is longer than the key length. The excess characters will be truncated.'
    Warning_CiphertextTooLong       = 'The ciphertext is longer than the key length. The excess characters will be truncated.'
    Warning_DataAlreadyProtected    = 'The data is already protected.'
    Warning_DataAlreadyUnprotected  = 'The data is already unprotected.'

    # Informational messages
    Info_EncryptionSuccessful       = 'Encryption successful.'
    Info_DecryptionSuccessful       = 'Decryption successful.'
    Info_DataProtectionSuccessful   = 'Data protection successful.'
    Info_DataUnprotectionSuccessful = 'Data unprotection successful.'
    Info_SessionCreated             = 'A new session has been created.'
    Info_MessageSent                = 'Message sent successfully.'
    Info_CredentialsSaved           = 'Credentials saved successfully.'
    Info_CredentialsDeleted         = 'Credentials deleted successfully.'
}
