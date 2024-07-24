# .SYNOPSIS
#     An open source secret management platform
# .DESCRIPTION
#     client to Infisical; a secure centralized secret management.
# .NOTES
#     Information or caveats about the function e.g. 'This function is not supported in Linux'
# .LINK
#     https://infisical.com/docs/api-reference/overview/introduction
#     https://infisical.com/docs/documentation/platform/pki/private-ca
#     https://github.com/Infisical/infisical
# .EXAMPLE
#     [InfisicalClient]::InstallCLI() -Verbose
#     Explanation of the function or its result. You can include multiple examples with additional .EXAMPLE lines
class InfisicalClient {
    [string]$DASHB_URL = "https://app.infisical.com/"
    [string]$ClientId
    [string]$ClientSecret
    InfisicalClient() {
        # --plain flag will output only the token, so it can be fed to an environment variable. --silent will disable any update messages.
        export INFISICAL_TOKEN=$(infisical login --method=universal-auth --client-id=<identity-client-id> --client-secret=<identity-client-secret> --silent --plain)
        # export INFISICAL_DISABLE_UPDATE_CHECK=true
    }
    static [void] InstallCLI() {
        # https://infisical.com/docs/cli/overview#installation
        &yay -S infisical-bin
    }
    static [void] Login() {
        infisical login
    }
    [string] GetSecrets() {
        # $ infisical secrets get <secret-name-a> <secret-name-b>
        # Example
        # $ infisical secrets get DOMAIN
        # $ infisical secrets get DOMAIN PORT
        return ''
    }
    [void] SetSecrets() {
        # infisical secrets set <key1=value1> <key2=value2>
        # Example
        # infisical secrets set STRIPE_API_KEY=sjdgwkeudyjwe DOMAIN=example.com HASH=jebhfbwe  --type=personal
    }
    [void] deleteSecrets() {
        # infisical secrets delete <keyName1> <keyName2>
        # Example
        # infisical secrets delete STRIPE_API_KEY DOMAIN HASH
    }
    [void] exportSecrets([string]$Format) {
        # infisical export

        # Export variables to a .env file
        # infisical export > .env

        # # Export variables to a .env file (with export keyword)
        # infisical export --format=dotenv-export > .env

        # # Export variables to a CSV file
        # infisical export --format=csv > secrets.csv

        # # Export variables to a JSON file
        # infisical export --format=json > secrets.json

        # # Export variables to a YAML file
        # infisical export --format=yaml > secrets.yaml

        # # Render secrets using a custom template file
        # infisical export --template=<path to template>
    }
}
function Install-InfisicalCLI {
    [CmdletBinding()]
    param ()
    process {
        [InfisicalClient]::InstallCLI();
    }
}

Export-ModuleMember -Function '*' -Variable '*' -Cmdlet '*' -Alias '*' -Verbose:($VerbosePreference -eq "Continue")