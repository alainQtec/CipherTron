function Encrypt-Data {
    <#
    .SYNOPSIS
        This function is be used to encrypt a given piece of data using a specified encryption algorithm.
    .DESCRIPTION
        A longer description of the function, its purpose, common use cases, etc.
    .NOTES
        Information or caveats about the function e.g. 'This function is not supported in Linux'
    .LINK
        https://github.com/alainQtec/CipherTron/blob/main/Public/Encrpt_Decrpt/Encrypt-Data.ps1
    .EXAMPLE
        Encrypt-Data -Data "Hello World" -key $Key
        Explanation of the function or its result. You can include multiple examples with additional .EXAMPLE lines
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Justification = 'Prefer verb usage')]
    [CmdletBinding(DefaultParameterSetName = 'ByStringK3Y')]
    param (
        # The data to be encrypted
        [Parameter(Position = 0, Mandatory = $true)]
        [string]$Data,

        # The encryption key to be used
        [Parameter(Mandatory = $true, ParameterSetName = 'ByStringK3Y')]
        [string]$Key,

        # The encryption k3y to be used
        [Parameter(Mandatory = $true)]
        [K3Y]$K3y
    )

    begin {
        #requires -Version 5.0
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'ByStringK3Y') {
        }
    }

    end {
    }
}