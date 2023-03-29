Describe "Protect-Data" {
    It "should have command" {
        Get-Command Protect-Data | Should -Not -BeNullOrEmpty
    }
}

Describe "UnProtect-Data" {
    It "should have command" {
        Get-Command UnProtect-Data | Should -Not -BeNullOrEmpty
    }
}

Describe "Decrypt-Object" {
    It "should have command" {
        Get-Command Decrypt-Object | Should -Not -BeNullOrEmpty
    }
}

Describe "Encrypt-Object" {
    It "should have command" {
        Get-Command Encrypt-Object | Should -Not -BeNullOrEmpty
    }
}

Describe "New-K3Y" {
    It "should have command" {
        Get-Command New-K3Y | Should -Not -BeNullOrEmpty
    }
    It "should work" {
        (New-K3Y -UserName $(whoami) -Password $(
            ConvertTo-SecureString 01000000d08c9ddf0115d1118c7a00c04fc297eb0100000061c13c1d04b3a742933426b767e4fe4500000000020000000000106600000001000020000000fd1c66d393d9fb0e72a4ba57ef148849182becffbf9a60faa4e8e26de1467971000000000e800000000200002000000018410dbc98aef6561cb9523d7112a217ba45b7bdc8c7654fb1d7b1c20fd24ae210000000da40a9af92dd654bd6439566774068da40000000aa082fc44c9d1f1cf389b664e5b5e41b7048205c0dec669a68f5034264eca1ef8d26aae02b90c0ecc8fe612992cef38c61ac5ebc2db45da387a8cc3dce67204c
        ) -Protect) | Should -Not -BeNullOrEmpty
    }
}
