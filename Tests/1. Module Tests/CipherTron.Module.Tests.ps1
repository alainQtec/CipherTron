$projectRoot = Resolve-Path "$PSScriptRoot\..\.."
$ModulePath = Resolve-Path "$projectRoot\BuildOutput\$($([Environment]::GetEnvironmentVariable($env:RUN_ID + 'ProjectName')))"
$decompiledModulePath = Resolve-Path "$projectRoot\$($([Environment]::GetEnvironmentVariable($env:RUN_ID + 'ProjectName')))"

# Verbose output for non-main builds on appveyor
# Handy for troubleshooting.
# Splat @Verbose against commands as needed (here or in pester tests)
$Verbose = @{}
if ($([Environment]::GetEnvironmentVariable($env:RUN_ID + 'BranchName')) -eq "development" -or $([Environment]::GetEnvironmentVariable($env:RUN_ID + 'CommitMessage')) -match "!verbose") {
    $Verbose.add("Verbose", $True)
}

Import-Module $ModulePath -Force -Verbose:$false


Describe "Module tests: $($([Environment]::GetEnvironmentVariable($env:RUN_ID + 'ProjectName')))" -Tag 'Module' {
    Context "Confirm files are valid Powershell syntax" {
        $scripts = Get-ChildItem $decompiledModulePath -Include *.ps1, *.psm1, *.psd1 -Recurse

        $testCase = $scripts | ForEach-Object { @{file = $_ } }
        It "Script <file> should be valid Powershell" -TestCases $testCase {
            param($file)

            $file.fullname | Should Exist

            $contents = Get-Content -Path $file.fullname -ErrorAction Stop
            $errors = $null
            $null = [System.Management.Automation.PSParser]::Tokenize($contents, [ref]$errors)
            $errors.Count | Should Be 0
        }
    }
    Context "Confirm there are no duplicate function names in private and public folders" {
        It 'Should have no duplicate functions' {
            $functions = Get-ChildItem "$decompiledModulePath\Public" -Recurse -Include *.ps1 | Select-Object -ExpandProperty BaseName
            $functions += Get-ChildItem "$decompiledModulePath\Private" -Recurse -Include *.ps1 | Select-Object -ExpandProperty BaseName
            ($functions | Group-Object | Where-Object { $_.Count -gt 1 }).Count | Should -BeLessThan 1
        }
    }
}
