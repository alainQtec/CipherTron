$script:localizedData = if ($null -ne (Get-Command Get-LocalizedData -ErrorAction SilentlyContinue)) {
    Get-LocalizedData -DefaultUICulture 'en-US'
} else {
    $dataFile = [System.IO.FileInfo]::new([IO.Path]::Combine((Get-Location), 'en-US', 'CipherTron.strings.psd1'))
    if (!$dataFile.Exists) { throw [System.IO.FileNotFoundException]::new('Unable to find the LocalizedData file.', 'CipherTron.strings.psd1') }
    [scriptblock]::Create("$([IO.File]::ReadAllText($dataFile))").Invoke()
}
$Private = Get-ChildItem ([IO.Path]::Combine($PSScriptRoot, 'Private')) -Filter "*.ps1" -ErrorAction SilentlyContinue
$Public = Get-ChildItem ([IO.Path]::Combine($PSScriptRoot, 'Public')) -Recurse -Filter "*.ps1" -ErrorAction SilentlyContinue
# Load dependencies
$PrivateModules = Get-ChildItem ([IO.Path]::Combine($PSScriptRoot, 'Private')) -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer }

# Import Private modules
if ($PrivateModules.Count -gt 0) {
    foreach ($Module in $PrivateModules) {
        Try {
            Import-Module ("{0}.psd1" -f [IO.Path]::Combine($Module.FullName, $Module.BaseName)) -ErrorAction Stop
        } Catch {
            Write-Error "Failed to import module $($Module.BaseName) : $_"
        }
    }
}
# Dot source the files
foreach ($Import in @($Public + $Private)) {
    Try {
        . $Import.fullname
    } Catch {
        Write-Warning "Failed to import function $($Import.fullname): $_"
    }
    Export-ModuleMember $import.BaseName
}
Export-ModuleMember -Alias @('<Aliases>')