

$script:localizedData = if ($null -ne (Get-Command Get-LocalizedData -ErrorAction SilentlyContinue)) {
  Get-LocalizedData -DefaultUICulture 'en-US'
} else {
  $dataFile = [System.IO.FileInfo]::new([IO.Path]::Combine((Get-Location), 'en-US', 'CipherTron.strings.psd1'))
  if (!$dataFile.Exists) { throw [System.IO.FileNotFoundException]::new('Unable to find the LocalizedData file.', 'CipherTron.strings.psd1') }
  [scriptblock]::Create("$([IO.File]::ReadAllText($dataFile))").Invoke()
}

# Types that will be available to users when they import the module.
$typestoExport = @(
  [CipherTron]
)
$TypeAcceleratorsClass = [psobject].Assembly.GetType('System.Management.Automation.TypeAccelerators')
foreach ($Type in $typestoExport) {
  if ($Type.FullName -in $TypeAcceleratorsClass::Get.Keys) {
    $Message = @(
      "Unable to register type accelerator '$($Type.FullName)'"
      'Accelerator already exists.'
    ) -join ' - '

    throw [System.Management.Automation.ErrorRecord]::new(
      [System.InvalidOperationException]::new($Message),
      'TypeAcceleratorAlreadyExists',
      [System.Management.Automation.ErrorCategory]::InvalidOperation,
      $Type.FullName
    )
  }
}
# Add type accelerators for every exportable type.
foreach ($Type in $typestoExport) {
  $TypeAcceleratorsClass::Add($Type.FullName, $Type)
}
# Remove type accelerators when the module is removed.
$MyInvocation.MyCommand.ScriptBlock.Module.OnRemove = {
  foreach ($Type in $typestoExport) {
    $TypeAcceleratorsClass::Remove($Type.FullName)
  }
}.GetNewClosure();

$Private = Get-ChildItem ([IO.Path]::Combine($PSScriptRoot, 'Private')) -Filter "*.ps1" -ErrorAction SilentlyContinue
$Public = Get-ChildItem ([IO.Path]::Combine($PSScriptRoot, 'Public')) -Filter "*.ps1" -ErrorAction SilentlyContinue
foreach ($file in $($Public + $Private)) {
  Try {
    if ([string]::IsNullOrWhiteSpace($file.fullname)) { continue }
    . "$($file.fullname)"
  } Catch {
    Write-Warning "Failed to import function $($file.BaseName): $_"
    $host.UI.WriteErrorLine($_)
  }
}
$Param = @{
  Function = $Public.BaseName
  Variable = 'localizedData'
  Cmdlet   = '*'
  Alias    = @('<Aliases>')
}
Export-ModuleMember @Param -Verbose
