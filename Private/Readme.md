# **Core** & **Utility** functions

To simplify development (code completion & intellisence) they all in [CipherTron.Core/CipherTron.Core.psm1][core.psm1]

This is because they relly heavily on .Net & custom classes.

But some of them can be available to users. See: [CipherTron.Core/CipherTron.Core.psd1/FunctionsToExport][core.psd1]

[core.psm1]: CipherTron.Core/CipherTron.Core.psm1
[core.psd1]: CipherTron.Core/CipherTron.Core.psd1#FunctionsToExport

<!-- test core in cli:
copy ./Private/CipherTron.Core/CipherTron.Core.psm1 ./core.ps1; . ./core.ps1; Remove-Item ./core.ps1
 -->