![image](https://github.com/alainQtec/CipherTron/blob/main/docs/images/ncPoster.png)

An all-in-one, powerful but user-friendly cryptography [PsModule](https://www.powershellgallery.com/packages/CipherTron).

Most core classes used in this module are public and can be accesed as 'Gists'.

**Example**:

- 1. Load the classes

```PowerShell
iex $((Invoke-RestMethod -Method Get https://api.github.com/gists/217860de99e8ddb89a8820add6f6980f).files.'CipherTron.Core.ps1'.content)
```
- 2. Use the classes in your own functions:

```PowerShell
$Obj = [CipherTron]::new("H3llo W0rld!");
$eOb = $Obj.Encrypt(3); # Encrypt 3 times
$dOb = $Obj.Decrypt(3); # Decrypt 3 times
[xconvert]::BytesToObject($dOb);
#You get back: H3llo W0rld!
```

---

**Versioning**

This repo uses [semver](https://semver.org/).
