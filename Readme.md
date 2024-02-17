<img align="right" alt="logo" height="90" width="90" src="https://github.com/alainQtec/CipherTron/assets/79479952/b140dbd3-8934-4efd-88e5-c2622273b157">

## [**CipherTron**](https://www.PowerShellGallery.com/packages/CipherTron)
Your all in one Cryptography Powershell module.
<br />
<div align="Left">
  </br>
  <!-- Upload Artifacts -->
  <a href="https://github.com/alainQtec/CipherTron/actions/workflows/Upload_Artifact.yaml">
    <img src="https://github.com/alainQtec/CipherTron/actions/workflows/Upload_Artifact.yaml/badge.svg"
      alt="Upload artifact from Ubuntu" title="Upload artifacts" />
  </a>
  <!-- Publish Module -->
    <a href="https://github.com/alainQtec/CipherTron/actions/workflows/Publish.yaml">
        <img src="https://github.com/alainQtec/CipherTron/actions/workflows/Publish.yaml/badge.svg"
      alt="Publish Module" title="Publish Module" />
    </a>
  <!-- PS Gallery -->
  <a href="https://www.PowerShellGallery.com/packages/CipherTron">
    <img src="https://img.shields.io/powershellgallery/dt/CipherTron.svg?style=flat&logo=powershell&color=blue"
      alt="PowerShell Gallery" title="PowerShell Gallery" />
  </a>
  <!-- Continuous Intergration -->
  <a href="https://github.com/alainQtec/CipherTron/actions/workflows/CI.yaml">
    <img src="https://github.com/alainQtec/CipherTron/actions/workflows/CI.yaml/badge.svg?branch=main"
      alt="CI/CD" title="Continuous Intergration" />
  </a>
  <!-- GitHub Releases -->
  <a href="https://github.com/alainQtec/CipherTron/releases/latest">
    <img src="https://img.shields.io/github/downloads/alainQtec/CipherTron/total.svg?logo=github&color=blue"
      alt="Downloads" title="GitHub Release downloads" />
  </a>
  <!-- Latest gitHub Release version -->
  <a href="https://github.com/alainQtec/CipherTron/releases/latest">
    <img src="https://img.shields.io/github/release/alainQtec/CipherTron.svg?label=version&logo=github"
      alt="Version" title="GitHub Release versions" />
  </a>
</div>
<br />

## 📖 **Description**

Ciphertron is a personnal Cryptography assistance bot writen written as a PowerShell module.

Cryptography is an important field with a wide range of practical applications, and anyone with an interest in security or computer science can benefit.

<img align="right" alt="logo" height="319" src="https://github.com/alainQtec/CipherTron/blob/main/docs/images/CryptographyNerd.png">

This Module's features focus mainly on **Data encryption**, **Data protection**, **Secure communication** and **User authentication**

## 🧑‍💻 **How to install**

```powershell
Find-module CipherTron | install-Module
```

Or

```powershell
Install-Module CipherTron -Scope CurrentUser -Repository PSGallery
```

Another option is to build the module from source using `build.ps1`.

```PowerShell
git clone https://github.com/alainQtec/CipherTron.git .
cd CipherTron
build.ps1
```

Then you can manually import the module from  the BuildOutput Folder

```PowerShell
Import-Module BuildOutput\$version\CipherTron\CipherTron.psd1
```

If you Only want to run the Pester tests locally? Pass `Test` as the value to the `Task` script parameter like so:

```powershell
.\build.ps1 -Task Test
```

To Run all Tests:

```PowerShell
.\Test-Module.ps1 -Module BuildOutput\$version\CipherTron -Tests ".\tests"
```

## 📚 **Wikis**

For an extended usage guide, read the [Wiki](https://github.com/alainQtec/CipherTron/wiki)

### 🚀 **GitHub Releases**

Please see the [Releases section of this repository](https://github.com/alainQtec/CipherTron/releases) for instructions.

## 🤝 **Contributions**

![Alt](https://repobeats.axiom.co/api/embed/d201fa56239511a45aa4aacb0e06e24f756cc531.svg "Repobeats analytics image")

This repository is open to suggestions, contributions and all other forms of help.

Interested in helping out with the Module development? Please check out our [Contribution Guidelines](https://github.com/alainQtec/CipherTron/blob/main/CONTRIBUTING.md)!

Building the module locally to test changes is as easy as running the `build.ps1` file in the root of the repo. This will compile the module with your changes and import the newly compiled module at the end by default.

## Code of Conduct

Please adhere to our [Code of Conduct](https://github.com/alainQtec/CipherTron/blob/main/CODE_OF_CONDUCT.md) when interacting with this repo.
