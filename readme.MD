# SEPPmail Legacy API Powershell Module

Receive data and manage GINA-Users from your SEPPmail Appliance!

Beginning with SEPPmail Version 11.1.9, the Legacy-API an retrieve statistics and encryption information via REST, including the option to mass-generate GINA-Users.
Even though the API is not officially supported, some people find it pretty useful.
This PowerShell module is a wrapper around this API to allow more convenient operation and interaction from the command line.

## Prerequisites

The module requires minimum SEPPmail version 11.1.9 and minimum Powershell 5.1 on Windows, PowerShell 7 on Windows, Linux or macOS.

On the SEPPmail Appliance, you need to have a user configured in the "legacyappadmin" group. Create the group if needed.

## PowerShell Multi-Edition Support

The module supports both PowerShell Core and Desktop editions. It has been tested with PS 5.1 (Windows) and PS 7.0.2 (MacOS and Ubuntu).
Other Versions (6.x) and other operating systems will most likely work as well.

## Installation and Setup Info

### PowerShell Gallery (preferred option)

We have published the module on the <https://www.PowerShellGallery.com>. You can install the module by running:

```powershell
Install-module SEPPmailLegacy
```

To install it in the users scope use:

```powershell
Install-module SEPPmailLegacy -Scope CurrentUser
```

### Github

If you have no access to the PowerShell Gallery but git installed, clone the module into a folder which is listed in the $env:PSmodulePath, preferably your home-PSmodule folder ~\Documents\PowerShell\Modules.

Set your location to this folder and enter:
`git clone https://github.com/SEPPmail/SeppmailLegacy`

If you do not have git installed, download the files from the repository, unblock the zip file (PS CmdLet `Unblock-File`) and place it in the modules folder.

IMPORTANT: Its imperative, that the Module is installed in a folder which is included in the $env:PSModulePath, otherwise it will not work.

## Loading and initial configuration of the module

Be sure the module is accessible with

```powershell
Get-Module SEPPmailLegacy -Listavailable
```

and load it into memory with

```powershell
Import-Module SEPPmailLegacy
```

During the first import, the module checks if there is a configuration file named SLCurrent.config in $HOME/.SEPPMailLegacy, which does not exist by default. Use

```powershell
New-SLConfig
```

to create one.

### Storing secrets

To avoid entering your legacy-api-user-credentials every time you make a request, or storing it in a script, we store credentials in an encrypted XML file in the config folder. Remember that the XML files only work with the account they have been created.

## Using the module

Start with:

```powershell
Import-Module SEPPmailLegacy
```

This will load the module. The very first time, you will get an error that there is no configuration file.

```powershell
New-SLConfig
```

will ask you for SEPPmail FQDN, Username and Passwort of a Legacy-API user and create a proper configuration for you.

Usage examples can be found in the module example folder \examples.

## Finding Help

Use the PowerShell help system to get examples and parameter help for each CmdLet as the example below.

```powershell
Get-Help Get-SLEncInfo
Get-Help Get-SLEncInfo -Parameter personal
Get-Help Get-SLEncInfo -Examples
```

--- This is the end of the file ---
