# SEPPmail Legacy API Powershell Module

Beginning from SEPPmail Appliance Version 11.1.7, SEPPmail supports a Legacy-API to retrieve statistics and encryption via REST, including the option to mass-generate GINA-Users. This PowerSHell module is a wrapper around this API to allow more convenient operation and interaction from the command line.

## Prerequisites

The module requires SEPPmail minimum version 11.1.7, Powershell 7.0 and the Microsoft.PowerShell.SecretManagement module version 0.2.0 minimum installed. Even that the Secret Management Module is in early alpha today it provides great support for storing credentials. For installation use "Install-Module Microsoft.PowerShell.SecretManagement -AllowPreRelease -Scope CurrentUser"

On the SEPPmail Appliance, you need to have a user configured in the reporting group as documented in the Legacy-API to access the API via REST.

## Installation

Clone the module into a folder which is listed in the $env:PSmodulePath, preferably your home-PSmodule folder (~\Documents\PowerShell\Modules). Set your location to this folder and enter :
git clone https://github.com/SEPPmail/SeppmailLegacy

If you dont have git installed, download the files from the repository, unblock the zip file (PS CmdLet Unblock-File) and place it in the modules folder.

## Loading and initial configuration of the module

Be sure the module is accessible with "Get-Module SEPPmailLegacy -Listavailable" and load it into memory with "Import-Module SEPPmailLegacy".
During the first import, the module checks if there is a configuration file named SLConfig.config in %LocalAppdata%\SEPPmailLegacy, which is not by default. Use "New-SLConfig" to create one.

### Using a secret from the secrets management module

The module Microsoft.PowerShell.SecretManagement allows it to store credentials (or other secret information) in a locally secure place. The Module uses this store to create credentials automatically when creating a new SLConfig.

## Using the module

Please find a general overview of the functionality of the module. More info can be found in the module example folder \Examples.
