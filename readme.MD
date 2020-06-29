# SEPPmail Legacy API Powershell Module

Beginning from SEPPmail Appliance Version 11.1.7, SEPpmail supports a Legacy-API, including the option to generate GINA-Users in advance. The API is based on a REST-API. This PowerSHell module is a wrapper around this API to allow more convenient operation and interaction from the command line.

## Prerequisites

The module requires SEPPmail minimum version 11.1.7, Powershell 7.0 and the Microsoft.PowerShell.SecretsManagement module version 0.2.0 minimum installed. Even thoe the Secret Management Module is in early alpha today it provides great support for storing credentials. For installation use "Install-Module Microsoft.PowerShell.SecretManagement -AllowPreRelease -Scope CurrentUser"

On the SEPPmail Appliance, you need to have a user configured in the reporting group as documented in the Legacy-API to access the API via REST.

## Installation

Clone the module into a folder which is listed in the $env:PSmodulePath, preferably your home-PSmodule folder (~\Documents\PowerShell\Modules). Set your location to this folder and enter :
git clone https://github.com/SEPPmail/SeppmailLegacy

## Loading and initial configuration of the module

Be sure the module is accessible with "Get-Module SEPPmailLegacy -Listavailable" and load it into memory with "Import-Module SEPPmailLegacy".  During the first import, the module checks if there is a configuration file in %LocalAppdata%\SEPPmailLegacy, which is not by default. Use New-SLConfig to create one.

### Using a secret from the secrets management module

The module Microsoft.PowerShell.SecretManagement allows it to store credentials (or other secret information) in a locally secure place. the Module uses this store to create credentials automatically when creating a new SLCOnfig.

## Using the module

Please find a general overview of the functionality of the module. More info can be found in the module example folder \Examples.

### License Information

Get-SLLicenseInfo provides information about the current licensing status (user-based licenses). There is a parameterset for individual licenses and one for a summary report.

### Group Information

Users can be organizes into groups for administrative purposes in SEPPmail. To receive this group Information use Get-SLGroupInfo.
