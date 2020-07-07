# SEPPmail Legacy API Powershell Module

Beginning from SEPPmail Appliance Version 11.1.7, SEPPmail supports a Legacy-API to retrieve statistics and encryption information via REST, including the option to mass-generate GINA-Users. This PowerSHell module is a wrapper around this API to allow more convenient operation and interaction from the command line.

## Prerequisites

The module requires minimum SEPPmail version 11.1.7 and Powershell 5.1"

On the SEPPmail Appliance, you need to have a user configured in the reporting group as documented in the Legacy-API to access the API via REST.

## PowerShell Multi-Edition Support

The module supports both PowerShell Core and Desktop editions. It has been tested with PS 5.1 (Windows) and PS 7.0.2 (MacOS and Ubuntu)

## Installation

Clone the module into a folder which is listed in the $env:PSmodulePath, preferably your home-PSmodule folder (~\Documents\PowerShell\Modules). Set your location to this folder and enter :
git clone https://github.com/SEPPmail/SeppmailLegacy

If you dont have git installed, download the files from the repository, unblock the zip file (PS CmdLet Unblock-File) and place it in the modules folder.

IMPORTANT: Its imperative, that the Module is installed in a folder which is included in the $env:PSModulePath, otherwise it will not work.

## Loading and initial configuration of the module

Be sure the module is accessible with "Get-Module SEPPmailLegacy -Listavailable" and load it into memory with "Import-Module SEPPmailLegacy".
During the first import, the module checks if there is a configuration file named SLCurrent.config in $HOME\.SEPPMailLegacy, which does not exist by default. Use "New-SLConfig" to create one.

### Storing secrets

To avoid entering your legacy-api-user-credentials every time you make a request, or storing it in a script, the we stopre credentials in an encrypted XML file in the config folder. Remember that the XML files only work with the account they have been created.

The module Microsoft.PowerShell.SecretManagement allows it to store credentials (or other secret information) in a locally secure place. The Module uses this store to create credentials automatically when creating a new SLConfig.

## Using the module

Usage examples can be found in the module example folder \Examples.
