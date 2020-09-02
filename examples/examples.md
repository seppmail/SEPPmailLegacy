# Examples to use the SEPPmailLegacy Module

Below, find some examples on how to use the module. The modulesCmdLets output are PSObjects for easier further processing. Read the LegacyAPI documentation for explanation of the data.

## Manage Configurations

## Creating a new configuration file with New-SLConfig

You need to run this before operating the module otherwise it will not know where to connect to.

```powershell
New-SLConfig
```

The CmdLet asks for FQDN and credential parameters and creates a config file with the name `FQDN.config`, (i.e. `securemail.contoso.de.config`).

By default it also copies this file to the `SLCurrent.config` file which is the default configuration. You can turn off this behavior by using the `-notcurrent` parameter.

```powershell
New-SLConfig -notcurrent
```

If you want to immediately operate with the config use:

```powershell
$global:SLConfig = New-SLConfig
```

### Using multiple configurations

As most customers have multiple SEPPmail instances (test and prod), you can store multiple config files and use them.

Calling

```powershell
Set-SLConfig
```

will always try to read the default config file SLCurrent.config and load it, except you specify a different FQDN via the `-SEPPmailFQDN` parameter.

So if you have created multiple config files with `New-SLconfig`,

```powershell
Set-SLConfig
```

can switch between them.

### Testing if a configuration works

```powershell
Test-SLConfig
```

tests the config by trying to reach the SEPPmail appliance and retrieve some data.

## Use the SEPPmailLegacy Module

### License Examples

#### License Info for a specific User

```powershell
Get-SLLicenseInfo|Where-Object userid -like 'max@mustermann.com'
```

#### Licenses used within the latest 3 months (active users)

```powershell
Get-SLLicenseInfo|Where-Object lastused -gt (Get-Date).AddMonths(-3)
```

#### Licenses used older than 3 months

```powershell
Get-SLLicenseInfo|Where-Object lastused -lt (Get-Date).AddMonths(-3)
```

#### Show License summary

```powershell
Get-SLLicenseInfo -summary
```

### Group Info Examples

Users can be member of groups for administrative access and other proposes. Use this CmdLets to get information about groups.

### List all Groups and all members

```powershell
Get-SLGroupInfo
```

#### Get the group-membership of a specific user

```powershell
Get-SLGroupInfo -Membername max@mustermann.com
```

#### Get all members of a specific group

```powershell
Get-SLGroupInfo -GroupName legacyappadmin
```

### Encryption Information examples

SEPPmail stores information which encryption capabilities are available for an external recipient. The CmdLet

```powershell
Get-SLEncInfo
```

can retrieve this data.
This CmdLets support the `-rebuild` parameter to get current infos of the statistics database.

The CMdLet has three operation modes (ParameterSets), personal, domain and EMailAddress. See examples below.

#### Show external recipients having SMIME as encryption method

```powershell
Get-SLEncInfo -personal -encModePer SMIME
```

#### Show external recipients having PGP as encryption method

```powershell
Get-SLEncInfo -personal -encModePer PGP
```

#### Show external recipients having GINA as encryption method

```powershell
Get-SLEncInfo -personal -encModePer GINA
Get-SLEncInfo -personal -encModePer GINA|Where-Object registered -eq 1
Get-SLEncInfo -personal -encModePer GINA|Where-Object status -ne 'enabled'
```

#### Show external domains have SMIME as encryption method

```powershell
Get-SLEncInfo -domain -encModeDom SMIME
```

#### Show external domains having PGP as encryption method

```powershell
Get-SLEncInfo -domain -encModeDom PGP
```

#### Show external domains having HIN as encryption method

```powershell
Get-SLEncInfo -domain -encModeDom HIN
```

#### Show external domains having TLS as encryption method

```powershell
Get-SLEncInfo -domain -encModeDOM TLS
```

#### Find out what encryption methods are possible for an external recipient

```powershell
Get-SLEncInfo -eMailAddress max@mustermann.com
```

### Read statistics from your SEPPmail

### Get all statistics data (i.e. for daily reports)

```powershell
Get-SLStatsInfo
```

### Get (sending) user-based status info only

```powershell
Get-SLStatsInfo -type user | Where-Object emailAddress -like 'internal.user@contoso.de'
```

### Get (sending) domain-based status info only

```powershell
Get-SLStatsInfo -type domain|Where-Object domainname -like mustermann.com
```

### Manage GINA Users

This API allows you to create and modify GINA Users. This avoids the registration process for external recipients and allows the usage of known passwords for the user (i.e. an invoice Number, social security number or similar) and the mobile number
to communicate via a second channel.

#### Create a New GINA-User

To create a new GINA user use the CmdLet as below.

```powershell
New-SLGINAUser -userName 'Max Mustermann' -eMailAddress max.mustermann@test.co -oneTimePw 'hZ76$59' -mobile '+49123456789'
```

You could also create a CSV-File with values for the users properties and pipe them into the command. (Very useful for mass-imports.)
Try or modify the CSV from the examples folder and use the command below.

```powershell
Import-Csv .\examples\NewGINAUsers.csv|New-SLGINAUser
```

#### Change a GINA Users properties

To modify and add additional properties use Set-GINAUser. This CmdLet is also pipeline-aware.
So either change single properties from the command line:

```powershell
Set-SLGINAUser -eMailAddress 'alice.miller@contoso.com' -answer 'Red'
```

You can also pipe the data into the CmdLet for mass-changes.

```powershell
Import-Csv .\examples\UpdateGINAUsers.csv|Set-SLGINAUser
```

--- This is the end of the file ---
