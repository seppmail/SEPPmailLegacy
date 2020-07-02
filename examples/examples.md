# Examples to use the SEPPmailLegacy Module

The modules output are PSObjects for easier processing. Read the LegacyAPI documentation for explanation of the data.

## Manage Configurations

## Creating a new configuration file with New-SLConfig

You need to run this before operating the module otherise it will not know where to connect to. New-SLConfig asks for FQDN and Credential parameters and
creates a config file with the name FQDN.config

By default it also copies this file to the SLConfig.config file which is the default config. You can turn off this behavior by using the -notcurrent parameter.
If you want to immediately operato with the config use $global:SLConfig = New-SLConfig

### Using multiple configurations

As most customers have multiple SEPPmail instances, you can store multiple config files and use them.

Calling Set-SLConfig will always try to read the Default Config file SLConfig.config and load it, except you speficy a FQDN parameter.

So if you have created multiple config files with new-slconfig, SET-SLConfig can switch between them.

### Testing if a configuration works

Test-SLConfig tests the config by trying to reach the SEPPmail appliance and retrieve some data.


## License examples

### License Info for a specific User

Get-SLLicenseInfo|where-Object userid -like 'max@mustermann.com'

### Licenses used within the latest 3 months (active users)

Get-SLLicenseInfo|where-Object lastused -gt (Get-Date).AddMonths(-3)

### Licenses used older than 3 months

Get-SLLicenseInfo|where-Object lastused -lt (Get-Date).AddMonths(-3)

### Show License summary

Get-SLLicenseInfo -summary

## Group Info Examples

### List all Groups and all members

Get-SLGroupInfo

### Get the group-membership of a specific user

Get-SLgroupInfo -Membername max@mustermann.com

### Get all members of a specific group

Get-SLGroupInfo -GroupName legacyappadmin

## Encryption Information examples

All EncInfo CmdLets support the -rebuild parameter to get current infos of the statistics database

### Show external recipients having SMIME as encryption method

Get-SLEncInfo -personal -encModePer SMIME

### Show external recipients having PGP as encryption method

Get-SLEncInfo -personal -encModePer PGP

### Show external recipients having GINA as encryption method

Get-SLEncInfo -personal -encModePer GINA
Get-SLEncInfo -personal -encModePer GINA|where registered -eq 1
Get-SLEncInfo -personal -encModePer GINA|where status -ne 'enabled'

### Show external domains have SMIME as encryption method

Get-SLEncInfo -domain -encModeDom SMIME

### Show external domains having PGP as encryption method

Get-SLEncInfo -domain -encModeDom PGP

### Show external domains havig HIN as encryption method

Get-SLEncInfo -domain -encModeDom HIN

### Show external domains having TLS as encryption method

Get-SLEncInfo -domain -encModeDOM TLS

### Find out what encryption methods are possible for an external recipient

Get-SLEncInfo -eMailAddress max@mustermann.com

## Read statistics from your SEPPmail

### Get all statistics data (i.e. for daily reports)

Get-SLStatsInfo

### Get (sending) user-based status info only

Get-SLStatsInfo -type user | Where-Object emailAddress -like 'internal.user@contoso.de'

### Get (sending) domain-based status info only

Get-SLStatsInfo -type domain|Where-Object domainname -like mustermann.com

## Create a New GINA-User

New-SLGINAUser -userName 'Max Mustermann' -eMailAddress max.mustermann@test.co -oneTimePw 'hZ76$59' -mobile '+49123456789'

You could also create a CSV-File with values for the users and pipe them into the command. (Very useful for mass-imports.)

Try or modify the CSV from the examples folder and use the command below.

Import-Csv .\examples\Ginaimport.csv|New-SLGINAUser

