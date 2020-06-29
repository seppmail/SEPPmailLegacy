# Examples to use the SEPPmailLegacy Module

The modules output are PSObjects for easier processing. Read the LegacyAPI documentation for explanation of the data.

## Configuration examples

### Find out the current used configuration

Get-SLConfig - reads the corrent config and displays the settings
Test-SLConfig - Tests the config by trying to reach the SEPPmail appliance and retrieve some data.

### Create a new configuration

Set-SLConfig - Changes an existing config with new values


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

Get-SLStatsInfo -type user | Where-Object emailAddress -like 'max@mustermann.com'

### Get (sending) domain-based status info only

Get-SLStatsInfo -type domain|Where-Object domainname -like mustermann.com

## Create a New GINA-User

New-SLGINAUser -userName 'Max Mustermann' -eMailAddress max.mustermann@test.co -oneTimePw 'hZ76$59' -mobile '+49123456789'

You could also create a CSV-File with values for the users and pipe them into the command. (Very useful for mass-imports.)

Try or modify the CSV from the examples folder and use the command below.

Import-Csv .\examples\Ginaimport.csv|New-SLGINAUser

