New-SLConfig -SEPPmailFQDN mail.seppmail.ch -UserName 'stadlmair@seppmail.at' 
New-SLConfig -SEPPmailFQDN securemail.rconsult.at -UserName 'legacyAPIUser'
Test-SLConfig

Get-SLLicenseInfo|where-Object lastused -gt (Get-Date).AddMonths(-3)
Get-SLLicenseInfo|where-Object lastused -lt (Get-Date).AddMonths(-3)
Get-SLLicenseInfo -summary
Get-SLGroupInfo
Get-SLGroupInfo -GroupName legacyappadmin
Get-SLEncInfo -personal -encModePer SMIME
Get-SLEncInfo -personal -encModePer PGP
Get-SLEncInfo -personal -encModePer GINA
Get-SLEncInfo -domain -encModeDom SMIME
Get-SLEncInfo -domain -encModeDom PGP
Get-SLEncInfo -domain -encModeDom HIN
Get-SLEncInfo -domain -encModeDOM TLS
Get-SLEncInfo -eMailAddress 'info@seppmail.ch'
Get-SLStatsInfo
Get-SLStatsInfo -type user | Where-Object emailAddress -like 'internal.user@contoso.de'
Get-SLStatsInfo -type domain|Where-Object domainname -like mustermann.com
New-SLGINAUser -userName 'Max Mustermann' -eMailAddress max.mustermann@test.co -oneTimePw 'hZ76$59' -mobile '+49123456789'
Import-Csv .\examples\Ginaimport.csv|New-SLGINAUser
