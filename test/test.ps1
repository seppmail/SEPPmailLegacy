$env:PSModulePath = $env:PSModulePath + ";C:\Users\roman.THEGALAXY\GitRepo"
Import-Module seppmaillegacy
set-slconfig -seppmailfqdn securemail.rconsult.at 

# Create GINA User manually
New-SLGinaUser -eMailAddress 'max.mustermann@contoso.at' -userName 'Max Mustermann' -pwd '0815Max'

# Update User 
Set-SLGinaUser -eMailAddress 'max.mustermann@contoso.at' -mobile '+4366311223344' -userName 'Max Mustermann'

# Bulk-Create GINA Users (just the first 2)
Import-Csv .\examples\NewGINAUsers.csv|New-SLGINAUser

# Inform Users per sms
$smsdata = Import-Csv .\examples\NewGINAUsers.csv|select-object mobile,password 
foreach ($i in $smsdata) {
    & ./test/send-aspsms.ps1 -mobile $($i.mobile) -text "Ihr Zugangskennwort ist $($i.password)"
}

# Bulk-Update GINA Users (just the first 2)
Import-Csv .\examples\UpdateGINAUsers.csv |Set-SLGINAUser


[string]$reportFileName = "{0:ddMMyyyy}" -f (Get-Date) + "-" + $SLConfig.SEPPmailFQDN + ".csv"
Get-SLStatsInfo -rebuild|Where-Object {(($_.emailAddress -notlike '*admin*') -and ($_.emailAddress -notlike '*legacy*') -and ($_.emailAddress -notlike '*o365connector*'))}|select-Object emailAddress,smimeEncMailsSent,smimeEncMailsReceived,smimeSigMailsSent,smimeSigMailsReceived,openPGPEncMailsSent,openPGPEncMailsReceived,ginaEncMailsSent,ginaEncMailsReceived,smimeDomainEncMailsSent,smimeDomainEncMailsReceived,openPGPDomainEncMailsSent,openPGPDomainEncMailsReceived|Add-Member -NotePropertyName 'ReportDate' -NotePropertyValue (Get-Date) -PassThru|Export-Csv -Path $ReportFileName -Encoding UTF8 -Delimiter ';' -NoTypeInformation -force
