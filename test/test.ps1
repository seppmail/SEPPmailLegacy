$env:PSModulePath = $env:PSModulePath + ";C:\Users\roman.THEGALAXY\GitRepo"
Import-Module seppmaillegacy

# Create GINA User manually
New-SLGinaUser -eMailAddress 'max.mustermann@kufgem.at' -userName 'Max Mustermann' -pwd '0815Max'

# Update User 
Set-SLGinaUser -eMailAddress 'max.mustermann@kufgem.at' -mobile '+4366311223344'

# Bulk-Create GINA Users (just the first 2)
Import-Csv .\examples\NewGINAUsers.csv|select-object -first 2|New-SLGINAUser

# Inform Users per sms
$smsdata = Import-Csv .\examples\NewGINAUsers.csv|select-object -first 2|select-object mobile,password 
foreach ($i in $smsdata) {
    & ./test/send-aspsms.ps1 -mobile $($i.mobile) -text $($i.password)
}

# Bulk-Update GINA Users (just the first 2)
Import-Csv .\examples\UpdateGINAUsers.csv |select-object -first 2|Set-SLGINAUser

