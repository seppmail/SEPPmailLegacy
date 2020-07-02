$ModulePath = Split-Path ((Get-Module -Name SEPPmailLegacy -Listavailable).Path) 
. $ModulePath\Public\SEPPmailLegacyCmdLets.ps1
. $ModulePath\Public\SEPPmailLegacyConfig.ps1
. $ModulePath\Private\SEPPmailLegacyPrivate.ps1

