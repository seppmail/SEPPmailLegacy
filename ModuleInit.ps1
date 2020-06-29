<#
.SYNOPSIS
    Module init script
.DESCRIPTION
    This script sets some global variables for the configuration paths and files and tests if those are available.
    If missing in creates the default path for configuration files and warns you about creating configs
.EXAMPLE
    no examples
.INPUTS
.OUTPUTS
.NOTES
#>
[CmdLetBinding()]
param()
If (($isWindows -ne $true))
{
    Write-Error "This module currently works only on PowerShell 7 on the Windows platform, module loading aborted"
    break
}

Write-Verbose 'Setting Default variables'
$global:SLConfig = $null
$global:SlConfigContent = [ordered]@{}
Write-Verbose 'Set config path to %localappdata%\SEPPmailLegacy'
$global:SLConfigPath = Join-Path -Path $env:LocalAppdata -ChildPath 'SEPPmailLegacy'
$global:SLConfigFilePath = Join-Path -Path $SLConfigPath -ChildPath 'SLConfig.config'
Write-verbose 'Setting Secrets Management Vault to default BuiltInLocalVault'
$global:SecretVaultName = 'BuiltInLocalVault'

Write-Verbose 'Testing Config Filepath'
if (!(Test-Path $SLConfigPath))
{
    Write-Warning 'No configuration path found, creating one'
    New-Item -Path $SLConfigPath -ItemType 'Directory' |Out-Null
}
Write-Verbose 'Testing current config file existence'
if (!(Test-Path $SLConfigFilePath))
{
    Write-Warning "No configuration file in default configuration path $SLConfigPath found."
    Write-Warning "Run New-SLConfig, otherwise the module will not work."
}




