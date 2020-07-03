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

Write-Verbose 'Setting Default variables'
$global:SLConfig = $null
$global:SlConfigContent = [ordered]@{}

Write-Verbose 'Set config path to Homedrive\.SEPPmailLegacy'
If ($iswindows) {
    $FullHomePath = Join-Path -Path ([Environment]::GetEnvironmentVariable('HOMEDRIVE')) -ChildPath ([Environment]::GetEnvironmentVariable('HOMEPATH'))
} else {
    $FullHomePath = $env:Home
}
If (!($Fullhomepath)) {
    Write-Error 'Could not set $fullHomePath to users home directory. Set the variable $FullHomePath manually and try to load the module again'
    break
}

$global:SLConfigPath = Join-Path -Path $FullHomepath -ChildPath '.SEPPmailLegacy'
$global:SLConfigFilePath = Join-Path -Path $SLConfigPath -ChildPath 'SLCurrent.config'

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




