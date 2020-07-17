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
$global:SLConfigPath = Join-Path -Path $HOME -ChildPath '.SEPPmailLegacy'
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
} else {
    "Using Configuration from default config path $SLconfigFilePath"
    Get-content $SLConfigFilePath|convertfrom-JSON
}





