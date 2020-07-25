<#
.SYNOPSIS
    Sets the Config to a defined SEPPmail instance and credential
.DESCRIPTION
    Use this commandlet to define a SEPPmail Legacy configuration (SLConfig) for the SL Commandlets. Each SLConfig is stored with its FQND and the extension .config in the SLConfig directory. If you run Set-SLConfig, you need to specify a FQDN for a SEPPmail. The CmdLet reads the config, copies it over the default config (current.config) and loads it into the $SLConfig variable for use with other CmdLets.
.EXAMPLE
    PS> Set-SLConfig -SEPPmailFQDN securemail.contoso.de
    This will read the config file for the FQDN and set it as current config (stores in in the global variable $SLConfig)
.EXAMPLE
    PS> Set-SLConfig -SEPPmailFQDN securemail.contoso.de -SetasDefault
    This will read the config file for the FQDN and set it as current config and overwrites the default config file SLCurrent.config
#>

function Set-SLConfig
{

    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $true
        )]
        [String]$SEPPmailFQDN,

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Overwrites the default config file SLCurrent.Config so that future requests use the new config'
        )]
        [switch]$setAsDefault = $false
    )

    begin
    {
        $conf = $null
    }
    
    process
    {
        if ($SEPPmailFQDN)
        {
            Write-Verbose "Check if a file $SEPPmailFQDN.config exists"
            $SLConfigFilePath = (Join-Path -Path $SLConfigPath -ChildPath $SEPPmailFQDN) + '.config'
        }
        else
        {
            Write-Verbose "No FQDN specified, load default config file"
            $SLConfigFilePath = Join-Path -Path $SLConfigPath -ChildPath 'SLCurrent.config'
        }

        if (!(Test-Path $SLConfigFilePath))
        {
            Write-Warning 'Configuration file does not exist - please check FQDN or create a new configuration with New-SLConfig'
            break
        }

        Write-Verbose "Check if the $SEPPmailFQDN.config file contains all needed properties"
        $conf = Get-Content $SLConfigFilePath | ConvertFrom-Json
        If ((!($conf.SEPPmailFQDN)) -or (!($conf.Secret)) -or (!($conf.AdminPort)))
        {
            Write-Warning -Message "Configuration incomplete! Run New-SLConfig to create a proper configuration"
            break
        }

        Write-Verbose "Testing if $($conf.Secret) exists in secrets store."
        $SecFilePath = Join-Path -Path $SLConfigPath -ChildPath ("$($Conf.Secret)" + '.xml')
        if (!(Test-Path -Path $SecFilePath))
        {
            Write-Warning "Stored credentials XML file $($conf.Secret) is missing! Run New-SLConfig to create a proper configuration"
            break
        }
        else
        {
            $secureSecret = Import-Clixml -Path $SecFilePath
        }
        if ($setAsDefault -eq $true) {
            Write-Verbose "Writing default-Config File SLCurrent.config"
            $defaultconfigFilePath = Join-Path $SLConfigPath -ChildPath 'SLCurrent.config'
            Set-Content $defaultconfigFilePath -Value ($conf| ConvertTo-Json)
        }

        Write-Verbose "Writing securesecret to config variable."
        $global:SLConfig = [ordered]@{
            SEPPmailFQDN         = $conf.SEPPmailFQDN
            Secret               = $secureSecret
            AdminPort            = $conf.Adminport
            SkipCertificateCheck = $true
        }

    }
    
    end
    {
        if (!(Test-Path $SLConfigFilePath))
        {
            Write-Warning 'There is no current configuration file defined (SLConfig.config). Run New-SLConfig without the -NotCurrent parameter to create one.'
        }
        return $conf
    }
}

<#
.SYNOPSIS
    Creates or overwrites a new Configuration file
.DESCRIPTION
    Use this commandlet to create a SEPPmail Legacy configuration (SLConfig) for the SL Commandlets. Each SLConfig is stored with its FQND and the extension .config in the SLCOnfig directory. If you run New-SLConfig, you need to specify a FQDN  a username and a Password for the Legacy-enabled User for a SEPPmail. The CmdLet creates the config file.
.EXAMPLE
    PS> New-SLConfig -SEPPmailFQDN securemail.contoso.de -UserName Legacyadmin@contoso.de
    This will create the config file for the FQDN.
.EXAMPLE
    PS> New-SLConfig -SEPPmailFQDN localhost -UserName Legacyadmin@contoso.de -SkipCertificateCheck $true
    This will create the config file for the FQDN and will not run Certificatechecks on this machine.
.EXAMPLE
    PS> New-SLConfig -SEPPmailFQDN securemail.contoso.de -UserName Legacyadmin@contoso.de -AdminPort 10443
    This will create the config file for the FQDN with a different AdminPort
.EXAMPLE
    PS> New-SLConfig -SEPPmailFQDN securemail.contoso.de -UserName Legacyadmin@contoso.de -NotCurrent
    This will create a config file but NOT copy it to the SLConfig.config. So it will not be used immediately.
#>
function New-SLConfig
{
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Alias("FQDN")]
        [ValidatePattern("^(?!:\/\/)(?=.{1,255}$)((.{1,63}\.){1,127}(?![0-9]*$)[a-z0-9-]+\.?)$")]
        [String]$SEPPmailFQDN,

        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Alias("sec")]
        [String]$UserName,

        [Parameter(
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Default is 8443, but you may use another port like 10443')]
        [Alias("Port")]
        [String]$AdminPort = '8443',

        [Parameter(
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'For testmachines which have no valid certificates, turn this on by simply adding -SkipCertificateCheck $true in the commandline')]
        [Alias("Skip")]
        [bool]$SkipCertificateCheck = $false,
         
        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Set if you do NOT want this new config to be set as default'
        )]
        [Switch]$NotCurrent = $false

    )
    
    begin
    {
        Write-Verbose 'Create an empty config hashtable'
        $conf = [ordered]@{}
    }
    
    process
    {
        $SecFilePath = Join-Path -Path $SLConfigPath -ChildPath ("$UserName" + ".xml")
        Write-Verbose "Create secret here: $SecFilePath if it does not exists"
        if (!(Test-Path -Path $SecFilePath))
        {
            Write-Verbose "Secret for username: $userName not found, creating new" 
            [Securestring]$secretPassword = Read-Host -Prompt "Enter Password for the above username" -AsSecureString
            New-Object -TypeName PSCredential -ArgumentList ($userName, $secretpassword) | Export-Clixml -Path $SecFilePath
        }

        Write-Verbose "Set Parametervalues into temporary config"
        $conf.SEPPmailFQDN = $SEPPmailFQDN
        If ($UserName) { $conf.Secret = $UserName }
        If ($AdminPort) { $conf.AdminPort = $AdminPort }
        $conf.SkipCertificateCheck = $SkipCertificateCheck

        Write-Verbose "Writing new config to file."
        $SLConfigFilePath = (Join-Path $SLConfigPath -ChildPath $SEPPmailFQDN) + ".config"
        $conf | ConvertTo-Json | New-Item -Path $SLConfigFilePath -Force | Out-Null
        
        If ($Notcurrent)
        {
            Write-Verbose 'Just created config file, not copying it to SLCurrent.config'
        }
        else
        {
            $CurrentSLConfigFilePath = (Join-Path $SLConfigPath -ChildPath 'SLCurrent') + '.config'
            Copy-Item -Path $SLConfigFilePath -Destination $CurrentSLConfigFilePath | Out-Null
        }
    }
    
    end
    {
        return $conf
    }
}

<#
.SYNOPSIS
    Test a SEPPmail config
.DESCRIPTION
    After defining a configuration to a SEPPmail appliance, this CmdLet tests
    to read some data
.EXAMPLE
    PS C:\> Test-SLConfig -SEPPmailFQDN 'securemail.contoso.de'
    Tests if legacyapi access to securemail.contoso.de works and raises relevant errors.
#>
function Test-SLConfig
{
    [CmdLetBinding()]
    param()

    begin
    {
        Set-SLConfig

    }
    process
    {
        try
        {
            if ($IsWindows)
            {
                if (!((Resolve-DnsName -Name $SLConfig.SEPPmailFQDN -ErrorAction 0).IPAddress))
                {
                    Write-Error "Could not resolve SEPPmailFQDN, please check DNS and FQDN Name!"
                }
                else
                {
                    Write-Host "DNS query to $($SLConfig.SEPPmailFQDN) worked." -ForegroundColor Green
                }
            }

            #((Test-Netconnection -ComputerName $SLConfig.SEPPmailFQDN -Port $SLConfig.AdminPort).TcpTestSucceeded)
            if ($IsWindows -or ($PSversiontable.PSEdition -eq 'Desktop'))
            {
                if (!((Test-NetConnection -ComputerName $SLConfig.SEPPmailFQDN -Port $SLConfig.AdminPort -WarningAction SilentlyContinue).TcpTestSucceeded))
                {
                    Write-Error "Could not connect to port $SLConfig.AdminPort! Check Firewalls and Port configuration." 
                }
                else
                {
                    Write-Host "TCP Connect to $($SLConfig.SEPPmailFQDN) on Port $($SLConfig.AdminPort) worked." -ForegroundColor Green
                }
            }
            else
            {
                if (!(Test-Connection -ComputerName $SLConfig.SEPPmailFQDN -TcpPort $SLConfig.AdminPort -WarningAction SilentlyContinue -Quiet))
                {
                    Write-Error "Could not connect to port $SLConfig.AdminPort! Check Firewalls and Port configuration." 
                }
                else
                {
                    Write-Host "TCP Connect to $($SLConfig.SEPPmailFQDN) on Port $($SLConfig.AdminPort) worked." -ForegroundColor Green
                }
            }
            
            # Try login at SEPPmail and receive group INfo

            $urlroot = New-SLUrlRoot -FQDN $SLConfig.SEPPmailFQDN -adminPort $SLConfig.adminPort
            $uri = $urlroot + 'statistics' + '?' + 'returnType' + '=' + 'CSV'
            try 
            {
                if ((Invoke-RestMethod -Uri $uri -Method GET -Credential $SLConfig.secret | ConvertFrom-Csv -Delimiter ';' | Select-Object -First 1).Length -eq '1') 
                {
                    Write-Host "Data access with $($SLConfig.secret.UserName) worked." -ForegroundColor Green
                }
            }
            catch
            {
                Write-Error "Most likely an access error"
                Write-Error "Check e-Mail/password and membership of the user to the group `"legacyappadmin`". Create the group if necessary."
                $_
            }
        }
        catch
        {
            Write-Error "Configuratiton is not valid! See error below"
            $_
        }
    }
    end
    {
        # No code here
    }
}

<#
.SYNOPSIS
    Removes a Configuration file
.DESCRIPTION
    Use this commandlet to remove an existing SEPPmail Legacy configuration (SLConfig) for the SL Commandlets.
.EXAMPLE
    PS> Remove-SLConfig -SEPPmailFQDN securemail.contoso.de
    This will remove the config file for the FQDN and the secret in the BuildInLocalLault
#>
function Remove-SLConfig
{

    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Alias("FQDN")]
        [String]$SEPPmailFQDN

    )
    
    begin
    {
    }
    
    process
    {
        try
        {
            Write-Verbose "Read File "
            $FQDNConfigFilePath = (Join-Path $SLConfigPath -ChildPath $SEPPmailFQDN) + ".config"

            if ($FQDNConfigFilePath)
            {
                Write-Verbose 'Config file found, trying to remove secrets'
                $SecretName = (Get-Content $FQDNConfigFilePath | ConvertFrom-Json).Secret
                $SecFilePath = Join-Path -Path $SLConfigPath -ChildPath ("$SecretName" + ".xml")
                If ((Import-Clixml -Path $SecFilePath -ea 0))
                {
                    Write-Verbose "Removing Credentials file $SecFilePath"
                    Remove-Item -Path $SecFilePath -Force
                }
                if (Test-Path $FQDNConfigFilePath)
                {
                    Write-Verbose "Removing File $FQDNConfigFilePath"
                    Remove-Item -Path $FQDNConfigFilePath -Force
                }
                else
                {
                    Write-Warning "Config File for $SEPPmailFQDN not found"
                }
            }
        }
        catch
        {
            $_.Exception
        }
    }
    end
    {
    }
}

<#
.SYNOPSIS
    List existing configurations
.DESCRIPTION
    Reads the .SEPPmailLegacy directory and reads all sonfig files.
.EXAMPLE
    PS C:\> Find-SLConfig
    Lists all the configurations found, including parameters
.EXAMPLE
    PS C:\> Find-SLConfig -Config securemail.sontoso.de
    List a specific config, including parameters
#>
function Find-SLConfig
{
    [CmdletBinding()]
    param (        
        [Parameter(
            Mandatory = $false
        )]
        [String]$ConfigName

    )
    begin
    {
        try {
            if ($ConfigName)
            {
                Write-Verbose 'Storing names $Configurations array'
                $Configurations = @(Get-ChildItem -Path (Join-Path $SLConfigPath -ChildPath '\*.config') -Exclude 'SLCurrent*' | Where-Object Name -Like $ConfigName)
            }
            else
            {
                Write-Verbose 'Storing $Configurations array of all configuration files'
                $Configurations = @(Get-ChildItem -Path (Join-Path $SLConfigPath -ChildPath '\*.config')-Exclude 'SLCurrent*')
            }
        }
        catch {
            Write-Error "Find-SLConfig failes with error $_.CategoryInfo"
        }
    }
    process
    {
        try {
            Write-Verbose 'Looping through $configurations array'
            foreach ($conf in $Configurations)
            {
                Write-Verbose 'Emit Configuration'
                Get-Content $conf | ConvertFrom-Json
            }
        }
        catch {
            Write-Error "Find-SLConfig failes with error $_.CategoryInfo"
        }
    }
    end
    {
    }
}

# SIG # Begin signature block
# MIIL1wYJKoZIhvcNAQcCoIILyDCCC8QCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU5pzYxv9teFj4dO/ZQ4diAT6r
# +8uggglAMIIEmTCCA4GgAwIBAgIQcaC3NpXdsa/COyuaGO5UyzANBgkqhkiG9w0B
# AQsFADCBqTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDHRoYXd0ZSwgSW5jLjEoMCYG
# A1UECxMfQ2VydGlmaWNhdGlvbiBTZXJ2aWNlcyBEaXZpc2lvbjE4MDYGA1UECxMv
# KGMpIDIwMDYgdGhhd3RlLCBJbmMuIC0gRm9yIGF1dGhvcml6ZWQgdXNlIG9ubHkx
# HzAdBgNVBAMTFnRoYXd0ZSBQcmltYXJ5IFJvb3QgQ0EwHhcNMTMxMjEwMDAwMDAw
# WhcNMjMxMjA5MjM1OTU5WjBMMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMdGhhd3Rl
# LCBJbmMuMSYwJAYDVQQDEx10aGF3dGUgU0hBMjU2IENvZGUgU2lnbmluZyBDQTCC
# ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJtVAkwXBenQZsP8KK3TwP7v
# 4Ol+1B72qhuRRv31Fu2YB1P6uocbfZ4fASerudJnyrcQJVP0476bkLjtI1xC72Ql
# WOWIIhq+9ceu9b6KsRERkxoiqXRpwXS2aIengzD5ZPGx4zg+9NbB/BL+c1cXNVeK
# 3VCNA/hmzcp2gxPI1w5xHeRjyboX+NG55IjSLCjIISANQbcL4i/CgOaIe1Nsw0Rj
# gX9oR4wrKs9b9IxJYbpphf1rAHgFJmkTMIA4TvFaVcnFUNaqOIlHQ1z+TXOlScWT
# af53lpqv84wOV7oz2Q7GQtMDd8S7Oa2R+fP3llw6ZKbtJ1fB6EDzU/K+KTT+X/kC
# AwEAAaOCARcwggETMC8GCCsGAQUFBwEBBCMwITAfBggrBgEFBQcwAYYTaHR0cDov
# L3QyLnN5bWNiLmNvbTASBgNVHRMBAf8ECDAGAQH/AgEAMDIGA1UdHwQrMCkwJ6Al
# oCOGIWh0dHA6Ly90MS5zeW1jYi5jb20vVGhhd3RlUENBLmNybDAdBgNVHSUEFjAU
# BggrBgEFBQcDAgYIKwYBBQUHAwMwDgYDVR0PAQH/BAQDAgEGMCkGA1UdEQQiMCCk
# HjAcMRowGAYDVQQDExFTeW1hbnRlY1BLSS0xLTU2ODAdBgNVHQ4EFgQUV4abVLi+
# pimK5PbC4hMYiYXN3LcwHwYDVR0jBBgwFoAUe1tFz6/Oy3r9MZIaarbzRutXSFAw
# DQYJKoZIhvcNAQELBQADggEBACQ79degNhPHQ/7wCYdo0ZgxbhLkPx4flntrTB6H
# novFbKOxDHtQktWBnLGPLCm37vmRBbmOQfEs9tBZLZjgueqAAUdAlbg9nQO9ebs1
# tq2cTCf2Z0UQycW8h05Ve9KHu93cMO/G1GzMmTVtHOBg081ojylZS4mWCEbJjvx1
# T8XcCcxOJ4tEzQe8rATgtTOlh5/03XMMkeoSgW/jdfAetZNsRBfVPpfJvQcsVncf
# hd1G6L/eLIGUo/flt6fBN591ylV3TV42KcqF2EVBcld1wHlb+jQQBm1kIEK3Osgf
# HUZkAl/GR77wxDooVNr2Hk+aohlDpG9J+PxeQiAohItHIG4wggSfMIIDh6ADAgEC
# AhBdMTrn+ZR0fTH9F/xerQI2MA0GCSqGSIb3DQEBCwUAMEwxCzAJBgNVBAYTAlVT
# MRUwEwYDVQQKEwx0aGF3dGUsIEluYy4xJjAkBgNVBAMTHXRoYXd0ZSBTSEEyNTYg
# Q29kZSBTaWduaW5nIENBMB4XDTIwMDMxNjAwMDAwMFoXDTIzMDMxNjIzNTk1OVow
# XTELMAkGA1UEBhMCQ0gxDzANBgNVBAgMBkFhcmdhdTERMA8GA1UEBwwITmV1ZW5o
# b2YxFDASBgNVBAoMC1NFUFBtYWlsIEFHMRQwEgYDVQQDDAtTRVBQbWFpbCBBRzCC
# ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKE54Nn5Vr8YcEcTv5k0vFyW
# 26kzBt9Pe2UcawfjnyqvYpWeCuOXxy9XXif24RNuBROEc3eqV4EHbA9v+cOrE1me
# 4HTct7byRM0AQCzobeFAyei3eyeDbvb963pUD+XrluCQS+L80n8yCmcOwB+weX+Y
# j2CY7s3HZfbArzTxBHo5AKEDp9XxyoCc/tUQOq6vy+wdbOOfLhrNMkDDCsBWSLqi
# jx3t1E+frAYF7tXaO5/FEGTeb/OjXqOpoooNL38FmCJh0CKby090sBJP5wSienn1
# NdhmBOKRL+0K3bomozoYmQscpT5AfWo4pFQm+8bG4QdNaT8AV4AHPb4zf23bxWUC
# AwEAAaOCAWowggFmMAkGA1UdEwQCMAAwHwYDVR0jBBgwFoAUV4abVLi+pimK5PbC
# 4hMYiYXN3LcwHQYDVR0OBBYEFPKf1Ta/8vAMTng2ZeBzXX5uhp8jMCsGA1UdHwQk
# MCIwIKAeoByGGmh0dHA6Ly90bC5zeW1jYi5jb20vdGwuY3JsMA4GA1UdDwEB/wQE
# AwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzBuBgNVHSAEZzBlMGMGBmeBDAEEATBZ
# MCYGCCsGAQUFBwIBFhpodHRwczovL3d3dy50aGF3dGUuY29tL2NwczAvBggrBgEF
# BQcCAjAjDCFodHRwczovL3d3dy50aGF3dGUuY29tL3JlcG9zaXRvcnkwVwYIKwYB
# BQUHAQEESzBJMB8GCCsGAQUFBzABhhNodHRwOi8vdGwuc3ltY2QuY29tMCYGCCsG
# AQUFBzAChhpodHRwOi8vdGwuc3ltY2IuY29tL3RsLmNydDANBgkqhkiG9w0BAQsF
# AAOCAQEAdszNU8RMB6w9ylqyXG3EjWnvii7aigN0/8BNwZIeqLP9aVrHhDEIqz0R
# u+KJG729SgrtLgc7OenqubaDLiLp7YICAsZBUae3a+MS7ifgVLuDKBSdsMEH+oRu
# N1iGMfnAhykg0P5ltdRlNfDvQlIFiqGCcRaaGVC3fqo/pbPttbW37osyIxTgmB4h
# EWs1jo8uDEHxw5qyBw/3CGkBhf5GNc9mUOHeEBMnzOesmlq7h9R2Q5FaPH74G9FX
# xAG2z/rCA7Cwcww1Qgb1k+3d+FGvUmVGxJE45d2rVj1+alNc+ZcB9Ya9+8jhMssM
# LjhJ1BfzUWeWdZqRGNsfFj+aZskwxjGCAgEwggH9AgEBMGAwTDELMAkGA1UEBhMC
# VVMxFTATBgNVBAoTDHRoYXd0ZSwgSW5jLjEmMCQGA1UEAxMddGhhd3RlIFNIQTI1
# NiBDb2RlIFNpZ25pbmcgQ0ECEF0xOuf5lHR9Mf0X/F6tAjYwCQYFKw4DAhoFAKB4
# MBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQB
# gjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkE
# MRYEFEY0nLzbWlSaqHAF2uxoHQ36BKEoMA0GCSqGSIb3DQEBAQUABIIBAHhpwDyh
# lz6r6kR7BYJtfhyFnNrLcwqbOLIF1FmnHBifOy0F0GkHJ6A8wUSADYn2rDoM7Oea
# EOMA+9NEzQe1faCzRxqJg8kHFeO+U6AEjjWE4S7pQVF/6EoZjI2lckOExC9aK4qA
# ZUEDTTrQiQ7G1nwzu1kLot7lkcU91z+wXLd2spnxhpe3V8JjJ9u0AEY0vRs82CJF
# 4Yn+qNu+A/bjuWUhAS9TM7C098QzGCrAyFHqMFcYLyGHPK4a9g9OFI09R6g01Qpx
# 3Ec8qiYO5xwdQSQR1BlML8WE8AFAu2N1/tKmR2Yyz7slCCrA0B47Ao9aXsnheLCz
# 9ZyGc4M6o9kDuK0=
# SIG # End signature block
