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
