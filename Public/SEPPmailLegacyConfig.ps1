function Set-SLConfig {
<#
.SYNOPSIS
    Sets the Config to a defined SEPPmail instance and credential
.DESCRIPTION
    Use this commandlet to define a SEPPmail Legacy configuration (SLConfig) for the SL Commandlets. Each SLConfig is stored with its FQND and the extension .config in the SLConfig directory. If you run Set-SLConfig, you need to specify a FQDN for a SEPPmail. The CmdLet reads the config, copies it over the default config (current.config) and loads it into the $SLConfig variable for use with other CmdLets.
.EXAMPLE
    PS> Set-SLConfig -SEPPmailFQDN securemail.contoso.de
    This will read the config file for the FQDN and set it as current config (stores in in the global variable $SLConfig)
.INPUTS
    Inputs (if any)
.OUTPUTS
    Output (if any)
.NOTES
    General notes
#>

    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $true
        )]
        [String]$SEPPmailFQDN

    )

    begin
    {
        $conf = $null
    }
    
    process
    {
        if ($SEPPmailFQDN) {
            Write-Verbose "Check if a file $SEPPmailFQDN.config exists"
            $SLConfigFilePath = (Join-Path -Path $SLConfigPath -ChildPath $SEPPmailFQDN) + '.config'
        }
        else {
            Write-Verbose "No FQDN specified, load default config file"
            $SLConfigFilePath = Join-Path -Path $SLConfigPath -ChildPath 'SLConfig.config'
        }

        if (!(Test-Path $SLConfigFilePath)) {
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
        if (!(Get-Secret $conf.Secret -Vault $SecretVaultName))
        {
            Write-Warning "$($conf.Secret) is missing in vault $SecretVaultName! Run New-SLConfig to create a proper configuration"
            break
        }
        else
        {
            $secureSecret = Get-Secret $conf.Secret -Vault $conf.secretVaultName
        }
        <#
        Write-Verbose "Writing default-Config File"
        $defaultconfigFilePath = Join-Path $SLConfigFilePath -ChildPath 'CurrentConfig.config'
        $conf = Set-Content $defaultconfigFilePath | ConvertFrom-Json
        #>
        Write-Verbose "Writing securesecret to config variable."
        $global:SLConfig = [ordered]@{
            SEPPmailFQDN    = $conf.SEPPmailFQDN
            Secret          = $secureSecret
            SecretVaultName = $SecretVaultName
            AdminPort       = $conf.Adminport
        }
    }
    
    end
    {
        if (!(Test-Path $SLConfigFilePath)) {
            Write-Warning 'There is no current configuration file defined (SLConfig.config). Run New-SLConfig without the -NotCurrent parameter to create one.'
        }
        return $conf
    }
}

function New-SLConfig
{
<#
.SYNOPSIS
    Creates or overwrites a new Configuration file
.DESCRIPTION
    Use this commandlet to create a SEPPmail Legacy configuration (SLConfig) for the SL Commandlets. Each SLConfig is stored with its FQND and the extension .config in the SLCOnfig directory. If you run New-SLConfig, you need to specify a FQDN  a username and a Password for the Legacy-enabled User for a SEPPmail. The CmdLet creates the config file.
.EXAMPLE
    PS> New-SLConfig -SEPPmailFQDN securemail.contoso.de -UserName Legacyadmin@contoso.de
    This will create the config file for the FQDN.

    PS> New-SLConfig -SEPPmailFQDN securemail.contoso.de -UserName Legacyadmin@contoso.de -AdminPort 8663
    This will create the config file for the FQDN with a different AdminPort

    PS> New-SLConfig -SEPPmailFQDN securemail.contoso.de -UserName Legacyadmin@contoso.de -NotCurrent
    This will create a config file but NOT copy it to the SLConfig.config. So it will not be used immediately.

.INPUTS
    Inputs (if any)
.OUTPUTS
    Output (if any)
.NOTES
    General notes
#>

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
            ValueFromPipelineByPropertyName = $true)]
        [Alias("Port")]
        [String]$AdminPort = '8443',

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
        Write-Verbose "Create secret in the secret vault if it does not exists"
        if (!(Get-SecretInfo $userName -Vault $secretVaultName))
        {
            Write-Verbose "Secret for username: $userName not found, creating new" 
            [Securestring]$secretPassword = Read-Host -Prompt "Enter Password for the above username" -AsSecureString
            Set-Secret -Vault $secretVaultName -Name $userName -Secret (New-Object -TypeName PSCredential -ArgumentList ($userName, $secretpassword))
        }

        Write-Verbose "Set Parametervalues into temporary config"
        $conf.SEPPmailFQDN = $SEPPmailFQDN
        If ($UserName) { $conf.Secret = $UserName }
        If ($SecretVaultName) { $conf.SecretVaultName = $SecretVaultName }
        If ($AdminPort) { $conf.AdminPort = $AdminPort }

        Write-Verbose "Writing new config to file."
        $SLConfigFilePath = (Join-Path $SLConfigPath -ChildPath $SEPPmailFQDN) + ".config"
        $conf | ConvertTo-Json | New-Item -Path $SLConfigFilePath -Force | Out-Null
        
        If ($Notcurrent) {
            Write-Verbose 'Just created config file, not copying it to SLConfig.config'
        }
        else {
            $CurrentSLConfigFilePath = (Join-Path $SLConfigPath -ChildPath 'SLconfig') + '.config'
            Copy-Item -Path $SLConfigFilePath -Destination $CurrentSLConfigFilePath |out-null
        }
    }
    
    end
    {
        return $conf
    }
}

function Test-SLConfig
{
    [CmdLetBinding()]
    param()

    begin
    {
        $conf = Set-SLConfig

    }
    process
    {
        try
        {
            if (!((Resolve-DnsName -Name $conf.SEPPmailFQDN -ErrorAction 0).IPAddress))
            {
                Write-Error "Could not resolve SEPPmailFQDN, please check DNS and FQDN Name!"
            }
            else
            {
                Write-Host "DNS query to $($conf.SEPPmailFQDN) worked." -ForegroundColor Green
            }
            #((Test-Netconnection -ComputerName $conf.SEPPmailFQDN -Port $conf.AdminPort).TcpTestSucceeded)
            if (!((Test-NetConnection -ComputerName $conf.SEPPmailFQDN -Port $conf.AdminPort -WarningAction SilentlyContinue).TcpTestSucceeded))
            {
                Write-Error "Could not connect to port $conf.AdminPort! Check Firewalls and Port configuration." 
            }
            else
            {
                Write-Host "TCP Connect to $($conf.SEPPmailFQDN) on Port $($conf.AdminPort) worked." -ForegroundColor Green
            }
            # Try login at SEPPmail and receive group INfo

            $urlroot = New-SLUrlRoot -FQDN $conf.SEPPmailFQDN -adminPort $conf.adminPort
            $uri = $urlroot + 'statistics' + '?' + 'returnType' + '=' + 'CSV'
            try 
            {
                if ((Invoke-RestMethod -Uri $uri -Method GET -Authentication Basic -Credential $conf.secret | ConvertFrom-Csv -Delimiter ';' | Select-Object -First 1).Length -eq '1') 
                {
                    Write-Host "Data access with $($conf.secret.UserName) worked." -ForegroundColor Green
                }
            }
            catch
            {
                Write-Error "Most likely an access error"
                Write-Error "Check group membership of Legacy API group, username and password, details below"
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
        # shall return true or false
    }
}

function Remove-SLConfig
{
<#
.SYNOPSIS
    Removes a Configuration file
.DESCRIPTION
    Use this commandlet to remove an existing SEPPmail Legacy configuration (SLConfig) for the SL Commandlets.
.EXAMPLE
    PS> Remove-SLConfig -SEPPmailFQDN securemail.contoso.de
    This will remove the config file for the FQDN and the secret in the BuildInLocalLault
.INPUTS
    Inputs (if any)
.OUTPUTS
    Output (if any)
.NOTES
    General notes
#>

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
        try {
            Write-Verbose "Read File "
            $FQDNConfigFilePath = (Join-Path $SLConfigPath -ChildPath $SEPPmailFQDN) + ".config"

            Write-Verbose 'Config file found, trying to remove secrets'
            $secretName = (Get-Content $FQDNConfigFilePath|convertfrom-JSON).secret
            $secretVaultName = (Get-Content $FQDNConfigFilePath|convertfrom-JSON).secretVaultName
            If (Get-Secret -Name $secretName -Vault $SecretVaultName)  {
                Remove-Secret -Name $secretName -Vault $SecretVaultName
            }

            if (Test-Path $FQDNConfigFilePath) {
                Write-Verbose "Removing File $FQDNConfigFilePath"
                Remove-Item $FQDNConfigFilePath
            }
            else {
                Write-Warning "Config File for $SEPPmailFQDN not found"
            }
            

        }
    catch {
            $_.Exception
        }
    }
    
    end
    {
    }
}

function Find-SLConfig
{
<#
.SYNOPSIS
    Lists available Configuration files
.DESCRIPTION
    Use this commandlet to get an overview of existing SEPPmail Legacy configurations (SLConfig).
.EXAMPLE
    PS> Find-SLConfig
.INPUTS
    Inputs (if any)
.OUTPUTS
    Output (if any)
.NOTES
    General notes
#>

    [CmdletBinding()]
    param (        
    [Parameter(
        Mandatory = $false
        )]
    [String]$ConfigName

    )
    begin
    {
        if ($ConfigName) {
            $Configurations = @(Get-ChildItem -Path $SLConfigPath -Exclude 'SLConfig*'|where-object Name -like $ConfigName)
#            $Configurations = @(Get-ChildItem -Path $SLConfigPath -Filter "$ConfigName.config")
        }
        else {
            $Configurations = @(Get-ChildItem -Path $SLConfigPath -Exclude 'SLConfig*')
#            $Configurations = @(Get-ChildItem -Path $SLConfigPath -Filter "*.config")
        }
    }
    process
    {
        foreach ($conf in $Configurations) {
            Get-Content $conf |ConvertFrom-JSON
        }
    }
    end
    {
    }
}
