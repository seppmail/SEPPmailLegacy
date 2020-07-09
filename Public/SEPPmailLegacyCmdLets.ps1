function Get-SLLicenseInfo
{
    [CmdletBinding()]
    param (
    
        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Receive a table with license summary info instead of single entries for each user'
        )]
        [switch]$summary
    )
    
    begin
    {
        Set-SLConfig | Out-Null
    }
    
    process
    {
        $urlroot = New-SLUrlRoot -FQDN $SLConfig.SEPPmailFQDN -adminPort $SLConfig.adminPort
        $uri = $urlroot + 'statistics' + '?' + 'returnType' + '=' + 'CSV'
        $csvstats = Invoke-RestMethod -Uri $uri -Method GET -Credential $SLConfig.secret | ConvertFrom-Csv -Delimiter ';'
        #'Account last used' Datum länger als 3 Monate her - keine Lizenz
        # wenn 'May not sign mails'-like 'YES' UND 'May not encrypt mails' -like 'YES - keine Lizenz verbraucht == Deaktiviert

        # Transform output to HT-Array and make sure to have proper values everywhere. 
        $statsarray = @()
        $statsArray = $csvstats | Select-Object 'User ID', 'Registered User', 'May not sign mails', 'May not encrypt mails', 'Account last used'`
        | ForEach-Object {
            [ordered]@{    
                'userid'   = if (($_.'User ID').Length -eq '0') { 'none' } else { $_.'User ID' };
                'reguser'  = $_.'Registered user';
                'nosig'    = if (($_.'May not sign mails').Length -eq '0') { $true } else { $false };
                'noenc'    = if (($_.'May not encrypt mails').Length -eq '0') { $true } else { $false };
                'lastused' = if (($_.'Account last used').Length -eq '0') { Get-Date -Day 1 -Month 1 -Year 2000 } else { Get-Date $_.'Account last used' }
            }
        }

    }
    
    end
    {
        if ($summary)
        {
            $totalKnownUsers = ($statsArray.count)
            $totalLic = ($statsArray | Where-Object { ($_.'reguser' -eq '1') } | Measure-Object).Count
            $inactiveLic = ($statsArray | Where-Object { ($_.'reguser' -eq '0') } | Measure-Object).Count
            $nosend3m = ($statsArray | Where-Object { ($_.'reguser' -eq '1') -and ($_.'nosig' -eq $true) -and ($_.'noenc' -eq $true) -and ($_.'lastused' -gt (Get-Date).AddMonths(-3)) } | Measure-Object).Count
            $usedLic = ($statsArray | Where-Object { ($_.userid -ne 'none') -and ($_.'reguser' -eq '1') -and ($_.'nosig' -eq $true) -and ($_.'noenc' -eq $true) -and ($_.'lastused' -gt (Get-Date).AddMonths(-3)) } | Measure-Object).Count
            <# Total of 3 encryption/signature users with an account, 
            but 0 set to inactive and 2 did not send mails in the last three months
            #>
            [psobject]$sum = @{
                'Total known users'                       = $totalKnownUsers
                'Total ever used licenses'                = $totalLic
                'Deactivated Licenses'                    = $inactiveLic
                'released licenses (inactive > 3 months)' = $nosend3m
                'Currently used Licenses'                 = $usedLic
            }
            return $sum

        }
        else
        {
            return $statsarray | ForEach-Object { [pscustomobject]$_ }
        }
    }
}

function Get-SLGroupInfo 
{
    [CmdletBinding()]
    param (
    
        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Username to look for group membership'
        )]
        [string]$MemberName,

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Groupname to look for user membership'
        )]
        [string]$GroupName

    )

    begin
    {
        #Write-Verbose 'Writing SLConfig to $global:SLConfig'
        Set-SLConfig | Out-Null
    }

    process
    {
        $urlroot = New-SLUrlRoot -FQDN $SLConfig.SEPPmailFQDN -adminPort $SLConfig.adminPort
        $uri = $urlroot + 'groupinfo' + '?' + 'returnType' + '=' + 'CSV'
        Write-Verbose 'Call REST-API'
        $groupraw = Invoke-RestMethod -Uri $uri -Method GET -Credential $SLConfig.secret | ConvertFrom-Csv -Delimiter ';'
        
        Write-Verbose 'Transform output to HT-Array and make sure to have proper values everywhere. '
        # [0] returns object with 2 members 'group name' and 'member names'
        # GroupName param set
        if ($groupName)
        {
            if ($groupraw | Where-Object { $_.'group name' -like $groupName })
            {
                $groupraw | Where-Object { $_.'group name' -like $groupName }
            }
            else
            {
                Write-Warning 'Group name not found, run without parameters to get list of group names'
            }
        }
        # MemberName param set

        if ($memberName)
        {
            foreach ($group in $groupraw) 
            {
                [string[]]$members = $group.'member names' -replace ' ', '' -split ','
                foreach ($m in $members) 
                {
                    if ($m -like $memberName) 
                    {
                        "User " + $m + " is member of " + "GroupName: " + $group.'group name'
                    }
                }
            }
        }

        # Ausgabe der Daten wenn keine Parameter angegeben werden
        if ((!($groupName)) -and (!($membername))) 
        {
            return $groupraw
        }

    }
}

function Get-SLStatsInfo
{
    [CmdletBinding()]
    param(

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Get user or domain statistics'
        )]
        [ValidateSet('user', 'domain')]
        [string]$type = 'user',

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Rebuild cached stats info database'
        )]
        [switch]$rebuild = $false
    )

    begin
    {
        Set-SLConfig | Out-Null | Out-Null
    }

    process 
    {
        $urlroot = New-SLUrlRoot -FQDN $SLConfig.SEPPmailFQDN -adminPort $SLConfig.adminPort
        if ($rebuild)
        {
            $uribase = $urlroot + 'statistics' + '?' + 'returnType' + '=' + 'CSV' + '&rebuildList'
        }
        else 
        {
            $uribase = $urlroot + 'statistics' + '?' + 'returnType' + '=' + 'CSV'
        }
        
        if ($type -like 'user') 
        {
            $uri = $uribase + '&statisticsType=user'
            $userStatsRaw = Invoke-RestMethod -Uri $uri -Method GET -Credential $SLConfig.secret | ConvertFrom-Csv -Delimiter ';'
            $userStatsRaw.'accountLastUsed'
            $userArray = @()
            $userArray = $userStatsRaw | ForEach-Object `
            {
                [ordered]@{
                    'emailAddress'                  = [string]$_.'E-mail address'
                    'userId'                        = if ((!($_.'User ID'))) { 'none' } else { [String]$_.'User ID' }
                    #'userId'                        = $_.'User ID'
                    'accountLastUsed'               = if (!($_.'Account last used')) { 'none' } else { [DateTime]$_.'Account last used' }
                    'noEnc'                         = if (($_.'May not encrypt mails').Length -eq '0') { $true } else { $false }
                    'noDec'                         = if (($_.'May not decrypt mails').Length -eq '0') { $true } else { $false }
                    'noSig'                         = if (($_.'May not sign mails').Length -eq '0') { $true } else { $false }
                    'groupMembership'               = [String[]]$_.'Group membership'
                    'regUser'                       = if ($_.'Registered user' -eq '0') { $false } else { $true }
                    'usesLicense'                   = if ($_.'Uses License' -eq '0') { $false } else { $true }
                    'certificateExpiresOn'          = if (($_.'Certificate expires on').Length -eq '0') { 'no expiration date set' } else { [DateTime]$_.'Certificate expires on' }
                    'smimeEncMailsSent'             = [int]$_.'S/MIME encrypted mails sent'
                    'smimeEncMailsReceived'         = [int]$_.'S/MIME encrypted mails received'
                    'smimeSigMailsSent'             = [int]$_.'S/MIME signed mails sent'
                    'smimeSigMailsReceived'         = [int]$_.'S/MIME signed mails received'
                    'openPGPEncMailsSent'           = [int]$_.'openPGP encrypted mails sent'
                    'openPGPEncMailsReceived'       = [int]$_.'openPGP encrypted mails received'
                    'ginaEncMailsSent'              = [int]$_.'GINA encrypted mails sent'
                    'ginaEncMailsReceived'          = [int]$_.'GINA encrypted mails received'
                    'smimeDomainEncMailsSent'       = [int]$_.'S/MIME Domain encrypted mails sent'
                    'smimeDomainEncMailsReceived'   = [int]$_.'S/MIME Domain encrypted mails received'
                    'openPGPDomainEncMailsSent'     = [int]$_.'openPGP Domain encrypted mails sent'
                    'openPGPDomainEncMailsReceived' = [int]$_.'openPGP Domain encrypted mails received'
                    'hinDomainEncMailsSent'         = [int]$_.'HIN Domain encrypted mails sent'
                    'hinDomainEncMailsReceived'     = [int]$_.'HIN domain encrypted mails received'
                    'mailsReroutedToIncamail'       = [int]$_.'Mails rerouted to Incamail'
                }
            }
            return $userArray | ForEach-Object { [pscustomobject]$_ }
        }
        if ($type -like 'domain') 
        {
            $uri = $uribase + '&statisticsType=domain'
            $domStatsRaw = Invoke-RestMethod -Uri $uri -Method GET -Credential $SLConfig.secret | ConvertFrom-Csv -Delimiter ';'
            Write-Verbose "Creating output Hashtables"
            $domArray = @()
            $domArray = $domstatsraw | ForEach-Object `
            {
                [ordered]@{
                    'domainName'                    = [string]$_.'Domain Name'
                    'smimeEncMailsSent'             = [int]$_.'S/MIME encrypted mails sent'
                    'smimeEncMailsReceived'         = [int]$_.'S/MIME encrypted mails received'
                    'smimeSignedMailsSent'          = [int]$_.'S/MIME signed mails sent'
                    'smimeSignedMailsReceived'      = [int]$_.'S/MIME signed mails received'
                    'openPGPEncMailsSent'           = [int]$_.'openPGP encrypted mails sent'
                    'openPGPEncMailsReceived'       = [int]$_.'openPGP encrypted mails received'
                    'ginaEncMailsSent'              = [int]$_.'GINA encrypted mails sent'
                    'ginaEncMailsReceived'          = [int]$_.'GINA encrypted mails received'
                    'smimeDomainEncMailsSent'       = [int]$_.'S/MIME Domain encrypted mails sent'
                    'smimeDomainEncMailsReceived'   = [int]$_.'S/MIME Domain encrypted mails received'
                    'openPGPDomainEncMailsSent'     = [int]$_.'openPGP Domain encrypted mails sent'
                    'openPGPDomainEncMailsReceived' = [int]$_.'openPGP Domain encrypted mails received'
                    'hinDomainEncMailsSent'         = [int]$_.'HIN Domain encrypted mails sent'
                    'hinDomainEncMailsReceived'     = [int]$_.'HIN domain encrypted mails received'
                    'mailsReroutedToIncamail'       = [int]$_.'Mails rerouted to Incamail'
                }
            }
            return $domArray | ForEach-Object { [pscustomobject]$_ }
        }
    }
}

function Get-SLEncInfo
{
    [CmdletBinding()]
    param (
        # Param block personal
        [Parameter(
            ParameterSetName = 'personal',
            Mandatory = $true,
            HelpMessage = 'Restrict to smtp-address-based encryption info'
        )]
        [switch]$personal,
        
        [Parameter(
            ParameterSetName = 'personal',
            Mandatory = $true,
            HelpMessage = 'Filter output to a specific encryption method'
        )]
        [ValidateSet('SMIME', 'PGP', 'GINA')]
        [Alias('encp')]
        [String]$encModePer,

        # Param block domain
        [Parameter(
            ParameterSetName = 'domain',
            Mandatory = $true,
            HelpMessage = 'Restrict to eMail-domain-based encryption info'
        )]
        [switch]$domain,
            
        [Parameter(
            ParameterSetName = 'domain',
            Mandatory = $true,
            HelpMessage = 'Filter output to a specific encryption method'
        )]
        [ValidateSet('SMIME', 'PGP', 'HIN', 'TLS')]
        [Alias('encd')]
        [String]$encModeDom,
                
        # param Block used in 'eMail' and multiple paramsets
        [Parameter(
            ParameterSetName = 'personal',
            Mandatory = $false,
            HelpMessage = 'Define a specific eMail adress'
        )]
        [Parameter(
            ParameterSetName = 'eMail',
            Mandatory = $true,
            HelpMessage = 'Define a specific eMail adress'
        )]
        [ValidatePattern('([a-z0-9][-a-z0-9_\+\.]*[a-z0-9])@([a-z0-9][-a-z0-9\.]*[a-z0-9]\.(arpa|root|aero|biz|cat|com|coop|edu|gov|info|int|jobs|mil|mobi|museum|name|net|org|pro|tel|travel|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cx|cy|cz|de|dj|dk|dm|do|dz|ec|ee|eg|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|st|su|sv|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)|([0-9]{1,3}\.{3}[0-9]{1,3}))')]
        [Alias('eMail')]
        [string]$eMailAddress,

        [Parameter(
            ParameterSetName = 'personal',
            Mandatory = $false,
            HelpMessage = 'Rebuild cached encryption info database'
        )]
        [Parameter(
            ParameterSetName = 'domain',
            Mandatory = $false,
            HelpMessage = 'Rebuild cached encryption info database'
        )]
        [Parameter(
            ParameterSetName = 'eMail',
            Mandatory = $false,
            HelpMessage = 'Rebuild cached encryption info database'
        )]
        [switch]$rebuild = $false

    )
    
    begin
    {
        Set-SLConfig | Out-Null
        $urlroot = New-SLUrlRoot -FQDN $SLConfig.SEPPmailFQDN -adminPort $SLConfig.adminPort
    }
    
    process
    {
        # Powershell 2-6 editions
        if ($PSCmdlet.ParameterSetName -eq 'personal') 
        {
            #$uri = "{0}{1}{2}/personal{3}{4}" -f $urlroot, 'encinfo', ($encModePer ? '/' + $encModePer.ToUpper():$null), ($eMailAddress ? '?mailAddress=' + $eMailAddress.ToLower():$null), ($rebuild ? '?rebuildList=1':$null)
            
            Write-Verbose 'Constructing personal parameterset'
            $encModePerParam = if ($encModePer) { '/' + "$($encModePer.ToUpper())" } else { $null }
            $eMailParam = if ($eMailAddress) { '?mailAddress=' + "$($eMailAddress.ToLower())" } else { $null }
            $rebuildParam = if ($rebuild) { '?rebuildList=1' } else { $null }
            
            Write-Verbose "passing encModeParam: $EncModePerParam, eMailParam: $eMailParam, rebuildParam: $rebuildParam"
            $uri = "{0}{1}{2}/personal{3}{4}" -f $urlroot, 'encinfo', $encModeParam, $eMailParam, $rebuildParam
            Write-Verbose "Final URI: $URI"
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'domain')
        {
            #$uri = "{0}{1}{2}/domain{3}" -f $urlroot, 'encinfo', ($encModeDom ? '/' + $encModeDom.ToUpper():$null), ($rebuild ? '?rebuildList=1':$null)
            
            Write-Verbose 'Constructing domain parameterset'
            $encModeDomParam = if ($encModeDom) { '/' + "$($encModeDom.ToUpper())" } else { $null }
            $rebuildParam = if ($rebuild) { '?rebuildList=1' } else { $null }            
            
            Write-Verbose "passing encModeParam: $EncModeParam, eMailParam: $eMailParam, rebuildParam: $rebuildParam"
            $uri = "{0}{1}{2}/domain{3}" -f $urlroot, 'encinfo', $encModeDomParam, $rebuildParam
            Write-Verbose "Final URI: $URI"
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'eMail')
        {
            $uri = "{0}{1}/?mailAddress={2}" -f $urlroot, 'encinfo', $eMailAddress
        }
        $rawdata = Invoke-RestMethod -Uri $uri -Method GET -Credential $SLConfig.secret
        switch ($PSCmdlet.ParameterSetname) 
        {
            personal
            {
                Switch ($encModePer)
                {
                    SMIME { return $rawdata.smime.personal }
                    PGP { return $rawdata.pgp.personal }
                    GINA { return $rawdata.gina.personal }
                }
            }
            domain
            {
                switch ($encModeDom)
                {
                    SMIME { return $rawdata.smime.domain }
                    PGP { return $rawdata.pgp.domain }
                    HIN { return $rawdata.hin.domain }
                    TLS { return $rawdata.tls.domain }
                }
            }
            eMail 
            {
                $returndata = New-Object -TypeName PSObject
                if ($rawdata.smime.domain.domain) { $returndata | Add-Member -MemberType Noteproperty -Name SMIMEdomain -Value $rawdata.smime.domain.domain }
                if ($rawdata.smime.personal.status) { $returndata | Add-Member -MemberType Noteproperty -Name SMIMEpersonal -Value $rawdata.smime.personal.status }
                if ($rawdata.pgp.domain.domain) { $returndata | Add-Member -MemberType Noteproperty -Name PGPdomain -Value $rawdata.pgp.domain.domain }
                if ($rawdata.pgp.personal.status) { $returndata | Add-Member -MemberType Noteproperty -Name PGPdomain -Value $rawdata.pgp.personal.status }
                if ($rawdata.hin.domain.domain) { $returndata | Add-Member -MemberType Noteproperty -Name HINdomain -Value $rawdata.hin.domain.domain }
                if ($rawdata.tls.domain.domain) { $returndata | Add-Member -MemberType Noteproperty -Name TLSdomain -Value $rawdata.tls.domain.domain }
                if ($rawdata.gina.personal.status) { $returndata | Add-Member -MemberType Noteproperty -Name GINAperonal -Value $rawdata.gina.personal.status }
                return $returndata
            }
        }
    }
    end
    {
        
    }
}

function New-SLGINAUser
{
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory                       = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage                     = 'GINA user full name'
        )]
        [Alias("user")]
        [string]$userName,

        [Parameter(
            Mandatory                       = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage                     = 'GINA user eMail address'
            )]
        [ValidatePattern('([a-z0-9][-a-z0-9_\+\.]*[a-z0-9])@([a-z0-9][-a-z0-9\.]*[a-z0-9]\.(arpa|root|aero|biz|cat|com|coop|edu|gov|info|int|jobs|mil|mobi|museum|name|net|org|pro|tel|travel|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cx|cy|cz|de|dj|dk|dm|do|dz|ec|ee|eg|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|st|su|sv|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)|([0-9]{1,3}\.{3}[0-9]{1,3}))')]
        [Alias("email")]
        [string]$eMailAddress,

        [Parameter(
            Mandatory                       = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage                     = 'One time password'
            )]
        [Alias("otp")]
        [string]$oneTimePw,

        [Parameter(
            Mandatory                       = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage                     = 'GINA user mobile number including country code'
            )]
        [ValidatePattern('^([+](\d{1,3})\s?)?((\(\d{3,5}\)|\d{3,5})(\s)?)\d{3,8}$')]
        [string]$mobile
    )
    begin
    {
        try {
            Set-SLConfig | Out-Null
        }
        catch {
            Write-error "Could not load configuration with set-SLConfig"
        }    }
    process
    {

        $urlRoot = New-SLUrlRoot -FQDN $SLConfig.SEPPmailFQDN -adminPort $SLConfig.adminPort
        $uri = $urlRoot + 'newginauser'
        $userData = [ordered]@{
            email    = $eMailAddress
            name     = $userName
            password = $oneTimePw
            mobile   = $mobile 
        } | ConvertTo-Json
        
        $invokeParam = @{
            Uri         = $uri 
            Method      = 'POST '
            Credential  = $SLConfig.secret
            ContentType = "application/json"
            body        = $userData
        }
        
        $NewGinaUser = Invoke-RestMethod @invokeParam
        return $newGinaUser.message
    }
    
    end
    {
        
    }
}

function Set-SLGINAUser
{
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory                       = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage                     = 'GINA user eMail adress'
            )]
        [ValidatePattern('([a-z0-9][-a-z0-9_\+\.]*[a-z0-9])@([a-z0-9][-a-z0-9\.]*[a-z0-9]\.(arpa|root|aero|biz|cat|com|coop|edu|gov|info|int|jobs|mil|mobi|museum|name|net|org|pro|tel|travel|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cx|cy|cz|de|dj|dk|dm|do|dz|ec|ee|eg|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|st|su|sv|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)|([0-9]{1,3}\.{3}[0-9]{1,3}))')]
        [Alias("email")]
        [string]$eMailAddress,

        [Parameter(
            Mandatory                       = $false,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage                     = 'GINA user full name'
            )]
        [Alias("user")]
        [string]$userName,

        [Parameter(
            Mandatory                       = $false,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage                     = 'For MSP´s and multi-customer environments, set the GINA users customer'
            )]
        [string]$customer,

        [Parameter(
            Mandatory                       = $false,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage                     = 'GINA user language setting e or d'
            )]
        [ValidateSet('e', 'd')]
        [string]$language = 'd',

        [Parameter(
            Mandatory                       = $false,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage                     = 'GINA user mobile number including country code, i.e. +4911122233344'
            )]
        [ValidatePattern('^([+](\d{1,3})\s?)?((\(\d{3,5}\)|\d{3,5})(\s)?)\d{3,8}$')]
        [string]$mobile,

        [Parameter(
            Mandatory                       = $false,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage                     = 'GINA user password'
            )]
        [string]$password,

        [Parameter(
            Mandatory                       = $false,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage                     = 'GINA user setting ZIP attachment setting'
            )]
        [ValidateSet('0','1')]
        [string]$zip_attachment,

        [Parameter(
            Mandatory                       = $false,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage                     = 'GINA user passwort reset question'
            )]
        [string]$question,

        [Parameter(
            Mandatory                       = $false,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage                     = 'GINA user passwort reset answer'
            )]
        [string]$answer,

        [Parameter(
            Mandatory                       = $false,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage                     = 'GINA user created by information'
            )]
        [string]$creator,

        [Parameter(
            Mandatory                       = $false,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage                     = 'GINA user expired setting 0 or 1'
            )]
        [ValidateSet('0','1')]
        [string]$expired
    )
    
    begin
    {
        try {
            Set-SLConfig | Out-Null
        }
        catch {
            Write-error "Could not load configuration with set-SLCOnfig"
        }
    }
    
    process
    {
        try {
            $urlRoot = New-SLUrlRoot -FQDN $SLConfig.SEPPmailFQDN -adminPort $SLConfig.adminPort
            $uri = $urlRoot + 'modifyginauser'
            $userData = [ordered]@{
                email          = $eMailAddress
                name           = $userName
                customer       = $customer
                language       = $language
                password       = $password
                mobile         = $mobile
                zip_attachment = $zip_attachment
                question       = $question
                answer         = $answer
                creator        = $creator
                expired        = $expired
            } | ConvertTo-Json

            $invokeParam = @{
                Uri         = $uri 
                Method      = 'POST '
                Credential  = $SLConfig.secret
                ContentType = "application/json"
                body        = $userData
            }
            Write-Verbose "Modifying User $EMailAddress using URL $uri"
            $SetGinaUser = Invoke-RestMethod @invokeParam
            if ($($SetGinaUser.Errorcode) -eq '0') {
                return $SetGinaUser.message
            }
            else {
                $errormessage = Convert-SLRestError -interror $SetGinaUser.Errorcode
                Write-Error "SEPPmail returned Error $ErrorMessage"
            }
        }
        catch {
                Write-Error "An error occured, see $error"
        }
    }
    end
    {
        
    }
}
