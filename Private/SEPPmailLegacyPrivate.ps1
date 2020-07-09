# Place for module - internal functions
function New-SLUrlRoot {
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory                       = $false,
            ValueFromPipelineByPropertyName = $true
            )]
        $FQDN,
        
        [Parameter(
            Mandatory                       = $false,
            ValueFromPipelineByPropertyName = $true
            )]
        $adminPort = '8443'
    )
    begin {
    }
    process {
        $urlroot = 'https://' + $FQDN + ':' + $adminport + '/v1/legacy.app/'
    }
    end {
        return $urlroot
    }
}

<#
.SYNOPSIS
    Converts REST Errors to readable errors
.DESCRIPTION
    the REST-API returns 11 different error numeric codes, this cmdLet transforms them into written messages.
.EXAMPLE
    
.EXAMPLE
    Another example of how to use this cmdlet
#>
function Convert-SLRestError {
    [CmdletBinding()]
    [OutputType([String])]
    param(
        [Parameter(
            Mandatory=$true
            )]
        [string]$interror
    )
    
    begin {
    }
    
    process {
        switch (${interror}) {
            {$_ -eq '-2'} {'unknown command'}
            {$_ -eq '-3'} {'unknown category'}
            {$_ -eq '-4'} {'invalid HTTP Method'}
            {$_ -eq '-5'} {'POST-Data error'}
            {$_ -eq '-6'} {'Error when parsing JSON POST-data'}
            {$_ -eq '-8'} {'Error while reading/writing database'}
            {$_ -eq '-9'} {'unknown error'}
            {$_ -eq '-11'} {'invalid REST-Path'}
            {$_ -eq '-12'} {'invalid parameter in REST-Path'}
        }
    }
    end {
    }
}
