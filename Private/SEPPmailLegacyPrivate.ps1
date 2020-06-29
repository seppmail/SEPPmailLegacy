# Place for module - internal functions
function New-SLUrlRoot {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        $FQDN,
        
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
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
