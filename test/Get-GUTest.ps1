[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(
        Mandatory                       = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage                     = 'GINA user eMail adress or parts of it like domain or firstname.lastname'
        )]
    [Alias('email')]
    [string]$eMailAddress,

    [Parameter(
        Mandatory                       = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage                     = 'GINA user full name'
        )]
    [Alias('user')]
    [string]$Name,

    [Parameter(
        Mandatory                       = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage                     = 'GINA user mobile number or parts of it'
        )]
    [string]$mobile,

    [Parameter(
        Mandatory                       = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage                     = 'For MSP´s and multi-customer environments, set the GINA users customer'
        )]
    [string]$customer
)

$urlRoot = New-SLUrlRoot -FQDN $SLConfig.SEPPmailFQDN -adminPort $SLConfig.adminPort
$uri = "{0}{1}" -f $urlroot, 'ginauser/get'

if ($emailAddress -or $mobile -or $name -or $customer ) {
    $uri = "{0}{1}" -f $uri, "?"

    if ($emailAddress) {
        $uri = "{0}{1}" -f $uri, "&email=%2A$emailAddress%2A"
    }
    if ($mobile) {
        $uri = "{0}{1}" -f $uri, "&mobile=%2A$mobile%2A"
    }
    if ($name) {
        $uri = "{0}{1}" -f $uri, "&name=%2A$name%2A"
    }
    if ($customer) {
        $uri = "{0}{1}" -f $uri, "&customer=%2A$customer%2A"
    }
}

$invokeParam = @{
    Uri         = $uri 
    Method      = 'GET'
    Credential  = $SLConfig.secret
    ContentType = "application/json"
}

Write-Verbose "Call RESTSEPPmail REST-API $uri" 
$ginaUserRaw = Invoke-RestMethod @invokeparam

Write-Verbose 'Filter data and return as PSObject'
($ginaUserRaw|Select-Object -ExcludeProperty errormessage,errorcode).psobject.Members|Where-Object membertype -eq noteproperty|Select-Object -expandproperty Value|Sort-Object
