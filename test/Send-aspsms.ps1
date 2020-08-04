[CmdLetBinding()]
param(
    $mobile,
    $text
)

#region mit aspsms.com
$cred = Import-CliXML c:\temp\aspsms.xml
$baseurl = 'https://json.aspsms.com'

#region SendSimpleTextSMS
$smsBodyHt = [ordered]@{
    UserName = $cred.UserName;
    Password = $cred.GetNetworkCredential().Password;
    Originator = "SEPPmail";
    Recipients = @($mobile);
    MessageText = $text;
}
$smsJSONBody = ConvertTo-Json $smsBodyHt

$urlext = '/SendSimpleTextSMS'
$uri = "$baseurl"+"$urlext"
Invoke-RestMethod -Credential $cred -Uri $uri -Method POST -body $smsJSONBody


