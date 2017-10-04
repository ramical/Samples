Param(
        [Parameter(Mandatory=$true)]
        [String]
        $UserPrincipalName,

        [Parameter(Mandatory=$true)]
        [int]
        $BypassLengthMinutes,
        
        [Parameter(Mandatory=$false)]
        [String]
        $BypassGroupName
 )

$Cred = Get-AutomationPSCredential -Name "AADRunbook"
Connect-AzureAD -Credential $Cred

Set-AzureMFABypassValidTo -UserPrincipalName $UserPrincipalName -BypassLengthMinutes $BypassLengthMinutes -BypassGroupName $BypassGroupName -Debug