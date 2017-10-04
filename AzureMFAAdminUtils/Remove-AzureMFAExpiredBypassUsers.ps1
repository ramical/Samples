param
(        
    [Parameter(Mandatory=$true)]
    [String]
    $BypassGroupName                
)

$Cred = Get-AutomationPSCredential -Name "AADRunbook"
Connect-AzureAD -Credential $Cred
Remove-AzureMFAExpiredBypassUsers -BypassGroupName $BypassGroupName -Debug