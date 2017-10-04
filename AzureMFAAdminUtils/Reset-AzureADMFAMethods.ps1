Param(
 [Parameter(Mandatory=$True)] `
 [string]$UserPrincipalName
 )

$Cred = Get-AutomationPSCredential -Name "AADRunbook"
Connect-MSOLService -Credential $Cred
Reset-AzureMFAUserMethods -UserPrincipalName $UserPrincipalName