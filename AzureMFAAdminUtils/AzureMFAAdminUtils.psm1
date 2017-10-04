#Requires –Version 5
#Requires -Modules AzureAD, MSOnline

<# 
 
.SYNOPSIS
	AADMFAAdminUtils.psm1 is a Windows PowerShell module with some Azure AD helper functions for Azure MFA administrative tasks

.DESCRIPTION

	Version: 1.0.0

	AzureADUtils.psm1 is a Windows PowerShell module with some Azure AD helper functions for common administrative tasks


.DISCLAIMER
	THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
	ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
	THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
	PARTICULAR PURPOSE.

	Copyright (c) Microsoft Corporation. All rights reserved.
#>

$ExtensionAppName = "Azure MFA Admin Utils Schema Extensions"
$MFABypassExtensionName = "AzureMFABypassValidToUTC"


<# 
 .Synopsis
  Installs the Schema Extensions needed by the module.

 .Description
  This function finds the schema extensions app, and add new extensions to it

 .Example
  Install-AzureADUtilsModule
#>
function Install-AzureMFAAdminSchemaExtensions
{
    [CmdletBinding()]
    param()

    #Source : https://docs.microsoft.com/en-us/powershell/azure/active-directory/using-extension-attributes-sample?view=azureadps-2.0
    
    $ExtensionApp = Get-AzureADApplication -Filter "displayName eq '$($ExtensionAppName)'"

    if ($ExtensionApp -eq $null)
    {
        Write-Debug "Creating Application to add extensions"
        $ExtensionApp = New-AzureADApplication -DisplayName $ExtensionAppName  -IdentifierUris "urn:azuremfa:adminutils"
    }

    $ExtensionSP = Get-AzureADServicePrincipal -Filter "AppId eq '$($ExtensionApp.AppId)'" 

    if ($ExtensionSP -eq $null)
    {
        Write-Debug "Creating Service Principal to add extensions"
        $ExtensionSP = New-AzureADServicePrincipal -AppId $ExtensionApp.AppId
    }

    #Clear all extension properties from this SP 
    Get-AzureADApplicationExtensionProperty -ObjectId $ExtensionApp.ObjectId | % { 
        Write-Debug "Removing Existing schema extension: $($_.Name)"
        Remove-AzureADApplicationExtensionProperty -ObjectId $ExtensionApp.ObjectId -ExtensionPropertyId $_.ObjectId 
    }

    #Add the extension properties
    New-AzureADApplicationExtensionProperty -ObjectId $ExtensionApp.ObjectId -Name $MFABypassExtensionName -DataType "String" -TargetObjects "User"
}

<# 
 .Synopsis
  Sets the MFA Bypass time stamp to a given user

 .Description
  This functions set the extension value based on the specified length of the bypass in minutes. It also adds it to the bypass group if specified

 .Example
  Set-AzureMFABypassValidTo -UserPrincipalName "jsmith@contoso.com" -BypassLengthInMinutes 60 -BypassGroupName "MFA bypassed users"
#>
function Set-AzureMFABypassValidTo
{
    [CmdletBinding()]
    param
    (
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


    $User = Get-AzureADUser -Filter "userprincipalname eq '$($UserPrincipalName)'"

    Write-Debug "User $UserPrincipalName found. ObjectId is '$($User.ObjectId)'"

    $ExtensionApp = Get-AzureADApplication -Filter "displayName eq '$($ExtensionAppName)'"
    $ExtensionName = (Get-AzureADApplicationExtensionProperty -ObjectId $ExtensionApp.ObjectId).Name
    $ValidTo = (Get-Date).ToUniversalTime().AddMinutes($BypassLengthMinutes).ToString("u")
    
    Write-Debug "Setting bypass extension '$($ExtensionName)' to user '$($UserPrincipalName)' to '$($ValidTo)'"
    Set-AzureADUserExtension -ObjectId $User.ObjectId -ExtensionName $ExtensionName -ExtensionValue $ValidTo

    if (-not [String]::IsNullOrWhiteSpace($BypassGroupName))
    {
        Write-Debug "Adding user '$UserPrincipalName' to group '$BypassGroupName'"
        $BypassGroup = Get-AzureADGroup -Filter "displayName eq '$($BypassGroupName)'"
        Add-AzureADGroupMember -ObjectId $BypassGroup.ObjectId -RefObjectId $User.ObjectId
    }
}

<# 
 .Synopsis
  Removes Azure MFA Expired users from the target group

 .Description
  This function locates the users whose MFA Bypass has expired and removes them from the target group, and cleans the timestamp information

 .Example
  Remove-AzureMFAExpiredBypassUsers -BypassGroupName "MFA bypassed users"
#>
function Remove-AzureMFAExpiredBypassUsers
{
    [CmdletBinding()]
    param
    (        
        [Parameter(Mandatory=$true)]
        [String]
        $BypassGroupName                
    )

    $Group = Get-AzureADGroup -Filter "displayName eq '$($BypassGroupName)'"
    
    $ExtensionApp = Get-AzureADApplication -Filter "displayName eq '$($ExtensionAppName)'"
    $ExtensionName = (Get-AzureADApplicationExtensionProperty -ObjectId $ExtensionApp.ObjectId).Name
    $Members = Get-AzureADGroupMember -ObjectId $Group.ObjectId -All $true

    $CutoffTime = (Get-Date).ToUniversalTime() 

    foreach($Member in $Members)
    {
        $Extensions = Get-AzureADUserExtension -ObjectId $Member.ObjectId 

        if ($Extensions[$ExtensionName] -ne $null)
        {
            $TimeStamp = ([datetime]($Extensions[$ExtensionName])).ToUniversalTime()
            
            if ($CutoffTime -gt $TimeStamp)
            {
                Write-Debug "Removing user '$($Member.UserPrincipalName)' from Group '$BypassGroupName'. MFABypassTime was '$($TimeStamp)' and cutoff time is '$($CutoffTime)'"
                Remove-AzureADGroupMember -ObjectId $Group.ObjectId -MemberId $Member.ObjectId

                Write-Debug "Removing bypass value for user '$($Member.UserPrincipalName)'"
                Remove-AzureADUserExtension -ObjectId $Member.ObjectID -ExtensionName $ExtensionName
            }
        }
    }
}

<# 
 .Synopsis
  Removes Azure MFA Strong Authentication methods for a user

 .Description
  This function clears the Strong Authentication Methods associated with the user account

 .Example
  Reset-AzureMFAUserMethods -UserPrincipalName "jsmith@contoso.com"  
#>
function Reset-AzureMFAUserMethods
{
    [CmdletBinding()]
    param
    (        
        [Parameter(Mandatory=$false)]
        [String]
        $UserPrincipalName                
    )

    Get-MSOLUser -UserPrincipalName $UserPrincipalName | Select -ExpandProperty StrongAuthenticationMethods
    Set-MSOLUser -UserPrincipalName $UserPrincipalName -StrongAuthenticationMethods @()

}

Export-ModuleMember Install-AzureMFAAdminSchemaExtensions
Export-ModuleMember Set-AzureMFABypassValidTo
Export-ModuleMember Remove-AzureMFAExpiredBypassUsers
Export-ModuleMember Reset-AzureMFAUserMethods