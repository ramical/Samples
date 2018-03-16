#Requires –Version 5

<# 
 
.SYNOPSIS
	MSCloudIdAssessment.psm1 is a Windows PowerShell module to gather configuration information across different components of the identity infrastrucutre

.DESCRIPTION

	Version: 1.0.0

	MSCloudIdUtils.psm1 is a Windows PowerShell module with some Azure AD helper functions for common administrative tasks


.DISCLAIMER
	THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
	ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
	THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
	PARTICULAR PURPOSE.

	Copyright (c) Microsoft Corporation. All rights reserved.
#>


<# 
 .Synopsis
  Starts the sessions to AzureAD and MSOnline Powershell Modules

 .Description
  This function prompts for authentication against azure AD 

#>
function Start-MSCloudIdSession		
{
    Connect-MsolService
    Connect-AzureAD
}

<# 
 .Synopsis
  Gets Azure AD Application Proxy Connector Logs

 .Description
  This functions returns the events from the Azure AD Application Proxy Connector Admin Log

 .Parameter DaysToRetrieve
  Indicates how far back in the past will the events be retrieved

 .Example
  Get the last seven days of logs and saves them on a CSV file   
  Get-MSCloudIdAppProxyConnectorLog -DaysToRetrieve 7 | Export-Csv -Path ".\AzureADAppProxyLogs-$env:ComputerName.csv" 
#>
function Get-MSCloudIdAppProxyConnectorLog
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [int]
        $DaysToRetrieve
    )
    $TimeFilter = $DaysToRetrieve * 86400000
    $EventFilterXml = '<QueryList><Query Id="0" Path="Microsoft-AadApplicationProxy-Connector/Admin"><Select Path="Microsoft-AadApplicationProxy-Connector/Admin">*[System[TimeCreated[timediff(@SystemTime) &lt;= {0}]]]</Select></Query></QueryList>' -f $TimeFilter
    Get-WinEvent -FilterXml $EventFilterXml
}

<# 
 .Synopsis
  Gets the Azure AD Password Writeback Agent Log

 .Description
  This functions returns the events from the Azure AD Password Write Bag source from the application Log

 .Parameter DaysToRetrieve
  Indicates how far back in the past will the events be retrieved

 .Example
  Get the last seven days of logs and saves them on a CSV file   
  Get-MSCloudIdPasswordWritebackAgentLog -DaysToRetrieve 7 | Export-Csv -Path ".\AzureADAppProxyLogs-$env:ComputerName.csv" 
#>
function Get-MSCloudIdPasswordWritebackAgentLog
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [int]
        $DaysToRetrieve
    )
    $TimeFilter = $DaysToRetrieve * 86400000
    $EventFilterXml = "<QueryList><Query Id='0' Path='Application'><Select Path='Application'>*[System[Provider[@Name='PasswordResetService'] and TimeCreated[timediff(@SystemTime) &lt;= {0}]]]</Select></Query></QueryList>" -f $TimeFilter
    Get-WinEvent -FilterXml $EventFilterXml
}

<# 
 .Synopsis
  Gets various email addresses that Azure AD sends notifications to

 .Description
  This functions returns a list with the email notification scope and type, the recipient name and an email address

 .Example
  Get-MSCloudIdNotificationEmailAddresses | Export-Csv -Path ".\NotificationsEmailAddresses.csv" 
#>
function Get-MSCloudIdNotificationEmailAddresses
{
    $technicalNotificationEmail = Get-MSOLCompanyInformation | Select -ExpandProperty TechnicalNotificationEmails
    $result = New-Object -TypeName psobject -Property @{ NotificationEmailScope = "Tenant"; NotificationType = "Technical Notification"; RecipientName = "N/A";  EmailAddress = $technicalNotificationEmail }

    Write-Output $result

	#Get email addresses of all users with privileged roles

    $roles = Get-AzureADDirectoryRole

    foreach ($role in $roles)
    {
        $roleMembers = Get-AzureADDirectoryRoleMember -ObjectId $role.ObjectId
        foreach ($roleMember in $roleMembers)
        {
            $result = New-Object -TypeName psobject -Property @{ NotificationEmailScope = "Role"; NotificationType = $role.DisplayName; RecipientName = $roleMember.DisplayName;  EmailAddress = $roleMember.Mail }
            Write-Output $result
        }
    }
}


<# 
 .Synopsis
  Gets a report of all assignments to all applications

 .Description
  This functions returns a list indicating the applications and their user/groups assignments  

 .Example
  Get-MSCloudIdAppAssignmentReport | Export-Csv -Path ".\AppAssignments.csv" 
#>
function Get-MSCloudIdAppAssignmentReport
{
	#Get all app assignemnts using "all users" group
	#Get all app assignments to users directly

    Get-AzureADServicePrincipal -All $true | Get-AzureADServiceAppRoleAssignment
}

<# 
 .Synopsis
  Gets a report of all members of roles 

 .Description
  This functions returns a list of users who hold special roles in the directory

 .Example
  Get-MSCloudIdAdminRolesReport | Export-Csv -Path ".\AdminRoles.csv" 
#>
function Get-MSCloudIdAdminRolesReport
{	
	$roles = Get-AzureADDirectoryRole

    foreach ($role in $roles)
    {
        $roleMembers = Get-AzureADDirectoryRoleMember -ObjectId $role.ObjectId
        foreach ($roleMember in $roleMembers)
        {
            $result = New-Object -TypeName psobject -Property @{ RoleName = $role.DisplayName; RoleMemberDisplayName = $roleMember.DisplayName; RoleMemberEmail = $roleMember.Mail; RoleMemberUPN = $roleMember.UserPrincipalName }
            Write-Output $result
        }
    }
}

<# 
 .Synopsis
  Gets a report of all members of roles 

 .Description
  This functions returns a list of consent grants in the directory

 .Example
  Get-MSCloudIdConsentGrantList | Export-Csv -Path ".\ConsentGrantList.csv" 
#>
function Get-MSCloudIdConsentGrantList
{
	
    $AllGrants = Get-AzureADOAuth2PermissionGrant  -All $true
    foreach ($grant in $AllGrants)
    {
        $ClientInfo = Get-AzureADObjectByObjectId -ObjectIds $grant.ClientId
        $ClientDisplayName = $ClientInfo | Select-Object -ExpandProperty DisplayName

        $PrincipalId = "N/A"
        $PrincipalDisplayName = "N/A"

        if ($grant.ConsentType -eq "Principal")
        {
            $PrincipalId = $grant.PrincipalId
            $PrincipalInfo = Get-AzureADObjectByObjectId -ObjectIds $grant.PrincipalId
            $PrincipalDisplayName = $PrincipalInfo | Select-Object -ExpandProperty DisplayName
        }

        $ResourceInfo = Get-AzureADObjectByObjectId -ObjectIds $grant.ResourceId
        $ResourceDisplayName = $ResourceInfo | Select-Object -ExpandProperty DisplayName

        $Result = New-Object -TypeName PSObject -Property `
        @{
            ClientId = $grant.ClientId;
            ClientDisplayName = $ClientDisplayName;
            ConsentType = $grant.ConsentType;
            ExpiryTime = $grant.ExpiryTime;
            PrincipalId = $PrincipalId;
            PrincipalDisplayName = $PrincipalDisplayName;
            ResourceId = $grant.ResourceId;
            ResourceDisplayName = $ResourceDisplayNAme;
            Scope = $grant.Scope;
        }

        Write-Output $Result
    }
}

<# 
 .Synopsis
  Gets the list of all enabled endpoints in ADFS

 .Description
  Gets the list of all enabled endpoints in ADFS

 .Example
  Get-MSCloudIdADFSEndpoints | Export-Csv -Path ".\ADFSEnabledEndpoints.csv" 
#>
function Get-MSCloudIdADFSEndpoints
{
	Get-AdfsEndpoint | where {$_.Enabled -eq "True"} 
}


Function Remove-InvalidFileNameChars 
{
  param(
    [Parameter(Mandatory=$true,
      Position=0,
      ValueFromPipeline=$true,
      ValueFromPipelineByPropertyName=$true)]
    [String]$Name
  )

  $invalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $re = "[{0}]" -f [RegEx]::Escape($invalidChars)
  return ($Name -replace $re)
}

<# 
 .Synopsis
  Exports the configuration of Relying Party Trusts and Claims Provider Trusts

 .Description
  Creates and zips a set of files that hold the configuration of ADFS claim providers and relying parties

 .Example
  Export-MSCloudIdADFSConfiguration
#>

Function Export-MSCloudIdADFSConfiguration
{
    $filePathBase = "C:\ADFS\apps\"
    $zipfileBase = "c:\ADFS\zip\"
    $zipfileName = $zipfileBase + "ADFSApps.zip"
    mkdir $filePathBase -ErrorAction SilentlyContinue
    mkdir $zipfileBase -ErrorAction SilentlyContinue

    $AdfsRelyingPartyTrusts = Get-AdfsRelyingPartyTrust
    foreach ($AdfsRelyingPartyTrust in $AdfsRelyingPartyTrusts)
    {
        $RPfileName = $AdfsRelyingPartyTrust.Name.ToString()
        $CleanedRPFileName = Remove-InvalidFileNameChars -Name $RPfileName
        $RPName = "RPT - " + $CleanedRPFileName
        $filePath = $filePathBase + $RPName + '.xml'
        $AdfsRelyingPartyTrust | Export-Clixml $filePath -ErrorAction SilentlyContinue
    }

    $AdfsClaimsProviderTrusts = Get-AdfsClaimsProviderTrust
    foreach ($AdfsClaimsProviderTrust in $AdfsClaimsProviderTrusts)
    {
 
        $CPfileName = $AdfsClaimsProviderTrust.Name.ToString()
        $CleanedCPFileName = Remove-InvalidFileNameChars -Name $CPfileName
        $CPTName = "CPT - " + $CleanedCPFileName
        $filePath = $filePathBase + $CPTName + '.xml'
        $AdfsClaimsProviderTrust | Export-Clixml $filePath -ErrorAction SilentlyContinue
 
    } 

    Compress-Archive -Path $filePathBase -DestinationPath $zipfileName
    invoke-item $zipfileBase
}

Export-ModuleMember -Function Get-MSCloudIdAppProxyConnectorLog
Export-ModuleMember -Function Get-MSCloudIdPasswordWritebackAgentLog
Export-ModuleMember -Function Get-MSCloudIdNotificationEmailAddresses
Export-ModuleMember -Function Start-MSCloudIdSession		
Export-ModuleMember -Function Get-MSCloudIdAppAssignmentReport
Export-ModuleMember -Function Get-MSCloudIdConsentGrantList
Export-ModuleMember -Function Export-MSCloudIdADFSConfiguration