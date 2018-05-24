#Requires –Version 5

<# 
 
.SYNOPSIS
	MSCloudIdUtils.psm1 is a Windows PowerShell module with some Azure AD helper functions for common administrative tasks

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


######################
#HELPER CODE FOR ADAL
######################

$source = @" 
using System;
using System.Diagnostics;
using System.Net;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography.X509Certificates;

using Microsoft.IdentityModel.Clients.ActiveDirectory;


public static class AdalHelper
{

    public static AuthenticationResult ObtainAadAuthenticationResultByPromptingUserCredential(string aadTokenIssuerUri, string resource, string clientId, string redirectUri)
    {
        AuthenticationContext authenticationContext = new AuthenticationContext(aadTokenIssuerUri);
        AuthenticationResult authenticationResult = authenticationContext.AcquireToken
        (
            resource: resource,
            clientId: clientId, 
            redirectUri: new Uri(redirectUri),
            promptBehavior: PromptBehavior.Always,
            userId: UserIdentifier.AnyUser,
            extraQueryParameters: "nux=1"
        );

        return authenticationResult;
    }

    public static string ObtainAadAccessTokenByPromptingUserCredential(string aadTokenIssuerUri, string resource, string clientId, string redirectUri)
    {
        AuthenticationContext authenticationContext = new AuthenticationContext(aadTokenIssuerUri);
        AuthenticationResult authenticationResult = authenticationContext.AcquireToken
        (
            resource: resource,
            clientId: clientId, 
            redirectUri: new Uri(redirectUri),
            promptBehavior: PromptBehavior.Always,
            userId: UserIdentifier.AnyUser,
            extraQueryParameters: "nux=1"
        );

        return authenticationResult.AccessToken;
    }
         
    public static string ObtainAadAccessTokenWia(string aadTokenIssuerUri, string resource, string clientId)
    {
        AuthenticationContext authenticationContext = new AuthenticationContext(aadTokenIssuerUri);
        UserCredential uc = new UserCredential();
        AuthenticationResult authenticationResult = authenticationContext.AcquireToken
        (
            resource: resource,
            clientId: clientId,
            userCredential: uc            
        );
        return authenticationResult.AccessToken;
    }


    public static string ObtainAadAccessTokenWithCert(string aadTokenIssuerUri, X509Certificate2 cert, string resource, string clientId)
    {
        AuthenticationContext authenticationContext = new AuthenticationContext(aadTokenIssuerUri);
        ClientAssertionCertificate certCred = new ClientAssertionCertificate(clientId, cert);
        AuthenticationResult authenticationResult = authenticationContext.AcquireToken
        (
            resource: resource,
            clientCertificate: certCred
        );
        return authenticationResult.AccessToken;
    }

    public static string ObtainAadAccessTokenOnbehalfOfUser(string aadTokenIssuerUri,NetworkCredential clientCredential, string resource, string userToken)
    {

        ClientCredential adalClientCreds = new ClientCredential(clientCredential.UserName, clientCredential.SecurePassword); 
        AuthenticationContext authenticationContext = new AuthenticationContext(aadTokenIssuerUri);
        UserAssertion userAssertion = new UserAssertion(userToken);
        

        AuthenticationResult authenticationResult = authenticationContext.AcquireToken( resource, adalClientCreds, userAssertion );
        return authenticationResult.AccessToken;
    }
}
"@

function Initialize-ActiveDirectoryAuthenticationLibrary()
{
   $moduleDirPath = [Environment]::GetFolderPath("MyDocuments") + "\WindowsPowerShell\Modules"
   $modulePath = $moduleDirPath + "\MSCloudIdUtils"

   if (Test-Path $modulePath) 
   {
      $adalPackageDirectories = (Get-ChildItem -Path ($modulePath+"\Nugets") -Filter "Microsoft.IdentityModel.Clients.ActiveDirectory*" -Directory)

      $ADAL_Assembly = (Get-ChildItem "Microsoft.IdentityModel.Clients.ActiveDirectory.dll" -Path $adalPackageDirectories[$adalPackageDirectories.length-1].FullName -Recurse)

      $ADAL_WindowsForms_Assembly = (Get-ChildItem "Microsoft.IdentityModel.Clients.ActiveDirectory.WindowsForms.dll" -Path $adalPackageDirectories[$adalPackageDirectories.length-1].FullName -Recurse)

      if($ADAL_Assembly.Length -gt 0 -and $ADAL_WindowsForms_Assembly.Length -gt 0)
      {
        Write-Host "Loading ADAL Assemblies ..." -ForegroundColor Green
        [System.Reflection.Assembly]::LoadFrom($ADAL_Assembly[0].FullName) | out-null
        [System.Reflection.Assembly]::LoadFrom($ADAL_WindowsForms_Assembly.FullName) | out-null
        $reqAssem = @($ADAL_Assembly[0].FullName, $ADAL_WindowsForms_Assembly.FullName)
        Add-Type -ReferencedAssemblies $reqAssem -TypeDefinition $source -Language CSharp -IgnoreWarnings
        return $true
      }
      else
      {
        Write-Host "Fixing Active Directory Authentication Library package directories ..." -ForegroundColor Yellow
        $adalPackageDirectories | Remove-Item -Recurse -Force | Out-Null
        Write-Host  ("Not able to load ADAL assembly. Delete the Nugets folder under {0}, restart PowerShell session and try again ..." -f $modulePath)
        return $false
      }
    }
    else
    {
        Write-Host "Current module is not part of the Powershell Module path. Please run Install-MSCloudIdUtilsModule, restart the PowerShell session and try again.." -ForegroundColor Yellow
    }
}

#Bootstrap the initialization of ADAL
Initialize-ActiveDirectoryAuthenticationLibrary


<# 
 .Synopsis
  Gets an access token based on a user credential using web authentication to access the Azure AD Graph API.

 .Description
  This function returns a string with the access token from a user. This will pop up a web authentication prompt for a user

 .Parameter TenantDomain
  The domain name of the tenant you want the token for.

 .Parameter ClientId
  The client ID of the application you want the token for
  
 .Parameter Redirect URI
  Redirect URI for the OAuth request
  

 .Example
   $accessToken = Get-MSCloudIdAccessTokenFromUser -TenantDomain "contoso.com"
#>
Function Get-MSCloudIdAccessTokenFromUser
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [string]
        $TenantDomain,
        [Parameter(Mandatory=$true)]
        [string]
        $ClientId,
        [Parameter(Mandatory=$true, ParameterSetName="PromptUserCredential")]
        [string]
        $RedirectUri,
        [Parameter(ParameterSetName="WIA")]
        [switch]
        $WindowsAuthentication,
        [Parameter(Mandatory=$true)]
        [string]
        $Resource

    )
    if ($WindowsAuthentication)
    {
        $AadToken = [AdalHelper]::ObtainAadAccessTokenWia("https://login.windows.net/$TenantDomain/", $Resource, $ClientId);
        Write-Output $AadToken
    }
    else
    {
        $AadToken = [AdalHelper]::ObtainAadAccessTokenByPromptingUserCredential("https://login.windows.net/$TenantDomain/", $Resource, $ClientId, $RedirectUri);
        Write-Output $AadToken
    }
}


<# 
 .Synopsis
  Gets an access token based on a user credential using web authentication to access the Azure AD Graph API.

 .Description
  This function returns a string with the access token from a user. This will pop up a web authentication prompt for a user

 .Parameter TenantDomain
  The domain name of the tenant you want the token for.

 .Parameter ClientId
  The client ID of the application you want the token for
  
 .Parameter Redirect URI
  Redirect URI for the OAuth request
  

 .Example
   $accessToken = Get-MSCloudIdIdTokenFromUser -TenantDomain "contoso.com"
#>
Function Get-MSCloudIdIdTokenFromUser
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [string]
        $TenantDomain,
        [Parameter(Mandatory=$true)]
        [string]
        $ClientId,
        [Parameter(Mandatory=$true, ParameterSetName="PromptUserCredential")]
        [string]
        $RedirectUri,
        [Parameter(Mandatory=$true)]
        [string]
        $Resource

    )
    
    $AuthResult = [AdalHelper]::ObtainAadAuthenticationResultByPromptingUserCredential("https://login.windows.net/$TenantDomain/", $Resource, $ClientId, $RedirectUri);
    Write-Output $AuthResult
}

<# 
 .Synopsis
  Gets an access token based on a confidential client credential

 .Description
  This function returns a string with the access token for the Azure AD Graph API.

 .Parameter TenantDomain
  The domain name of the tenant you want the token for.

 .Parameter ClientCredential
  A Powershell Credential with UserName=ClientID, Password=Application Key


 .Example
   $accessToken = Get-MSCloudIdGraphAPIAccessTokenFromAppKey -TenantDomain "contoso.com" -ClientCredential (Get-Credential)
#>
Function Get-MSCloudIdGraphAPIAccessTokenFromAppKey
{
    [CmdletBinding()]
    param
    (    
        [Parameter(Mandatory=$true)]
        [string]
        $TenantDomain,        
        [Parameter(Mandatory=$true)]
        [pscredential]
        $ClientCredential # Credential object that captures the client credentials                      
    )

    $ClientID = $ClientCredential.UserName                    
    $ClientSecret = $ClientCredential.GetNetworkCredential().Password         

    if ([String]::IsNullOrWhiteSpace($ClientID))
    {
        throw "Client ID is missing"
    }

    if ([String]::IsNullOrWhiteSpace($ClientSecret))
    {
        throw "Client secret is missing"
    }

    $loginURL = "https://login.windows.net"

    # Get an Oauth 2 access token based on client id, secret and tenant domain
    $body = @{grant_type="client_credentials";resource="https://graph.microsoft.com";client_id=$ClientID;client_secret=$ClientSecret}
    $oauth = Invoke-RestMethod -Method Post -Uri $loginURL/$TenantDomain/oauth2/token?api-version=1.0 -Body $body

    if ($null -eq $oauth.access_token) 
    {
        throw "ERROR: No Access Token"
    }

    Write-Output $oauth.access_token
}

<# 
 .Synopsis
  Gets an access token based on a user credential using web authentication to access an application in Azure AD.

 .Description
  This function returns a string with the access token from a user. This will pop up a web authentication prompt for a user

 .Parameter TenantDomain
  The domain name of the tenant you want the token for.

 .Parameter ClientId
  The client ID of the application you want the token for
  
 .Parameter Redirect URI
  Redirect URI for the OAuth request


 .Example
   $accessToken = Get-MSCloudIdAzureADGraphAccessTokenFromUser -TenantDomain "contoso.com" -Resource "myapp"
#>
Function Get-MSCloudIdAzureADGraphAccessTokenFromUser
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [string]
        $TenantDomain,
        [Parameter(Mandatory=$true)]
        [string]
        $ClientId,
        [Parameter(Mandatory=$true, ParameterSetName="PromptUserCredential")]
        [string]
        $RedirectUri,
        [Parameter(ParameterSetName="WIA")]
        [switch]
        $WindowsAuthentication

    )
    if ($WindowsAuthentication)
    {
        $AadToken = [AdalHelper]::ObtainAadAccessTokenWia("https://login.windows.net/$TenantDomain/", "https://graph.windows.net/", $ClientId);
        Write-Output $AadToken
    }
    else
    {
        $AadToken = [AdalHelper]::ObtainAadAccessTokenByPromptingUserCredential("https://login.windows.net/$TenantDomain/", "https://graph.windows.net/", $ClientId, $RedirectUri);
        Write-Output $AadToken
    }
}

<# 
 .Synopsis
  Gets an access token based on a user credential using web authentication to access an application in Azure AD.

 .Description
  This function returns a string with the access token from a user. This will pop up a web authentication prompt for a user

 .Parameter TenantDomain
  The domain name of the tenant you want the token for.

 .Parameter ClientId
  The client ID of the application you want the token for
  
 .Parameter Redirect URI
  Redirect URI for the OAuth request

  .Parameter Resource
  The Resource you want the token for
  

 .Example
   $accessToken = Get-MSCloudIdAzureADGraphAccessTokenFromUser -TenantDomain "contoso.com" -Resource "myapp"
#>
Function Get-MSCloudIdAccessTokenOnBehalfOfUser
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [string]
        $TenantDomain,
        [Parameter(Mandatory=$true)]
        [pscredential]
        $ClientCredential,
        [Parameter(Mandatory=$true)]
        [string]
        $UserToken,
        [Parameter(Mandatory=$true)]
        [string]
        $Resource
    )
    $AadToken = [AdalHelper]::ObtainAadAccessTokenOnbehalfOfUser("https://login.windows.net/$TenantDomain/", $ClientCredential, $Resource, $UserToken );
    Write-Output $AadToken
}

<# 
 .Synopsis
  Gets an access token based on a certificate credential

 .Description
  This function returns a string with the access token from a certificate credential to access the Azure AD Graph API.  

 .Parameter TenantDomain
  The domain name of the tenant you want the token for.

 .Parameter ClientID
  The client ID of the application that has the certificate

 .Parameter Certificate
  The X509Certificate2 certificate. The private key of the certificate should be accessible to obtain the access token
  
 .Example

  $ReportingClientId = "9a0112fb-6626-4761-a96b-a5f433c69ef7"
  $Cert = dir Cert:\LocalMachine\my\0EA8A7037A584C3C7BB54119D754DE1024AABAB2
  $AccessToken = Get-MSCloudIdAzureADGraphAccessTokenFromCert  -TenantDomain "contoso.com" -ClientId $ReportingClientId -Certificate $Cert
#>
Function Get-MSCloudIdAzureADGraphAccessTokenFromCert
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [string]
        $TenantDomain,
        [Parameter(Mandatory=$true)]
        [string]
        $ClientId,
        [Parameter(Mandatory=$true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate
    )
    $AadToken = [AdalHelper]::ObtainAadAccessTokenWithCert("https://login.windows.net/$TenantDomain/", $Certificate, "https://graph.windows.net/", $ClientId);
    Write-Output $AadToken
}

<# 
 .Synopsis
  Gets an access token based on a certificate credential

 .Description
  This function returns a string with the access token from a certificate credential to access the Azure AD Graph API.  

 .Parameter TenantDomain
  The domain name of the tenant you want the token for.

 .Parameter ClientID
  The client ID of the application that has the certificate

 .Parameter Certificate
  The X509Certificate2 certificate. The private key of the certificate should be accessible to obtain the access token
  
 .Example

  $ReportingClientId = "9a0112fb-6626-4761-a96b-a5f433c69ef7"
  $Cert = dir Cert:\LocalMachine\my\0EA8A7037A584C3C7BB54119D754DE1024AABAB2
  $AccessToken = Get-MSCloudIdMSGraphAccessTokenFromCert  -TenantDomain "contoso.com" -ClientId $ReportingClientId -Certificate $Cert
#>
Function Get-MSCloudIdMSGraphAccessTokenFromCert
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [string]
        $TenantDomain,
        [Parameter(Mandatory=$true)]
        [string]
        $ClientId,
        [Parameter(Mandatory=$true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate
    )
    $AadToken = [AdalHelper]::ObtainAadAccessTokenWithCert("https://login.windows.net/$TenantDomain/", $Certificate, "https://graph.microsoft.com/", $ClientId);
    Write-Output $AadToken
}

<# 
 .Synopsis
  Performs a query against Azure AD Graph API.

 .Description
  This functions invokes the Azure AD Graph API and returns the results as objects in the pipeline. This function also traverses all pages of the query, if needed.

 .Parameter TenantDomain
  The domain name of the tenant you want the token for.

 .Parameter AccessToken
  Access token for Azure AD Graph API

 .Parameter GraphQuery
  The Query against Graph API
  
 .Example

  $ReportingClientId = "9a0112fb-6626-4761-a96b-a5f433c69ef7"
  $Cert = dir Cert:\LocalMachine\my\0EA8A7037A584C3C7BB54119D754DE1024AABAB2
  $AccessToken = Get-MSCloudIdAzureADGraphAccessTokenFromCert  -TenantDomain "contoso.com" -ClientId $ReportingClientId -Certificate $Cert
  $SignInLog = Invoke-MSCloudIdAzureADGraphQuery -AccessToken $AccessToken -TenantDomain $TenantDomain -GraphQuery "/activities/signinEvents?api-version=beta" 
#>
Function Invoke-MSCloudIdAzureADGraphQuery
{
    [CmdletBinding()]
    param
    (
       
        [Parameter(Mandatory=$true)]
        [string]
        $TenantDomain, # For example, contoso.onmicrosoft.com    
        [Parameter(Mandatory=$true)]
        [string]
        $AccessToken, # For example, contoso.onmicrosoft.com,        
        [string]
        $GraphQuery,
        [ScriptBlock]
        $TokenRenewalCallback
    )

    Write-Progress -Id 1 -Activity "Querying directory" -CurrentOperation "Invoking Azure AD Graph API"

    $headerParams  = @{'Authorization'="Bearer $AccessToken"}
       
    $queryResults = @()
    $originalUrl = "https://graph.windows.net/$TenantDomain/$GraphQuery"
    $queryUrl = "https://graph.windows.net/$TenantDomain/$GraphQuery"
    $queryCount = 0

    while (-not [String]::IsNullOrEmpty($queryUrl))
    {
        $batchResult = (Invoke-WebRequest -Headers $headerParams -Uri $queryUrl).Content | ConvertFrom-Json
        if ($null -ne $batchResult.value)
        {
            $queryResults += $batchResult.value
        }
        else
        {
            $queryResults += $batchResult
        }
        $queryCount = $queryResults.Count
        Write-Progress -Id 1 -Activity "Querying directory" -CurrentOperation "Retrieving results ($queryCount found so far)" 
        $queryUrl = ""

        $odataNextLink = $batchResult | Select-Object -ExpandProperty "@odata.nextLink" -ErrorAction SilentlyContinue

        if ($null -ne $odataNextLink)
        {
            $queryUrl =  $odataNextLink
        }
        else
        {
            $odataNextLink = $batchResult | Select-Object -ExpandProperty "odata.nextLink" -ErrorAction SilentlyContinue
            if ($null -ne $odataNextLink)
            {
                $absoluteUri = [Uri]"https://bogus/$odataNextLink"
                $skipToken = $absoluteUri.Query.TrimStart("?")
                $queryUrl = "https://graph.windows.net/$TenantDomain/$odataNextLink&api-version=1.6" #"$originalUrl&$skipToken"
            }
        }
    }

    Write-Progress -Id 1 -Activity "Querying directory" -Completed

    Write-Output $queryResults
}

<# 
 .Synopsis
  Performs a query against Microsoft Graph API.

 .Description
  This functions invokes the Microsoft Graph API and returns the results as objects in the pipeline. This function also traverses all pages of the query, if needed.

  .Parameter AccessToken
  Access token for Azure AD Graph API

 .Parameter GraphQuery
  The Query against Graph API
  
 .Example

  $ReportingClientId = "9a0112fb-6626-4761-a96b-a5f433c69ef7"
  $Cert = dir Cert:\LocalMachine\my\0EA8A7037A584C3C7BB54119D754DE1024AABAB2
  $AccessToken = Get-MSCloudIdMSGraphAccessTokenFromCert  -TenantDomain "contoso.com" -ClientId $ReportingClientId -Certificate $Cert
  $SignInLog = Invoke-MSCloudIdMSGraphQuery -AccessToken $AccessToken -GraphQuery "/beta/identityRiskEvents" 
#>
Function Invoke-MSCloudIdMSGraphQuery
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [string]
        $AccessToken, # For example, contoso.onmicrosoft.com,        
        [string]
        $GraphQuery,
        [ScriptBlock]
        $TokenRenewalCallback
    )

    Write-Progress -Id 1 -Activity "Querying directory" -CurrentOperation "Invoking MS Graph API"

    $headerParams  = @{'Authorization'="Bearer $AccessToken"}
       
    $queryResults = @()
    $originalUrl = "https://graph.microsoft.com/$GraphQuery"
    $queryUrl = "https://graph.microsoft.com/$GraphQuery"
    $queryCount = 0

    while (-not [String]::IsNullOrEmpty($queryUrl))
    {
        $batchResult = (Invoke-WebRequest -Headers $headerParams -Uri $queryUrl).Content | ConvertFrom-Json
        if ($null -ne $batchResult.value)
        {
            $queryResults += $batchResult.value
        }
        else
        {
            $queryResults += $batchResult
        }
        $queryCount = $queryResults.Count
        Write-Progress -Id 1 -Activity "Querying directory" -CurrentOperation "Retrieving results ($queryCount found so far)" 
        $queryUrl = ""

        $odataNextLink = $batchResult | Select-Object -ExpandProperty "@odata.nextLink" -ErrorAction SilentlyContinue

        if ($null -ne $odataNextLink)
        {
            $queryUrl =  $odataNextLink
        }
        else
        {
            $odataNextLink = $batchResult | Select-Object -ExpandProperty "odata.nextLink" -ErrorAction SilentlyContinue
            if ($null -ne $odataNextLink)
            {
                $absoluteUri = [Uri]"https://bogus/$odataNextLink"
                $skipToken = $absoluteUri.Query.TrimStart("?")
                $queryUrl = "https://graph.windows.net/$TenantDomain/$odataNextLink&api-version=1.6" #"$originalUrl&$skipToken"
            }
        }
    }

    Write-Progress -Id 1 -Activity "Querying directory" -Completed

    Write-Output $queryResults
}

<# 
 .Synopsis
  Generates a Report of all assignments to applications.

 .Description
  This function queries all the applications, and for each one, obtain the list of role assignments.

 .Parameter TenantDomain
  The domain name of the tenant you want the token for.

 .Parameter AccessToken
  Access token for Azure AD Graph API

  
 .Example
  $ReportingClientId = "9a0112fb-6626-4761-a96b-a5f433c69ef7"
  $Cert = dir Cert:\LocalMachine\my\0EA8A7037A584C3C7BB54119D754DE1024AABAB2
  $AccessToken = Get-MSCloudIdAzureADGraphAccessTokenFromCert  -TenantDomain "contoso.com" -ClientId $ReportingClientId -Certificate $Cert
  $SignInLog = Invoke-AzureADAppAssignmentReport -AccessToken $AccessToken -TenantDomain $TenantDomain 
#>
Function Get-MSCloudIdAppAssignmentReport
{    
    [CmdletBinding()]
    param
    (       
        [Parameter(Mandatory=$true)]
        [string]
        $TenantDomain,  
        [Parameter(Mandatory=$true)]
        [string]
        $AccessToken           
    )
    
    Write-Progress -Id 10 -Activity "Building app assignment report" -CurrentOperation "Getting list of applications" 


    $apps = Invoke-MSCloudIdAzureADGraphQuery -AccessToken $AccessToken -TenantDomain $TenantDomain -GraphQuery "servicePrincipals?api-version=1.5"

    $results = @()
    $appCount = $apps.Count
    $appIndex = 1

    foreach($app in $apps)
    {
        Write-Progress -Id 10 -Activity "Building app assignment report" -PercentComplete (100 * $appIndex / $appCount)  -CurrentOperation "Extracting permissions for each application ($appIndex/$appCount)"  

        $appObjectId = $app.objectId
        $appRoles = Invoke-MSCloudIdAzureADGraphQuery -AccessToken $AccessToken -TenantDomain $TenantDomain -GraphQuery "servicePrincipals/$appObjectId/appRoleAssignedTo?api-version=1.5"
        foreach($appPermission in $appRoles)
        {
            $result = New-Object -TypeName PSObject
	        $result | add-member -MemberType NoteProperty -name "appObjectId" -value $app.objectId
            $result | add-member -MemberType NoteProperty -name "appDisplayName" -value $app.appDisplayName
            $result | add-member -MemberType NoteProperty -name "principalId" -value $appPermission.principalId
            $result | add-member -MemberType NoteProperty -name "principalDisplayName" -value $appPermission.principalDisplayName
            $result | add-member -MemberType NoteProperty -name "principalType" -value $appPermission.principalType
            $results += $result
        }
        $appIndex++
    }

    Write-Progress -Id 10 -Activity "Building app assignment report" -Completed

    Write-Output $results
}

$script:TenantSkus = $null

Function Get-AzureADTenantSkus
{
	[CmdletBinding()]
	param()
    if ($null -eq $script:TenantSkus)
    {
        $script:TenantSkus = Get-AzureADSubscribedSku
    }
    Write-Output $script:TenantSkus
}

Function Get-MSCloudIdUserLastSigninDateTime 
{

    [CmdletBinding()]
    param
    (       
        [Parameter(Mandatory=$true)]
        [string]
        $TenantDomain,  
        [Parameter(Mandatory=$true)]
        [string]
        $AccessToken,
        [Parameter(Mandatory=$true)]
        [Int]
        $CutOffDays,
        [Parameter(Mandatory=$true)]
        [string]
        $UserPrincipalName

    )

    $CutOffDateFilter = "{0:s}Z" -f (Get-Date).AddDays(-1 * $CutOffDays)
   
    #Step 1: Get sign in info from the user
    $signInActivity = Invoke-MSCloudIdAzureADGraphQuery -TenantDomain $TenantDomain -AccessToken $AccessToken -GraphQuery "/activities/signinEvents?api-version=beta&`$filter=signinDateTime ge $CutOffDateFilter and userPrincipalName eq '$UserPrincipalName'"

    #If we had at least one result, then get-member will retrieve the property metadata
    $atLeastOneSignIn = $signInActivity | Get-Member userId

    if ($null -eq $atLeastOneSignIn)
    {
        Write-Output $null
    }
    else
    {
        $lastSignin = $signInActivity | Sort-Object -Property "signinDateTime" -Descending | Select-Object -First 1 -ExpandProperty signInDateTime
        Write-Output $lastSignin
    }

}

Function Get-MSCloudIdAppStaleLicensingReportByUser
{
    [CmdletBinding()]
    param
    (       
        [Parameter(Mandatory=$true)]
        [string]
        $TenantDomain,  
        [Parameter(Mandatory=$true)]
        [string]
        $AccessToken,
        [Parameter(Mandatory=$true)]
        [Int]
        $CutOffDays,
        [Parameter(Mandatory=$true)]
        [string]
        $UserPrincipalName

    )
    $LastSignIn = Get-MSCloudIdUserLastSigninDateTime -TenantDomain $TenantDomain -AccessToken $AccessToken -CutOffDays $CutOffDays -UserPrincipalName $UserPrincipalName
    $TenantSKUs = Get-AzureADTenantSkus
    $user= Get-AzureADUser -SearchString $UserPrincipalName
    $userSkus = $user.AssignedLicenses
    
    $skuString = ""
        
    if ($Null -ne $userSkus)
    {

        $skuString = ""

        foreach ($userSku in $userSkus)
        {
            $skuName = $TenantSKUs | Where-Object {$_.SkuId -eq $userSku.SkuId} | Select-Object -ExpandProperty SkuPartNumber
            $skuString +=  $skuName + ";"

        }
    }

    $signinStaleStatus = $null

    if ($null -eq $LastSignIn)
    {
        $signinStaleStatus = "Stale"
    }
    else
    {
        $signinStaleStatus = "Not stale"
    }

    $result = New-Object PSObject -Property @{"UPN" = $UserPrincipalName; "SKUs" = $skuString; "StaleStatus" = $signinStaleStatus; "Last Sign In" = $LastSignIn }
    Write-Output $result
}

Function Get-AzureADSignInReportByApp 
{
    [CmdletBinding()]
    param
    (       
        [Parameter(Mandatory=$true)]
        [string]
        $TenantDomain,  
        [Parameter(Mandatory=$true)]
        [string]
        $AccessToken,
        [Parameter(Mandatory=$true)]
        [Int]
        $CutOffDays
    )
    $CutOffDateFilter = "{0:s}Z" -f (Get-Date).AddDays(-1 * $CutOffDays)
   
    #Step 1: Get all sign ins from all folks
    $signInActivity = Invoke-MSCloudIdAzureADGraphQuery -TenantDomain $TenantDomain -AccessToken $AccessToken -GraphQuery "/activities/signinEvents?api-version=beta&`$filter=signinDateTime ge $CutOffDateFilter"

    $signInActivity | Group-Object  -NoElement 


}

<# 
 .Synopsis
  Adds certificate Credentials to an application 

 .Description
  This functions installs a client certificate credentials 

 .Parameter ApplicationObjectId
  The application Object ID that will be associated to the certificate credential
  
 .Example

  $ReportingClientId = "9a0112fb-6626-4761-a96b-a5f433c69ef7"
  $Cert = dir Cert:\LocalMachine\my\0EA8A7037A584C3C7BB54119D754DE1024AABAB2

  New-MSCloudIdApplicationCertificateCredential -ApplicationObjectId $ReportingClientId -Certificate $Cert
  
#>
Function New-MSCloudIdApplicationCertificateCredential
{
  param
  (
        [Parameter(Mandatory=$true)]
        [string]
        $ApplicationObjectId,
        [Parameter(Mandatory=$true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate
  )

    $bin = $Certificate.GetRawCertData()
    $base64Value = [System.Convert]::ToBase64String($bin)
    $thumbprint = $Certificate.GetCertHash()
    $base64Thumbprint = [System.Convert]::ToBase64String($thumbprint)

    New-AzureADApplicationKeyCredential `
        -ObjectId $ApplicationObjectId `
        -CustomKeyIdentifier $base64Thumbprint `
        -Type AsymmetricX509Cert `
        -Usage Verify `
        -Value $base64Value `
        -StartDate $Certificate.NotBefore `
        -EndDate $Certificate.NotAfter
}

<# 
 .Synopsis
  Provides a report to show all the keys expiration date accross application and service principals 

 .Description
  Provides a report to show all the keys expiration date accross application and service principals
  
 .Example
  Connect-AzureAD
  Get-MSCloudIdApplicationKeyExpirationReport
  
#>
Function Get-MSCloudIdApplicationKeyExpirationReport
{
    param()
    
    $apps = Get-AzureADApplication -Top 100000

    foreach($app in $apps)
    {
        $appObjectId = $app.ObjectId
        $appName = $app.DisplayName
        

        $appKeys = Get-AzureADApplicationKeyCredential -ObjectId $appObjectId

        foreach($appKey in $appKeys)
        {        
            $result = New-Object PSObject
            $result  | Add-Member -MemberType NoteProperty -Name "Display Name" -Value $appName
            $result  | Add-Member -MemberType NoteProperty -Name "Object Type" -Value "Application"
            $result  | Add-Member -MemberType NoteProperty -Name "KeyType" -Value $appKey.Type
            $result  | Add-Member -MemberType NoteProperty -Name "Start Date" -Value $appKey.StartDate
            $result  | Add-Member -MemberType NoteProperty -Name "End Date" -Value $appKey.EndDate
            $result  | Add-Member -MemberType NoteProperty -Name "Usage" -Value $appKey.Usage
            Write-Output $result
        }

        $appKeys = Get-AzureADApplicationPasswordCredential -ObjectId $appObjectId
        
        foreach($appKey in $app.PasswordCredentials)
        {        
            $result = New-Object PSObject
            $result  | Add-Member -MemberType NoteProperty -Name "Display Name" -Value $appName
            $result  | Add-Member -MemberType NoteProperty -Name "Object Type" -Value "Application"
            $result  | Add-Member -MemberType NoteProperty -Name "KeyType" -Value "Password"
            $result  | Add-Member -MemberType NoteProperty -Name "Start Date" -Value $appKey.StartDate
            $result  | Add-Member -MemberType NoteProperty -Name "End Date" -Value $appKey.EndDate
            Write-Output $result
        }
    }

    
    $servicePrincipals = Get-AzureADServicePrincipal -Top 10000

    foreach($sp in $servicePrincipals)
    {
        $spName = $sp.DisplayName
        $spObjectId = $sp.ObjectId

        $spKeys = Get-AzureADServicePrincipalKeyCredential -ObjectId $spObjectId        

        foreach($spKey in $spKeys)
        {
            $result = New-Object PSObject
            $result  | Add-Member -MemberType NoteProperty -Name "Display Name" -Value $spName
            $result  | Add-Member -MemberType NoteProperty -Name "Object Type" -Value "Service Principal"
            $result  | Add-Member -MemberType NoteProperty -Name "KeyType" -Value $spKey.Type
            $result  | Add-Member -MemberType NoteProperty -Name "Start Date" -Value $spKey.StartDate
            $result  | Add-Member -MemberType NoteProperty -Name "End Date" -Value $spKey.EndDate
            $result  | Add-Member -MemberType NoteProperty -Name "Usage" -Value $spKey.Usage
            Write-Output $result
        }    
        
        $spKeys = Get-AzureADServicePrincipalPasswordCredential -ObjectId $spObjectId    

        
        foreach($spKey in $spKeys)
        {
            $result = New-Object PSObject
            $result  | Add-Member -MemberType NoteProperty -Name "Display Name" -Value $spName
            $result  | Add-Member -MemberType NoteProperty -Name "Object Type" -Value "Service Principal"
            $result  | Add-Member -MemberType NoteProperty -Name "KeyType" -Value "Password"
            $result  | Add-Member -MemberType NoteProperty -Name "Start Date" -Value $spKey.StartDate
            $result  | Add-Member -MemberType NoteProperty -Name "End Date" -Value $spKey.EndDate
            Write-Output $result
        }    

    }
}

<# 
 .Synopsis
  Removes all on premises synchronized users from a tenant

 .Description
  Removes all on premises synchronized users from a tenant. This cmdlet requires the Azure AD Powershell Module

 .Parameter Force
  When this parameter is set, then the confirmation message is not shown to the user.

 .Example
  Connect-MSOLService
  Remove-MSCloudIdSyncUsers -Force
#>
Function Remove-MSCloudIdSyncUsers
{
    [CmdletBinding()]
    param
    (   
       [Switch]
       $Force    
    )    

    $Proceed = $Force

    if (-not $Force)
    {
        $title = "Remove Synchronized Accounts"
        $message = "This will remove ALL on-premises synchronized users from your tenant. Do you want to proceed"

        $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", `
        "Remove all synchronized user accounts from Azure AD. You will need to execute a full sync cycle"

        $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", `
        "Keep all the objects on premises."

        $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
        $result = $host.ui.PromptForChoice($title, $message, $options, 0) 

        if ($result -eq 0)
        {
            $Proceed = $true
        }
    }

    if ($Proceed)
    {

        Write-Progress -Id 10 -Activity "Removing On-Premises users from your tenant..." -CurrentOperation "Connecting to Azure AD" 
        Connect-MsolService
        Write-Progress -Id 10 -Activity "Removing On-Premises users from your tenant..." -CurrentOperation "Removing users the cloud" 
        $UsersToRemove = Get-MsolUser -Synchronized | Where-Object {$_.UserPrincipalName -notlike "Sync*"}
        $UsersToRemove | ForEach-Object {Remove-MsolUser -ObjectId $_.ObjectId -Force }
        Get-MsolUser -ReturnDeletedUsers | ForEach-Object { Remove-MsolUser -ObjectId $_.ObjectId -RemoveFromRecycleBin -Force }        
        $UsersCount = $UsersToRemove | Measure-Object  | Select-Object -ExpandProperty Count
        "$UsersCount have been deleted from the tenant. To Resynchronize, clean the Azure AD Connect connector spaces and force an Initial Sync Cycle"
    }
}

<# 
 .Synopsis
  Adds a custom signing certificate to a service principal

 .Description
  This functions takes an X509Certificate, serializes it and associates it to a service principal.
  It will return the Raw HTTP output of the Azure AD Graph Call. A successful call to this cmdlet should result in an 204 Output code 

 .Parameter AccessToken
  Access token to Azure AD Graph (See functions *GraphAccessToken* in this module)
  
 .Parameter ServicePrincipalObjectId
  Object ID of the service principal to be updated.

 .Parameter Certificate
  Certificate object to be uploaded. This certificate must have the private key accessible.
  
 .Example
  $AccessToken =  Get-MSCloudIdAzureADGraphAccessTokenFromUser -TenantDomain contoso.com -ClientId dbf240f7-84cb-471c-978a-a97890bd2393  -RedirectUri urn:your:returnurl
  $ServicePrincipalObjectId = c1bc4a39-3be3-456d-a7f1-5a0d1b8531c2
  $Cert = dir Cert:\LocalMachine\my\0EA8A7037A584C3C7BB54119D754DE1024AA1234
  New-MSCloudIdServicePrincipalSigningCertificate -AccessToken $AccessToken -ServicePrincipalObjectId $ServicePrincipalObjectId -Certificate $Cert

  ----------------
  Sample Output
  ----------------

  HTTP/1.1 204 No Content
  Pragma: no-cache
...
  X-AspNet-Version: 4.0.30319
  X-Powered-By: ASP.NET,ASP.NET
#>
Function New-MSCloudIdServicePrincipalSigningCertificate
{
    param
    (
            [Parameter(Mandatory=$true)]
            [string]
            $AccessToken,
            [Parameter(Mandatory=$true)]
            [string]
            $ServicePrincipalObjectId,
            [Parameter(Mandatory=$true)]
            [System.Security.Cryptography.X509Certificates.X509Certificate2]
            $Certificate
    )
    #Create the Pfx File Placeholder
    $TempPfxFileInfo = New-TemporaryFile
    $TempPfxFilePath = $TempPfxFileInfo.FullName

    try 
    {
        if (-not $Certificate.HasPrivateKey)
        {
            Write-Error "Certificate supplied does not have the private key."
        }

        #Generate a temporary 128 symmetric key as the password of the exported PFX file
        $pfxKeyBytes = new-object "System.Byte[]" 128 
        $rnd = new-object System.Security.Cryptography.RNGCryptoServiceProvider
        $rnd.GetBytes($pfxKeyBytes)
        $PfxPassword = [Convert]::ToBase64String($pfxKeyBytes)
        $PfxPasswordSecureString = ConvertTo-SecureString -String $PfxPassword -Force -AsPlainText
        $Certificate | Export-PfxCertificate -FilePath $TempPfxFilePath -Password $PfxPasswordSecureString | Out-Null

        #Get the parameters needed in the Azure AD Graph API call
        $StartDate = ([DateTime]$Certificate.NotBefore).ToUniversalTime().ToString("s")+"Z"
        $EndDate = ([DateTime]$Certificate.NotAfter).ToUniversalTime().ToString("s")+"Z"
        $KeyId = [Guid]::NewGuid().Guid.ToString();
        $RawCertBytes = Get-Content -Path $TempPfxFilePath -Encoding Byte
        $RawCertBase64String = [Convert]::ToBase64String($RawCertBytes)

        $PatchBodyTemplate = '{5}
            "keyCredentials":
            [{5}
                "startDate":"{0}",
                "endDate":"{1}", 
                "type":"X509CertAndPassword", 
                "usage":"Sign", 
                "keyId" : "{2}",
                "value": "{3}"
            {6}],
            "passwordCredentials": 
            [{5}
                    "startDate":"{0}",
                    "endDate":"{1}", 
                    "keyId" : "{2}",
                    "value": "{4}"
            {6}]
        {6}' 

        $PatchBody = $PatchBodyTemplate -f $StartDate,$EndDate,$KeyId,$RawCertBase64String,$PfxPassword,"{","}"
        $GraphEndpoint = "https://graph.windows.net/myorganization/servicePrincipals/{0}?api-version=1.6" -f $ServicePrincipalObjectId
        $headers  = @{'Authorization'="Bearer $AccessToken"}

        #Invoke Graph API. Result should be 204
        Invoke-WebRequest -Method Patch -Uri $GraphEndpoint -Body $PatchBody -Headers $headers -ContentType "application/json" -UseBasicParsing | Select-Object -ExpandProperty RawContent
    }
    finally
    {
        #Delete the PFX file
        Remove-Item -LiteralPath $TempPfxFilePath
    }
}

function Convert-FromBase64StringWithNoPadding([string]$data)
{
    $data = $data.Replace('-', '+').Replace('_', '/')
    switch ($data.Length % 4)
    {
        0 { break }
        2 { $data += '==' }
        3 { $data += '=' }
        default { throw New-Object ArgumentException('data') }
    }
    return [System.Convert]::FromBase64String($data)
}

function Decode-JWT([string]$rawToken)
{
    $parts = $rawToken.Split('.');
    $headers = [System.Text.Encoding]::UTF8.GetString((Convert-FromBase64StringWithNoPadding $parts[0]))
    $claims = [System.Text.Encoding]::UTF8.GetString((Convert-FromBase64StringWithNoPadding $parts[1]))
    $signature = (Convert-FromBase64StringWithNoPadding $parts[2])

    $customObject = [PSCustomObject]@{
        headers = ($headers | ConvertFrom-Json)
        claims = ($claims | ConvertFrom-Json)
        signature = $signature
    }

    Write-Verbose -Message ("JWT`r`n.headers: {0}`r`n.claims: {1}`r`n.signature: {2}`r`n" -f $headers,$claims,[System.BitConverter]::ToString($signature))
    return $customObject
}

<# 
 .Synopsis
  Decodes a JSON Web Token (JWT)  

 .Description
  This cmdlet takes a JWT, decodes and emits it out in the output stream

 .Example
  ConvertFrom-MSCloudIDJWT

#>
function ConvertFrom-MSCloudIDJWT
{
    [CmdletBinding()]  
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true)]
        [string] $Token,
        [switch] $Recurse
    )
    
    if ($Recurse)
    {
        $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Token))
        $DecodedJwt = Decode-JWT -rawToken $decoded
    }
    else
    {
        $DecodedJwt = Decode-JWT -rawToken $Token
    }
     Write-Host ($DecodedJwt | Select-Object headers,claims | ConvertTo-Json)
    return $DecodedJwt
}


<# 
 .Synopsis
  Installs this Powershell Module in the Powershell module path, downloading and copying the right dependencies 

 .Description
  This cmdlet copies the module in the module path, and downloads the ADAL library using Nuget

 .Example
  Install-MSCloudIdUtilsModule

#>
function Install-MSCloudIdUtilsModule
{
    [CmdletBinding()]
    param()

    $myDocumentsModuleFolderIsInPSModulePath = $false
    [Environment]::GetEnvironmentVariable("PSModulePath") -Split ';' | ForEach-Object {
      if ($_.ToLower() -eq ([Environment]::GetFolderPath("MyDocuments") + "\WindowsPowerShell\Modules").ToLower()){
        $myDocumentsModuleFolderIsInPSModulePath = $true
      }
    }

    if(-not $myDocumentsModuleFolderIsInPSModulePath){
      $newPSModulePath = [Environment]::GetEnvironmentVariable("PSModulePath") + ";" + [Environment]::GetFolderPath("MyDocuments") + "\WindowsPowerShell\Modules";
      [Environment]::SetEnvironmentVariable("PSModulePath",$newPSModulePath, "Process")
      [Environment]::SetEnvironmentVariable("PSModulePath",$newPSModulePath, "User")

    }


    $moduleDirPath = [Environment]::GetFolderPath("MyDocuments") + "\WindowsPowerShell\Modules"
    $modulePath = $moduleDirPath + "\MSCloudIdUtils"

    if (Test-Path $modulePath)
    {
        Write-Host "Removing existing module directory under "$moduleDirPath -ForegroundColor Green
        Remove-Item -Path $modulePath -Recurse -Force | Out-Null
    }

    Write-Host "Creating module directory under "$moduleDirPath -ForegroundColor Green
    New-Item -Path $modulePath -Type "Directory" -Force | Out-Null
    New-Item -Path $modulePath"\Nugets" -Type "Directory" -Force | Out-Null
    New-Item -Path $modulePath"\Cmdlets" -Type "Directory" -Force | Out-Null


  if(-not (Test-Path ($modulePath+"\Nugets"))) {New-Item -Path ($modulePath+"\Nugets") -ItemType "Directory" | out-null}

  $adalPackageDirectories = (Get-ChildItem -Path ($modulePath+"\Nugets") -Filter "Microsoft.IdentityModel.Clients.ActiveDirectory*" -Directory)

  if($adalPackageDirectories.Length -eq 0){
    Write-Host "Active Directory Authentication Library Nuget doesn't exist. Downloading now ..." -ForegroundColor Yellow
    if(-not(Test-Path ($modulePath + "\Nugets\nuget.exe")))
    {
      Write-Host "nuget.exe not found. Downloading from http://www.nuget.org/nuget.exe ..." -ForegroundColor Yellow
      $wc = New-Object System.Net.WebClient
      $wc.DownloadFile("http://www.nuget.org/nuget.exe",$modulePath + "\Nugets\nuget.exe");
    }

    $nugetUpdateExpression = $modulePath + "\Nugets\nuget.exe update -self"
    Invoke-Expression $nugetUpdateExpression

    $nugetDownloadExpression = $modulePath + "\Nugets\nuget.exe install Microsoft.IdentityModel.Clients.ActiveDirectory -Version 2.14.201151115 -OutputDirectory " + $modulePath + "\Nugets | out-null"
    Invoke-Expression $nugetDownloadExpression

  }

    Copy-Item "$PSScriptRoot\MSCloudIdUtils.psm1" -Destination $modulePath -Force


    Get-Command -Module MSCloudIdUtils

}
