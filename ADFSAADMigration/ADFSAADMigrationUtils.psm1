<# 
 
.SYNOPSIS
	ADFSAADMigrationUtils.psm1 is a Windows PowerShell module that contains functions to analyze ADFS configuration and tests for compatibility to Migrate to Azure Active Directory

.DESCRIPTION

	Version: 1.0.0

	ADFSAADMigrationUtils.psm1 is a Windows PowerShell module that contains functions to analyze ADFS configuration and tests for compatibility to Migrate to Azure Active Directory


.DISCLAIMER
	THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
	ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
	THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
	PARTICULAR PURPOSE.

	Copyright (c) Microsoft Corporation. All rights reserved.
#>

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

Function Export-ADFS2AADOnPremRPTrusts
{
    $filePathBase = "$env:SystemDrive\ADFS\apps\"
    $zipfileBase = "$env:SystemDrive\ADFS\zip\"
    $zipfileName = $zipfileBase + "ADFSApps.zip"
    mkdir $filePathBase -ErrorAction SilentlyContinue
    mkdir $zipfileBase -ErrorAction SilentlyContinue

    $AdfsRelyingPartyTrusts = Get-AdfsRelyingPartyTrust
    foreach ($AdfsRelyingPartyTrust in $AdfsRelyingPartyTrusts)
    {
        $CleanedFileName = Remove-InvalidFileNameChars -Name $AdfsRelyingPartyTrust.Name
        $filePath = $filePathBase + $CleanedFileName + '.xml'
        $AdfsRelyingPartyTrust | Export-Clixml $filePath -ErrorAction SilentlyContinue
    }

    Compress-Archive -Path $filePathBase -DestinationPath $zipfileName -Force 

    Dir $zipfileName
}


###AD FS Relying Party Migration Checks



Add-Type -Language CSharp @"
public class MigrationTestResult
{
	public string TestName;
    public string ADFSObjectType;
    public string ADFSObjectIdentifier;

	public ResultType Result;
	public string Message;
	public string ExceptionMessage;
    public System.Collections.Hashtable Details;

    public MigrationTestResult()
	{
		Result = ResultType.Pass;
        Details = new System.Collections.Hashtable();        
	}
}

public enum ResultType
{
	Pass = 0,
	Warning = 1,
	Fail = 2
}
"@;


##########
#templatized claim rules
##########

$MFAMigratableRules =
@{
"MFA for a User" = 
@"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid", Value == "__ANYVALUE__"]
 => issue(Type = "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod", Value = "http://schemas.microsoft.com/claims/multipleauthn");
"@;
"MFA for a Group" = 
@"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid", Value == "__ANYVALUE__"]
 => issue(Type = "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod", Value = "http://schemas.microsoft.com/claims/multipleauthn");
"@;
"MFA for unregistered devices" = 
@"
c:[Type == "http://schemas.microsoft.com/2012/01/devicecontext/claims/isregistereduser", Value == "false"]
 => issue(Type = "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod", Value = "http://schemas.microsoft.com/claims/multipleauthn");
"@
"MFA for extranet" = 
@"
c:[Type == "http://schemas.microsoft.com/ws/2012/01/insidecorporatenetwork", Value == "false"]
 => issue(Type = "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod", Value = "http://schemas.microsoft.com/claims/multipleauthn");
"@
}

$DelegationMigratableRules =
@{
}

$ImpersonationMigratableRules =
@{
"ADFS V2 - ProxySid by user" = 
@"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid", Issuer =~ "^(AD AUTHORITY|SELF AUTHORITY|LOCAL AUTHORITY)$"]
 => issue(store = "_ProxyCredentialStore", types = ("http://schemas.microsoft.com/authorization/claims/permit"), query = "isProxySid({0})", param = c.Value);
"@
"ADFS V2 - ProxySid by group" =
@"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid", Issuer =~ "^(AD AUTHORITY|SELF AUTHORITY|LOCAL AUTHORITY)$"]
 => issue(store = "_ProxyCredentialStore", types = ("http://schemas.microsoft.com/authorization/claims/permit"), query = "isProxySid({0})", param = c.Value);
"@
"ADFS V2 - Proxy Trust check" =
@"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/proxytrustid", Issuer =~ "^SELF AUTHORITY$"]
 => issue(store = "_ProxyCredentialStore", types = ("http://schemas.microsoft.com/authorization/claims/permit"), query = "isProxyTrustProvisioned({0})", param = c.Value);
"@
}

$IssuanceAuthorizationMigratableRules =
@{
"Permit All" = 
@"
@RuleTemplate = "AllowAllAuthzRule"
 => issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "true");
"@
"Permit a group" =
@"
Assign to groups
@RuleTemplate = "Authorization"
@RuleName = "__ANYVALUE__"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid", Value =~ "__ANYVALUE__"]
 => issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "PermitUsersWithClaim");
"@
}

$IssuanceTransformMigratableRules =
@{ 
"Extract Attributes from AD" = 
@"
@RuleTemplate = "LdapClaims"
@RuleName = "__ANYVALUE__"
c:[Type == "__ANYVALUE__", Issuer == "AD AUTHORITY"]
 => issue(store = "Active Directory", types = (__ANYVALUE__), query = ";__ANYVALUE__;{0}", param = c.Value);
"@
}

Function Invoke-ADFSClaimRuleAnalysis
{
 [CmdletBinding()]
    param
    (    
        [String]
        $ADFSRuleSet,
        [Parameter(Mandatory=$true)]
        [System.Collections.Hashtable]
        $KnownRules,
        [Switch]
        $SummarizeResult,
        [String]
        $RuleSetName        
    )

    #BUGBUG: This is very flaky 
    #$ADFSRuleArray = $ADFSRuleSet.TrimEnd().Split(';', [System.StringSplitOptions]::RemoveEmptyEntries)

    $ADFSRuleArray = @()

    if (-not [String]::IsNullOrEmpty($ADFSRuleSet))
    {
        $ADFSRuleArray = New-AdfsClaimRuleSet -ClaimRule $ADFSRuleSet 
    } 

    
    $Details = ""
    $ruleIndex = 0
    $AnalysisPassed = $true

    foreach($Rule in $ADFSRuleArray.ClaimRules)
    {
        $ruleIndex++
        $matchFound = $false
        $RuleResultDetail = ""
        $RuleAnalysisPass = $false

        foreach($knownRuleKey in $KnownRules.Keys)
        {
            $knownRuleRegex = $KnownRules[$knownRuleKey]
            $knownRuleRegex = [Regex]::Escape($knownRuleRegex).Replace("__ANYVALUE__", ".*").TrimEnd() 
                        
            if ($rule -match $knownRuleRegex)
            {
                $RuleResultDetail = "Rule '{0}' matches known AD FS rule pattern '{1}'{2}" -f $ruleIndex, $knownRuleKey, [Environment]::NewLine
                $matchFound = $true
                $RuleAnalysisPass = $true
            }
        }
        if (-not $matchFound)
        {
            $RuleResultDetail = "Rule '{0}' does not match any known pattern. Rule='{1}'{2}" -f $ruleIndex, $rule, [Environment]::NewLine
            $AnalysisPassed = $false            
        }

        if (-not $SummarizeResult)
        {
            New-Object PSObject -Property @{ ClaimRule=$rule; ClaimRuleIndex=$ruleIndex; AnalysisPassed=$RuleAnalysisPass; Detail=$RuleResultDetail; RuleSetName = $RuleSetName }
        }

        $Details += $RuleResultDetail
    }

    if ($SummarizeResult)
    {
        New-Object PSObject -Property @{ AnalysisPassed = $AnalysisPassed; Details = $Details.Trim(); RuleSetName = $RuleSetName  }
    }
}

Function Test-ADFSRPAdditionalAuthenticationRules
{
    [CmdletBinding()]
    param
    (    
        [Parameter(Mandatory=$true)]
        $ADFSRelyingPartyTrust,
        [Switch]
        $SummarizeResult
    )

    $TestResult = New-Object MigrationTestResult

    $RuleAnalysis = Invoke-ADFSClaimRuleAnalysis -ADFSRuleSet $ADFSRelyingPartyTrust.AdditionalAuthenticationRules -KnownRules $MFAMigratableRules -SummarizeResult:$SummarizeResult -RuleSetName "AdditionalAuthentication"

    if (-not $RuleAnalysis.AnalysisPassed)
    {
        $TestResult.Result = [ResultType]::Fail
        $TestResult.Message = "At least one non-migratable rule was detected"        
    }

    $TestResult.Details.Add("MFARuleAnalysisResult", $RuleAnalysis.Details)

    Return $TestResult
}

Function Test-ADFSRPAdditionalWSFedEndpoint
{
    [CmdletBinding()]
    param
    (    
        [Parameter(Mandatory=$true)]
        $ADFSRelyingPartyTrust
    )

    $TestResult = New-Object MigrationTestResult

    if ($ADFSRelyingPartyTrust.AdditionalWSFedEndpoint.Count -gt 0)
    {
        $TestResult.Result = [ResultType]::Fail
        $TestResult.Message = "Relying Party has additional WS-Federation Endpoints."
        
    }
    else
    {
        $TestResult.Message = "No additional WS-Federation endpoints were found"
    }

    $TestResult.Details.Add("AdditionalWSFedEndpoint.Count", $ADFSRelyingPartyTrust.AdditionalWSFedEndpoint.Count)

    Return $TestResult
}

Function Test-ADFSRPAllowedAuthenticationClassReferences
{
    [CmdletBinding()]
    param
    (    
        [Parameter(Mandatory=$true)]
        $ADFSRelyingPartyTrust
    )

    $TestResult = New-Object MigrationTestResult

    if ($ADFSRelyingPartyTrust.AllowedAuthenticationClassReferences.Count -gt 0)
    {
        $TestResult.Result = [ResultType]::Fail
        $TestResult.Message = "Relying Party has set AllowedAuthenticationClassReferences."
        
    }
    else
    {
        $TestResult.Message = "AllowedAuthenticationClassReferences is not set up."
    }

    $TestResult.Details.Add("AllowedAuthenticationClassReferences.Count", $ADFSRelyingPartyTrust.AllowedAuthenticationClassReferences.Count)

    Return $TestResult
}

Function Test-ADFSRPAlwaysRequireAuthentication
{
    [CmdletBinding()]
    param
    (    
        [Parameter(Mandatory=$true)]
        $ADFSRelyingPartyTrust
    )

    $TestResult = New-Object MigrationTestResult

    if ($ADFSRelyingPartyTrust.AlwaysRequireAuthentication)
    {
        $TestResult.Result = [ResultType]::Fail
        $TestResult.Message = "Relying Party has AlwaysRequireAuthentication enabled"        
    }
    else
    {
        $TestResult.Message = "AlwaysRequireAuthentication is not set up."
    }

    $TestResult.Details.Add("AlwaysRequireAuthentication", $ADFSRelyingPartyTrust.AlwaysRequireAuthentication)

    Return $TestResult
}

Function Test-ADFSRPAutoUpdateEnabled
{
    [CmdletBinding()]
    param
    (    
        [Parameter(Mandatory=$true)]
        $ADFSRelyingPartyTrust
    )

    $TestResult = New-Object MigrationTestResult

    if ($ADFSRelyingPartyTrust.AutoUpdateEnabled)
    {
        $TestResult.Result = [ResultType]::Warning
        $TestResult.Message = "Relying Party has AutoUpdateEnabled set to true"
        
    }
    else
    {
        $TestResult.Message = "AutoUpdateEnabled is not set up."
    }

    $TestResult.Details.Add("AutoUpdateEnabled", $ADFSRelyingPartyTrust.AutoUpdateEnabled)

    Return $TestResult
}

Function Test-ADFSRPClaimsProviderName
{
    [CmdletBinding()]
    param
    (    
        [Parameter(Mandatory=$true)]
        $ADFSRelyingPartyTrust
    )

    $TestResult = New-Object MigrationTestResult
    $TestResult.Details.Add("ClaimsProviderName.Count", $ADFSRelyingPartyTrust.ClaimsProviderName.Count)

    if ($ADFSRelyingPartyTrust.ClaimsProviderName.Count -gt 1)
    {
        $TestResult.Result = [ResultType]::Fail
        $TestResult.Message = "Relying Party has multiple ClaimsProviders enabled"        
    }
    elseif ($ADFSRelyingPartyTrust.ClaimsProviderName.Count -eq 1 -and $ADFSRelyingPartyTrust.ClaimsProviderName[0] -ne 'Active Directory')
    {
        $TestResult.Result = [ResultType]::Fail
        $TestResult.Message = "Relying Party has a non-Active Directory store: $($ADFSRelyingPartyTrust.ClaimsProviderName[0])"        
    }
    else
    {
        $TestResult.Message = "No Additional Claim Providers were configured."
    }

    

    Return $TestResult
}

Function Test-ADFSRPDelegationAuthorizationRules
{
    [CmdletBinding()]
    param
    (    
        [Parameter(Mandatory=$true)]
        $ADFSRelyingPartyTrust,
        [Switch]
        $SummarizeResult
    )

    $TestResult = New-Object MigrationTestResult

    $RuleAnalysis = Invoke-ADFSClaimRuleAnalysis -ADFSRuleSet $ADFSRelyingPartyTrust.DelegationAuthorizationRules -KnownRules $DelegationMigratableRules -SummarizeResult:$SummarizeResult -RuleSetName "DelegationAuthorization"

    if (-not $RuleAnalysis.AnalysisPassed)
    {
        $TestResult.Result = [ResultType]::Warning
        $TestResult.Message = "Delegation Rules detected"        
    }

    $TestResult.Details.Add("DelegationAuthorizationRulesAnalysisResult", $RuleAnalysis.Details)

    Return $TestResult
}

Function Test-ADFSRPEncryptClaims
{
    [CmdletBinding()]
    param
    (    
        [Parameter(Mandatory=$true)]
        $ADFSRelyingPartyTrust
    )

    $TestResult = New-Object MigrationTestResult

    if (($ADFSRelyingPartyTrust.EncryptClaims -or $ADFSRelyingPartyTrust.EncryptedNameIdRequired) -and $ADFSRelyingPartyTrust.EncryptionCertificate -ne $null)
    {
        $TestResult.Result = [ResultType]::Fail
        $TestResult.Message = "Relying Party is set to encrypt claims and/or nameid."
        
    }
    else
    {
        $TestResult.Message = "Relying Party is set to encrypt claims and/or nameid."
    }

    $TestResult.Details.Add("EncryptClaims", $ADFSRelyingPartyTrust.EncryptClaims)
    $TestResult.Details.Add("EncryptedNameIdRequired", $ADFSRelyingPartyTrust.EncryptedNameIdRequired)

    Return $TestResult
}

Function Test-ADFSRPImpersonationAuthorizationRules
{
    [CmdletBinding()]
    param
    (    
        [Parameter(Mandatory=$true)]
        $ADFSRelyingPartyTrust,
        [Switch]
        $SummarizeResult
    )

    $TestResult = New-Object MigrationTestResult

    $RuleAnalysis = Invoke-ADFSClaimRuleAnalysis -ADFSRuleSet $ADFSRelyingPartyTrust.ImpersonationAuthorizationRules -KnownRules $ImpersonationMigratableRules -SummarizeResult:$SummarizeResult -RuleSetName "ImpersonationAuthorization"

    if (-not $RuleAnalysis.AnalysisPassed)
    {
        $TestResult.Result = [ResultType]::Warning
        $TestResult.Message = "Impersonation Rules detected"        
    }

    $TestResult.Details.Add("ImpersonationAuthorizationRulesAnalysisResult", $RuleAnalysis.Details)

    Return $TestResult
}

Function Test-ADFSRPIssuanceAuthorizationRules
{
    [CmdletBinding()]
    param
    (    
        [Parameter(Mandatory=$true)]
        $ADFSRelyingPartyTrust,
        [Switch]
        $SummarizeResult
    )

    $TestResult = New-Object MigrationTestResult

    $RuleAnalysis = Invoke-ADFSClaimRuleAnalysis -ADFSRuleSet $ADFSRelyingPartyTrust.IssuanceAuthorizationRules -KnownRules $IssuanceAuthorizationMigratableRules -SummarizeResult:$SummarizeResult -RuleSetName "IssuanceAuthorization"

    if (-not $RuleAnalysis.AnalysisPassed)
    {
        $TestResult.Result = [ResultType]::Warning
        $TestResult.Message = "Non-migratable issuance authorization rules detected"        
    }

    $TestResult.Details.Add("IssuanceAuthorizationRulesAnalysisResult", $RuleAnalysis.Details)

    Return $TestResult
}

Function Test-ADFSRPIssuanceTransformRules
{
    [CmdletBinding()]
    param
    (    
        [Parameter(Mandatory=$true)]
        $ADFSRelyingPartyTrust,
        [Switch]
        $SummarizeResult
    )

    $TestResult = New-Object MigrationTestResult

    $RuleAnalysis = Invoke-ADFSClaimRuleAnalysis -ADFSRuleSet $ADFSRelyingPartyTrust.IssuanceTransformRules -KnownRules $IssuanceTransformMigratableRules -SummarizeResult:$SummarizeResult -RuleSetName "IssuanceTransform"

    if (-not $RuleAnalysis.AnalysisPassed)
    {
        $TestResult.Result = [ResultType]::Warning
        $TestResult.Message = "Non-migratable issuance transform rules detected"        
    }

    $TestResult.Details.Add("IssuanceTransformRulesAnalysisResult", $RuleAnalysis.Details)

    Return $TestResult
}

Function Test-ADFSRPMonitoringEnabled
{
    [CmdletBinding()]
    param
    (    
        [Parameter(Mandatory=$true)]
        $ADFSRelyingPartyTrust
    )

    $TestResult = New-Object MigrationTestResult

    if ($ADFSRelyingPartyTrust.MonitoringEnabled)
    {
        $TestResult.Result = [ResultType]::Warning
        $TestResult.Message = "Relying Party has MonitoringEnabled set to true"
        
    }
    else
    {
        $TestResult.Message = "MonitoringEnabled is not set up."
    }

    $TestResult.Details.Add("MonitoringEnabled", $ADFSRelyingPartyTrust.MonitoringEnabled)

    Return $TestResult
}

Function Test-ADFSRPNotBeforeSkew
{
    [CmdletBinding()]
    param
    (    
        [Parameter(Mandatory=$true)]
        $ADFSRelyingPartyTrust
    )

    $TestResult = New-Object MigrationTestResult

    if ($ADFSRelyingPartyTrust.NotBeforeSkew -gt 0)
    {
        $TestResult.Result = [ResultType]::Warning
        $TestResult.Message = "Relying Party has NotBeforeSkew configured"
        
    }
    else
    {
        $TestResult.Message = "NotBeforeSkew is not set up."
    }

    $TestResult.Details.Add("NotBeforeSkew", $ADFSRelyingPartyTrust.NotBeforeSkew)

    Return $TestResult
}

Function Test-ADFSRPRequestMFAFromClaimsProviders 
{
    [CmdletBinding()]
    param
    (    
        [Parameter(Mandatory=$true)]
        $ADFSRelyingPartyTrust
    )

    $TestResult = New-Object MigrationTestResult

    if ($ADFSRelyingPartyTrust.RequestMFAFromClaimsProviders)
    {
        $TestResult.Result = [ResultType]::Warning
        $TestResult.Message = "Relying Party has RequestMFAFromClaimsProviders set to true"
        
    }
    else
    {
        $TestResult.Message = "RequestMFAFromClaimsProviders is not set up."
    }

    $TestResult.Details.Add("RequestMFAFromClaimsProviders", $ADFSRelyingPartyTrust.RequestMFAFromClaimsProviders)

    Return $TestResult
}

Function Test-ADFSRPSignedSamlRequestsRequired 
{
    [CmdletBinding()]
    param
    (    
        [Parameter(Mandatory=$true)]
        $ADFSRelyingPartyTrust
    )

    $TestResult = New-Object MigrationTestResult

    if ($ADFSRelyingPartyTrust.SignedSamlRequestsRequired)
    {
        $TestResult.Result = [ResultType]::Fail
        $TestResult.Message = "Relying Party has SignedSamlRequestsRequired set to true"
        
    }
    else
    {
        $TestResult.Message = "SignedSamlRequestsRequired is not set up."
    }

    $TestResult.Details.Add("SignedSamlRequestsRequired", $ADFSRelyingPartyTrust.SignedSamlRequestsRequired)

    Return $TestResult
}

Function Test-ADFSRPTokenLifetime
{
    [CmdletBinding()]
    param
    (    
        [Parameter(Mandatory=$true)]
        $ADFSRelyingPartyTrust
    )

    $TestResult = New-Object MigrationTestResult

    if ($ADFSRelyingPartyTrust.TokenLifetime -gt 0 -and $ADFSRelyingPartyTrust.TokenLifetime -lt 10)
    {
        $TestResult.Result = [ResultType]::Fail
        $TestResult.Message = "TokenLifetime is set to less than 10 minutes"
        
    }
    else
    {
        $TestResult.Message = "TokenLifetime is set to a supported value."
    }

    $TestResult.Details.Add("TokenLifetime", $ADFSRelyingPartyTrust.TokenLifetime)

    Return $TestResult
}

###########################################
# Orchestrating functions
###########################################

Function Invoke-TestFunctions([array]$functionsToRun, $ADFSRelyingPartyTrust)
{
    $RPStopWatch = [System.Diagnostics.Stopwatch]::StartNew()
    $results = @()
    $totalFunctions = $functionsToRun.Count
    $functionCount = 0
    foreach($function in $functionsToRun)
    {
        $FunctionStopWatch = [System.Diagnostics.Stopwatch]::StartNew()
        $StartTime = (Get-Date).Millisecond
        $functionCount++
        $percent = 100 * $functionCount / $totalFunctions
        #Write-Progress -Activity "Executing Tests" -Status $function -PercentComplete $percent -Id 10 -ParentId 1
        $ScriptString = "param(`$ADFSRP) $function -ADFSRelyingPartyTrust `$ADFSRP"
        $functionScriptBlock = [ScriptBlock]::Create($ScriptString)        
        $result = Invoke-Command -NoNewScope -ScriptBlock $functionScriptBlock  -ArgumentList ($ADFSRelyingPartyTrust)
        $result.TestName = $function
        $result.ADFSObjectType = "Relying Party"
        $result.ADFSObjectIdentifier = $ADFSRelyingPartyTrust.Name
        $results = $results + $result
        $FunctionStopWatch.Stop()
        #Write-Debug "$function`: $($FunctionStopWatch.Elapsed.TotalMilliseconds) milliseconds to run"
    }
    $RPStopWatch.Stop()
    Write-Debug "-------------$($ADFSRelyingPartyTrust.Name)`: $($RPStopWatch.Elapsed.TotalMilliseconds) milliseconds to run"

    return $results
}

Function Test-ADFSRPTrustAADMigration
{
    [CmdletBinding()]
    param
    (    
        [Parameter(Mandatory=$true)]
        $ADFSRelyingPartyTrust
    )
    
    $functionsToRun =  @( `
	    "Test-ADFSRPAdditionalAuthenticationRules",
        "Test-ADFSRPAdditionalWSFedEndpoint",
        "Test-ADFSRPAllowedAuthenticationClassReferences",
        "Test-ADFSRPAlwaysRequireAuthentication",
        "Test-ADFSRPAutoUpdateEnabled",
        "Test-ADFSRPClaimsProviderName",
        "Test-ADFSRPDelegationAuthorizationRules",
        "Test-ADFSRPEncryptClaims",
        "Test-ADFSRPImpersonationAuthorizationRules",
        "Test-ADFSRPIssuanceAuthorizationRules",
        "Test-ADFSRPIssuanceTransformRules",
        "Test-ADFSRPMonitoringEnabled",
        "Test-ADFSRPNotBeforeSkew",
        "Test-ADFSRPRequestMFAFromClaimsProviders",
        "Test-ADFSRPSignedSamlRequestsRequired",
        "Test-ADFSRPTokenLifetime"
    );


    Return Invoke-TestFunctions -FunctionsToRun $functionsToRun -ADFSRelyingPartyTrust $ADFSRelyingPartyTrust
}

Function Test-ADFSConfigClaimRules
{
    [CmdletBinding()]
    param
    (    
        [Parameter(Mandatory=$true)]
        $ADFSConfigFilesPath,
        [Parameter(Mandatory=$true)]
        [System.Collections.Hashtable]
        $ReportMetadata
    )

    $fileEntries = [IO.Directory]::GetFiles("$ADFSConfigFilesPath\apps");
    $totalFiles = $fileEntries.Count
    $rpCount = 0
    foreach($fileName in $fileEntries) 
    {
        $rpCount++
        $percent = 100 * $rpCount / $totalFiles
        #Write-Progress -Activity "Analyzing Relying Parties" -Status $fileName -PercentComplete $percent -Id 1
        #Write-Debug $fileName
        $ADFSRelyingPartyTrust = Import-clixml $fileName
        
        $Results = @() 
        $Results += Invoke-ADFSClaimRuleAnalysis -ADFSRuleSet $ADFSRelyingPartyTrust.AdditionalAuthenticationRules -KnownRules $MFAMigratableRules -RuleSetName "AdditionalAuthenticationRules"
        $Results += Invoke-ADFSClaimRuleAnalysis -ADFSRuleSet $ADFSRelyingPartyTrust.DelegationAuthorizationRules -KnownRules $DelegationMigratableRules -RuleSetName "DelegationAuthorizationRules"
        $Results += Invoke-ADFSClaimRuleAnalysis -ADFSRuleSet $ADFSRelyingPartyTrust.ImpersonationAuthorizationRules -KnownRules $ImpersonationMigratableRules -RuleSetName "ImpersonationAuthorizationRules"
        $Results += Invoke-ADFSClaimRuleAnalysis -ADFSRuleSet $ADFSRelyingPartyTrust.IssuanceAuthorizationRules -KnownRules $IssuanceAuthorizationMigratableRules -RuleSetName "IssuanceAuthorizationRules"
        $Results += Invoke-ADFSClaimRuleAnalysis -ADFSRuleSet $ADFSRelyingPartyTrust.IssuanceTransformRules -KnownRules $IssuanceTransformMigratableRules -RuleSetName "IssuanceTransformRules"

        foreach($result in $Results)
        {
            $result | Add-Member -MemberType NoteProperty -Name "RP Name" -Value $ADFSRelyingPartyTrust.Name
            if ($ReportMetadata -ne $null)
            {
                foreach ($metadataKey in $ReportMetadata.Keys)
                {
                    $value = $ReportMetadata[$metadataKey]
                    $result | Add-Member -MemberType NoteProperty -Name $metadataKey -Value $value
                }
            }
            Write-Output $result
        }        
    }
}

Function Test-ADFSConfigAADMigration
{
    [CmdletBinding()]
    param
    (    
        [Parameter(Mandatory=$true)]
        $ADFSConfigFilesPath,
        [Switch]
        $AggregateResults
    )

    $fileEntries = [IO.Directory]::GetFiles("$ADFSConfigFilesPath\apps");
    $totalFiles = $fileEntries.Count
    $rpCount = 0
    foreach($fileName in $fileEntries) 
    {
        $rpCount++
        $percent = 100 * $rpCount / $totalFiles
        #Write-Progress -Activity "Analyzing Relying Parties" -Status $fileName -PercentComplete $percent -Id 1
        $ADFSRPTrust = Import-clixml $fileName
        $rpTestResults  = Test-ADFSRPTrustAADMigration -ADFSRelyingPartyTrust $ADFSRPTrust

        #now, assemble the result
        $reportRow = New-Object -TypeName PSObject
        $reportRow | Add-Member -MemberType NoteProperty -Name "RP Name" -Value $ADFSRPTrust.Name
        $reportRow | Add-Member -MemberType NoteProperty -Name "Result" -Value Pass

        $aggregateMessage = ""
        $aggregateDetail = ""
        $aggregateNotPassTests = ""
        

        foreach($rpTestResult in $rpTestResults)
        {
            if ($AggregateResults)
            {
                $reportRow | Add-Member -MemberType NoteProperty -Name $rpTestResult.TestName -Value $rpTestResult.Result

                if ($rpTestResult.Result -eq [ResultType]::Fail)
                {
                    $reportRow.Result = [ResultType]::Fail
                    $aggregateNotPassTests += $rpTestResult.TestName + "(Fail);" 
                }

                if ($rpTestResult.Result -eq [ResultType]::Warning -and $reportRow.Result -ne [ResultType]::Fail)
                {
                    $reportRow.Result = [ResultType]::Warning
                    $aggregateNotPassTests += $rpTestResult.TestName + "(Warning);"
                }

                

                if (-Not [String]::IsNullOrWhiteSpace( $rpTestResult.Message))
                {
                    $aggregateMessage += $rpTestResult.TestName + "::" + $rpTestResult.Message.replace("`r``n",",") + "||"              
                }
            
                foreach($detailKey in $rpTestResult.Details.Keys)
                {
                    if (-Not [String]::IsNullOrWhiteSpace($rpTestResult.Details[$detailKey]))
                    {
                        $aggregateDetail += $rpTestResult.TestName + "::" + $detailKey + "->" +  $rpTestResult.Details[ $detailKey].ToString().replace("`r`n",",") + "||"
                    }
                }
            }
            else
            {
                Write-Output $rpTestResult
            }
        }

        $reportRow | Add-Member -MemberType NoteProperty -Name "Message" -Value $aggregateMessage
        $reportRow | Add-Member -MemberType NoteProperty -Name "Details" -Value $aggregateDetail
        $reportRow | Add-Member -MemberType NoteProperty -Name "NotPassedTests" -Value $aggregateNotPassTests

        if ($AggregateResults)
        {
            Write-Output $reportRow
        }      
    }
}

Export-ModuleMember Export-ADFSConfiguration
Export-ModuleMember Test-ADFSConfigAADMigration
Export-ModuleMember Test-ADFSConfigClaimRules