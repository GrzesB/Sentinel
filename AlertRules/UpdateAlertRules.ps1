<#
    .SYNOPSIS
    Updates analytics rules for Microsoft Sentinel to the latest version.

    .DESCRIPTION
    Updates analytics rules for Microsoft Sentinelto the latest version offered by templates. Updated are only 'Scheduled' rules.

    .PARAMETER ResourceGroupName
    Specifies the resource group name for Microsoft Sentinel.

    .PARAMETER WorkspaceName
    Specifies the Log Analytics workspace name for Microsoft Sentinel.

    .PARAMETER SubscriptionName
    Optional parameter specifies the subscription name for Microsoft Sentinel.

    .PARAMETER SkipAuthentication
    Switch parameter that allows to skip authentication (in case PowerShell session to Azure is already authenticated).

    .PARAMETER AlertRuleDisplayName
    Optional parameter to specify rule name.

    .INPUTS
    None. You cannot pipe objects to CreateAlertRules script.

    .OUTPUTS
    None.

    .EXAMPLE
    UpdateAlertRules.ps1 -ResourceGroupName sentinelrg -WorkspaceName sentinel-la 

    Connects to "sentinel-la" Log Analytics workspace on "sentinelrg" resource group to update all alert rules.

    .EXAMPLE
    UpdateAlertRules.ps1 -ResourceGroupName sentinelrg -WorkspaceName sentinel-la -AlertRuleDisplayName "Rule XYZ"

    Connects to "sentinel-la" Log Analytics workspace on "sentinelrg" resource group to update "Rule XYZ" alert rule.

    .EXAMPLE
    UpdateAlertRules.ps1 -ResourceGroupName sentinelrg -WorkspaceName sentinel-la -SubscriptionName "Visual Studio"

    Connects to "sentinel-la" Log Analytics workspace on "sentinelrg" resource group. Subscription context is changed to subscription named "Visual Studio".

    .EXAMPLE
    UpdateAlertRules.ps1 -ResourceGroupName sentinelrg -WorkspaceName sentinel-la -SkipAuthentication

    Connects to "sentinel-la" Log Analytics workspace on "sentinelrg" resource group. 
    Authentication process is skipped (assumes authentication was already done, otherwise script will fail).
#>

# version 2022-03-07
# Script is distributed under MIT License - https://github.com/GrzesB/Sentinel/blob/master/AlertRules/LICENSE


[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)] [string] $ResourceGroupName,
    [Parameter(Mandatory=$true)] [string] $WorkspaceName,
    [Parameter(Mandatory=$false)] [string] $SubscriptionName,
    [Parameter(Mandatory=$false)] [string] $AlertRuleDisplayName,
    [Parameter(Mandatory=$false)] [switch] $SkipAuthentication
)

#region Helper functions

function Get-SentinelAlertRuleTemplate
{
    param(
    [Parameter(Mandatory=$true)] [string] $ResourceGroupName,
    [Parameter(Mandatory=$true)] [string] $WorkspaceName
    )

    $URL = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/alertRuleTemplates?api-version=$($apiVersion)"
    $response = Invoke-WebRequest -Method Get -Headers $authHeader -Uri $url
    $values = (ConvertFrom-Json $response.Content).value
    foreach ($template in $values)
    {
        $rule = [PSCustomObject]@{
            displayName = $template.properties.displayName.Trim('.')
            name = $template.Name
            kind = $template.kind
            properties = $template.properties
            alertRulesCreatedByTemplateCount = $template.properties.alertRulesCreatedByTemplateCount
            version = $template.properties.version
        }

        $rule
    }
}


function Get-SentinelAlertRule
{
    param(
    [Parameter(Mandatory=$true)] [string] $ResourceGroupName,
    [Parameter(Mandatory=$true)] [string] $WorkspaceName
    )

    $URL = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/alertRules?api-version=$($apiVersion)"
    $response = Invoke-WebRequest -Method Get -Headers $authHeader -Uri $url
    $values = (ConvertFrom-Json $response.Content).value

    foreach ($alertRule in $values)
    {
        $rule = [PSCustomObject]@{
            displayName = $alertRule.properties.displayName.Trim('.')
            templateVersion = $alertRule.properties.templateVersion
            alertRuleTemplateName = $alertRule.properties.alertRuleTemplateName
            enabled = $alertRule.properties.enabled
            name = $alertRule.name
            etag = $alertRule.etag
            kind = $alertRule.kind
        }

        $rule
    }
}

function Update-SentinelAlertRule
{
    param(
    [Parameter(Mandatory=$true)] [string] $ResourceGroupName,
    [Parameter(Mandatory=$true)] [string] $WorkspaceName,
    [Parameter(Mandatory=$true)] [string] $RuleId,
    [Parameter(Mandatory=$true)] [string] $Json
    )

    $URL = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/alertRules/$($RuleId)?api-version=$($apiVersion)"
    $contentType = "application/json"
    try 
    {
        $response = Invoke-WebRequest -Method Put -Headers $authHeader -Uri $url -ContentType $contentType -Body $json
        $resCode = $response.StatusCode
        $resMsg = $response.StatusDescription
    }
    catch 
    {
        $resMsg = $_.Exception.Message
        $resCode = $_.Exception.Response.StatusCode.value__
    }
    finally
    {
        [PSCustomObject]@{
            StatusCode = $resCode
            StatusDescription = $resMsg
        }    
    }
}
#endregion

# Main code
$apiVersion = "2021-10-01-preview"

# Check if required modules needs to be installed
if ((Get-InstalledModule Az.Accounts -ErrorAction SilentlyContinue) -eq $null)
{
    Write-Host "Az.Accounts module must be installed." -ForegroundColor Yellow
    exit 1
}

#region Authenticate to Azure
if (-not $SkipAuthentication)
{
    Connect-AzAccount | Out-Null
}

if ($SubscriptionName -ne "")
{
    Set-AzContext -Subscription $SubscriptionName
}

$context = Get-AzContext
$AzProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
$profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($AzProfile)
$token = $profileClient.AcquireAccessToken($context.Subscription.TenantId)

$authHeader = @{
    'Content-Type'  = 'application/json'
    'Authorization' = 'Bearer ' + $token.AccessToken
}

$subscriptionId = $context.Subscription
#endregion


$sentinelConnection = @{
    ResourceGroupName = $ResourceGroupName
    WorkspaceName = $WorkspaceName
}


# Get rule templates
try
{  
    $templates = Get-SentinelAlertRuleTemplate @sentinelConnection -ErrorAction Stop | `
        Where-Object {$_.kind -eq "Scheduled"}
}
catch
{
    Write-Host "Error reading template rules list:`n`t$($_.Exception.Message)`n" -ForegroundColor Red
    exit(1)
}

# Get active rules
try
{  
    $rules = Get-SentinelAlertRule @sentinelConnection | Where-Object {$_.kind -eq "Scheduled"}
}
catch
{
    Write-Host "Error reading active rules list:`n`t$($_.Exception.Message)`n" -ForegroundColor Red
    exit(1)
}
if ($AlertRuleDisplayName -ne "")
{
    $rules = $rules | Where-Object  {$_.displayName -eq $AlertRuleDisplayName}
    if ($rules.Count -eq 0)
    {
        Write-Host "Alert rule '$AlertRuleDisplayName' was not found." -ForegroundColor Red
        exit(1)
    }
}

$ruleCount = 0
foreach ($rule in $rules)
{
    if ($null -ne $rule.alertRuleTemplateName)
    {
        $template = $templates | Where-Object {$rule.alertRuleTemplateName -eq $_.name}
        if ($rule.templateVersion -ne $template.version)
        {   
            $ruleCount++
            Write-Host "Updating rule '$($rule.displayName)'..." -ForegroundColor Green
            $template.properties | Add-Member -MemberType NoteProperty -Name "alertRuleTemplateName" -Value $rule.alertRuleTemplateName -ErrorAction Stop
            $template.properties | Add-Member -MemberType NoteProperty -Name "enabled" -Value $rule.enabled -ErrorAction Stop
            $template.properties | Add-Member -MemberType NoteProperty -Name "templateVersion" -Value $template.version -ErrorAction Stop
            $propertiesToExclude = "alertRulesCreatedByTemplateCount", "status", "version", "lastUpdatedDateUTC", "createdDateUTC", "requiredDataConnectors"
            if ($template.properties.techniques.Count -eq 0)
            {
                $propertiesToExclude += "techniques"
            }    
            $template.properties = $template.properties | Select-Object * -ExcludeProperty $propertiesToExclude
            if ("suppressionEnabled" -notin $template.properties.PSObject.Properties.Name)
            {
                $template.properties | Add-Member -MemberType NoteProperty -Name "suppressionEnabled" -Value $false -ErrorAction Stop
                $template.properties | Add-Member -MemberType NoteProperty -Name "suppressionDuration" -Value $template.properties.queryFrequency -ErrorAction Stop
            }
            if ("incidentConfiguration" -notin $template.properties.PSObject.Properties.Name)
            {
                $template.properties | Add-Member -MemberType NoteProperty -Name "incidentConfiguration" -Value "" -ErrorAction Stop
            }
            if ("eventGroupingSettings" -notin $template.properties.PSObject.Properties.Name)
            {
                $template.properties | Add-Member -MemberType NoteProperty -Name "eventGroupingSettings" -Value "" -ErrorAction Stop
            }
            $body = @{
                kind = $template.kind
                etag = $rule.etag
                properties = $template.properties
            }
            $RuleId = $rule.name
            $RuleConfig = $body | Convertto-Json -Depth 8
            $result = Update-SentinelAlertRule @sentinelConnection -RuleId $RuleId -Json $RuleConfig
            if ($result.StatusCode -ne 200)
            {
                $ruleCount--
                Write-Host "There was an error updating rule. Error code is: $($result.StatusCode) - $($result.StatusDescription)" -ForegroundColor Yellow
            }
        }
        elseif ($null -eq $template) 
        {
            Write-Host "No template found for '$($rule.displayName)'." -ForegroundColor Yellow                
        }
        elseif ($rule.templateVersion -eq $template.version -and $AlertRuleDisplayName -ne "")
        {
            Write-Host "'$($rule.displayName)' - rule is up to date."              
        }
    }
}
Write-Host "$ruleCount rule(s) modified."
