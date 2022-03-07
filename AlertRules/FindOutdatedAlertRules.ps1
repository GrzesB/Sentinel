
<#
    .SYNOPSIS
    Compares alert rules for Microsoft Sentinel to the template.

    .DESCRIPTION
    Compares alert rules for Microsoft Sentinelto the version offered by templates.

    .PARAMETER ResourceGroupName
    Specifies the resource group name for Microsoft Sentinel.

    .PARAMETER WorkspaceName
    Specifies the Log Analytics workspace name for Microsoft Sentinel.

    .PARAMETER SubscriptionName
    Optional parameter specifies the subscription name for Microsoft Sentinel.

    .PARAMETER SkipAuthentication
    Switch parameter that allows to skip authentication (in case PowerShell session to Azure is already authenticated).

    .INPUTS
    None. You cannot pipe objects to CreateAlertRules script.

    .OUTPUTS
    None.

    .EXAMPLE
    FindOutdatedAlertRules.ps1 -ResourceGroupName sentinelrg -WorkspaceName sentinel-la 

    Connects to "sentinel-la" Log Analytics workspace on "sentinelrg" resource group.

    .EXAMPLE
    FindOutdatedAlertRules.ps1 -ResourceGroupName sentinelrg -WorkspaceName sentinel-la -SubscriptionName "Visual Studio"

    Connects to "sentinel-la" Log Analytics workspace on "sentinelrg" resource group. Subscription context is changed to subscription named "Visual Studio".

    .EXAMPLE
    FindOutdatedAlertRules.ps1 -ResourceGroupName sentinelrg -WorkspaceName sentinel-la -SkipAuthentication

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
    [Parameter(Mandatory=$false)] [switch] $SkipAuthentication
)

#region Helper functions

function Get-SentinelAlertRuleTemplate
{
    param(
    [Parameter(Mandatory=$true)] [string] $ResourceGroupName,
    [Parameter(Mandatory=$true)] [string] $WorkspaceName
    )

    $URL = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/alertRuleTemplates?api-version=2021-10-01"
    $response = Invoke-WebRequest -Method Get -Headers $authHeader -Uri $url
    $values = (ConvertFrom-Json $response.Content).value
    foreach ($template in $values)
    {
        $rule = [PSCustomObject]@{
            displayName = $template.properties.displayName.Trim('.')
            version = $template.properties.version
            name = $template.Name
            alertRulesCreatedByTemplateCount = $template.properties.alertRulesCreatedByTemplateCount
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

    $URL = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/alertRules?api-version=2021-10-01"
    $response = Invoke-WebRequest -Method Get -Headers $authHeader -Uri $url
    $values = (ConvertFrom-Json $response.Content).value

    foreach ($alertRule in $values)
    {
        $rule = [PSCustomObject]@{
            displayName = $alertRule.properties.displayName.Trim('.')
            templateVersion = $alertRule.properties.templateVersion
            alertRuleTemplateName = $alertRule.properties.alertRuleTemplateName
            enabled = $alertRule.properties.enabled
        }

        $rule
    }
}
#endregion

# Main code

# Check if required modules needs to be installed
if ((Get-InstalledModule Az.Accounts -ErrorAction SilentlyContinue) -eq $null)
{
    Write-Host "Az.Accounts module must be installed." -ForegroundColor Yellow
    exit 1
}

# Authenticate to Azure
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

$sentinelConnection = @{
    ResourceGroupName = $ResourceGroupName
    WorkspaceName = $WorkspaceName
}


# Get rule templates
try
{  
    $templates = Get-SentinelAlertRuleTemplate @sentinelConnection -ErrorAction Stop | `
        Where-Object {$_.alertRulesCreatedByTemplateCount -gt 0}
}
catch
{
    Write-Host "Error reading template rules list:`n`t$($_.Exception.Message)`n" -ForegroundColor Red
    exit(1)
}

try
{  
    $rules = Get-SentinelAlertRule @sentinelConnection
}
catch
{
    Write-Host "Error reading active rules list:`n`t$($_.Exception.Message)`n" -ForegroundColor Red
    exit(1)
}

$count = 0
foreach ($rule in $rules)
{
    $template = $templates | Where-Object {$_.name -eq $rule.alertRuleTemplateName}
    if ($rule.templateVersion -ne $template.version)
    {
        if ($null -eq $rule.templateVersion)
        {
            $rule.templateVersion = "Not set"
        }
        $ruleToUpdate = [PSCustomObject]@{
            displayName = $rule.displayName
            ruleVersion = $rule.templateVersion
            templateVersion = $template.version
        }
        $ruleToUpdate
        $count++
    }
}
if ($count -eq 0)
{
    Write-Host "All rules are up to date."
}