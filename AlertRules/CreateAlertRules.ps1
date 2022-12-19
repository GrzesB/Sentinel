<#
    .SYNOPSIS
    Creates analytics rules for Microsoft Sentinel.

    .DESCRIPTION
    Creates analytics rules for Microsoft Sentinel based on the templates. Templates that were not used to create analytics rules are 
    presented using Out-GridView. Out-GridView allows sorting and filtering the list - selected items are used to create active analytics rules.

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
    CreateAlertRules.ps1 -ResourceGroupName sentinelrg -WorkspaceName sentinel-la 

    Connects to "sentinel-la" Log Analytics workspace on "sentinelrg" resource group.

    .EXAMPLE
    CreateAlertRules.ps1 -ResourceGroupName sentinelrg -WorkspaceName sentinel-la -SubscriptionName "Visual Studio"

    Connects to "sentinel-la" Log Analytics workspace on "sentinelrg" resource group. Subscription context is changed to subscription named "Visual Studio".

    .EXAMPLE
    CreateAlertRules.ps1 -ResourceGroupName sentinelrg -WorkspaceName sentinel-la -SkipAuthentication

    Connects to "sentinel-la" Log Analytics workspace on "sentinelrg" resource group. 
    Authentication process is skipped (assumes authentication was already done, otherwise script will fail).
#>

# version 2022-10-14
# Script is distributed under MIT License - https://github.com/GrzesB/Sentinel/blob/master/AlertRules/LICENSE


[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)] [string] $ResourceGroupName,
    [Parameter(Mandatory=$true)] [string] $WorkspaceName,
    [Parameter(Mandatory=$false)] [string] $SubscriptionName,
    [Parameter(Mandatory=$false)] [switch] $SkipAuthentication
)


#region Helper Functions
function Get-SentinelAlertRuleTemplate
{
    param(
    [Parameter(Mandatory=$true)] [string] $ResourceGroupName,
    [Parameter(Mandatory=$true)] [string] $WorkspaceName
    )

    $URL = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/alertRuleTemplates?api-version=$apiVersion"
    $response = Invoke-WebRequest -Method Get -Headers $authHeader -Uri $url
    $values = (ConvertFrom-Json $response.Content).value
    foreach ($template in $values)
    {
        $template
        $rule = [PSCustomObject]@{
            displayName = $template.properties.displayName
            version = $template.properties.version
            alertRuleTemplateName = $template.name
            name = $template.Name
            kind = $template.kind
            properties = $template.properties
            alertRulesCreatedByTemplateCount = $template.properties.alertRulesCreatedByTemplateCount
        }

        foreach ($property in $template.properties.PSObject.properties)
        {
            if ($property.Name -eq "requiredDataConnectors")
            {
                $rule | Add-Member -NotePropertyName "RequiredTables" -NotePropertyValue $property.Value.dataTypes
                $rule | Add-Member -NotePropertyName "RequiredDataConnectors" -NotePropertyValue $property.Value.connectorId -Force
            }
            elseif ($property.Name -eq "Description") {
                $rule | Add-Member -NotePropertyName "Description" -NotePropertyValue $property.Value
            }
            elseif ($property.Name -eq "Severity") {
                $rule | Add-Member -NotePropertyName "Severity" -NotePropertyValue $property.Value
            }
        }

        $rule
    }
}

function Create-SentinelAlertRule
{
    param(
    [Parameter(Mandatory=$true)] [string] $ResourceGroupName,
    [Parameter(Mandatory=$true)] [string] $WorkspaceName,
    [Parameter(Mandatory=$true)] [string] $Guid,
    [Parameter(Mandatory=$true)] [string] $Json
    )

    $URL = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/alertRules/$guid/?api-version=$($apiVersion)"
    $contentType = "application/json"
    try 
    {
        $response = Invoke-WebRequest -Method Put -Headers $authHeader -Uri $url -ContentType $contentType -Body $json
        $resCode = $response.StatusCode
        $resMsg = $response.StatusDescription
    }
    catch 
    {
        $resMsg = $_.Exception.Message + "`nPlease verify the analytics rule with portal wizard."
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
        Where-Object {$_.Kind -eq "Scheduled" -and $_.AlertRulesCreatedByTemplateCount -eq 0}
}
catch
{
    Write-Host "Error reading template rules list:`n`t$($_.Exception.Message)`n" -ForegroundColor Red
    exit 1
}


$selectedRules = $templates | Select-Object DisplayName, RequiredDataConnectors, RequiredTables, Description, Severity, Name | 
    Sort-Object Severity, DisplayName | Out-GridView -PassThru -Title "Select rules to be created"

$ruleCount = 0
foreach ($rule in $selectedRules)
{
    $guid = (New-Guid).Guid
    $template = $templates | Where-Object {$_.name -eq $rule.name}
    $ruleCount++
    $template.properties | Add-Member -MemberType NoteProperty -Name "alertRuleTemplateName" -Value $template.alertRuleTemplateName -ErrorAction Stop
    $template.properties | Add-Member -MemberType NoteProperty -Name "enabled" -Value $true -ErrorAction Stop
    $template.properties | Add-Member -MemberType NoteProperty -Name "templateVersion" -Value $template.version -ErrorAction Stop
    $propertiesToExclude = "alertRulesCreatedByTemplateCount", "status", "version", "lastUpdatedDateUTC", "createdDateUTC", "requiredDataConnectors"
    if ($template.properties.techniques.length -eq 0)
    {
        $propertiesToExclude += "techniques"
    }
    elseif ($template.properties.techniques[0] -eq "")
    {
        $propertiesToExclude += "techniques"
    }
    if ($template.properties.sentinelEntitiesMappings.Count -eq 0)
    {
        $propertiesToExclude += "sentinelEntitiesMappings"
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
        properties = $template.properties
    }
    $RuleConfig = $body | Convertto-Json -Depth 8
    #$RuleConfig
    #exit
    $result = Create-SentinelAlertRule @sentinelConnection -Json $RuleConfig -Guid $guid
    if ($result.StatusCode -ne 201)
    {
        $ruleCount--
        Write-Host "There was an error creating rule '$($template.DisplayName)'. Error code is: $($result.StatusCode)`n`t$($result.StatusDescription)" -ForegroundColor Yellow
    }
    else 
    {
        Write-Host "Rule '$($template.DisplayName)' created succesfully." -ForegroundColor Green
    }
}
Write-Host "$ruleCount rule(s) created."
