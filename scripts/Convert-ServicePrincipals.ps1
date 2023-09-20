# MIT License

# Copyright (c) 2023 DevOps Shield

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

param (
    [Parameter(mandatory = $true)]
    [string] $WorkspaceName,
    [Parameter(mandatory = $true)]
    [string] $ResourceGroupName,
    [Parameter(mandatory = $true)]
    [string] $subscriptionIdOrName,
    [string] $queryFile = '../queries/service-connections.kql',
    [string] $serviceConnectionCsvPath = "../data/export_data_kql.csv",
    [int]    $jsonDepth = 100,
    [bool]   $isProductionRun = $false,
    [string] $apiVersion = "6.0-preview.4",
    [bool]   $skipPauseAfterError = $false,
    [bool]   $skipPauseAfterWarning = $false
)

# # sample production call
# ./Convert-ServicePrincipals.ps1 -WorkspaceName 'log-devopsshield-ek010devfd63l2gacbtca' `
#     -ResourceGroupName  'rg-devopsshieldek010dev' `
#     -subscriptionIdOrName "Microsoft Azure Sponsorship" `
#     -isProductionRun $true `
#     -skipPauseAfterError $false `
#     -skipPauseAfterWarning $false

# STEP 1
Write-Host 'Step 1: Login to your Azure account using Connect-AzAccount (use an account that has access to your DevOps Shield application) ...'

#Disconnect-AzAccount
Clear-AzContext -Force

$login = Connect-AzAccount

if (!$login) {
    Write-Error 'Error logging in and validating your credentials.'
    return;
}

Write-Host "setting subscription to `"$subscriptionIdOrName`""
Set-AzContext -Subscription $subscriptionIdOrName

$totalNumberOfArmServiceConnections = 0
$numberOfArmServiceConnectionsWithWorkloadIdentityFederationAutomatic = 0
$numberOfArmServiceConnectionsWithWorkloadIdentityFederationManual = 0
$numberOfArmServiceConnectionsWithServicePrincipalAutomatic = 0
$numberOfArmServiceConnectionsWithServicePrincipalManual = 0
$numberOfArmServiceConnectionsWithManagedIdentity = 0
$numberOfArmServiceConnectionsWithPublishProfile = 0

$numberOfFederatedCredentialsCreatedManually = 0
$numberOfSharedArmServiceConnections = 0

$totalNumberOfArmServiceConnectionWithServicePrincipalConvertedToWorkloadIdentityFederation = 0

$totalNumberOfArmServiceConnectionWithServicePrincipalThatDidNotConvertToWorkloadIdentityFederation = 0

function Get-AzureDevOpsOrganizationOverview {
    <#
    .SYNOPSIS
    Function for getting the list of all Azure DevOps organizations in your AzureAD tenant.

    .DESCRIPTION
    Function for getting the list of all Azure DevOps organizations that uses your AzureAD directory.
    It is the same data as the downloaded csv from https://dev.azure.com/<organizationName>/_settings/organizationAad.    

    .PARAMETER tenantId
    Your Azure AD tenant ID.

    .EXAMPLE
    Get-AzureDevOpsOrganizationOverview -tenantId <YOUR-AZURE-AD-TENANT-ID>

    Returns all DevOps organizations in your Azure tenant.

    .NOTES
    This will convert the downloaded csv data and save it to a json file.
    #>

    [CmdletBinding()]
    param (
        [string] $tenantId
    )

    #Disconnect-AzAccount
    Clear-AzContext -Force

    $login = Connect-AzAccount -Tenant $tenantId

    if (!$login) {
        Write-Error 'Error logging in and validating your credentials.'
        return;
    }

    $adoResourceId = "499b84ac-1321-427f-aa17-267ca6975798" # Azure DevOps app ID

    $msalToken = (Get-AzAccessToken -ResourceUrl $adoResourceId).Token 

    if (!$tenantId) {
        $tenantId = $msalToken.tenantId
        Write-Verbose "Set TenantId to $tenantId (retrieved from MSAL token)"
    }

    # URL retrieved thanks to developer mod at page https://dev.azure.com/<organizationName>/_settings/organizationAad
    $response = Invoke-WebRequest -Uri "https://aexprodweu1.vsaex.visualstudio.com/_apis/EnterpriseCatalog/Organizations?tenantId=$tenantId" `
        -Method get -ContentType "application/json" `
        -Headers @{Authorization = ("Bearer {0}" -f $msalToken) } | Select-Object -ExpandProperty content | ConvertFrom-Csv

    $responseJson = $response | ConvertTo-Json -Depth $jsonDepth

    $outputFile = "organizations_${tenantId}.json"
    Set-Content -Value $responseJson -Path $outputFile
}
function Get-OrganizationId {
    param (
        [string] $organizationName,
        [string] $tenantId
    )
    $outputFile = "organizations_${tenantId}.json"
    $exists = Test-Path -Path $outputFile -PathType Leaf
    if (-not $exists) {
        Write-Host "File $outputFile not found..."
        Get-AzureDevOpsOrganizationOverview -tenantId $tenantId
    }
    $allOrganizationsJson = Get-Content -Path $outputFile 
    $allOrganizations = $allOrganizationsJson | ConvertFrom-Json

    $organizationFound = $allOrganizations | Where-Object { $_."Organization Name" -eq $organizationName }
    
    if ($organizationFound) {
        Write-Host $organizationFound
        $organizationId = $organizationFound[0]."Organization Id"
        Write-Host "Organization $organizationName has id ${organizationId}"
        return $organizationId
    }
    else {
        Write-Warning "did not find org $organizationName in tenant $tenantId"
        return ""
    }
}

function Get-ServiceConnections {
    param (
        [string] $WorkspaceName, # = 'log-devopsshield-ek010devfd63l2gacbtca',
        [string] $ResourceGroupName, # = 'rg-devopsshieldek010dev',
        [string] $queryFile = '../queries/service-connections.kql',
        [string] $serviceConnectionCsvPath = '../data/export_data_kql.csv'
    )
    $exported = $false

    $query = Get-Content -Raw $queryFile
    $query = $query.Replace('\n', ' ').Replace('\r', ' ')
    Write-Host "The following Kusto Query will be used to fetch service connections:"
    Write-Host $query
    $Workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName `
        -Name $WorkspaceName
    $QueryResults = Invoke-AzOperationalInsightsQuery -Workspace $Workspace `
        -Query $query
    $QueryResults.Results | export-csv -Delimiter "," `
        -Path $serviceConnectionCsvPath #-NoTypeInformation

    $exported = $true

    return $exported
}

function New-FederatedCredential {
    param (
        [Parameter(mandatory = $true)]
        [string] $organizationName,
        [Parameter(mandatory = $true)]
        [string] $projectName,
        [Parameter(mandatory = $true)]
        [string] $serviceConnectionName,
        [Parameter(mandatory = $true)]
        [string] $appObjectId,
        [Parameter(mandatory = $true)]
        [string] $endpointId,
        [Parameter(mandatory = $true)]
        [string] $organizationId
    )
    $minifiedString = Get-Content .\credential.template.json | Out-String    
    $parametersJsonContent = (ConvertFrom-Json $minifiedString) | ConvertTo-Json -Depth 100 -Compress; #for PowerShell 7.3

    #$issuer = "https://vstoken.dev.azure.com/${organizationId}"
    $parametersJsonContent = $parametersJsonContent.Replace("__ENDPOINT_ID__", $endpointId)
    $parametersJsonContent = $parametersJsonContent.Replace("__ORGANIZATION_NAME__", $organizationName)
    $parametersJsonContent = $parametersJsonContent.Replace("__PROJECT_NAME__", $projectName)
    $parametersJsonContent = $parametersJsonContent.Replace("__SERVICE_CONNECTION_NAME__", $serviceConnectionName)
    $parametersJsonContent = $parametersJsonContent.Replace("__ORGANIZATION_ID__", $organizationId)

    Set-Content -Value $parametersJsonContent -Path .\credential.json

    $responseJson = az ad app federated-credential create --id $appObjectId --parameters credential.json

    return $responseJson
}

function PauseOn {
    param (
        [bool] $boolValue
    )
    if ($boolValue) {
        Write-Host -NoNewLine 'Press any key to continue...';
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
        Write-Host  
    }
}
function ConvertTo-WorkloadIdentityFederation {
    param (
        [string] $body,
        [string] $patTokenBase64,
        [string] $organizationName,
        [string] $endpointId
    )
    
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Authorization", "Basic $patTokenBase64")    

    Try {
        # undocumented REST API call that is in preview
        $uri = "https://dev.azure.com/${organizationName}/_apis/serviceendpoint/endpoints/${endpointId}?operation=ConvertAuthenticationScheme&api-version=${apiVersion}"
        Write-Host "Trying url:"
        Write-Host $uri
        Write-Host
    
        $response = Invoke-RestMethod $uri -Method 'PUT' -Headers $headers -Body $body

        if ($response -is [string]) {
            if ($response.Contains("Azure DevOps Services | Sign In")) {
                Write-Warning "need to sign in - ensure it's the right tenant"
                PauseOn -boolValue (-not $skipPauseAfterError)
                return ""
            }
        }

        $responseJson = $response | ConvertTo-Json -Depth $jsonDepth        
    }
    Catch {
        if ($_.ErrorDetails.Message) {
            $errorMessage = $_.ErrorDetails.Message
            Write-Error $errorMessage
            
            #{"$id":"1","innerException":null,"message":"Converting endpoint type azurerm scheme from WorkloadIdentityFederation to WorkloadIdentityFederation is neither an upgrade or a downgrade and is not supported.","typeName":"System.ArgumentException, mscorlib","typeKey":"ArgumentException","errorCode":0,"eventId":0}
            if ($errorMessage.Contains("is neither an upgrade or a downgrade and is not supported")) {                
                PauseOn -boolValue (-not $skipPauseAfterError)
                return ""
            }
            elseif ($errorMessage.Contains("Azure Stack environment")) {
                #{"$id":"1","innerException":null,"message":"Unable to connect to the Azure Stack environment. Ignore the failure if the source is Azure DevOps.","typeName":"Microsoft.VisualStudio.Services.ServiceEndpoints.WebApi.ServiceEndpointException, Microsoft.VisualStudio.Services.ServiceEndpoints.WebApi","typeKey":"ServiceEndpointException","errorCode":0,"eventId":3000}
                PauseOn -boolValue (-not $skipPauseAfterError)
                return ""
            }
            else {
                throw "unhandled exception (unexpected exception)" # you may find more errors depending on your environment
            }
        }
        else {
            Write-Host $_
            throw "should NOT happen" # if it does - ensure you handle it appropriately
        }
    }

    return $responseJson
}

function Get-Body {
    param (
        [string] $id,
        [string] $type,
        [string] $authorizationScheme,
        [object] $serviceEndpointProjectReferences
    )
           
    $myBody = [PSCustomObject]@{
        id                               = $id
        type                             = $type
        authorization                    = [PSCustomObject]@{
            scheme = $authorizationScheme
        }
        serviceEndpointProjectReferences = @( $serviceEndpointProjectReferences ) # array
    }
    $myBodyJson = $myBody | ConvertTo-Json -Depth $jsonDepth

    return $myBodyJson
}

function Get-Base64 {
    param (
        [string] $MyPat
    )
    #Convert To Base64   
    $B64Pat = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("`:$MyPat"))
    return $B64Pat
}

function Get-PatTokenBase64 {
    param (
        [string] $tenantId
    )
    #Expecting an environment variable such as ADO-PAT-TOKEN-TENANT-a34*****-****-****-****-************
    
    Write-Host "ADO PAT is not set. Trying to get it from environment..."
    $AdoPAT = [Environment]::GetEnvironmentVariable("ADO-PAT-TOKEN-TENANT-$tenantId", "User")    

    $AdoPATBase64 = Get-Base64 -MyPat $AdoPAT
   
    return $AdoPATBase64
}

try {
    # STEP 2
    Write-Host "Step 2: Get Service Connections from Log Analytics Workspace $WorkspaceName and export to CSV $serviceConnectionCsvPath ..."
    $exported = Get-ServiceConnections -WorkspaceName $WorkspaceName `
        -ResourceGroupName $ResourceGroupName `
        -queryFile $queryFile `
        -serviceConnectionCsvPath $serviceConnectionCsvPath
}
catch {
    throw
}

if ($exported) {
    Write-Host 'Step 3: Loop through all service connections ...'

    Write-Host 'Login to your Azure account using az login (use an account that has access to your Microsoft Entra ID) ...'

    az account clear

    $login = az login --only-show-errors

    if (!$login) {
        Write-Error 'Error logging in and validating your credentials.'
        return;
    }

    $accountJson = az account show
    $account = $accountJson | ConvertFrom-Json
    $currentTenantId = $($account.tenantId)
    Write-Host "Current Tenant ID: $currentTenantId"

    $csv = Import-Csv -path $serviceConnectionCsvPath
    foreach ($line in $csv) {
        $properties = $line | Get-Member -MemberType Properties
        $lineContainsArmServiceConnection = $false
        for ($i = 0; $i -lt $properties.Count; $i++) {
            $column = $properties[$i]
            $columnValue = $line | Select-Object -ExpandProperty $column.Name

            if ($column.Name -eq 'spnObjectId' -and $columnValue) {
                $spObjId = $columnValue
                $lineContainsArmServiceConnection = $true
            }
            if ($column.Name -eq 'appObjectId' -and $columnValue) {
                $appObjId = $columnValue
                $lineContainsArmServiceConnection = $true
            }
            if ($column.Name -eq 'Data_s' -and $columnValue) {
                $dataJson = $columnValue
                $dataObj = $dataJson | ConvertFrom-Json
            }
            if ($column.Name -eq 'Organization' -and $columnValue) {
                $organizationName = $columnValue
            }
            if ($column.Name -eq 'Project' -and $columnValue) {
                $projectName = $columnValue
            }
            if ($column.Name -eq 'Name' -and $columnValue) {
                $serviceConnectionName = $columnValue
            }
            if ($column.Name -eq 'EndpointId' -and $columnValue) {
                $endpointId = $columnValue
            }
            if ($column.Name -eq 'authorizationScheme' -and $columnValue) {
                $authorizationScheme = $columnValue
            }
            if ($column.Name -eq 'workloadIdentityFederationIssuer' -and $columnValue) {
                $workloadIdentityFederationIssuer = $columnValue
            }
            if ($column.Name -eq 'workloadIdentityFederationSubject' -and $columnValue) {
                $workloadIdentityFederationSubject = $columnValue
            }
            if ($column.Name -eq 'revertSchemeDeadline' -and $columnValue) {
                $revertSchemeDeadline = $columnValue
            }          
            if ($column.Name -eq 'creationMode' -and $columnValue) {
                $creationMode = $columnValue
            }
            if ($column.Name -eq 'AuthenticationMethod' -and $columnValue) {
                $AuthenticationMethod = $columnValue
            }
        }

        $totalNumberOfArmServiceConnections++

        Write-Host "-----------------------"

        $applicationRegistrationClientId = $($dataObj.authorization.parameters.serviceprincipalid)
        Write-Host "App Registration Client Id   : $applicationRegistrationClientId"

        $tenantId = $($dataObj.authorization.parameters.tenantid)
        Write-Host "Tenant ID                    : $tenantId"
        Write-Host "Current AAD Tenant is        : $currentTenantId"
        Write-Host "Service Connection Tenant    : $tenantId"
        $tenantsMatch = $tenantId -eq $currentTenantId
        Write-Host "Tenants Match                : $tenantsMatch"

        Write-Host "Authorization Scheme         : $authorizationScheme"

        Write-Host "Organization                 : $organizationName"
        Write-Host "Project                      : $projectName"
        Write-Host "Endpoint ID                  : $endpointId"
        
        if ($creationMode -eq "Automatic") {
            $foregroundColor = "Green"
        }
        elseif ($creationMode -eq "Manual") {
            $foregroundColor = "Yellow"
        }
        elseif ($creationMode -eq "") {
            $foregroundColor = "Red"
            $creationMode = "<EMPTY>"
            PauseOn -boolValue (-not $skipPauseAfterError)
        }
        else {
            throw "Unexpected creation mode $creationMode"
        }
        Write-Host "Creation Mode                : " -NoNewline
        Write-Host "$creationMode" -ForegroundColor $foregroundColor

        Write-Host "Authentication Method        : $AuthenticationMethod"

        if ($AuthenticationMethod -eq "Workload Identity Federation (Automatic)") {
            $numberOfArmServiceConnectionsWithWorkloadIdentityFederationAutomatic++
        }
        elseif ($AuthenticationMethod -eq "Workload Identity Federation (Manual)") {
            $numberOfArmServiceConnectionsWithWorkloadIdentityFederationManual++
        }
        elseif ($AuthenticationMethod -eq "Service Principal (Automatic)") {
            $numberOfArmServiceConnectionsWithServicePrincipalAutomatic++
        }
        elseif ($AuthenticationMethod -eq "Service Principal (Manual)") {
            $numberOfArmServiceConnectionsWithServicePrincipalManual++
        }
        elseif ($AuthenticationMethod -eq "Managed Identity") {
            $numberOfArmServiceConnectionsWithManagedIdentity++
        }
        elseif ($AuthenticationMethod -eq "Publish Profile") {
            $numberOfArmServiceConnectionsWithPublishProfile++
        }
        else {
            throw "Unexpected authentication mode $AuthenticationMode"
        }

        $isShared = $($dataObj.isShared)
        Write-Host "Is Shared                    : $isShared"
        if ($isShared) {
            Write-Warning "connection is shared!"
            $numberOfSharedArmServiceConnections++
            PauseOn -boolValue (-not $skipPauseAfterWarning)
        }

        Write-Host "Body                         :"
        $serviceEndpointProjectReferences = $($dataObj.serviceEndpointProjectReferences)
        Write-Host $serviceEndpointProjectReferences
        $serviceEndpointProjectReferencesJson = $serviceEndpointProjectReferences | ConvertTo-Json
        Write-Host $serviceEndpointProjectReferencesJson

        $refCount = $serviceEndpointProjectReferences.Length
        Write-Host "Number of Project Refs       : $refCount"
        if ($refCount -eq 1) {
            # Write-Host "expected"
        }
        else {
            Write-Warning "Shared Service Connections are discouraged. This one is shared with $refCount projects."
            PauseOn -boolValue (-not $skipPauseAfterWarning)
        }

        $id = $($dataObj.id)
        $type = $($dataObj.type)
        $myBodyJson = Get-Body -id $id `
            -type $type `
            -authorizationScheme $authorizationScheme `
            -serviceEndpointProjectReferences $serviceEndpointProjectReferences
        Write-Host $myBodyJson

        if ($authorizationScheme -eq "WorkloadIdentityFederation") {
            Write-Host "Found workload identity service connection - will NOT convert"            
        }

        if ($authorizationScheme -eq "ServicePrincipal") {            
            Write-Host "Found Service Principal - analyzing if it's a candidate to convert"            
            if ($isProductionRun -and $tenantsMatch) {
                $patTokenBase64 = Get-PatTokenBase64 -tenantId $tenantId   
                $myNewBodyJson = Get-Body -id $id `
                    -type $type `
                    -authorizationScheme "WorkloadIdentityFederation" `
                    -serviceEndpointProjectReferences $serviceEndpointProjectReferences         

                if ($creationMode -eq "Manual") {
                    Write-Host "Need to create fed cred for Manual Svc Conn"
                    $organizationId = Get-OrganizationId -tenantId $tenantId `
                        -organizationName $organizationName

                    if ($organizationId) {
                        $existingFedCredsJson = az ad app federated-credential list --id  $applicationRegistrationClientId 
                        $existingFedCreds = $existingFedCredsJson | ConvertFrom-Json
                        $subject = "sc://$organizationName/$projectName/$serviceConnectionName"
                        $matchingCred = $existingFedCreds | Where-Object { $_.Subject -eq $subject }
                        if ($matchingCred) {
                            Write-Host "cred with subject $subject ALREADY exists!"
                            Write-Host $matchingCred 
                        }
                        else {
                            Write-Warning "cred with subject $subject does not exist! Creating it now..."               

                            $responseJson = New-FederatedCredential -organizationName $organizationName `
                                -projectName $projectName `
                                -organizationId $organizationId `
                                -serviceConnectionName $serviceConnectionName `
                                -endpointId $endpointId `
                                -appObjectId $applicationRegistrationClientId
                            
                            if ($responseJson) {
                                $numberOfFederatedCredentialsCreatedManually++
                            }

                            PauseOn -boolValue (-not $skipPauseAfterError)
                        }
                        
                    }
                    else {
                        Write-Warning "Skipping creation of fed cred since we did not find org id in tenant"
                    }
                }
                $responseJson = ConvertTo-WorkloadIdentityFederation -body $myNewBodyJson `
                    -organizationName $organizationName `
                    -endpointId $endpointId `
                    -patTokenBase64 $patTokenBase64
                if ($responseJson) {
                    Write-Host "Call was successful and returned JSON response:"
                    Write-Host $responseJson
                    Write-Host "Converted service connection!"
                    $totalNumberOfArmServiceConnectionWithServicePrincipalConvertedToWorkloadIdentityFederation++
                    PauseOn -boolValue (-not $skipPauseAfterError)
                }
                else {
                    Write-Warning "Got empty response (check above for message) so moving on..."
                    $totalNumberOfArmServiceConnectionWithServicePrincipalThatDidNotConvertToWorkloadIdentityFederation++
                }
            }
            else {
                if (-not $isProductionRun) {
                    Write-Host "Skipping conversion since not a production run"
                }
                else {
                    Write-Host "tenants do NOT match so skipping conversion"
                }
            }
        }

        Write-Host "-----------------------"

        Write-Host
        Write-Host "ARM SC with Workload Identity Federation (Automatic)                     : $numberOfArmServiceConnectionsWithWorkloadIdentityFederationAutomatic"
        Write-Host "ARM SC with Workload Identity Federation (Manual)                        : $numberOfArmServiceConnectionsWithWorkloadIdentityFederationManual"
        Write-Host "ARM SC with Service Principal (Automatic)                                : $numberOfArmServiceConnectionsWithServicePrincipalAutomatic"
        Write-Host "ARM SC with Service Principal (Manual)                                   : $numberOfArmServiceConnectionsWithServicePrincipalManual"
        Write-Host "ARM SC with Managed Identity                                             : $numberOfArmServiceConnectionsWithManagedIdentity"
        Write-Host "ARM SC with Publish Profile                                              : $numberOfArmServiceConnectionsWithPublishProfile"
        Write-Host
        Write-Host "Total Number of Arm Service Connections                                  : $totalNumberOfArmServiceConnections"
        Write-Host
        Write-Host "Total Number of Arm Service Connections Converted                        : $totalNumberOfArmServiceConnectionWithServicePrincipalConvertedToWorkloadIdentityFederation"
        Write-Host "Total Number of Arm Service Connections That did NOT Convert             : $totalNumberOfArmServiceConnectionWithServicePrincipalThatDidNotConvertToWorkloadIdentityFederation"
        Write-Host
        Write-Host "Number Of Federated Credentials Created Manually                         : $numberOfFederatedCredentialsCreatedManually"
        Write-Host "Number Of Shared Arm Service Connections                                 : $numberOfSharedArmServiceConnections"
    }
}