

# Local development:
# Connect-AzAccount
# Set-AzContext -Subscription "<your-subscription-id>"
# .\notify-vuln-images.ps1




function Main {

    

    ######################################################
    # Get all namespaces
    ######################################################
    Write-Host "|- Get all namespaces"
    #$namespaces = $(kubectl get ns -o jsonpath="{.items[*].metadata.name}").Split(" ") | Get-Unique
    $namespaces = "devops"



    ######################################################
    # Get all images in all namespaces
    ######################################################
    $all_images = @{}
    $namespace_to_contact_email = @{}
    $namespace_to_imageList = @{}
    $image_to_digest = @{}
    $digest_to_vulnResult = @{}

    foreach ($namespace in $namespaces) {
        Write-Host "|-|- Check Namespace '$namespace'"

            
        [string]$contact = $(kubectl get ns $namespace -o jsonpath="{.metadata.annotations.contact-email-address}")
        $namespace_to_contact_email["$namespace"] = $contact
        Write-Host "|-|-|- Contact-Email-Address for this Namespace is '$contact'"


        $namespace_to_imageList["$namespace"] = New-Object Collections.Generic.List[string]
        $images_in_this_namespace = $(kubectl get pods -n $namespace -o jsonpath="{.items[*].spec.containers[*].image}").Split(" ") | Get-Unique
        foreach ($image in $images_in_this_namespace) {
            $all_images["$image"] = {}
            $namespace_to_imageList["$namespace"].Add($image)
            Write-Host "|-|-|- Add Image '$image' to global list"
        }

    }


    # Create contact_email_to_namespaceList
    $contact_email_to_namespaceList = @{}
    foreach ($entry in $namespace_to_contact_email.GetEnumerator()) {
        if ($contact_email_to_namespaceList.ContainsKey($entry.Value)) {
            $contact_email_to_namespaceList[$entry.Value].Add($entry.Key)
        }
        else {
            $contact_email_to_namespaceList[$entry.Value] = New-Object Collections.Generic.List[string]
            $contact_email_to_namespaceList[$entry.Value].Add($entry.Key)
        }
    }

    Write-Host "|- Found all images ..."
    Write-Host "|-"
    Write-Host "|- Starting to fetch Vuln-Info from Azure Graph"



    ######################################################
    # Iterate all images and get Vuln infos
    ######################################################


    foreach ($image in $all_images.Keys) {

        
        Write-Host "|-|- Analyze Image '$image'"

        #https://regex101.com/library/eK9lPd?filterFlavors=pcre&filterFlavors=javascript&page=22
        $regexDigest = "@(sha256:[0-9A-Fa-f]{32,})"

        $digest = ""

        $resultDigest = $image -match $regexDigest
        if ($resultDigest) {
            $digest = $Matches.1
        }
        else {
            
            Write-Host "|-|-|- Find digest for image '$image'"
            
            $regexRegistryAndRepoAndTag = "^(.*?)\/(.*):(.*)$"
            $regexResultImageSplitted = $image -match $regexRegistryAndRepoAndTag
            if ($regexResultImageSplitted) {
                $registry = $Matches.1
                $repo = $Matches.2
                $tag = $Matches.3
                $digest = $(Get-DigestForTag -Registry $registry -Repo $repo -Tag $tag)
            }
            else {
                # ToDo
            }
        }

        Write-Host "|-|-|- Digest: '$digest'"
        $image_to_digest["$image"] = $digest




        $regexRegistryNameFromImage = "^(.*)\.azurecr\.io\/(.*)$"
        $regexResultRegistry = $image -match $regexRegistryNameFromImage
        $registryName = $Matches.1
        $digest_to_vulnResult["$digest"] = (Get-VulnForImage -Registry "$registryName.azurecr.io" -Digest $digest)




        ########################
        # Create Reports
        $adminReportContent = ""
        foreach ($contactEmail in $contact_email_to_namespaceList.Keys) {
            Write-Host "|-"
            $tmp = (Create-HTMLReportContentForContactEmail -ContactEmail $contactEmail)
            $adminReportContent += $tmp
            #Send-UserReport

            #Write-Host $tmp
        }
        Send-AdminReport -Content $adminReportContent

    }
}

function Send-AdminReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Content
    )

    $htmlEmail = ""


    $htmlEmail += @"
<html>
"@
    $htmlEmail += $emailHTMLHeader
    $htmlEmail += @"
<body>
"@
    $htmlEmail += $emailAdminPrefix
    $htmlEmail += $Content

    $htmlEmail += @"
</body>
"@
    $htmlEmail += @"
</html>
"@

    $htmlEmail | Out-File -FilePath "./admin-report.html"


}

function Create-HTMLReportContentForContactEmail {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$ContactEmail
    )


    Write-Host "|- Generating HTML report for Contact-Email $ContactEmail ..."
    [string]$content = ""
    $listOfNamespacesForThisContactEmail = $contact_email_to_namespaceList[$ContactEmail]
    foreach ($namespace in $listOfNamespacesForThisContactEmail) {
        $imagesInThisNamespace = $namespace_to_imageList[$namespace]
        foreach ($image in $imagesInThisNamespace) {
            $digestForThisImage = $image_to_digest[$image]
            $vulnReportForThisImage = $digest_to_vulnResult[$digestForThisImage]

            $content += @"
<b>$image</b><br>(Digest: $digestForThisImage)
<br>
<table>
    <tr>
        <th>Severity</th>
        <th>CVEScore3</th>
        <th>Category</th>
        <th>Name</th>
        <th>Description</th>
        <th>Impact</th>
        <th>CVEs</th>
    </tr>

"@
            
            foreach ($finding in  $vulnReportForThisImage) {

                $content += @"
    <tr>
        <td>$($finding.Severity)</td>
        <td>$($finding.CVEScore3)</td>
        <td>$($finding.Category)</td>
        <td>$($finding.Name)</td>
        <td>$($finding.Description)</td>
        <td>$($finding.Impact)</td>
        <td>

"@

                foreach ($cve in $($finding.CVEs)) {
                    $content += @"
                <a href="$($cve.URL)">$($cve.Id)</a>

"@
                }

                $content += @"
        </td>

"@               
                $content += @"
    </tr>

"@
            }
        }


        $content += @"
</table>
"@

    }


    Write-Output $content
}

function Get-VulnForImage {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Registry,
        [Parameter(Mandatory)]
        [string]$Digest
    )

    Write-Host "|-|-|- Query Vuln info for Registry '$Registry' and Digest '$Digest'"
    $azureResourceGraphQuery = @'
securityresources  | where type =~ "microsoft.security/assessments/subassessments"
  | extend assessmentKey=extract(@"(?i)providers/Microsoft.Security/assessments/([^/]*)", 1, id), subAssessmentId=tostring(properties.id), parentResourceId= extract("(.+)/providers/Microsoft.Security", 1, id)
  | extend resourceId = tostring(properties.resourceDetails.id)
  | extend subAssessmentName=tostring(properties.displayName),
    subAssessmentDescription=tostring(properties.description),
    subAssessmentRemediation=tostring(properties.remediation),
    subAssessmentCategory=tostring(properties.category),
    subAssessmentImpact=tostring(properties.impact),
    severity=tostring(properties.status.severity),
    status=tostring(properties.status.code),
    cause=tostring(properties.status.cause),
    statusDescription=tostring(properties.status.description),
    additionalData=tostring(properties.additionalData)
  | where assessmentKey == "dbd0cb49-b563-45e7-9724-889e799fa648"
  | extend additionalJsonData = parse_json(additionalData)
  | extend repositoryName = additionalJsonData.repositoryName
  | extend registry = additionalJsonData.registryHost
  | where registry == '$registry'
  | extend imageDigest = tostring(additionalJsonData.imageDigest)
  | where imageDigest == "$digest"
  | extend imagePublishedTime = tostring(additionalJsonData.publishedTime)
  | extend cveScore = tostring(additionalJsonData.cvss.["3.0"].base)
  | extend cveId = tostring(additionalJsonData.cve)
  | where status == "Unhealthy"
  | order by cveScore desc
  | project ["Severity"]=severity, ["CVE Score 3.0"]=cveScore, ["Category"]=subAssessmentCategory, ["Name"]=subAssessmentName, ["Description"]=subAssessmentDescription, ["Remediation"]=subAssessmentRemediation, ["Impact"]=subAssessmentImpact, ["CVE ID"]=cveId, ["Image Published Time"]=imagePublishedTime, ["Container Registry"]=registry, ["Image Repository"]=repositoryName,["Image Digest"]= imageDigest, additionalJsonData
'@

    $queryString = $azureResourceGraphQuery.replace('$registry', $Registry).Replace('$digest', $Digest).Replace("`n", '').Replace("`r", '')
    #Write-Host $queryString
    $vulnResult = (Search-AzGraph -Query $queryString -Subscription "1bb4bdb5-ca1b-4b74-b45b-24fa098e629d")
    #Write-Host $vulnResult.Data


    [System.Collections.Generic.List[VulnScanResultFinding]]$vulnScanResult = @()
    foreach ($finding in $vulnResult.Data) {
        
        $tmp = [VulnScanResultFinding] @{ 
            Severity    = $finding.Severity
            CVEScore3   = $finding."CVE Score 3.0"
            Category    = $finding.Category
            Name        = $finding.Name
            Description = $finding.Description
            Impact      = $finding.Impact
            CVEs        = @()
            Digest      = $Digest
        }
    
        $cveMap = $finding."CVE ID" | ConvertFrom-Json
        foreach ($cve in $cveMap) {
            $tmp.CVEs.Add([CVE]@{
                    Id  = $cve.title
                    URL = $cve.link
                })
        }
        
        $vulnScanResult.Add($tmp)
    }

    Write-Host "|-|-|- $($vulnScanResult.Count) findings"
    
    return $vulnScanResult
}

class VulnScanResultFinding {
    [string] $Severity
    [string] $CVEScore3
    [string] $Category
    [string] $Name
    [string] $Description
    [string] $Impact
    [System.Collections.Generic.List[CVE]] $CVEs
    [string] $Digest
}
class CVE {
    [string] $Id
    [string] $URL
}

function Get-DigestForTag {
    [CmdletBinding()]
    param( 
        [Parameter(Mandatory)]
        [string]$Registry,
        [Parameter(Mandatory)]
        [string]$Repo,
        [Parameter(Mandatory)]
        [string]$Tag
    ) 

    
    #$regexTag = ":([\w][\w.-]{0,127})$"
    $regexRegistryName = "^(.*)\.azurecr\.io$"

    # Get the resource group name for the container registry
    $registryName = [regex]::Match($Registry, $regexRegistryName).captures.groups[1].value

    # Get the access token for the registry
    $aad_access_token = (Get-AzAccessToken).Token
    $scope = "repository:${Repo}:pull"        
    $acr_refresh_token = (Invoke-RestMethod -Uri "https://$Registry/oauth2/exchange" -Method POST -ContentType 'application/x-www-form-urlencoded' -Body "grant_type=access_token&service=$registry&access_token=$aad_access_token" -UseBasicParsing).refresh_token
    $acr_access_token = (Invoke-RestMethod -Uri "https://$Registry/oauth2/token" -Method POST -ContentType 'application/x-www-form-urlencoded' -Body "grant_type=refresh_token&service=$registry&scope=$scope&refresh_token=$acr_refresh_token" -UseBasicParsing).access_token

    # Get the repository digest for the specified tag
    #$digest = (Invoke-WebRequest -Method Get -Uri "https://$Registry/v2/$Repo/manifests/$Tag" `
    #        -Headers @{ Authorization = "Bearer $acr_access_token"; "Accept" = "application/vnd.docker.distribution.manifest.v2+json" } `
    #        -UseBasicParsing).config.digest

    # Get the Container digest
    $response = (Invoke-WebRequest -Method Get -Uri "https://$Registry/v2/$Repo/manifests/$Tag" `
            -Headers @{ Authorization = "Bearer $acr_access_token"; "Accept" = "application/vnd.docker.distribution.manifest.v2+json" })
    $digest = $response.Headers["Docker-Content-Digest"]
    
    
    Write-Output $digest
}

$emailHTMLHeader = @"
<head>
<style>
table {
  font-family: arial, sans-serif;
  border-collapse: collapse;
  width: 100%;
}

td, th {
  border: 1px solid #dddddd;
  text-align: left;
  padding: 8px;
}
</style>
</head>
"@

$emailAdminPrefix = @"
<p>
Die folgenden Container Images in Namespaces haben Vulnerabilities:
</p>
<br>
"@

$emailUserPrefix = @"
<p>
Hallo,
</p>
<p>
die folgenden Container Images in Namespaces mit dieser Kontakt-Email-Adresse haben Vulnerabilities:
</p>
<br>
"@

$emailUserSuffix = @"
<br>
<p>
Hintergrund:
</p>
<p>
Dies ist eine unterstützende Information zur Einhaltung von IT-Security Richtlinie B XY.ToDo
</p>
<p>
Mit freundlichen Grüßen<br>
Euer AKS Platform Team
</p>
"@

Main
