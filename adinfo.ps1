#requires -Version 7.0
# Copyright (c) 2026 xyOps. All rights reserved.
<#!
xyOps Active Directory Info Event Plugin v3.0 (PowerShell 7)
A comprehensive collection of Active Directory query and reporting tools (25 tools):

Listing:          List Users, Groups, Computers, OUs
Investigation:    Group Membership, Group Members, User Detail
Security:         Privileged Accounts, Service Accounts, Disabled Accounts, Password Policy
Infrastructure:   Domain Info, Replication Status, Sites & Subnets, Trust Relationships, GPO Overview
Operational:      Stale Accounts, Password Expiry, Locked Accounts, Empty Groups,
                  Recent Changes, Account Expiration, Duplicate SPNs
Advanced:         LDAP Query, OU Comparison
Export:           CSV, Markdown, HTML, or Excel (XLSX)

Prerequisites:
- ActiveDirectory PowerShell module (RSAT)
- Domain-joined machine or connectivity to a domain controller
- Account with at least Read access to AD objects
- (Optional) ImportExcel module for XLSX export (auto-installed)

I/O contract:
- Read one JSON object from STDIN (job), write progress/messages as JSON lines of the
  form: { "xy": 1, ... } to STDOUT.
- On success, emit: { "xy": 1, "code": 0, "data": <result>, "description": "..." }
- On error, emit:   { "xy": 1, "code": <nonzero>, "description": "..." } and exit 1.

Test locally:
  pwsh -NoProfile -ExecutionPolicy Bypass -File .\adinfo.ps1 < job.json
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region xyOps Output Helpers

function Write-XY {
  param([hashtable]$Object)
  $payload = [ordered]@{ xy = 1 }
  foreach ($k in $Object.Keys) { $payload[$k] = $Object[$k] }
  [Console]::Out.WriteLine(($payload | ConvertTo-Json -Depth 20 -Compress))
  [Console]::Out.Flush()
}

function Write-XYProgress {
  param([double]$Value, [string]$Status)
  $o = @{ progress = [math]::Round($Value, 4) }
  if ($Status) { $o.status = $Status }
  Write-XY $o
}

function Write-XYSuccess {
  param($Data, [string]$Description, [array]$Files = @())
  $o = @{ code = 0; data = $Data }
  if ($Description) { $o.description = $Description }
  if ($Files.Count -gt 0) { $o.files = $Files }
  Write-XY $o
}

function Write-XYError {
  param([int]$Code, [string]$Description)
  Write-XY @{ code = $Code; description = $Description }
}

function Read-JobFromStdin {
  $raw = [Console]::In.ReadToEnd()
  if ([string]::IsNullOrWhiteSpace($raw)) { throw 'No job JSON received on STDIN' }
  return $raw | ConvertFrom-Json -ErrorAction Stop
}

function Get-Param {
  param($Params, [string]$Name, $Default = $null)
  if ($Params.PSObject.Properties.Name -contains $Name) { return $Params.$Name }
  return $Default
}

#endregion

#region Module Check

function Assert-ActiveDirectoryModule {
  Write-XYProgress 0.05 'Checking ActiveDirectory module...'

  if (-not (Get-Module -ListAvailable -Name 'ActiveDirectory')) {
    throw @"
ActiveDirectory PowerShell module is not installed.

To install RSAT on Windows 10/11:
  Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0

On Windows Server:
  Install-WindowsFeature RSAT-AD-PowerShell

The machine must be domain-joined or able to reach a domain controller.
The account running xyOps must have at least Read access to Active Directory.
"@
  }

  Import-Module ActiveDirectory -ErrorAction Stop
  Write-XYProgress 0.08 'ActiveDirectory module loaded'
}

function Install-ImportExcelModule {
  if (Get-Module -ListAvailable -Name 'ImportExcel') {
    Import-Module ImportExcel -ErrorAction Stop
    return
  }
  Write-XYProgress 0.80 'Installing ImportExcel module...'
  Install-Module -Name ImportExcel -Force -Scope CurrentUser -AllowClobber -ErrorAction Stop
  Import-Module ImportExcel -ErrorAction Stop
  Write-XYProgress 0.82 'ImportExcel module installed'
}

function Assert-GroupPolicyModule {
  try {
    if ($PSVersionTable.PSVersion.Major -ge 7) {
      Import-Module GroupPolicy -UseWindowsPowerShell -WarningAction SilentlyContinue -ErrorAction Stop
    } else {
      Import-Module GroupPolicy -ErrorAction Stop
    }
  }
  catch {
    throw @"
GroupPolicy PowerShell module could not be loaded.

On Windows Server:
  Install-WindowsFeature GPMC

On Windows 10/11:
  Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0

If GPMC is already installed and you are running PowerShell 7+, ensure the
Windows PowerShell compatibility layer is working:
  Import-Module GroupPolicy -UseWindowsPowerShell
"@
  }
}

#endregion

#region Field Definitions

function Get-FieldDefinition {
  param([string]$ObjectType, [string]$FieldSet)

  $definitions = @{
    users = @{
      essential = @('Name', 'SamAccountName', 'Enabled', 'EmailAddress')
      standard  = @('Name', 'SamAccountName', 'Enabled', 'EmailAddress',
                     'DisplayName', 'Title', 'Department', 'Office')
      extended  = @('Name', 'SamAccountName', 'Enabled', 'EmailAddress',
                     'DisplayName', 'Title', 'Department', 'Office',
                     'Manager', 'TelephoneNumber', 'Created', 'LastLogonDate',
                     'PasswordLastSet', 'AccountExpirationDate')
      all       = @('Name', 'SamAccountName', 'Enabled', 'EmailAddress',
                     'DisplayName', 'Title', 'Department', 'Office',
                     'Manager', 'TelephoneNumber', 'Created', 'LastLogonDate',
                     'PasswordLastSet', 'AccountExpirationDate',
                     'Description', 'DistinguishedName', 'SID', 'WhenChanged',
                     'PasswordNeverExpires', 'LockedOut')
      displayHeaders = @{
        'Name'='Name'; 'SamAccountName'='Username'; 'Enabled'='Enabled';
        'EmailAddress'='Email'; 'DisplayName'='Display Name'; 'Title'='Title';
        'Department'='Department'; 'Office'='Office'; 'Manager'='Manager';
        'TelephoneNumber'='Phone'; 'Created'='Created'; 'LastLogonDate'='Last Logon';
        'PasswordLastSet'='Password Set'; 'AccountExpirationDate'='Expires';
        'Description'='Description'; 'DistinguishedName'='DN'; 'SID'='SID';
        'WhenChanged'='Modified'; 'PasswordNeverExpires'='Pwd Never Expires';
        'LockedOut'='Locked Out'
      }
    }
    groups = @{
      essential = @('Name', 'GroupCategory', 'GroupScope', 'Description')
      standard  = @('Name', 'GroupCategory', 'GroupScope', 'Description',
                     'ManagedBy', 'MemberCount')
      extended  = @('Name', 'GroupCategory', 'GroupScope', 'Description',
                     'ManagedBy', 'MemberCount', 'Created', 'WhenChanged',
                     'SID', 'DistinguishedName')
      all       = @('Name', 'GroupCategory', 'GroupScope', 'Description',
                     'ManagedBy', 'MemberCount', 'Created', 'WhenChanged',
                     'SID', 'DistinguishedName', 'Mail', 'Info')
      displayHeaders = @{
        'Name'='Name'; 'GroupCategory'='Category'; 'GroupScope'='Scope';
        'Description'='Description'; 'ManagedBy'='Managed By'; 'MemberCount'='Members';
        'Created'='Created'; 'WhenChanged'='Modified'; 'SID'='SID';
        'DistinguishedName'='DN'; 'Mail'='Email'; 'Info'='Info'
      }
    }
    computers = @{
      essential = @('Name', 'OperatingSystem', 'Enabled', 'IPv4Address')
      standard  = @('Name', 'OperatingSystem', 'Enabled', 'IPv4Address',
                     'OperatingSystemVersion', 'LastLogonDate', 'Description')
      extended  = @('Name', 'OperatingSystem', 'Enabled', 'IPv4Address',
                     'OperatingSystemVersion', 'LastLogonDate', 'Description',
                     'Created', 'WhenChanged', 'Location', 'ManagedBy', 'DNSHostName')
      all       = @('Name', 'OperatingSystem', 'Enabled', 'IPv4Address',
                     'OperatingSystemVersion', 'LastLogonDate', 'Description',
                     'Created', 'WhenChanged', 'Location', 'ManagedBy', 'DNSHostName',
                     'DistinguishedName', 'SID', 'ServicePrincipalNames')
      displayHeaders = @{
        'Name'='Name'; 'OperatingSystem'='OS'; 'Enabled'='Enabled';
        'IPv4Address'='IP Address'; 'OperatingSystemVersion'='OS Version';
        'LastLogonDate'='Last Logon'; 'Description'='Description';
        'Created'='Created'; 'WhenChanged'='Modified'; 'Location'='Location';
        'ManagedBy'='Managed By'; 'DNSHostName'='DNS Name';
        'DistinguishedName'='DN'; 'SID'='SID';
        'ServicePrincipalNames'='SPNs'
      }
    }
    ous = @{
      essential = @('Name', 'DistinguishedName', 'Description')
      standard  = @('Name', 'DistinguishedName', 'Description',
                     'Created', 'WhenChanged', 'ManagedBy')
      extended  = @('Name', 'DistinguishedName', 'Description',
                     'Created', 'WhenChanged', 'ManagedBy',
                     'ProtectedFromAccidentalDeletion', 'LinkedGroupPolicyObjects')
      all       = @('Name', 'DistinguishedName', 'Description',
                     'Created', 'WhenChanged', 'ManagedBy',
                     'ProtectedFromAccidentalDeletion', 'LinkedGroupPolicyObjects',
                     'City', 'Country', 'State')
      displayHeaders = @{
        'Name'='Name'; 'DistinguishedName'='DN'; 'Description'='Description';
        'Created'='Created'; 'WhenChanged'='Modified'; 'ManagedBy'='Managed By';
        'ProtectedFromAccidentalDeletion'='Protected'; 'LinkedGroupPolicyObjects'='GPOs';
        'City'='City'; 'Country'='Country'; 'State'='State'
      }
    }
  }

  $typeDef = $definitions[$ObjectType]
  if (-not $typeDef) { throw "Unknown object type: $ObjectType" }

  $fields = $typeDef[$FieldSet]
  if (-not $fields) { $fields = $typeDef['essential'] }

  return @{
    Fields         = $fields
    DisplayHeaders = $typeDef.displayHeaders
  }
}

function Get-ADProperties {
  param([string]$ObjectType, [array]$Fields)

  $computed = @('MemberCount')
  $props = $Fields | Where-Object { $_ -notin $computed }

  if ($ObjectType -eq 'groups' -and $Fields -contains 'MemberCount') {
    if ($props -notcontains 'Members') { $props += 'Members' }
  }

  return $props
}

#endregion

#region Formatting Helpers

function Format-ADValue {
  param($Value, [string]$PropertyName)

  if ($null -eq $Value) { return '-' }

  if ($Value -is [datetime]) {
    if ($Value.Year -le 1601) { return 'Never' }
    return $Value.ToString('yyyy-MM-dd HH:mm')
  }

  if ($Value -is [bool]) {
    if ($Value) { return 'Yes' } else { return 'No' }
  }

  if ($Value -is [System.Security.Principal.SecurityIdentifier]) {
    return $Value.ToString()
  }

  if ($PropertyName -eq 'GroupCategory') {
    $catMap = @{ '0' = 'Distribution'; '1' = 'Security' }
    $key = [string][int]$Value
    return $(if ($catMap.ContainsKey($key)) { $catMap[$key] } else { [string]$Value })
  }

  if ($PropertyName -eq 'GroupScope') {
    $scopeMap = @{ '0' = 'DomainLocal'; '1' = 'Global'; '2' = 'Universal' }
    $key = [string][int]$Value
    return $(if ($scopeMap.ContainsKey($key)) { $scopeMap[$key] } else { [string]$Value })
  }

  if ($PropertyName -in @('Manager', 'ManagedBy') -and $Value -is [string] -and $Value -match 'CN=([^,]+)') {
    return $Matches[1]
  }

  if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
    $items = @($Value)
    if ($items.Count -eq 0) { return '-' }
    if ($items.Count -le 3) { return ($items -join ', ') }
    return "$($items[0..2] -join ', ') (+$($items.Count - 3) more)"
  }

  $str = [string]$Value
  if ([string]::IsNullOrWhiteSpace($str)) { return '-' }
  return $str
}

function Format-MarkdownTable {
  param([array]$Headers, [array]$Rows)

  $sb = [System.Text.StringBuilder]::new()
  [void]$sb.AppendLine("| $($Headers -join ' | ') |")
  $sep = ($Headers | ForEach-Object { '---' }) -join ' | '
  [void]$sb.AppendLine("| $sep |")
  foreach ($row in $Rows) {
    $escaped = $row | ForEach-Object { ([string]$_).Replace('|', '\|') }
    [void]$sb.AppendLine("| $($escaped -join ' | ') |")
  }
  return $sb.ToString()
}

#endregion

#region Common Query Helpers

function Get-CommonQueryOpts {
  param($Params)

  $searchBase = (Get-Param $Params 'searchBase' '').Trim()
  $searchScope = (Get-Param $Params 'searchScope' 'subtree').ToLower()
  $nameFilter = (Get-Param $Params 'nameFilter' '').Trim()
  $enabledOnly = if ($Params.PSObject.Properties.Name -contains 'enabledOnly') { [bool]$Params.enabledOnly } else { $false }
  $fieldSet = (Get-Param $Params 'fieldSet' 'essential').ToLower()
  $sortBy = (Get-Param $Params 'sortBy' 'name').ToLower()
  $sortOrder = (Get-Param $Params 'sortOrder' 'ascending').ToLower()
  $maxResultsStr = (Get-Param $Params 'maxResults' '1000').ToString().Trim()
  $exportEnabled = if ($Params.PSObject.Properties.Name -contains 'exportEnabled') { [bool]$Params.exportEnabled } else { $false }
  $exportFormat = (Get-Param $Params 'exportFormat' 'csv').ToLower()
  $exportFileName = (Get-Param $Params 'exportFileName' 'ad_export').Trim()

  $maxResults = 1000
  if ($maxResultsStr -match '^\d+$') { $maxResults = [int]$maxResultsStr }
  $maxResults = [Math]::Min(10000, [Math]::Max(1, $maxResults))

  $scopeMap = @{ 'base' = 'Base'; 'onelevel' = 'OneLevel'; 'subtree' = 'Subtree' }
  $adSearchScope = if ($scopeMap.ContainsKey($searchScope)) { $scopeMap[$searchScope] } else { 'Subtree' }

  if ($searchBase -and $searchBase -notmatch '(OU|DC|CN)=') {
    throw "Invalid SearchBase: '$searchBase'. Must be a valid distinguished name (e.g., OU=Users,DC=contoso,DC=com)"
  }

  return @{
    SearchBase     = $searchBase
    SearchScope    = $adSearchScope
    NameFilter     = $nameFilter
    EnabledOnly    = $enabledOnly
    FieldSet       = $fieldSet
    SortBy         = $sortBy
    SortOrder      = $sortOrder
    MaxResults     = $maxResults
    ExportEnabled  = $exportEnabled
    ExportFormat   = $exportFormat
    ExportFileName = $exportFileName
  }
}

function Build-TableOutput {
  param(
    [array]$RawResults,
    [hashtable]$FieldDef,
    [string]$ObjectType,
    [string]$Title,
    [string]$CaptionText,
    [hashtable]$QueryOpts
  )

  # Compute MemberCount for groups if needed
  if ($ObjectType -eq 'groups' -and $FieldDef.Fields -contains 'MemberCount') {
    foreach ($grp in $RawResults) {
      $memberCount = 0
      if ($grp.PSObject.Properties.Name -contains 'Members' -and $null -ne $grp.Members) {
        $memberCount = @($grp.Members).Count
      }
      $grp | Add-Member -NotePropertyName 'MemberCount' -NotePropertyValue $memberCount -Force
    }
  }

  # Sort
  $sortPropMap = @{ 'name' = 'Name'; 'created' = 'Created'; 'modified' = 'WhenChanged' }
  $sortProp = if ($sortPropMap.ContainsKey($QueryOpts.SortBy)) { $sortPropMap[$QueryOpts.SortBy] } else { 'Name' }
  if ($RawResults.Count -gt 0 -and $RawResults[0].PSObject.Properties.Name -notcontains $sortProp) {
    $sortProp = 'Name'
  }

  $sortedResults = @(if ($QueryOpts.SortOrder -eq 'descending') {
    $RawResults | Sort-Object -Property $sortProp -Descending
  } else {
    $RawResults | Sort-Object -Property $sortProp
  })

  # Build headers and rows
  $displayHeaders = @('#')
  foreach ($f in $FieldDef.Fields) {
    $header = if ($FieldDef.DisplayHeaders.ContainsKey($f)) { $FieldDef.DisplayHeaders[$f] } else { $f }
    $displayHeaders += $header
  }

  $tableRows = @()
  $dataRows = @()
  $outputItems = [System.Collections.Generic.List[object]]::new()

  $idx = 0
  foreach ($item in $sortedResults) {
    $idx++
    $displayRow = @($idx)
    $exportRow = @()
    $outputObj = [ordered]@{}

    foreach ($f in $FieldDef.Fields) {
      $rawValue = $null
      if ($item.PSObject.Properties.Name -contains $f) { $rawValue = $item.$f }
      $formatted = Format-ADValue -Value $rawValue -PropertyName $f
      $displayRow += $formatted
      $exportRow += $formatted
      $outputObj[$f] = $formatted
    }

    $tableRows += ,$displayRow
    $dataRows += ,$exportRow
    $outputItems.Add([pscustomobject]$outputObj)
  }

  return @{
    SortedResults  = $sortedResults
    DisplayHeaders = $displayHeaders
    TableRows      = $tableRows
    DataRows       = $dataRows
    OutputItems    = $outputItems
    ExportHeaders  = @($FieldDef.Fields | ForEach-Object {
      if ($FieldDef.DisplayHeaders.ContainsKey($_)) { $FieldDef.DisplayHeaders[$_] } else { $_ }
    })
  }
}

#endregion

#region AD Query Functions — List Tools

function Invoke-ADUserList {
  param($Params)

  Write-XYProgress 0.10 'Preparing user query...'
  $opts = Get-CommonQueryOpts $Params
  $fieldDef = Get-FieldDefinition -ObjectType 'users' -FieldSet $opts.FieldSet

  Write-XYProgress 0.25 'Querying Active Directory for users...'
  $adParams = @{
    Properties    = (Get-ADProperties 'users' $fieldDef.Fields)
    ResultSetSize = $opts.MaxResults
  }
  if ($opts.SearchBase) { $adParams.SearchBase = $opts.SearchBase }
  if ($opts.SearchScope) { $adParams.SearchScope = $opts.SearchScope }

  $filters = @()
  if ($opts.NameFilter) { $filters += "Name -like '$($opts.NameFilter)'" }
  if ($opts.EnabledOnly) { $filters += "Enabled -eq `$true" }
  $adParams.Filter = if ($filters.Count -gt 0) { $filters -join ' -and ' } else { '*' }

  $results = @(Get-ADUser @adParams)
  Write-XYProgress 0.50 "Retrieved $($results.Count) user(s)"

  return Emit-ListResults -RawResults $results -FieldDef $fieldDef -ObjectType 'users' -TypeName 'Users' -Opts $opts
}

function Invoke-ADGroupList {
  param($Params)

  Write-XYProgress 0.10 'Preparing group query...'
  $opts = Get-CommonQueryOpts $Params
  $fieldDef = Get-FieldDefinition -ObjectType 'groups' -FieldSet $opts.FieldSet

  Write-XYProgress 0.25 'Querying Active Directory for groups...'
  $adParams = @{
    Properties    = (Get-ADProperties 'groups' $fieldDef.Fields)
    ResultSetSize = $opts.MaxResults
  }
  if ($opts.SearchBase) { $adParams.SearchBase = $opts.SearchBase }
  if ($opts.SearchScope) { $adParams.SearchScope = $opts.SearchScope }

  $adParams.Filter = if ($opts.NameFilter) { "Name -like '$($opts.NameFilter)'" } else { '*' }

  $results = @(Get-ADGroup @adParams)
  Write-XYProgress 0.50 "Retrieved $($results.Count) group(s)"

  return Emit-ListResults -RawResults $results -FieldDef $fieldDef -ObjectType 'groups' -TypeName 'Groups' -Opts $opts
}

function Invoke-ADComputerList {
  param($Params)

  Write-XYProgress 0.10 'Preparing computer query...'
  $opts = Get-CommonQueryOpts $Params
  $fieldDef = Get-FieldDefinition -ObjectType 'computers' -FieldSet $opts.FieldSet

  Write-XYProgress 0.25 'Querying Active Directory for computers...'
  $adParams = @{
    Properties    = (Get-ADProperties 'computers' $fieldDef.Fields)
    ResultSetSize = $opts.MaxResults
  }
  if ($opts.SearchBase) { $adParams.SearchBase = $opts.SearchBase }
  if ($opts.SearchScope) { $adParams.SearchScope = $opts.SearchScope }

  $filters = @()
  if ($opts.NameFilter) { $filters += "Name -like '$($opts.NameFilter)'" }
  if ($opts.EnabledOnly) { $filters += "Enabled -eq `$true" }
  $adParams.Filter = if ($filters.Count -gt 0) { $filters -join ' -and ' } else { '*' }

  $results = @(Get-ADComputer @adParams)
  Write-XYProgress 0.50 "Retrieved $($results.Count) computer(s)"

  return Emit-ListResults -RawResults $results -FieldDef $fieldDef -ObjectType 'computers' -TypeName 'Computers' -Opts $opts
}

function Invoke-ADOUList {
  param($Params)

  Write-XYProgress 0.10 'Preparing OU query...'
  $opts = Get-CommonQueryOpts $Params
  $fieldDef = Get-FieldDefinition -ObjectType 'ous' -FieldSet $opts.FieldSet

  Write-XYProgress 0.25 'Querying Active Directory for organizational units...'
  $adParams = @{
    Properties    = (Get-ADProperties 'ous' $fieldDef.Fields)
    ResultSetSize = $opts.MaxResults
  }
  if ($opts.SearchBase) { $adParams.SearchBase = $opts.SearchBase }
  if ($opts.SearchScope) { $adParams.SearchScope = $opts.SearchScope }

  $adParams.Filter = if ($opts.NameFilter) { "Name -like '$($opts.NameFilter)'" } else { '*' }

  $results = @(Get-ADOrganizationalUnit @adParams)
  Write-XYProgress 0.50 "Retrieved $($results.Count) OU(s)"

  return Emit-ListResults -RawResults $results -FieldDef $fieldDef -ObjectType 'ous' -TypeName 'Organizational Units' -Opts $opts
}

#endregion

#region AD Query Functions — New Tools

function Invoke-GroupMembership {
  param($Params)

  $targetUser = (Get-Param $Params 'targetUser' '').Trim()
  if (-not $targetUser) { throw 'No target user specified. Provide a SamAccountName or Distinguished Name.' }

  Write-XYProgress 0.20 "Looking up group membership for '$targetUser'..."

  # Resolve the user
  $user = Get-ADUser -Identity $targetUser -Properties DisplayName, SamAccountName -ErrorAction Stop
  Write-XYProgress 0.35 "Found user: $($user.Name) ($($user.SamAccountName))"

  # Get all groups (recursive)
  $groups = @(Get-ADPrincipalGroupMembership -Identity $user -ErrorAction Stop)

  # Get extended info for each group
  Write-XYProgress 0.50 "Retrieving details for $($groups.Count) group(s)..."
  $detailedGroups = @()
  foreach ($g in $groups) {
    $detail = Get-ADGroup -Identity $g.DistinguishedName -Properties GroupCategory, GroupScope, Description, ManagedBy -ErrorAction SilentlyContinue
    if ($detail) { $detailedGroups += $detail }
  }

  Write-XYProgress 0.70 'Building output...'

  $displayHeaders = @('#', 'Group Name', 'Category', 'Scope', 'Description')
  $tableRows = @()
  $dataRows = @()
  $idx = 0
  foreach ($g in ($detailedGroups | Sort-Object Name)) {
    $idx++
    $desc = if ($g.Description) { $g.Description } else { '-' }
    $cat = Format-ADValue -Value $g.GroupCategory -PropertyName 'GroupCategory'
    $scope = Format-ADValue -Value $g.GroupScope -PropertyName 'GroupScope'
    $tableRows += ,@($idx, $g.Name, $cat, $scope, $desc)
    $dataRows += ,@($g.Name, $cat, $scope, $desc)
  }

  $captionText = "User '$($user.SamAccountName)' is a member of $($detailedGroups.Count) group(s)"

  # Export if requested
  $opts = Get-CommonQueryOpts $Params
  $generatedFiles = @()
  if ($opts.ExportEnabled) {
    $exportHeaders = @('Group Name', 'Category', 'Scope', 'Description')
    $exportPath = Export-ResultsToFile -Rows $dataRows -Headers $exportHeaders `
      -Format $opts.ExportFormat -FileName $opts.ExportFileName -Title "Group Membership - $($user.SamAccountName)"
    if ($exportPath -and (Test-Path $exportPath)) {
      $generatedFiles += (Get-Item $exportPath).Name
      $captionText += " | Exported: $((Get-Item $exportPath).Name)"
    }
  }

  Write-XY @{ table = @{ title = "Group Membership — $($user.Name)"; header = $displayHeaders; rows = $tableRows; caption = $captionText } }

  return [PSCustomObject]@{
    tool = 'Group Membership'; success = $true; targetUser = $user.SamAccountName
    totalGroups = $detailedGroups.Count; generatedFiles = $generatedFiles
  }
}

function Invoke-GroupMembers {
  param($Params)

  $targetGroup = (Get-Param $Params 'targetGroup' '').Trim()
  if (-not $targetGroup) { throw 'No target group specified. Provide a group Name, SamAccountName, or Distinguished Name.' }

  $recursive = if ($Params.PSObject.Properties.Name -contains 'recursive') { [bool]$Params.recursive } else { $false }

  Write-XYProgress 0.20 "Looking up members of '$targetGroup'..."

  $group = Get-ADGroup -Identity $targetGroup -Properties Description -ErrorAction Stop
  Write-XYProgress 0.35 "Found group: $($group.Name)"

  $memberParams = @{ Identity = $group }
  if ($recursive) { $memberParams.Recursive = $true }

  $members = @(Get-ADGroupMember @memberParams -ErrorAction Stop)
  Write-XYProgress 0.55 "Found $($members.Count) member(s)"

  # Get additional properties for each member
  Write-XYProgress 0.60 'Retrieving member details...'
  $detailedMembers = [System.Collections.Generic.List[object]]::new()
  foreach ($m in $members) {
    $obj = [ordered]@{ Name = $m.Name; SamAccountName = $m.SamAccountName; ObjectClass = $m.objectClass; Enabled = '-' }
    if ($m.objectClass -eq 'user') {
      try {
        $u = Get-ADUser -Identity $m.SamAccountName -Properties Enabled -ErrorAction SilentlyContinue
        if ($u) { $obj.Enabled = if ($u.Enabled) { 'Yes' } else { 'No' } }
      } catch {}
    } elseif ($m.objectClass -eq 'computer') {
      try {
        $c = Get-ADComputer -Identity $m.SamAccountName -Properties Enabled -ErrorAction SilentlyContinue
        if ($c) { $obj.Enabled = if ($c.Enabled) { 'Yes' } else { 'No' } }
      } catch {}
    }
    $detailedMembers.Add([pscustomobject]$obj)
  }

  Write-XYProgress 0.75 'Building output...'

  $displayHeaders = @('#', 'Name', 'Username', 'Type', 'Enabled')
  $tableRows = @()
  $dataRows = @()
  $idx = 0
  foreach ($m in ($detailedMembers | Sort-Object Name)) {
    $idx++
    $tableRows += ,@($idx, $m.Name, $m.SamAccountName, $m.ObjectClass, $m.Enabled)
    $dataRows += ,@($m.Name, $m.SamAccountName, $m.ObjectClass, $m.Enabled)
  }

  $modeText = if ($recursive) { 'recursive' } else { 'direct' }
  $captionText = "Group '$($group.Name)' has $($detailedMembers.Count) $modeText member(s)"

  $opts = Get-CommonQueryOpts $Params
  $generatedFiles = @()
  if ($opts.ExportEnabled) {
    $exportHeaders = @('Name', 'Username', 'Type', 'Enabled')
    $exportPath = Export-ResultsToFile -Rows $dataRows -Headers $exportHeaders `
      -Format $opts.ExportFormat -FileName $opts.ExportFileName -Title "Group Members - $($group.Name)"
    if ($exportPath -and (Test-Path $exportPath)) {
      $generatedFiles += (Get-Item $exportPath).Name
      $captionText += " | Exported: $((Get-Item $exportPath).Name)"
    }
  }

  Write-XY @{ table = @{ title = "Group Members — $($group.Name)"; header = $displayHeaders; rows = $tableRows; caption = $captionText } }

  return [PSCustomObject]@{
    tool = 'Group Members'; success = $true; targetGroup = $group.Name
    recursive = $recursive; totalMembers = $detailedMembers.Count; generatedFiles = $generatedFiles
  }
}

function Invoke-StaleAccounts {
  param($Params)

  $staleDaysStr = (Get-Param $Params 'staleDays' '90').ToString().Trim()
  $staleDays = 90
  if ($staleDaysStr -match '^\d+$') { $staleDays = [int]$staleDaysStr }
  $staleDays = [Math]::Max(1, $staleDays)

  $staleType = (Get-Param $Params 'staleObjectType' 'users').ToLower()
  $searchBase = (Get-Param $Params 'searchBase' '').Trim()

  $cutoffDate = (Get-Date).AddDays(-$staleDays)
  Write-XYProgress 0.15 "Finding accounts not logged in since $($cutoffDate.ToString('yyyy-MM-dd'))..."

  $allResults = @()

  if ($staleType -in @('users', 'both')) {
    Write-XYProgress 0.25 'Querying stale user accounts...'
    $userParams = @{
      Filter     = "LastLogonDate -lt '$($cutoffDate.ToString('yyyy-MM-ddTHH:mm:ss'))' -or LastLogonDate -notlike '*'"
      Properties = @('Name', 'SamAccountName', 'Enabled', 'LastLogonDate', 'PasswordLastSet', 'Created', 'Description', 'DistinguishedName')
    }
    if ($searchBase) { $userParams.SearchBase = $searchBase }
    $staleUsers = @(Get-ADUser @userParams)
    # Filter more precisely in PowerShell (AD filter for null dates can be tricky)
    $staleUsers = @($staleUsers | Where-Object { $null -eq $_.LastLogonDate -or $_.LastLogonDate -lt $cutoffDate })
    foreach ($u in $staleUsers) {
      $u | Add-Member -NotePropertyName 'ObjectType' -NotePropertyValue 'User' -Force
    }
    $allResults += $staleUsers
  }

  if ($staleType -in @('computers', 'both')) {
    Write-XYProgress 0.45 'Querying stale computer accounts...'
    $compParams = @{
      Filter     = "LastLogonDate -lt '$($cutoffDate.ToString('yyyy-MM-ddTHH:mm:ss'))' -or LastLogonDate -notlike '*'"
      Properties = @('Name', 'SamAccountName', 'Enabled', 'LastLogonDate', 'OperatingSystem', 'Created', 'Description', 'DistinguishedName')
    }
    if ($searchBase) { $compParams.SearchBase = $searchBase }
    $staleComps = @(Get-ADComputer @compParams)
    $staleComps = @($staleComps | Where-Object { $null -eq $_.LastLogonDate -or $_.LastLogonDate -lt $cutoffDate })
    foreach ($c in $staleComps) {
      $c | Add-Member -NotePropertyName 'ObjectType' -NotePropertyValue 'Computer' -Force
    }
    $allResults += $staleComps
  }

  Write-XYProgress 0.65 "Found $($allResults.Count) stale account(s)"

  $displayHeaders = @('#', 'Name', 'Username', 'Type', 'Enabled', 'Last Logon', 'Created')
  $tableRows = @()
  $dataRows = @()
  $idx = 0
  foreach ($item in ($allResults | Sort-Object LastLogonDate)) {
    $idx++
    $enabled = Format-ADValue -Value $item.Enabled -PropertyName 'Enabled'
    $lastLogon = Format-ADValue -Value $item.LastLogonDate -PropertyName 'LastLogonDate'
    $created = Format-ADValue -Value $item.Created -PropertyName 'Created'
    $tableRows += ,@($idx, $item.Name, $item.SamAccountName, $item.ObjectType, $enabled, $lastLogon, $created)
    $dataRows += ,@($item.Name, $item.SamAccountName, $item.ObjectType, $enabled, $lastLogon, $created)
  }

  $captionText = "Found $($allResults.Count) account(s) with no logon in $staleDays+ days"

  $opts = Get-CommonQueryOpts $Params
  $generatedFiles = @()
  if ($opts.ExportEnabled) {
    $exportHeaders = @('Name', 'Username', 'Type', 'Enabled', 'Last Logon', 'Created')
    $exportPath = Export-ResultsToFile -Rows $dataRows -Headers $exportHeaders `
      -Format $opts.ExportFormat -FileName $opts.ExportFileName -Title "Stale Accounts ($staleDays+ days)"
    if ($exportPath -and (Test-Path $exportPath)) {
      $generatedFiles += (Get-Item $exportPath).Name
      $captionText += " | Exported: $((Get-Item $exportPath).Name)"
    }
  }

  Write-XY @{ table = @{ title = "Stale Accounts ($staleDays+ Days)"; header = $displayHeaders; rows = $tableRows; caption = $captionText } }

  return [PSCustomObject]@{
    tool = 'Stale Accounts'; success = $true; staleDays = $staleDays
    objectType = $staleType; totalResults = $allResults.Count; generatedFiles = $generatedFiles
  }
}

function Invoke-PasswordExpiry {
  param($Params)

  $expiryDaysStr = (Get-Param $Params 'expiryDays' '14').ToString().Trim()
  $expiryDays = 14
  if ($expiryDaysStr -match '^\d+$') { $expiryDays = [int]$expiryDaysStr }
  $expiryDays = [Math]::Max(1, $expiryDays)

  $searchBase = (Get-Param $Params 'searchBase' '').Trim()

  Write-XYProgress 0.20 "Finding users with passwords expiring within $expiryDays days..."

  $userParams = @{
    Filter     = "Enabled -eq `$true -and PasswordNeverExpires -eq `$false"
    Properties = @('Name', 'SamAccountName', 'EmailAddress', 'PasswordLastSet',
                   'msDS-UserPasswordExpiryTimeComputed', 'PasswordNeverExpires',
                   'Department', 'Title')
  }
  if ($searchBase) { $userParams.SearchBase = $searchBase }

  $users = @(Get-ADUser @userParams)
  Write-XYProgress 0.50 "Checking $($users.Count) user(s)..."

  $now = Get-Date
  $expiringUsers = [System.Collections.Generic.List[object]]::new()

  foreach ($u in $users) {
    $expiryTimeRaw = $u.'msDS-UserPasswordExpiryTimeComputed'
    if ($null -eq $expiryTimeRaw -or $expiryTimeRaw -le 0) { continue }
    try {
      $expiryDate = [datetime]::FromFileTime($expiryTimeRaw)
      $daysLeft = [Math]::Floor(($expiryDate - $now).TotalDays)
      if ($daysLeft -le $expiryDays) {
        $u | Add-Member -NotePropertyName 'ExpiryDate' -NotePropertyValue $expiryDate -Force
        $u | Add-Member -NotePropertyName 'DaysLeft' -NotePropertyValue $daysLeft -Force
        $expiringUsers.Add($u)
      }
    } catch {}
  }

  Write-XYProgress 0.70 "Found $($expiringUsers.Count) user(s) with expiring passwords"

  $displayHeaders = @('#', 'Name', 'Username', 'Email', 'Pwd Set', 'Expires', 'Days Left')
  $tableRows = @()
  $dataRows = @()
  $idx = 0
  foreach ($u in ($expiringUsers | Sort-Object DaysLeft)) {
    $idx++
    $email = if ($u.EmailAddress) { $u.EmailAddress } else { '-' }
    $pwdSet = Format-ADValue -Value $u.PasswordLastSet -PropertyName 'PasswordLastSet'
    $expires = $u.ExpiryDate.ToString('yyyy-MM-dd HH:mm')
    $daysStr = if ($u.DaysLeft -lt 0) { "EXPIRED ($($u.DaysLeft)d)" } elseif ($u.DaysLeft -eq 0) { 'TODAY' } else { "$($u.DaysLeft)d" }
    $tableRows += ,@($idx, $u.Name, $u.SamAccountName, $email, $pwdSet, $expires, $daysStr)
    $dataRows += ,@($u.Name, $u.SamAccountName, $email, $pwdSet, $expires, $daysStr)
  }

  $captionText = "Found $($expiringUsers.Count) user(s) with password expiring within $expiryDays days"

  $opts = Get-CommonQueryOpts $Params
  $generatedFiles = @()
  if ($opts.ExportEnabled) {
    $exportHeaders = @('Name', 'Username', 'Email', 'Pwd Set', 'Expires', 'Days Left')
    $exportPath = Export-ResultsToFile -Rows $dataRows -Headers $exportHeaders `
      -Format $opts.ExportFormat -FileName $opts.ExportFileName -Title "Password Expiry Report ($expiryDays days)"
    if ($exportPath -and (Test-Path $exportPath)) {
      $generatedFiles += (Get-Item $exportPath).Name
      $captionText += " | Exported: $((Get-Item $exportPath).Name)"
    }
  }

  Write-XY @{ table = @{ title = "Password Expiry Report ($expiryDays Days)"; header = $displayHeaders; rows = $tableRows; caption = $captionText } }

  return [PSCustomObject]@{
    tool = 'Password Expiry'; success = $true; expiryDays = $expiryDays
    totalResults = $expiringUsers.Count; generatedFiles = $generatedFiles
  }
}

function Invoke-LockedAccounts {
  param($Params)

  Write-XYProgress 0.20 'Searching for locked-out accounts...'

  $locked = @(Search-ADAccount -LockedOut -UsersOnly -ErrorAction Stop)
  Write-XYProgress 0.45 "Found $($locked.Count) locked account(s)"

  # Get additional details
  $detailedLocked = [System.Collections.Generic.List[object]]::new()
  foreach ($l in $locked) {
    try {
      $u = Get-ADUser -Identity $l.SamAccountName -Properties Name, SamAccountName, Enabled,
        EmailAddress, LockedOut, AccountLockoutTime, BadLogonCount, LastLogonDate -ErrorAction SilentlyContinue
      if ($u) { $detailedLocked.Add($u) }
    } catch {}
  }

  Write-XYProgress 0.70 'Building output...'

  $displayHeaders = @('#', 'Name', 'Username', 'Email', 'Lockout Time', 'Bad Logons', 'Last Logon')
  $tableRows = @()
  $dataRows = @()
  $idx = 0
  foreach ($u in ($detailedLocked | Sort-Object AccountLockoutTime -Descending)) {
    $idx++
    $email = if ($u.EmailAddress) { $u.EmailAddress } else { '-' }
    $lockTime = Format-ADValue -Value $u.AccountLockoutTime -PropertyName 'AccountLockoutTime'
    $badLogons = if ($null -ne $u.BadLogonCount) { $u.BadLogonCount } else { '-' }
    $lastLogon = Format-ADValue -Value $u.LastLogonDate -PropertyName 'LastLogonDate'
    $tableRows += ,@($idx, $u.Name, $u.SamAccountName, $email, $lockTime, $badLogons, $lastLogon)
    $dataRows += ,@($u.Name, $u.SamAccountName, $email, $lockTime, $badLogons, $lastLogon)
  }

  $captionText = "Found $($detailedLocked.Count) currently locked-out account(s)"

  $opts = Get-CommonQueryOpts $Params
  $generatedFiles = @()
  if ($opts.ExportEnabled) {
    $exportHeaders = @('Name', 'Username', 'Email', 'Lockout Time', 'Bad Logons', 'Last Logon')
    $exportPath = Export-ResultsToFile -Rows $dataRows -Headers $exportHeaders `
      -Format $opts.ExportFormat -FileName $opts.ExportFileName -Title 'Locked Out Accounts'
    if ($exportPath -and (Test-Path $exportPath)) {
      $generatedFiles += (Get-Item $exportPath).Name
      $captionText += " | Exported: $((Get-Item $exportPath).Name)"
    }
  }

  Write-XY @{ table = @{ title = 'Locked Out Accounts'; header = $displayHeaders; rows = $tableRows; caption = $captionText } }

  return [PSCustomObject]@{
    tool = 'Locked Accounts'; success = $true
    totalResults = $detailedLocked.Count; generatedFiles = $generatedFiles
  }
}

function Invoke-EmptyGroups {
  param($Params)

  $searchBase = (Get-Param $Params 'searchBase' '').Trim()

  Write-XYProgress 0.20 'Querying all groups...'

  $groupParams = @{
    Filter     = '*'
    Properties = @('Name', 'GroupCategory', 'GroupScope', 'Description', 'Members', 'ManagedBy', 'Created')
  }
  if ($searchBase) { $groupParams.SearchBase = $searchBase }

  $allGroups = @(Get-ADGroup @groupParams)
  Write-XYProgress 0.50 "Checking $($allGroups.Count) group(s) for empty membership..."

  $emptyGroups = @($allGroups | Where-Object { $null -eq $_.Members -or @($_.Members).Count -eq 0 })
  Write-XYProgress 0.70 "Found $($emptyGroups.Count) empty group(s)"

  $displayHeaders = @('#', 'Name', 'Category', 'Scope', 'Description', 'Managed By', 'Created')
  $tableRows = @()
  $dataRows = @()
  $idx = 0
  foreach ($g in ($emptyGroups | Sort-Object Name)) {
    $idx++
    $desc = if ($g.Description) { $g.Description } else { '-' }
    $managedBy = Format-ADValue -Value $g.ManagedBy -PropertyName 'ManagedBy'
    $created = Format-ADValue -Value $g.Created -PropertyName 'Created'
    $cat = Format-ADValue -Value $g.GroupCategory -PropertyName 'GroupCategory'
    $scope = Format-ADValue -Value $g.GroupScope -PropertyName 'GroupScope'
    $tableRows += ,@($idx, $g.Name, $cat, $scope, $desc, $managedBy, $created)
    $dataRows += ,@($g.Name, $cat, $scope, $desc, $managedBy, $created)
  }

  $captionText = "Found $($emptyGroups.Count) empty group(s) out of $($allGroups.Count) total"

  $opts = Get-CommonQueryOpts $Params
  $generatedFiles = @()
  if ($opts.ExportEnabled) {
    $exportHeaders = @('Name', 'Category', 'Scope', 'Description', 'Managed By', 'Created')
    $exportPath = Export-ResultsToFile -Rows $dataRows -Headers $exportHeaders `
      -Format $opts.ExportFormat -FileName $opts.ExportFileName -Title 'Empty Groups'
    if ($exportPath -and (Test-Path $exportPath)) {
      $generatedFiles += (Get-Item $exportPath).Name
      $captionText += " | Exported: $((Get-Item $exportPath).Name)"
    }
  }

  Write-XY @{ table = @{ title = 'Empty Groups'; header = $displayHeaders; rows = $tableRows; caption = $captionText } }

  return [PSCustomObject]@{
    tool = 'Empty Groups'; success = $true
    totalEmpty = $emptyGroups.Count; totalGroups = $allGroups.Count; generatedFiles = $generatedFiles
  }
}

function Invoke-DomainInfo {
  param($Params)

  Write-XYProgress 0.15 'Querying domain information...'
  $domain = Get-ADDomain -ErrorAction Stop

  Write-XYProgress 0.30 'Querying forest information...'
  $forest = Get-ADForest -ErrorAction Stop

  Write-XYProgress 0.50 'Querying domain controllers...'
  $dcs = @(Get-ADDomainController -Filter * -ErrorAction Stop)

  Write-XYProgress 0.70 'Building output...'

  # Domain info table
  $domainRows = @(
    @('Domain Name', $domain.DNSRoot),
    @('NetBIOS Name', $domain.NetBIOSName),
    @('Domain Functional Level', $domain.DomainMode),
    @('Forest Functional Level', $forest.ForestMode),
    @('Forest Name', $forest.Name),
    @('Domain SID', $domain.DomainSID.ToString()),
    @('Infrastructure Master', $domain.InfrastructureMaster),
    @('RID Master', $domain.RIDMaster),
    @('PDC Emulator', $domain.PDCEmulator),
    @('Domain Naming Master', $forest.DomainNamingMaster),
    @('Schema Master', $forest.SchemaMaster)
  )

  # DC table
  $dcHeaders = @('#', 'Name', 'IPv4', 'Site', 'OS', 'FSMO Roles', 'Global Catalog')
  $dcRows = @()
  $idx = 0
  foreach ($dc in ($dcs | Sort-Object Name)) {
    $idx++
    $roles = @()
    if ($dc.OperationMasterRoles) { $roles = @($dc.OperationMasterRoles) }
    $rolesStr = if ($roles.Count -gt 0) { $roles -join ', ' } else { '-' }
    $gc = if ($dc.IsGlobalCatalog) { 'Yes' } else { 'No' }
    $dcRows += ,@($idx, $dc.Name, $dc.IPv4Address, $dc.Site, $dc.OperatingSystem, $rolesStr, $gc)
  }

  Write-XY @{ table = @{
    title = "Domain — $($domain.DNSRoot)"
    header = @('Property', 'Value')
    rows = $domainRows
    caption = "$($dcs.Count) domain controller(s) | Forest: $($forest.Name)"
  } }

  # xyOps only shows the LAST table, so we emit DCs as the final table
  Write-XY @{ table = @{
    title = 'Domain Controllers'
    header = $dcHeaders
    rows = $dcRows
    caption = "$($dcs.Count) DC(s) across $(@($dcs | Select-Object -ExpandProperty Site -Unique).Count) site(s)"
  } }

  return [PSCustomObject]@{
    tool = 'Domain Info'; success = $true; domainName = $domain.DNSRoot
    forestName = $forest.Name; dcCount = $dcs.Count; generatedFiles = @()
  }
}

function Invoke-LdapQuery {
  param($Params)

  $ldapFilter = (Get-Param $Params 'ldapFilter' '').Trim()
  if (-not $ldapFilter) { throw 'No LDAP filter specified. Example: (&(objectClass=user)(department=IT))' }

  $ldapPropsStr = (Get-Param $Params 'ldapProperties' 'Name,SamAccountName,ObjectClass').Trim()
  $ldapProps = @($ldapPropsStr -split '[,;\s]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
  if ($ldapProps.Count -eq 0) { $ldapProps = @('Name', 'SamAccountName', 'ObjectClass') }

  $searchBase = (Get-Param $Params 'searchBase' '').Trim()
  $maxResultsStr = (Get-Param $Params 'maxResults' '1000').ToString().Trim()
  $maxResults = 1000
  if ($maxResultsStr -match '^\d+$') { $maxResults = [int]$maxResultsStr }
  $maxResults = [Math]::Min(10000, [Math]::Max(1, $maxResults))

  Write-XYProgress 0.20 "Running LDAP query..."

  $adParams = @{
    LDAPFilter    = $ldapFilter
    Properties    = $ldapProps
    ResultSetSize = $maxResults
  }
  if ($searchBase) { $adParams.SearchBase = $searchBase }

  $results = @(Get-ADObject @adParams)
  Write-XYProgress 0.60 "Retrieved $($results.Count) object(s)"

  # Build table
  $displayHeaders = @('#') + $ldapProps
  $tableRows = @()
  $dataRows = @()
  $idx = 0
  foreach ($item in $results) {
    $idx++
    $row = @($idx)
    $exportRow = @()
    foreach ($prop in $ldapProps) {
      $val = $null
      if ($item.PSObject.Properties.Name -contains $prop) { $val = $item.$prop }
      $formatted = Format-ADValue -Value $val -PropertyName $prop
      $row += $formatted
      $exportRow += $formatted
    }
    $tableRows += ,$row
    $dataRows += ,$exportRow
  }

  $captionText = "LDAP filter returned $($results.Count) object(s) | Filter: $ldapFilter"

  $opts = Get-CommonQueryOpts $Params
  $generatedFiles = @()
  if ($opts.ExportEnabled) {
    $exportPath = Export-ResultsToFile -Rows $dataRows -Headers $ldapProps `
      -Format $opts.ExportFormat -FileName $opts.ExportFileName -Title 'LDAP Query Results'
    if ($exportPath -and (Test-Path $exportPath)) {
      $generatedFiles += (Get-Item $exportPath).Name
      $captionText += " | Exported: $((Get-Item $exportPath).Name)"
    }
  }

  Write-XY @{ table = @{ title = 'LDAP Query Results'; header = $displayHeaders; rows = $tableRows; caption = $captionText } }

  return [PSCustomObject]@{
    tool = 'LDAP Query'; success = $true; ldapFilter = $ldapFilter
    totalResults = $results.Count; generatedFiles = $generatedFiles
  }
}

function Invoke-CompareOUs {
  param($Params)

  $ou1 = (Get-Param $Params 'compareOU1' '').Trim()
  $ou2 = (Get-Param $Params 'compareOU2' '').Trim()
  $compareType = (Get-Param $Params 'compareObjectType' 'users').ToLower()

  if (-not $ou1) { throw 'Compare OU 1 is required.' }
  if (-not $ou2) { throw 'Compare OU 2 is required.' }

  Write-XYProgress 0.15 "Comparing $compareType between two OUs..."

  # Query OU 1
  Write-XYProgress 0.25 "Querying OU 1..."
  $items1 = @(switch ($compareType) {
    'users'     { Get-ADUser -Filter * -SearchBase $ou1 -Properties Name, SamAccountName, Enabled, Department }
    'groups'    { Get-ADGroup -Filter * -SearchBase $ou1 -Properties Name, GroupCategory, GroupScope }
    'computers' { Get-ADComputer -Filter * -SearchBase $ou1 -Properties Name, OperatingSystem, Enabled }
  })

  # Query OU 2
  Write-XYProgress 0.45 "Querying OU 2..."
  $items2 = @(switch ($compareType) {
    'users'     { Get-ADUser -Filter * -SearchBase $ou2 -Properties Name, SamAccountName, Enabled, Department }
    'groups'    { Get-ADGroup -Filter * -SearchBase $ou2 -Properties Name, GroupCategory, GroupScope }
    'computers' { Get-ADComputer -Filter * -SearchBase $ou2 -Properties Name, OperatingSystem, Enabled }
  })

  Write-XYProgress 0.65 'Comparing...'

  $names1 = @($items1 | ForEach-Object { $_.SamAccountName ?? $_.Name })
  $names2 = @($items2 | ForEach-Object { $_.SamAccountName ?? $_.Name })

  $onlyIn1 = @($names1 | Where-Object { $_ -notin $names2 })
  $onlyIn2 = @($names2 | Where-Object { $_ -notin $names1 })
  $inBoth  = @($names1 | Where-Object { $_ -in $names2 })

  # Summary table
  $summaryRows = @(
    @('OU 1', $ou1),
    @('OU 2', $ou2),
    @('Object Type', $compareType),
    @("Total in OU 1", $items1.Count),
    @("Total in OU 2", $items2.Count),
    @('In Both', $inBoth.Count),
    @('Only in OU 1', $onlyIn1.Count),
    @('Only in OU 2', $onlyIn2.Count)
  )

  # Diff table — show items only in one OU
  $diffHeaders = @('#', 'Name', 'Location')
  $diffRows = @()
  $dataRows = @()
  $idx = 0
  foreach ($name in ($onlyIn1 | Sort-Object)) {
    $idx++
    $diffRows += ,@($idx, $name, 'Only in OU 1')
    $dataRows += ,@($name, 'Only in OU 1')
  }
  foreach ($name in ($onlyIn2 | Sort-Object)) {
    $idx++
    $diffRows += ,@($idx, $name, 'Only in OU 2')
    $dataRows += ,@($name, 'Only in OU 2')
  }

  $captionText = "$($inBoth.Count) in common | $($onlyIn1.Count) only in OU 1 | $($onlyIn2.Count) only in OU 2"

  $opts = Get-CommonQueryOpts $Params
  $generatedFiles = @()
  if ($opts.ExportEnabled) {
    $exportHeaders = @('Name', 'Location')
    $exportPath = Export-ResultsToFile -Rows $dataRows -Headers $exportHeaders `
      -Format $opts.ExportFormat -FileName $opts.ExportFileName -Title 'OU Comparison'
    if ($exportPath -and (Test-Path $exportPath)) {
      $generatedFiles += (Get-Item $exportPath).Name
      $captionText += " | Exported: $((Get-Item $exportPath).Name)"
    }
  }

  # Emit summary first, then diff table (xyOps shows last table)
  Write-XY @{ table = @{ title = 'OU Comparison Summary'; header = @('Property', 'Value'); rows = $summaryRows; caption = '' } }
  Write-XY @{ table = @{ title = 'OU Differences'; header = $diffHeaders; rows = $diffRows; caption = $captionText } }

  return [PSCustomObject]@{
    tool = 'Compare OUs'; success = $true; compareType = $compareType
    ou1Count = $items1.Count; ou2Count = $items2.Count
    inBoth = $inBoth.Count; onlyInOU1 = $onlyIn1.Count; onlyInOU2 = $onlyIn2.Count
    generatedFiles = $generatedFiles
  }
}

#endregion

#region AD Query Functions — v3.0 Security Tools

function Invoke-PrivilegedAccounts {
  param($Params)

  Write-XYProgress 0.10 'Scanning privileged groups...'

  $privilegedGroups = @(
    'Domain Admins', 'Enterprise Admins', 'Schema Admins',
    'Account Operators', 'Backup Operators', 'Server Operators',
    'Print Operators', 'Administrators'
  )

  $allMembers = [System.Collections.Generic.List[object]]::new()
  $groupIdx = 0
  foreach ($groupName in $privilegedGroups) {
    $groupIdx++
    $pct = 0.10 + (0.55 * $groupIdx / $privilegedGroups.Count)
    Write-XYProgress $pct "Checking '$groupName'..."
    try {
      $members = @(Get-ADGroupMember -Identity $groupName -Recursive -ErrorAction SilentlyContinue)
      foreach ($m in $members) {
        # Avoid duplicates
        if ($allMembers | Where-Object { $_.SamAccountName -eq $m.SamAccountName -and $_.GroupName -eq $groupName }) { continue }
        try {
          $u = Get-ADUser -Identity $m.SamAccountName -Properties Name, SamAccountName, Enabled,
            LastLogonDate, PasswordLastSet, PasswordNeverExpires, WhenCreated, Description -ErrorAction SilentlyContinue
          if ($u) {
            $u | Add-Member -NotePropertyName 'GroupName' -NotePropertyValue $groupName -Force
            $pwdAge = if ($u.PasswordLastSet) { [Math]::Floor(((Get-Date) - $u.PasswordLastSet).TotalDays) } else { '-' }
            $u | Add-Member -NotePropertyName 'PasswordAgeDays' -NotePropertyValue $pwdAge -Force
            $allMembers.Add($u)
          }
        } catch {}
      }
    } catch {}
  }

  Write-XYProgress 0.70 'Building output...'

  $displayHeaders = @('#', 'Name', 'Username', 'Privileged Group', 'Enabled', 'Last Logon', 'Pwd Age (Days)', 'Pwd Never Expires')
  $tableRows = @()
  $dataRows = @()
  $idx = 0
  foreach ($u in ($allMembers | Sort-Object GroupName, Name)) {
    $idx++
    $enabled = Format-ADValue -Value $u.Enabled -PropertyName 'Enabled'
    $lastLogon = Format-ADValue -Value $u.LastLogonDate -PropertyName 'LastLogonDate'
    $pwdNeverExpires = Format-ADValue -Value $u.PasswordNeverExpires -PropertyName 'PasswordNeverExpires'
    $tableRows += ,@($idx, $u.Name, $u.SamAccountName, $u.GroupName, $enabled, $lastLogon, $u.PasswordAgeDays, $pwdNeverExpires)
    $dataRows += ,@($u.Name, $u.SamAccountName, $u.GroupName, $enabled, $lastLogon, $u.PasswordAgeDays, $pwdNeverExpires)
  }

  # Deduplicate for unique user count
  $uniqueUsers = @($allMembers | Select-Object -Property SamAccountName -Unique)
  $captionText = "$($allMembers.Count) membership(s) across $($privilegedGroups.Count) groups | $($uniqueUsers.Count) unique privileged user(s)"

  $opts = Get-CommonQueryOpts $Params
  $generatedFiles = @()
  if ($opts.ExportEnabled) {
    $exportHeaders = @('Name', 'Username', 'Privileged Group', 'Enabled', 'Last Logon', 'Pwd Age (Days)', 'Pwd Never Expires')
    $exportPath = Export-ResultsToFile -Rows $dataRows -Headers $exportHeaders `
      -Format $opts.ExportFormat -FileName $opts.ExportFileName -Title 'Privileged Accounts Audit'
    if ($exportPath -and (Test-Path $exportPath)) {
      $generatedFiles += (Get-Item $exportPath).Name
      $captionText += " | Exported: $((Get-Item $exportPath).Name)"
    }
  }

  Write-XY @{ table = @{ title = 'Privileged Accounts Audit'; header = $displayHeaders; rows = $tableRows; caption = $captionText } }

  return [PSCustomObject]@{
    tool = 'Privileged Accounts'; success = $true
    totalMemberships = $allMembers.Count; uniqueUsers = $uniqueUsers.Count
    generatedFiles = $generatedFiles
  }
}

function Invoke-ServiceAccounts {
  param($Params)

  $searchBase = (Get-Param $Params 'searchBase' '').Trim()

  Write-XYProgress 0.15 'Querying accounts with Service Principal Names...'

  $adParams = @{
    Filter     = 'ServicePrincipalNames -like "*"'
    Properties = @('Name', 'SamAccountName', 'Enabled', 'ServicePrincipalNames',
                   'PasswordLastSet', 'LastLogonDate', 'TrustedForDelegation',
                   'TrustedToAuthForDelegation', 'Description', 'Created')
  }
  if ($searchBase) { $adParams.SearchBase = $searchBase }

  $users = @(Get-ADUser @adParams)
  Write-XYProgress 0.40 "Found $($users.Count) user account(s) with SPNs"

  # Also check computer accounts with custom SPNs (beyond default)
  Write-XYProgress 0.45 'Checking computer accounts...'
  $compParams = @{
    Filter     = 'ServicePrincipalNames -like "*"'
    Properties = @('Name', 'SamAccountName', 'Enabled', 'ServicePrincipalNames',
                   'PasswordLastSet', 'LastLogonDate', 'TrustedForDelegation',
                   'TrustedToAuthForDelegation', 'Description', 'Created')
  }
  if ($searchBase) { $compParams.SearchBase = $searchBase }

  # Focus on user service accounts (most relevant for Kerberoasting)
  Write-XYProgress 0.60 'Building output...'

  $displayHeaders = @('#', 'Name', 'Username', 'Enabled', 'SPNs', 'Pwd Last Set', 'Delegation', 'Last Logon')
  $tableRows = @()
  $dataRows = @()
  $idx = 0
  foreach ($u in ($users | Sort-Object Name)) {
    $idx++
    $enabled = Format-ADValue -Value $u.Enabled -PropertyName 'Enabled'
    $spns = Format-ADValue -Value $u.ServicePrincipalNames -PropertyName 'ServicePrincipalNames'
    $pwdSet = Format-ADValue -Value $u.PasswordLastSet -PropertyName 'PasswordLastSet'
    $lastLogon = Format-ADValue -Value $u.LastLogonDate -PropertyName 'LastLogonDate'
    $delegation = @()
    if ($u.TrustedForDelegation) { $delegation += 'Unconstrained' }
    if ($u.TrustedToAuthForDelegation) { $delegation += 'Protocol Transition' }
    $delegStr = if ($delegation.Count -gt 0) { $delegation -join ', ' } else { 'None' }
    $tableRows += ,@($idx, $u.Name, $u.SamAccountName, $enabled, $spns, $pwdSet, $delegStr, $lastLogon)
    $dataRows += ,@($u.Name, $u.SamAccountName, $enabled, $spns, $pwdSet, $delegStr, $lastLogon)
  }

  $captionText = "Found $($users.Count) user service account(s) with SPNs"

  $opts = Get-CommonQueryOpts $Params
  $generatedFiles = @()
  if ($opts.ExportEnabled) {
    $exportHeaders = @('Name', 'Username', 'Enabled', 'SPNs', 'Pwd Last Set', 'Delegation', 'Last Logon')
    $exportPath = Export-ResultsToFile -Rows $dataRows -Headers $exportHeaders `
      -Format $opts.ExportFormat -FileName $opts.ExportFileName -Title 'Service Accounts (SPN)'
    if ($exportPath -and (Test-Path $exportPath)) {
      $generatedFiles += (Get-Item $exportPath).Name
      $captionText += " | Exported: $((Get-Item $exportPath).Name)"
    }
  }

  Write-XY @{ table = @{ title = 'Service Accounts (SPN)'; header = $displayHeaders; rows = $tableRows; caption = $captionText } }

  return [PSCustomObject]@{
    tool = 'Service Accounts'; success = $true
    totalResults = $users.Count; generatedFiles = $generatedFiles
  }
}

function Invoke-DisabledAccounts {
  param($Params)

  $objectType = (Get-Param $Params 'disabledObjectType' 'users').ToLower()
  $searchBase = (Get-Param $Params 'searchBase' '').Trim()

  Write-XYProgress 0.15 "Searching for disabled $objectType..."

  $allResults = [System.Collections.Generic.List[object]]::new()

  if ($objectType -in @('users', 'both')) {
    Write-XYProgress 0.25 'Querying disabled user accounts...'
    $searchParams = @{}
    if ($searchBase) { $searchParams.SearchBase = $searchBase }
    $disabledUsers = @(Search-ADAccount -AccountDisabled -UsersOnly @searchParams -ErrorAction Stop)
    foreach ($d in $disabledUsers) {
      try {
        $u = Get-ADUser -Identity $d.SamAccountName -Properties Name, SamAccountName,
          LastLogonDate, WhenChanged, Description, Created -ErrorAction SilentlyContinue
        if ($u) {
          $u | Add-Member -NotePropertyName 'ObjectType' -NotePropertyValue 'User' -Force
          $allResults.Add($u)
        }
      } catch {}
    }
  }

  if ($objectType -in @('computers', 'both')) {
    Write-XYProgress 0.50 'Querying disabled computer accounts...'
    $searchParams = @{}
    if ($searchBase) { $searchParams.SearchBase = $searchBase }
    $disabledComps = @(Search-ADAccount -AccountDisabled -ComputersOnly @searchParams -ErrorAction Stop)
    foreach ($d in $disabledComps) {
      try {
        $c = Get-ADComputer -Identity $d.SamAccountName -Properties Name, SamAccountName,
          LastLogonDate, WhenChanged, Description, Created, OperatingSystem -ErrorAction SilentlyContinue
        if ($c) {
          $c | Add-Member -NotePropertyName 'ObjectType' -NotePropertyValue 'Computer' -Force
          $allResults.Add($c)
        }
      } catch {}
    }
  }

  Write-XYProgress 0.70 'Building output...'

  $displayHeaders = @('#', 'Name', 'Username', 'Type', 'Last Logon', 'Last Modified', 'Created', 'Description')
  $tableRows = @()
  $dataRows = @()
  $idx = 0
  foreach ($item in ($allResults | Sort-Object WhenChanged -Descending)) {
    $idx++
    $lastLogon = Format-ADValue -Value $item.LastLogonDate -PropertyName 'LastLogonDate'
    $modified = Format-ADValue -Value $item.WhenChanged -PropertyName 'WhenChanged'
    $created = Format-ADValue -Value $item.Created -PropertyName 'Created'
    $desc = if ($item.Description) { $item.Description } else { '-' }
    $tableRows += ,@($idx, $item.Name, $item.SamAccountName, $item.ObjectType, $lastLogon, $modified, $created, $desc)
    $dataRows += ,@($item.Name, $item.SamAccountName, $item.ObjectType, $lastLogon, $modified, $created, $desc)
  }

  $captionText = "Found $($allResults.Count) disabled account(s)"

  $opts = Get-CommonQueryOpts $Params
  $generatedFiles = @()
  if ($opts.ExportEnabled) {
    $exportHeaders = @('Name', 'Username', 'Type', 'Last Logon', 'Last Modified', 'Created', 'Description')
    $exportPath = Export-ResultsToFile -Rows $dataRows -Headers $exportHeaders `
      -Format $opts.ExportFormat -FileName $opts.ExportFileName -Title 'Disabled Accounts'
    if ($exportPath -and (Test-Path $exportPath)) {
      $generatedFiles += (Get-Item $exportPath).Name
      $captionText += " | Exported: $((Get-Item $exportPath).Name)"
    }
  }

  Write-XY @{ table = @{ title = 'Disabled Accounts'; header = $displayHeaders; rows = $tableRows; caption = $captionText } }

  return [PSCustomObject]@{
    tool = 'Disabled Accounts'; success = $true; objectType = $objectType
    totalResults = $allResults.Count; generatedFiles = $generatedFiles
  }
}

function Invoke-PasswordPolicy {
  param($Params)

  Write-XYProgress 0.15 'Querying default domain password policy...'
  $defaultPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop

  $policyRows = @(
    @('Min Password Length', $defaultPolicy.MinPasswordLength),
    @('Password History Count', $defaultPolicy.PasswordHistoryCount),
    @('Max Password Age', $defaultPolicy.MaxPasswordAge.ToString()),
    @('Min Password Age', $defaultPolicy.MinPasswordAge.ToString()),
    @('Complexity Enabled', $(if ($defaultPolicy.ComplexityEnabled) { 'Yes' } else { 'No' })),
    @('Reversible Encryption', $(if ($defaultPolicy.ReversibleEncryptionEnabled) { 'Yes' } else { 'No' })),
    @('Lockout Threshold', $defaultPolicy.LockoutThreshold),
    @('Lockout Duration', $defaultPolicy.LockoutDuration.ToString()),
    @('Lockout Observation Window', $defaultPolicy.LockoutObservationWindow.ToString())
  )

  Write-XY @{ table = @{
    title = 'Default Domain Password Policy'
    header = @('Setting', 'Value')
    rows = $policyRows
    caption = 'Default policy applied to all users unless overridden by FGPP'
  } }

  # Fine-grained password policies
  Write-XYProgress 0.50 'Querying fine-grained password policies...'
  $fgpps = @()
  try {
    $fgpps = @(Get-ADFineGrainedPasswordPolicy -Filter * -Properties * -ErrorAction SilentlyContinue)
  } catch {}

  Write-XYProgress 0.70 'Building output...'

  if ($fgpps.Count -gt 0) {
    $fgppHeaders = @('#', 'Name', 'Precedence', 'Min Length', 'Max Age', 'Complexity', 'Lockout Threshold', 'Applies To')
    $fgppRows = @()
    $dataRows = @()
    $idx = 0
    foreach ($f in ($fgpps | Sort-Object Precedence)) {
      $idx++
      $complexity = if ($f.ComplexityEnabled) { 'Yes' } else { 'No' }
      $appliesTo = '-'
      if ($f.AppliesTo) {
        $subjects = @($f.AppliesTo | ForEach-Object {
          if ($_ -match 'CN=([^,]+)') { $Matches[1] } else { $_ }
        })
        $appliesTo = Format-ADValue -Value $subjects -PropertyName 'AppliesTo'
      }
      $fgppRows += ,@($idx, $f.Name, $f.Precedence, $f.MinPasswordLength, $f.MaxPasswordAge.ToString(), $complexity, $f.LockoutThreshold, $appliesTo)
      $dataRows += ,@($f.Name, $f.Precedence, $f.MinPasswordLength, $f.MaxPasswordAge.ToString(), $complexity, $f.LockoutThreshold, $appliesTo)
    }

    $captionText = "$($fgpps.Count) fine-grained password policy(ies) found"

    $opts = Get-CommonQueryOpts $Params
    $generatedFiles = @()
    if ($opts.ExportEnabled) {
      $exportHeaders = @('Name', 'Precedence', 'Min Length', 'Max Age', 'Complexity', 'Lockout Threshold', 'Applies To')
      $exportPath = Export-ResultsToFile -Rows $dataRows -Headers $exportHeaders `
        -Format $opts.ExportFormat -FileName $opts.ExportFileName -Title 'Password Policies'
      if ($exportPath -and (Test-Path $exportPath)) {
        $generatedFiles += (Get-Item $exportPath).Name
        $captionText += " | Exported: $((Get-Item $exportPath).Name)"
      }
    }

    Write-XY @{ table = @{ title = 'Fine-Grained Password Policies'; header = $fgppHeaders; rows = $fgppRows; caption = $captionText } }
  } else {
    Write-XY @{ table = @{
      title = 'Fine-Grained Password Policies'
      header = @('#', 'Info')
      rows = @(,@(1, 'No fine-grained password policies configured.'))
      caption = ''
    } }
    $generatedFiles = @()
  }

  return [PSCustomObject]@{
    tool = 'Password Policy'; success = $true
    fgppCount = $fgpps.Count; generatedFiles = $generatedFiles
  }
}

#endregion

#region AD Query Functions — v3.0 Infrastructure Tools

function Invoke-ReplicationStatus {
  param($Params)

  Write-XYProgress 0.15 'Querying AD replication status...'

  $replData = @()
  try {
    $replData = @(Get-ADReplicationPartnerMetadata -Target * -Scope Domain -ErrorAction Stop)
  } catch {
    # Fallback: try per-DC
    Write-XYProgress 0.20 'Querying per domain controller...'
    $dcs = @(Get-ADDomainController -Filter * -ErrorAction Stop)
    foreach ($dc in $dcs) {
      try {
        $replData += @(Get-ADReplicationPartnerMetadata -Target $dc.HostName -ErrorAction SilentlyContinue)
      } catch {}
    }
  }

  Write-XYProgress 0.60 "Retrieved $($replData.Count) replication partnership(s)"

  $displayHeaders = @('#', 'Server', 'Partner', 'Partition', 'Last Replication', 'Result', 'Failures')
  $tableRows = @()
  $dataRows = @()
  $idx = 0
  $failureCount = 0
  foreach ($r in ($replData | Sort-Object Server, Partner)) {
    $idx++
    $server = if ($r.Server) { ($r.Server -split '\.')[0] } else { '-' }
    $partner = if ($r.Partner) {
      $partnerStr = [string]$r.Partner
      if ($partnerStr -match 'CN=NTDS Settings,CN=([^,]+)') { $Matches[1] } else { ($partnerStr -split '\.')[0] }
    } else { '-' }
    $partition = if ($r.Partition) {
      $p = [string]$r.Partition
      if ($p -match 'DC=') { ($p -split ',DC=' | Select-Object -First 1) -replace 'DC=', '' }
      else { $p.Substring(0, [Math]::Min(30, $p.Length)) }
    } else { '-' }
    $lastRepl = Format-ADValue -Value $r.LastReplicationSuccess -PropertyName 'LastReplicationSuccess'
    $resultCode = if ($r.LastReplicationResult -eq 0) { 'Success' } else { "Error: $($r.LastReplicationResult)" }
    $failures = if ($null -ne $r.ConsecutiveReplicationFailures) { $r.ConsecutiveReplicationFailures } else { 0 }
    if ($failures -gt 0) { $failureCount++ }
    $tableRows += ,@($idx, $server, $partner, $partition, $lastRepl, $resultCode, $failures)
    $dataRows += ,@($server, $partner, $partition, $lastRepl, $resultCode, $failures)
  }

  $healthStatus = if ($failureCount -eq 0) { 'HEALTHY' } else { "WARNING: $failureCount partnership(s) with failures" }
  $captionText = "$($replData.Count) replication partnership(s) | Status: $healthStatus"

  $opts = Get-CommonQueryOpts $Params
  $generatedFiles = @()
  if ($opts.ExportEnabled) {
    $exportHeaders = @('Server', 'Partner', 'Partition', 'Last Replication', 'Result', 'Failures')
    $exportPath = Export-ResultsToFile -Rows $dataRows -Headers $exportHeaders `
      -Format $opts.ExportFormat -FileName $opts.ExportFileName -Title 'AD Replication Status'
    if ($exportPath -and (Test-Path $exportPath)) {
      $generatedFiles += (Get-Item $exportPath).Name
      $captionText += " | Exported: $((Get-Item $exportPath).Name)"
    }
  }

  Write-XY @{ table = @{ title = 'AD Replication Status'; header = $displayHeaders; rows = $tableRows; caption = $captionText } }

  return [PSCustomObject]@{
    tool = 'Replication Status'; success = $true
    totalPartnerships = $replData.Count; failureCount = $failureCount
    generatedFiles = $generatedFiles
  }
}

function Invoke-SitesAndSubnets {
  param($Params)

  Write-XYProgress 0.15 'Querying AD sites...'
  $sites = @(Get-ADReplicationSite -Filter * -Properties Name, Description, Location, Created -ErrorAction Stop)
  Write-XYProgress 0.35 "Found $($sites.Count) site(s)"

  Write-XYProgress 0.40 'Querying subnets...'
  $subnets = @(Get-ADReplicationSubnet -Filter * -Properties Name, Site, Location, Description -ErrorAction Stop)
  Write-XYProgress 0.55 "Found $($subnets.Count) subnet(s)"

  Write-XYProgress 0.60 'Querying site links...'
  $siteLinks = @(Get-ADReplicationSiteLink -Filter * -Properties Name, Cost, ReplicationFrequencyInMinutes, SitesIncluded -ErrorAction Stop)

  Write-XYProgress 0.70 'Building output...'

  # Sites table
  $displayHeaders = @('#', 'Site Name', 'Location', 'Subnets', 'Site Links', 'Description')
  $tableRows = @()
  $dataRows = @()
  $idx = 0
  foreach ($s in ($sites | Sort-Object Name)) {
    $idx++
    $location = if ($s.Location) { $s.Location } else { '-' }
    $desc = if ($s.Description) { $s.Description } else { '-' }

    # Find subnets for this site
    $siteSubnets = @($subnets | Where-Object {
      $siteDN = [string]$_.Site
      $siteDN -match "CN=$([regex]::Escape($s.Name)),"
    })
    $subnetStr = if ($siteSubnets.Count -gt 0) {
      Format-ADValue -Value @($siteSubnets | ForEach-Object { $_.Name }) -PropertyName 'Subnets'
    } else { '-' }

    # Find site links for this site
    $relatedLinks = @($siteLinks | Where-Object {
      $_.SitesIncluded | Where-Object { $_ -match "CN=$([regex]::Escape($s.Name))," }
    })
    $linkStr = if ($relatedLinks.Count -gt 0) {
      Format-ADValue -Value @($relatedLinks | ForEach-Object { "$($_.Name) (cost:$($_.Cost))" }) -PropertyName 'Links'
    } else { '-' }

    $tableRows += ,@($idx, $s.Name, $location, $subnetStr, $linkStr, $desc)
    $dataRows += ,@($s.Name, $location, $subnetStr, $linkStr, $desc)
  }

  $captionText = "$($sites.Count) site(s) | $($subnets.Count) subnet(s) | $($siteLinks.Count) site link(s)"

  $opts = Get-CommonQueryOpts $Params
  $generatedFiles = @()
  if ($opts.ExportEnabled) {
    $exportHeaders = @('Site Name', 'Location', 'Subnets', 'Site Links', 'Description')
    $exportPath = Export-ResultsToFile -Rows $dataRows -Headers $exportHeaders `
      -Format $opts.ExportFormat -FileName $opts.ExportFileName -Title 'AD Sites and Subnets'
    if ($exportPath -and (Test-Path $exportPath)) {
      $generatedFiles += (Get-Item $exportPath).Name
      $captionText += " | Exported: $((Get-Item $exportPath).Name)"
    }
  }

  Write-XY @{ table = @{ title = 'AD Sites and Subnets'; header = $displayHeaders; rows = $tableRows; caption = $captionText } }

  return [PSCustomObject]@{
    tool = 'Sites & Subnets'; success = $true
    totalSites = $sites.Count; totalSubnets = $subnets.Count; totalSiteLinks = $siteLinks.Count
    generatedFiles = $generatedFiles
  }
}

function Invoke-TrustRelationships {
  param($Params)

  Write-XYProgress 0.20 'Querying domain trust relationships...'

  $trusts = @(Get-ADTrust -Filter * -Properties * -ErrorAction Stop)
  Write-XYProgress 0.60 "Found $($trusts.Count) trust(s)"

  if ($trusts.Count -eq 0) {
    Write-XY @{ table = @{
      title = 'Trust Relationships'
      header = @('#', 'Info')
      rows = @(,@(1, 'No trust relationships found.'))
      caption = ''
    } }
    return [PSCustomObject]@{ tool = 'Trust Relationships'; success = $true; totalResults = 0; generatedFiles = @() }
  }

  $displayHeaders = @('#', 'Trust Name', 'Direction', 'Trust Type', 'Transitive', 'Forest Trust', 'Selective Auth', 'Created')
  $tableRows = @()
  $dataRows = @()
  $idx = 0
  foreach ($t in ($trusts | Sort-Object Name)) {
    $idx++
    $directionMap = @{ '1' = 'Inbound'; '2' = 'Outbound'; '3' = 'BiDirectional' }
    $direction = if ($directionMap.ContainsKey([string][int]$t.Direction)) { $directionMap[[string][int]$t.Direction] } else { [string]$t.Direction }
    $typeMap = @{ '1' = 'Downlevel'; '2' = 'Uplevel'; '3' = 'MIT'; '4' = 'DCE' }
    $trustType = if ($typeMap.ContainsKey([string][int]$t.TrustType)) { $typeMap[[string][int]$t.TrustType] } else { [string]$t.TrustType }
    $transitive = if ($t.IsTreeParent -or $t.IsTreeChild) { 'Yes (Tree)' }
                  elseif ($t.PSObject.Properties.Name -contains 'TrustAttributes' -and ($t.TrustAttributes -band 1)) { 'Non-Transitive' }
                  else { 'Transitive' }
    $forestTrust = if ($t.ForestTransitive) { 'Yes' } else { 'No' }
    $selectiveAuth = if ($t.SelectiveAuthentication) { 'Yes' } else { 'No' }
    $created = Format-ADValue -Value $t.Created -PropertyName 'Created'
    $tableRows += ,@($idx, $t.Name, $direction, $trustType, $transitive, $forestTrust, $selectiveAuth, $created)
    $dataRows += ,@($t.Name, $direction, $trustType, $transitive, $forestTrust, $selectiveAuth, $created)
  }

  $captionText = "$($trusts.Count) trust relationship(s)"

  $opts = Get-CommonQueryOpts $Params
  $generatedFiles = @()
  if ($opts.ExportEnabled) {
    $exportHeaders = @('Trust Name', 'Direction', 'Trust Type', 'Transitive', 'Forest Trust', 'Selective Auth', 'Created')
    $exportPath = Export-ResultsToFile -Rows $dataRows -Headers $exportHeaders `
      -Format $opts.ExportFormat -FileName $opts.ExportFileName -Title 'Trust Relationships'
    if ($exportPath -and (Test-Path $exportPath)) {
      $generatedFiles += (Get-Item $exportPath).Name
      $captionText += " | Exported: $((Get-Item $exportPath).Name)"
    }
  }

  Write-XY @{ table = @{ title = 'Trust Relationships'; header = $displayHeaders; rows = $tableRows; caption = $captionText } }

  return [PSCustomObject]@{
    tool = 'Trust Relationships'; success = $true
    totalResults = $trusts.Count; generatedFiles = $generatedFiles
  }
}

function Invoke-GPOOverview {
  param($Params)

  Assert-GroupPolicyModule

  Write-XYProgress 0.15 'Querying Group Policy Objects...'
  $gpos = @(Get-GPO -All -ErrorAction Stop)
  Write-XYProgress 0.40 "Found $($gpos.Count) GPO(s)"

  Write-XYProgress 0.45 'Gathering link information...'

  $displayHeaders = @('#', 'Display Name', 'Status', 'Created', 'Modified', 'Computer Ver.', 'User Ver.', 'Links')
  $tableRows = @()
  $dataRows = @()
  $idx = 0
  $gpoTotal = $gpos.Count
  foreach ($g in ($gpos | Sort-Object DisplayName)) {
    $idx++
    if ($idx % 10 -eq 0) {
      $pct = 0.45 + (0.25 * $idx / $gpoTotal)
      Write-XYProgress $pct "Processing GPO $idx of $gpoTotal..."
    }

    $statusMap = @{
      'AllSettingsDisabled' = 'All Disabled'
      'AllSettingsEnabled'  = 'Enabled'
      'UserSettingsDisabled' = 'User Disabled'
      'ComputerSettingsDisabled' = 'Computer Disabled'
    }
    $status = if ($statusMap.ContainsKey([string]$g.GpoStatus)) { $statusMap[[string]$g.GpoStatus] } else { [string]$g.GpoStatus }
    $created = Format-ADValue -Value $g.CreationTime -PropertyName 'CreationTime'
    $modified = Format-ADValue -Value $g.ModificationTime -PropertyName 'ModificationTime'
    $compVer = try { "$($g.Computer.DSVersion)/$($g.Computer.SysvolVersion)" } catch { '-' }
    $userVer = try { "$($g.User.DSVersion)/$($g.User.SysvolVersion)" } catch { '-' }

    # Get links via GPO report
    $links = '-'
    try {
      $xmlReport = [xml](Get-GPOReport -Guid $g.Id -ReportType Xml -ErrorAction SilentlyContinue)
      $linkNodes = $xmlReport.GPO.LinksTo
      if ($linkNodes) {
        $linkNames = @($linkNodes | ForEach-Object { $_.SOMPath })
        $links = Format-ADValue -Value $linkNames -PropertyName 'Links'
      }
    } catch {}

    $tableRows += ,@($idx, $g.DisplayName, $status, $created, $modified, $compVer, $userVer, $links)
    $dataRows += ,@($g.DisplayName, $status, $created, $modified, $compVer, $userVer, $links)
  }

  $captionText = "$($gpos.Count) Group Policy Object(s)"

  $opts = Get-CommonQueryOpts $Params
  $generatedFiles = @()
  if ($opts.ExportEnabled) {
    $exportHeaders = @('Display Name', 'Status', 'Created', 'Modified', 'Computer Ver.', 'User Ver.', 'Links')
    $exportPath = Export-ResultsToFile -Rows $dataRows -Headers $exportHeaders `
      -Format $opts.ExportFormat -FileName $opts.ExportFileName -Title 'GPO Overview'
    if ($exportPath -and (Test-Path $exportPath)) {
      $generatedFiles += (Get-Item $exportPath).Name
      $captionText += " | Exported: $((Get-Item $exportPath).Name)"
    }
  }

  Write-XY @{ table = @{ title = 'Group Policy Objects'; header = $displayHeaders; rows = $tableRows; caption = $captionText } }

  return [PSCustomObject]@{
    tool = 'GPO Overview'; success = $true
    totalResults = $gpos.Count; generatedFiles = $generatedFiles
  }
}

#endregion

#region AD Query Functions — v3.0 Operational Tools

function Invoke-UserDetail {
  param($Params)

  $targetUser = (Get-Param $Params 'targetUser' '').Trim()
  if (-not $targetUser) { throw 'No target user specified. Provide a SamAccountName or Distinguished Name.' }

  Write-XYProgress 0.15 "Looking up user '$targetUser'..."
  $user = Get-ADUser -Identity $targetUser -Properties * -ErrorAction Stop
  Write-XYProgress 0.35 "Found user: $($user.Name)"

  # Identity section
  $identityRows = @(
    @('Display Name', $(if ($user.DisplayName) { $user.DisplayName } else { '-' })),
    @('Username', $user.SamAccountName),
    @('UPN', $(if ($user.UserPrincipalName) { $user.UserPrincipalName } else { '-' })),
    @('SID', $user.SID.ToString()),
    @('Distinguished Name', $user.DistinguishedName),
    @('Object GUID', $user.ObjectGUID.ToString())
  )

  # Organization section
  $orgRows = @(
    @('Title', $(if ($user.Title) { $user.Title } else { '-' })),
    @('Department', $(if ($user.Department) { $user.Department } else { '-' })),
    @('Company', $(if ($user.Company) { $user.Company } else { '-' })),
    @('Office', $(if ($user.Office) { $user.Office } else { '-' })),
    @('Manager', $(Format-ADValue -Value $user.Manager -PropertyName 'Manager')),
    @('Phone', $(if ($user.TelephoneNumber) { $user.TelephoneNumber } else { '-' })),
    @('Email', $(if ($user.EmailAddress) { $user.EmailAddress } else { '-' }))
  )

  # Account status section
  $accountRows = @(
    @('Enabled', $(Format-ADValue -Value $user.Enabled -PropertyName 'Enabled')),
    @('Locked Out', $(Format-ADValue -Value $user.LockedOut -PropertyName 'LockedOut')),
    @('Created', $(Format-ADValue -Value $user.Created -PropertyName 'Created')),
    @('Last Modified', $(Format-ADValue -Value $user.WhenChanged -PropertyName 'WhenChanged')),
    @('Last Logon', $(Format-ADValue -Value $user.LastLogonDate -PropertyName 'LastLogonDate')),
    @('Logon Count', $(if ($null -ne $user.logonCount) { $user.logonCount } else { '-' })),
    @('Bad Pwd Count', $(if ($null -ne $user.BadLogonCount) { $user.BadLogonCount } else { '-' })),
    @('Password Last Set', $(Format-ADValue -Value $user.PasswordLastSet -PropertyName 'PasswordLastSet')),
    @('Password Never Expires', $(Format-ADValue -Value $user.PasswordNeverExpires -PropertyName 'PasswordNeverExpires')),
    @('Password Expired', $(Format-ADValue -Value $user.PasswordExpired -PropertyName 'PasswordExpired')),
    @('Account Expires', $(Format-ADValue -Value $user.AccountExpirationDate -PropertyName 'AccountExpirationDate')),
    @('Description', $(if ($user.Description) { $user.Description } else { '-' }))
  )

  # Emit identity table
  Write-XY @{ table = @{ title = "User Detail — $($user.Name) (Identity)"; header = @('Property', 'Value'); rows = $identityRows; caption = '' } }
  Write-XY @{ table = @{ title = "User Detail — $($user.Name) (Organization)"; header = @('Property', 'Value'); rows = $orgRows; caption = '' } }

  # Group memberships
  Write-XYProgress 0.60 'Retrieving group memberships...'
  $groups = @()
  try { $groups = @(Get-ADPrincipalGroupMembership -Identity $user -ErrorAction SilentlyContinue) } catch {}
  $groupNames = @($groups | ForEach-Object { $_.Name } | Sort-Object)
  $groupStr = if ($groupNames.Count -gt 0) { $groupNames -join ', ' } else { 'None' }
  $accountRows += @(,@('Group Memberships', "$($groupNames.Count) group(s): $groupStr"))

  # Direct reports
  Write-XYProgress 0.70 'Checking direct reports...'
  $directReports = @()
  try { $directReports = @(Get-ADUser -Filter "Manager -eq '$($user.DistinguishedName)'" -Properties Name -ErrorAction SilentlyContinue) } catch {}
  $reportsStr = if ($directReports.Count -gt 0) {
    $reportNames = @($directReports | ForEach-Object { $_.Name } | Sort-Object)
    Format-ADValue -Value $reportNames -PropertyName 'DirectReports'
  } else { 'None' }
  $accountRows += @(,@('Direct Reports', "$($directReports.Count): $reportsStr"))

  $captionText = "$($groupNames.Count) group(s) | $($directReports.Count) direct report(s)"

  # Export all sections combined
  $opts = Get-CommonQueryOpts $Params
  $generatedFiles = @()
  $allDataRows = @()
  $allDataRows += @(,@('--- Identity ---', ''))
  $allDataRows += $identityRows
  $allDataRows += @(,@('--- Organization ---', ''))
  $allDataRows += $orgRows
  $allDataRows += @(,@('--- Account Status ---', ''))
  $allDataRows += $accountRows

  if ($opts.ExportEnabled) {
    $exportHeaders = @('Property', 'Value')
    $exportPath = Export-ResultsToFile -Rows $allDataRows -Headers $exportHeaders `
      -Format $opts.ExportFormat -FileName $opts.ExportFileName -Title "User Detail - $($user.SamAccountName)"
    if ($exportPath -and (Test-Path $exportPath)) {
      $generatedFiles += (Get-Item $exportPath).Name
      $captionText += " | Exported: $((Get-Item $exportPath).Name)"
    }
  }

  # Account status is the last table (shown in gridview)
  Write-XY @{ table = @{ title = "User Detail — $($user.Name) (Account)"; header = @('Property', 'Value'); rows = $accountRows; caption = $captionText } }

  return [PSCustomObject]@{
    tool = 'User Detail'; success = $true; targetUser = $user.SamAccountName
    groupCount = $groupNames.Count; groups = $groupNames
    directReports = $directReports.Count
    generatedFiles = $generatedFiles
  }
}

function Invoke-RecentChanges {
  param($Params)

  $changeDaysStr = (Get-Param $Params 'changeDays' '7').ToString().Trim()
  $changeDays = 7
  if ($changeDaysStr -match '^\d+$') { $changeDays = [int]$changeDaysStr }
  $changeDays = [Math]::Max(1, $changeDays)

  $changeType = (Get-Param $Params 'changeType' 'both').ToLower()
  $objectType = (Get-Param $Params 'changeObjectType' 'all').ToLower()
  $searchBase = (Get-Param $Params 'searchBase' '').Trim()
  $maxResultsStr = (Get-Param $Params 'maxResults' '500').ToString().Trim()
  $maxResults = 500
  if ($maxResultsStr -match '^\d+$') { $maxResults = [int]$maxResultsStr }
  $maxResults = [Math]::Min(10000, [Math]::Max(1, $maxResults))

  $cutoff = (Get-Date).AddDays(-$changeDays).ToString('yyyy-MM-ddTHH:mm:ss')

  Write-XYProgress 0.15 "Finding objects changed in the last $changeDays day(s)..."

  $filters = @()
  if ($changeType -eq 'created') {
    $filters += "WhenCreated -ge '$cutoff'"
  } elseif ($changeType -eq 'modified') {
    $filters += "WhenChanged -ge '$cutoff'"
  } else {
    # both: modified is superset of created
    $filters += "WhenChanged -ge '$cutoff'"
  }

  # Object class filter
  $classFilter = switch ($objectType) {
    'users'     { "objectClass -eq 'user'" }
    'groups'    { "objectClass -eq 'group'" }
    'computers' { "objectClass -eq 'computer'" }
    default     { $null }
  }
  if ($classFilter) { $filters += $classFilter }

  $filterStr = $filters -join ' -and '

  $adParams = @{
    Filter        = $filterStr
    Properties    = @('Name', 'ObjectClass', 'WhenCreated', 'WhenChanged', 'Description', 'DistinguishedName')
    ResultSetSize = $maxResults
  }
  if ($searchBase) { $adParams.SearchBase = $searchBase }

  $results = @(Get-ADObject @adParams)
  Write-XYProgress 0.55 "Found $($results.Count) object(s)"

  # Determine if each was created or modified within the window
  $cutoffDate = (Get-Date).AddDays(-$changeDays)

  Write-XYProgress 0.65 'Building output...'

  $displayHeaders = @('#', 'Name', 'Type', 'Action', 'When Created', 'When Modified', 'Description')
  $tableRows = @()
  $dataRows = @()
  $idx = 0
  foreach ($item in ($results | Sort-Object WhenChanged -Descending)) {
    $idx++
    $action = if ($item.WhenCreated -ge $cutoffDate) { 'Created' } else { 'Modified' }
    $created = Format-ADValue -Value $item.WhenCreated -PropertyName 'WhenCreated'
    $modified = Format-ADValue -Value $item.WhenChanged -PropertyName 'WhenChanged'
    $desc = if ($item.Description) { $item.Description } else { '-' }
    $objClass = (Get-Culture).TextInfo.ToTitleCase([string]$item.ObjectClass)
    $tableRows += ,@($idx, $item.Name, $objClass, $action, $created, $modified, $desc)
    $dataRows += ,@($item.Name, $objClass, $action, $created, $modified, $desc)
  }

  $captionText = "$($results.Count) object(s) changed in the last $changeDays day(s)"

  $opts = Get-CommonQueryOpts $Params
  $generatedFiles = @()
  if ($opts.ExportEnabled) {
    $exportHeaders = @('Name', 'Type', 'Action', 'When Created', 'When Modified', 'Description')
    $exportPath = Export-ResultsToFile -Rows $dataRows -Headers $exportHeaders `
      -Format $opts.ExportFormat -FileName $opts.ExportFileName -Title "Recent AD Changes ($changeDays days)"
    if ($exportPath -and (Test-Path $exportPath)) {
      $generatedFiles += (Get-Item $exportPath).Name
      $captionText += " | Exported: $((Get-Item $exportPath).Name)"
    }
  }

  Write-XY @{ table = @{ title = "Recent AD Changes ($changeDays Days)"; header = $displayHeaders; rows = $tableRows; caption = $captionText } }

  return [PSCustomObject]@{
    tool = 'Recent Changes'; success = $true; changeDays = $changeDays
    changeType = $changeType; objectType = $objectType
    totalResults = $results.Count; generatedFiles = $generatedFiles
  }
}

function Invoke-AccountExpiration {
  param($Params)

  $expiryDaysStr = (Get-Param $Params 'accountExpiryDays' '30').ToString().Trim()
  $expiryDays = 30
  if ($expiryDaysStr -match '^\d+$') { $expiryDays = [int]$expiryDaysStr }
  $expiryDays = [Math]::Max(1, $expiryDays)

  $searchBase = (Get-Param $Params 'searchBase' '').Trim()

  Write-XYProgress 0.20 "Finding accounts expiring within $expiryDays days..."

  $searchParams = @{}
  if ($searchBase) { $searchParams.SearchBase = $searchBase }

  $expiring = @(Search-ADAccount -AccountExpiring -TimeSpan (New-TimeSpan -Days $expiryDays) -UsersOnly @searchParams -ErrorAction Stop)
  Write-XYProgress 0.50 "Found $($expiring.Count) expiring account(s)"

  # Get details
  $detailed = [System.Collections.Generic.List[object]]::new()
  foreach ($e in $expiring) {
    try {
      $u = Get-ADUser -Identity $e.SamAccountName -Properties Name, SamAccountName, Enabled,
        AccountExpirationDate, Department, Title, LastLogonDate, EmailAddress -ErrorAction SilentlyContinue
      if ($u) { $detailed.Add($u) }
    } catch {}
  }

  Write-XYProgress 0.70 'Building output...'

  $now = Get-Date
  $displayHeaders = @('#', 'Name', 'Username', 'Email', 'Department', 'Expires', 'Days Left', 'Enabled')
  $tableRows = @()
  $dataRows = @()
  $idx = 0
  foreach ($u in ($detailed | Sort-Object AccountExpirationDate)) {
    $idx++
    $email = if ($u.EmailAddress) { $u.EmailAddress } else { '-' }
    $dept = if ($u.Department) { $u.Department } else { '-' }
    $expires = Format-ADValue -Value $u.AccountExpirationDate -PropertyName 'AccountExpirationDate'
    $daysLeft = if ($u.AccountExpirationDate) {
      $d = [Math]::Floor(($u.AccountExpirationDate - $now).TotalDays)
      if ($d -lt 0) { "EXPIRED ($($d)d)" } elseif ($d -eq 0) { 'TODAY' } else { "$($d)d" }
    } else { '-' }
    $enabled = Format-ADValue -Value $u.Enabled -PropertyName 'Enabled'
    $tableRows += ,@($idx, $u.Name, $u.SamAccountName, $email, $dept, $expires, $daysLeft, $enabled)
    $dataRows += ,@($u.Name, $u.SamAccountName, $email, $dept, $expires, $daysLeft, $enabled)
  }

  $captionText = "$($detailed.Count) account(s) expiring within $expiryDays day(s)"

  $opts = Get-CommonQueryOpts $Params
  $generatedFiles = @()
  if ($opts.ExportEnabled) {
    $exportHeaders = @('Name', 'Username', 'Email', 'Department', 'Expires', 'Days Left', 'Enabled')
    $exportPath = Export-ResultsToFile -Rows $dataRows -Headers $exportHeaders `
      -Format $opts.ExportFormat -FileName $opts.ExportFileName -Title "Account Expiration ($expiryDays days)"
    if ($exportPath -and (Test-Path $exportPath)) {
      $generatedFiles += (Get-Item $exportPath).Name
      $captionText += " | Exported: $((Get-Item $exportPath).Name)"
    }
  }

  Write-XY @{ table = @{ title = "Account Expiration ($expiryDays Days)"; header = $displayHeaders; rows = $tableRows; caption = $captionText } }

  return [PSCustomObject]@{
    tool = 'Account Expiration'; success = $true; expiryDays = $expiryDays
    totalResults = $detailed.Count; generatedFiles = $generatedFiles
  }
}

function Invoke-DuplicateSPNs {
  param($Params)

  Write-XYProgress 0.15 'Scanning all accounts for Service Principal Names...'

  # Get all objects with SPNs
  $allWithSPN = @(Get-ADObject -LDAPFilter '(servicePrincipalName=*)' `
    -Properties Name, SamAccountName, ServicePrincipalName, ObjectClass -ErrorAction Stop)
  Write-XYProgress 0.40 "Found $($allWithSPN.Count) object(s) with SPNs"

  # Build SPN -> account mapping
  Write-XYProgress 0.50 'Analyzing for duplicates...'
  $spnMap = @{}
  foreach ($obj in $allWithSPN) {
    $accountName = if ($obj.SamAccountName) { $obj.SamAccountName } else { $obj.Name }
    foreach ($spn in @($obj.ServicePrincipalName)) {
      $spnLower = [string]$spn.ToLower()
      if (-not $spnMap.ContainsKey($spnLower)) {
        $spnMap[$spnLower] = [System.Collections.Generic.List[string]]::new()
      }
      $spnMap[$spnLower].Add("$accountName ($($obj.ObjectClass))")
    }
  }

  # Filter for duplicates
  $duplicates = @($spnMap.GetEnumerator() | Where-Object { $_.Value.Count -gt 1 })
  Write-XYProgress 0.70 "Found $($duplicates.Count) duplicate SPN(s)"

  $displayHeaders = @('#', 'SPN', 'Registered On', 'Count')
  $tableRows = @()
  $dataRows = @()
  $idx = 0
  foreach ($d in ($duplicates | Sort-Object { $_.Key })) {
    $idx++
    $accounts = $d.Value -join '; '
    $tableRows += ,@($idx, $d.Key, $accounts, $d.Value.Count)
    $dataRows += ,@($d.Key, $accounts, $d.Value.Count)
  }

  $totalSPNs = ($spnMap.Keys).Count
  $healthStatus = if ($duplicates.Count -eq 0) { 'HEALTHY — No duplicates found' } else { "WARNING — $($duplicates.Count) duplicate(s) detected" }
  $captionText = "$totalSPNs unique SPN(s) scanned | $healthStatus"

  if ($duplicates.Count -eq 0) {
    $tableRows = @(,@(1, 'No duplicate SPNs found', '-', 0))
  }

  $opts = Get-CommonQueryOpts $Params
  $generatedFiles = @()
  if ($opts.ExportEnabled) {
    $exportHeaders = @('SPN', 'Registered On', 'Count')
    $exportPath = Export-ResultsToFile -Rows $dataRows -Headers $exportHeaders `
      -Format $opts.ExportFormat -FileName $opts.ExportFileName -Title 'Duplicate SPNs'
    if ($exportPath -and (Test-Path $exportPath)) {
      $generatedFiles += (Get-Item $exportPath).Name
      $captionText += " | Exported: $((Get-Item $exportPath).Name)"
    }
  }

  Write-XY @{ table = @{ title = 'Duplicate SPN Analysis'; header = $displayHeaders; rows = $tableRows; caption = $captionText } }

  return [PSCustomObject]@{
    tool = 'Duplicate SPNs'; success = $true
    totalSPNs = $totalSPNs; duplicateCount = $duplicates.Count
    generatedFiles = $generatedFiles
  }
}

#endregion

#region Export Functions

function Export-ResultsToFile {
  param(
    [array]$Rows,
    [array]$Headers,
    [string]$Format,
    [string]$FileName,
    [string]$Title
  )

  $extensionMap = @{ 'csv' = '.csv'; 'markdown' = '.md'; 'html' = '.html'; 'xlsx' = '.xlsx' }
  $extension = if ($extensionMap.ContainsKey($Format)) { $extensionMap[$Format] } else { '.csv' }

  $cleanName = $FileName -replace '\.(csv|md|html|xlsx)$', ''
  $fileName = "$cleanName$extension"
  $outputPath = Join-Path (Get-Location).Path $fileName

  switch ($Format) {
    'csv'      { Export-ToCsv -Rows $Rows -Headers $Headers -OutputPath $outputPath }
    'markdown' { Export-ToMarkdown -Rows $Rows -Headers $Headers -OutputPath $outputPath -Title $Title }
    'html'     { Export-ToHtml -Rows $Rows -Headers $Headers -OutputPath $outputPath -Title $Title }
    'xlsx'     { Export-ToXlsx -Rows $Rows -Headers $Headers -OutputPath $outputPath -Title $Title }
    default    { Export-ToCsv -Rows $Rows -Headers $Headers -OutputPath $outputPath }
  }

  return $outputPath
}

function Export-ToCsv {
  param([array]$Rows, [array]$Headers, [string]$OutputPath)

  $sb = [System.Text.StringBuilder]::new()
  [void]$sb.AppendLine(($Headers | ForEach-Object { "`"$_`"" }) -join ',')
  foreach ($row in $Rows) {
    $escaped = $row | ForEach-Object { "`"$([string]$_ -replace '"', '""')`"" }
    [void]$sb.AppendLine($escaped -join ',')
  }
  $sb.ToString() | Out-File -FilePath $OutputPath -Encoding UTF8
}

function Export-ToMarkdown {
  param([array]$Rows, [array]$Headers, [string]$OutputPath, [string]$Title)

  $sb = [System.Text.StringBuilder]::new()
  [void]$sb.AppendLine("# $Title")
  [void]$sb.AppendLine('')
  [void]$sb.AppendLine("*Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')*")
  [void]$sb.AppendLine('')
  [void]$sb.Append((Format-MarkdownTable -Headers $Headers -Rows $Rows))
  [void]$sb.AppendLine('')
  [void]$sb.AppendLine("*Total: $($Rows.Count) item(s)*")
  $sb.ToString() | Out-File -FilePath $OutputPath -Encoding UTF8
}

function Export-ToHtml {
  param([array]$Rows, [array]$Headers, [string]$OutputPath, [string]$Title)

  $sb = [System.Text.StringBuilder]::new()
  [void]$sb.AppendLine('<!DOCTYPE html><html><head><meta charset="utf-8">')
  [void]$sb.AppendLine("<title>$([System.Web.HttpUtility]::HtmlEncode($Title))</title>")
  [void]$sb.AppendLine('<style>')
  [void]$sb.AppendLine('body{font-family:Segoe UI,Arial,sans-serif;margin:20px;background:#f5f5f5;color:#333}')
  [void]$sb.AppendLine('h1{color:#5b21b6;border-bottom:2px solid #5b21b6;padding-bottom:8px}')
  [void]$sb.AppendLine('table{border-collapse:collapse;width:100%;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.1)}')
  [void]$sb.AppendLine('th{background:#5b21b6;color:#fff;padding:10px 12px;text-align:left;font-weight:600}')
  [void]$sb.AppendLine('td{padding:8px 12px;border-bottom:1px solid #e5e7eb}')
  [void]$sb.AppendLine('tr:nth-child(even){background:#f9fafb}')
  [void]$sb.AppendLine('tr:hover{background:#ede9fe}')
  [void]$sb.AppendLine('.meta{color:#6b7280;font-size:.85em;margin:8px 0}')
  [void]$sb.AppendLine('</style></head><body>')
  [void]$sb.AppendLine("<h1>$([System.Web.HttpUtility]::HtmlEncode($Title))</h1>")
  [void]$sb.AppendLine("<p class='meta'>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Total: $($Rows.Count) item(s)</p>")
  [void]$sb.AppendLine('<table><thead><tr>')
  foreach ($h in $Headers) { [void]$sb.Append("<th>$([System.Web.HttpUtility]::HtmlEncode($h))</th>") }
  [void]$sb.AppendLine('</tr></thead><tbody>')
  foreach ($row in $Rows) {
    [void]$sb.Append('<tr>')
    foreach ($cell in $row) { [void]$sb.Append("<td>$([System.Web.HttpUtility]::HtmlEncode([string]$cell))</td>") }
    [void]$sb.AppendLine('</tr>')
  }
  [void]$sb.AppendLine('</tbody></table></body></html>')
  $sb.ToString() | Out-File -FilePath $OutputPath -Encoding UTF8
}

function Export-ToXlsx {
  param([array]$Rows, [array]$Headers, [string]$OutputPath, [string]$Title)

  Install-ImportExcelModule

  # Build objects for ImportExcel
  $objects = [System.Collections.Generic.List[object]]::new()
  foreach ($row in $Rows) {
    $obj = [ordered]@{}
    for ($i = 0; $i -lt $Headers.Count; $i++) {
      $val = if ($i -lt $row.Count) { $row[$i] } else { '' }
      $obj[$Headers[$i]] = $val
    }
    $objects.Add([pscustomobject]$obj)
  }

  $xlParams = @{
    Path          = $OutputPath
    WorksheetName = $Title.Substring(0, [Math]::Min(31, $Title.Length))
    AutoSize      = $true
    FreezeTopRow  = $true
    BoldTopRow    = $true
    TableStyle    = 'Medium6'
  }

  $objects | Export-Excel @xlParams
}

#endregion

#region Emit List Results Helper

function Emit-ListResults {
  param(
    [array]$RawResults,
    [hashtable]$FieldDef,
    [string]$ObjectType,
    [string]$TypeName,
    [hashtable]$Opts
  )

  if ($null -eq $RawResults) { $RawResults = @() }
  $RawResults = @($RawResults)

  Write-XYProgress 0.55 "Processing $($RawResults.Count) result(s)..."

  $tableOutput = Build-TableOutput -RawResults $RawResults -FieldDef $FieldDef `
    -ObjectType $ObjectType -Title "Active Directory $TypeName" -QueryOpts $Opts

  Write-XYProgress 0.70 'Building output...'

  # Build caption
  $searchInfo = @()
  if ($Opts.SearchBase) { $searchInfo += "OU: $($Opts.SearchBase)" }
  if ($Opts.NameFilter) { $searchInfo += "Filter: $($Opts.NameFilter)" }
  if ($Opts.EnabledOnly -and $ObjectType -in @('users', 'computers')) { $searchInfo += 'Enabled only' }
  $searchInfo += "Scope: $($Opts.SearchScope)"
  $searchInfo += "Fields: $((Get-Culture).TextInfo.ToTitleCase($Opts.FieldSet))"
  $captionText = "Found $($tableOutput.SortedResults.Count) $($TypeName.ToLower()) | $($searchInfo -join ' | ')"

  # Export
  $generatedFiles = @()
  if ($Opts.ExportEnabled) {
    Write-XYProgress 0.85 "Exporting to $($Opts.ExportFormat.ToUpper())..."
    $title = "Active Directory $TypeName"
    $exportPath = Export-ResultsToFile -Rows $tableOutput.DataRows -Headers $tableOutput.ExportHeaders `
      -Format $Opts.ExportFormat -FileName $Opts.ExportFileName -Title $title
    if (Test-Path $exportPath) {
      $fileInfo = Get-Item $exportPath
      $generatedFiles += $fileInfo.Name
      $sizeStr = if ($fileInfo.Length -ge 1MB) { "{0:N2} MB" -f ($fileInfo.Length / 1MB) }
                 elseif ($fileInfo.Length -ge 1KB) { "{0:N2} KB" -f ($fileInfo.Length / 1KB) }
                 else { "$($fileInfo.Length) B" }
      $captionText += " | Exported: $($fileInfo.Name) ($sizeStr)"
    }
  }

  # Emit table
  Write-XY @{ table = @{
    title   = "Active Directory $TypeName"
    header  = $tableOutput.DisplayHeaders
    rows    = $tableOutput.TableRows
    caption = $captionText
  } }

  Write-XYProgress 0.95 'Completed'

  return [PSCustomObject]@{
    tool            = "List $TypeName"
    success         = $true
    objectType      = $ObjectType
    fieldSet        = $Opts.FieldSet
    totalResults    = $tableOutput.SortedResults.Count
    items           = $tableOutput.OutputItems.ToArray()
    fields          = $FieldDef.Fields
    timestamp       = (Get-Date).ToString('o')
    generatedFiles  = $generatedFiles
  }
}

#endregion

#region Main Entry Point

try {
  $job = Read-JobFromStdin
  $Params = $job.params
  $tool = if ($Params.PSObject.Properties.Name -contains 'tool') { $Params.tool } else { 'listUsers' }
  $Cwd = if ($job.PSObject.Properties.Name -contains 'cwd') { $job.cwd } else { $null }
  if ($Cwd -and (Test-Path $Cwd -PathType Container)) { Set-Location $Cwd }

  Write-XYProgress 0.02 'Starting AD Info...'

  # Check AD module
  Assert-ActiveDirectoryModule

  $result = $null
  switch ($tool) {
    'listUsers'       { $result = Invoke-ADUserList -Params $Params }
    'listGroups'      { $result = Invoke-ADGroupList -Params $Params }
    'listComputers'   { $result = Invoke-ADComputerList -Params $Params }
    'listOUs'         { $result = Invoke-ADOUList -Params $Params }
    'groupMembership' { $result = Invoke-GroupMembership -Params $Params }
    'groupMembers'    { $result = Invoke-GroupMembers -Params $Params }
    'staleAccounts'   { $result = Invoke-StaleAccounts -Params $Params }
    'passwordExpiry'  { $result = Invoke-PasswordExpiry -Params $Params }
    'lockedAccounts'  { $result = Invoke-LockedAccounts -Params $Params }
    'emptyGroups'     { $result = Invoke-EmptyGroups -Params $Params }
    'domainInfo'      { $result = Invoke-DomainInfo -Params $Params }
    'ldapQuery'       { $result = Invoke-LdapQuery -Params $Params }
    'compareOUs'          { $result = Invoke-CompareOUs -Params $Params }
    'privilegedAccounts'  { $result = Invoke-PrivilegedAccounts -Params $Params }
    'serviceAccounts'     { $result = Invoke-ServiceAccounts -Params $Params }
    'disabledAccounts'    { $result = Invoke-DisabledAccounts -Params $Params }
    'passwordPolicy'      { $result = Invoke-PasswordPolicy -Params $Params }
    'replicationStatus'   { $result = Invoke-ReplicationStatus -Params $Params }
    'sitesAndSubnets'     { $result = Invoke-SitesAndSubnets -Params $Params }
    'trustRelationships'  { $result = Invoke-TrustRelationships -Params $Params }
    'gpoOverview'         { $result = Invoke-GPOOverview -Params $Params }
    'userDetail'          { $result = Invoke-UserDetail -Params $Params }
    'recentChanges'       { $result = Invoke-RecentChanges -Params $Params }
    'accountExpiration'   { $result = Invoke-AccountExpiration -Params $Params }
    'duplicateSPNs'       { $result = Invoke-DuplicateSPNs -Params $Params }
    default               { throw "Unknown tool: $tool" }
  }

  # Ensure generatedFiles is an array
  $filesArray = @()
  if ($result.PSObject.Properties['generatedFiles'] -and $result.generatedFiles) {
    $filesArray = @($result.generatedFiles)
  }

  $desc = if ($result.PSObject.Properties['totalResults']) {
    "$($result.tool): $($result.totalResults) result(s)"
  } else {
    "$($result.tool) completed successfully"
  }

  Write-XYSuccess -Data $result -Files $filesArray -Description $desc
  exit 0
}
catch {
  Write-XYError -Code 1 -Description $_.Exception.Message
  exit 1
}

#endregion
