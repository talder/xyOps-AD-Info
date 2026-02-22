<p align="center"><img src="https://raw.githubusercontent.com/talder/xyOps-AD-Info/refs/heads/main/logo.png" height="108" alt="xyOps AD Info Logo"/></p>
<h1 align="center">xyOps AD Info</h1>

# xyOps Active Directory Info Event Plugin

[![Version](https://img.shields.io/badge/version-3.0.0-blue.svg)](https://github.com/xyOps/xyOps-AD-Info)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE.md)
[![PowerShell](https://img.shields.io/badge/PowerShell-7.0+-blue.svg)](https://github.com/PowerShell/PowerShell)
[![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)]()

A comprehensive **toolset** for Active Directory queries and reporting. Includes **25 dedicated tools** across 6 categories — listing, investigation, security auditing, infrastructure health, operational monitoring, and advanced queries — all with export to **CSV, Markdown, HTML, or Excel (XLSX)**. This is an **event plugin** — use it as a step in an xyOps workflow.

## Disclaimer

**USE AT YOUR OWN RISK.** This software is provided "as is", without warranty of any kind, express or implied. The author and contributors are not responsible for any damages, data loss, or other issues that may arise from the use of this software. Always test in non-production environments first.

---

## Tools (25)

### Listing (4)
| Tool | Description |
|------|-------------|
| **List Users** | Query AD user accounts with customizable fields and filters |
| **List Groups** | Query AD security and distribution groups |
| **List Computers** | Query AD computer accounts |
| **List OUs** | Query AD Organizational Units |

### Investigation (3)
| Tool | Description |
|------|-------------|
| **Group Membership** | Look up all groups a user belongs to (recursive) |
| **Group Members** | List all members of a group, optionally recursive |
| **User Detail** | Deep dive into a single user — identity, org, account status, groups, reports |

### Security & Compliance (4)
| Tool | Description |
|------|-------------|
| **Privileged Accounts** | Audit members of Domain Admins, Enterprise Admins, Schema Admins, etc. |
| **Service Accounts** | Find accounts with SPNs — delegation settings, password age (Kerberoasting risk) |
| **Disabled Accounts** | List disabled users and/or computers for cleanup review |
| **Password Policy** | Default domain policy + fine-grained password policies (FGPPs) |

### Infrastructure (5)
| Tool | Description |
|------|-------------|
| **Domain Info** | Display domain/forest details, FSMO roles, and domain controllers |
| **Replication Status** | AD replication health — last sync, result status, consecutive failures |
| **Sites & Subnets** | Site topology with associated subnets and site links |
| **Trust Relationships** | Domain/forest trusts with direction, type, transitivity |
| **GPO Overview** | All GPOs with status, versions, and link locations |

### Operational (7)
| Tool | Description |
|------|-------------|
| **Stale Accounts** | Find accounts with no logon in N days (users, computers, or both) |
| **Password Expiry** | Find users with passwords expiring within N days |
| **Locked Accounts** | Find all currently locked-out user accounts |
| **Empty Groups** | Find groups with zero members |
| **Recent Changes** | AD objects created or modified in the last N days |
| **Account Expiration** | Users whose account (not password) expires within N days |
| **Duplicate SPNs** | Scan for duplicate Service Principal Names (breaks Kerberos) |

### Advanced (2)
| Tool | Description |
|------|-------------|
| **LDAP Query** | Run custom LDAP filter queries with configurable properties |
| **Compare OUs** | Compare objects between two OUs and show differences |

## Features

### Field Set Presets (List Tools)
Choose how much detail you need with four curated presets:
- **Essential** — Core identifying fields only (3–4 columns)
- **Standard** — Commonly needed operational fields (6–8 columns)
- **Extended** — Detailed administrative fields (8–14 columns)
- **All** — Every available field (12–20 columns)

### Search & Filtering (List Tools)
- **OU Scoping** — Narrow results to a specific Organizational Unit via Distinguished Name
- **Search Scope** — Control depth: Subtree (all levels), OneLevel (direct children), or Base
- **Name Filter** — Wildcard pattern matching (e.g., `*admin*`, `SRV-*`, `IT-*`)
- **Enabled Only** — Filter to show only enabled accounts (Users and Computers)
- **Result Limit** — Configurable maximum (1–10,000 objects)

### Export (All Tools)
- **CSV** — Comma-separated values with proper quoting for Excel/data tools
- **Markdown** — Formatted table document with title and metadata
- **HTML** — Styled inline-CSS tables with xyOps purple branding
- **Excel (XLSX)** — Auto-formatted spreadsheets via ImportExcel module (auto-installed on first use)
- **Workflow Integration** — Export files declared as artifacts for downstream plugins

## Prerequisites

> **Important:** The machine running this plugin must meet the following requirements.

### 1. ActiveDirectory PowerShell Module (RSAT)

The plugin requires the **ActiveDirectory** PowerShell module, which is part of the Remote Server Administration Tools (RSAT).

**Windows 10/11:**
```powershell
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
```

**Windows Server:**
```powershell
Install-WindowsFeature RSAT-AD-PowerShell
```

### 2. GroupPolicy PowerShell Module (GPO Overview only)

The **GPO Overview** tool requires the **GroupPolicy** module. This is only needed if you use that specific tool.

**Windows Server:**
```powershell
Install-WindowsFeature GPMC
```

**Windows 10/11:**
```powershell
Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0
```

> **Note:** When running under PowerShell 7+, the module is loaded via the Windows PowerShell compatibility layer (`-UseWindowsPowerShell`). This requires Windows PowerShell 5.1 to be available on the machine.

### 3. Domain Connectivity

The machine must be **domain-joined** or have network connectivity to a domain controller. The plugin uses the default AD connection context.

### 4. Account Permissions

The account under which xyOps runs must have **at least Read access** to Active Directory objects. For most queries, standard domain user permissions are sufficient. Specific scenarios:

| Scenario | Required Permission |
|----------|-------------------|
| List users, groups, computers | Domain Users (default Read) |
| View all user properties | Domain Users (most properties) |
| View sensitive properties (e.g., password info) | Delegated Read permissions |
| Query across all OUs | Domain Users (default) |
| View GP links on OUs | Domain Users (default Read) |

## Installation

1. Clone or download this repository to your xyOps plugins directory
2. The plugin will verify that the ActiveDirectory module is installed on first run
3. If the module is missing, a detailed error message with installation instructions is displayed

## Configuration

The plugin uses a **toolset** architecture — select a tool from the dropdown, and only the relevant parameters for that tool are shown.

### Common Parameters (List Tools)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `searchBase` | Text | *(domain root)* | OU DN to scope the search |
| `searchScope` | Select | `subtree` | Search depth: `subtree`, `onelevel`, or `base` |
| `nameFilter` | Text | *(all)* | Wildcard pattern for Name |
| `enabledOnly` | Checkbox | `false` | Only enabled accounts (Users/Computers) |
| `fieldSet` | Select | `essential` | Detail level: `essential`, `standard`, `extended`, `all` |
| `sortBy` | Select | `name` | Sort by: `name`, `created`, or `modified` |
| `sortOrder` | Select | `ascending` | Sort direction |
| `maxResults` | Number | `1000` | Max objects to return (1–10,000) |

### Tool-Specific Parameters

| Parameter | Tool(s) | Type | Description |
|-----------|---------|------|-------------|
| `targetUser` | Group Membership | Text | SamAccountName or DN of user |
| `targetGroup` | Group Members | Text | Name, SamAccountName, or DN of group |
| `recursive` | Group Members | Checkbox | Include nested group members |
| `staleDays` | Stale Accounts | Number | Days without logon (default: 90) |
| `staleObjectType` | Stale Accounts | Select | `users`, `computers`, or `both` |
| `expiryDays` | Password Expiry | Number | Days until password expiry (default: 14) |
| `ldapFilter` | LDAP Query | Text | LDAP filter expression |
| `ldapProperties` | LDAP Query | Text | Comma-separated AD properties |
| `compareOU1` / `compareOU2` | Compare OUs | Text | DNs of the two OUs to compare |
| `compareObjectType` | Compare OUs | Select | `users`, `groups`, or `computers` |
| `targetUser` | User Detail | Text | SamAccountName or DN of user |
| `disabledObjectType` | Disabled Accounts | Select | `users`, `computers`, or `both` |
| `changeDays` | Recent Changes | Number | Days to look back (default: 7) |
| `changeType` | Recent Changes | Select | `both`, `created`, or `modified` |
| `changeObjectType` | Recent Changes | Select | `all`, `users`, `groups`, or `computers` |
| `accountExpiryDays` | Account Expiration | Number | Days until expiry (default: 30) |

### Export Parameters (All Tools except Domain Info)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `exportEnabled` | Checkbox | `false` | Save results to file |
| `exportFormat` | Select | `csv` | Format: `csv`, `markdown`, `html`, or `xlsx` |
| `exportFileName` | Text | `ad_export` | Output filename (extension added automatically) |

## Field Reference

### User Fields

| Field Set | Fields |
|-----------|--------|
| **Essential** | Name, Username, Enabled, Email |
| **Standard** | + Display Name, Title, Department, Office |
| **Extended** | + Manager, Phone, Created, Last Logon, Password Set, Expires |
| **All** | + Description, DN, SID, Modified, Pwd Never Expires, Locked Out |

### Group Fields

| Field Set | Fields |
|-----------|--------|
| **Essential** | Name, Category, Scope, Description |
| **Standard** | + Managed By, Members (count) |
| **Extended** | + Created, Modified, SID, DN |
| **All** | + Email, Info |

### Computer Fields

| Field Set | Fields |
|-----------|--------|
| **Essential** | Name, OS, Enabled, IP Address |
| **Standard** | + OS Version, Last Logon, Description |
| **Extended** | + Created, Modified, Location, Managed By, DNS Name |
| **All** | + DN, SID, SPNs |

### OU Fields

| Field Set | Fields |
|-----------|--------|
| **Essential** | Name, DN, Description |
| **Standard** | + Created, Modified, Managed By |
| **Extended** | + Protected from Deletion, GPO Links |
| **All** | + City, Country, State |

## Output Data Structure

Each tool returns a structured JSON result. The `tool` field identifies which tool was used.

| Field | Type | Description |
|-------|------|-------------|
| `tool` | String | Tool identifier (e.g., `"List Users"`, `"Stale Accounts"`) |
| `success` | Boolean | `true` if operation succeeded |
| `totalResults` | Number | Count of objects returned |
| `generatedFiles` | Array | List of exported filenames (if export enabled) |
| `timestamp` | String | ISO 8601 timestamp (list tools) |
| `groups` | Array | Group names the user belongs to (User Detail only) |
| `groupCount` | Number | Number of group memberships (User Detail only) |
| `directReports` | Number | Number of direct reports (User Detail only) |

---

## Examples

### Example 1: List All Users (Essential Fields)

**Tool:** `List Users`
```json
{ "fieldSet": "essential", "sortBy": "name" }
```
Lists all users with Name, Username, Enabled, Email — sorted alphabetically.

---

### Example 2: Users in a Specific OU

**Tool:** `List Users`
```json
{
  "searchBase": "OU=Sales,DC=contoso,DC=com",
  "fieldSet": "standard",
  "enabledOnly": true
}
```
Enabled users in the Sales OU with department and title info.

---

### Example 3: Export Groups to Excel

**Tool:** `List Groups`
```json
{
  "fieldSet": "extended",
  "exportEnabled": true,
  "exportFormat": "xlsx",
  "exportFileName": "ad_groups_audit"
}
```
Exports all groups with full details to a formatted Excel spreadsheet.

---

### Example 4: Find Server Computers

**Tool:** `List Computers`
```json
{ "nameFilter": "SRV-*", "enabledOnly": true, "fieldSet": "standard" }
```
Filters to servers only — shows OS, IP, last logon.

---

### Example 5: User's Group Membership

**Tool:** `Group Membership`
```json
{ "targetUser": "jdoe" }
```
Shows all groups (recursive) that user `jdoe` is a member of.

---

### Example 6: Stale Accounts Report

**Tool:** `Stale Accounts`
```json
{
  "staleDays": 60,
  "staleObjectType": "both",
  "exportEnabled": true,
  "exportFormat": "html",
  "exportFileName": "stale_accounts"
}
```
Finds all users and computers with no logon in 60+ days, exports styled HTML report.

---

### Example 7: Password Expiry Check

**Tool:** `Password Expiry`
```json
{ "expiryDays": 7 }
```
Shows users whose passwords expire within the next 7 days.

---

### Example 8: Custom LDAP Query

**Tool:** `LDAP Query`
```json
{
  "ldapFilter": "(&(objectClass=user)(department=IT)(enabled=TRUE))",
  "ldapProperties": "Name,SamAccountName,Title,Manager"
}
```
Runs a custom LDAP filter and returns only the specified properties.

---

### Example 9: Compare Two OUs

**Tool:** `Compare OUs`
```json
{
  "compareOU1": "OU=Berlin,DC=contoso,DC=com",
  "compareOU2": "OU=Munich,DC=contoso,DC=com",
  "compareObjectType": "users"
}
```
Shows users that exist only in one OU and users common to both.

---

### Example 10: Privileged Accounts Audit

**Tool:** `Privileged Accounts`
```json
{ "exportEnabled": true, "exportFormat": "xlsx", "exportFileName": "privileged_audit" }
```
Exports all Domain Admins, Enterprise Admins, etc. with password age to Excel.

---

### Example 11: User Deep Dive

**Tool:** `User Detail`
```json
{ "targetUser": "jdoe" }
```
Shows identity, org, account status, all group memberships, and direct reports for user `jdoe`.

---

### Example 12: Recent AD Changes

**Tool:** `Recent Changes`
```json
{ "changeDays": 3, "changeType": "created", "changeObjectType": "users" }
```
Shows user accounts created in the last 3 days.

---

### Example 13: Replication Health Check

**Tool:** `Replication Status`
```json
{ "exportEnabled": true, "exportFormat": "html", "exportFileName": "repl_health" }
```
Shows DC replication status with HEALTHY/WARNING indicator, exports styled HTML report.

---

## Value Formatting

The plugin applies intelligent formatting to raw AD values:

| Value Type | Formatting |
|------------|-----------|
| DateTime | `yyyy-MM-dd HH:mm` format |
| DateTime (epoch/null) | `Never` |
| Boolean | `Yes` / `No` |
| GroupCategory | `Security` / `Distribution` |
| GroupScope | `Global` / `DomainLocal` / `Universal` |
| DN references (Manager, ManagedBy) | Resolved to Common Name |
| Arrays (≤ 3 items) | Comma-separated list |
| Arrays (> 3 items) | First 3 items + `(+N more)` |
| SID | String representation |
| Null / empty | `-` |

## Common Use Cases

| Use Case | Tool |
|----------|------|
| User account auditing | List Users (extended fields) |
| Group membership investigation | Group Membership / Group Members |
| User investigation | User Detail |
| Empty group cleanup | Empty Groups |
| Server inventory | List Computers (name filter `SRV-*`) |
| OU documentation | List OUs → Markdown/HTML export |
| Stale account cleanup | Stale Accounts |
| Password expiry warnings | Password Expiry |
| Account lockout monitoring | Locked Accounts |
| Domain/forest overview | Domain Info |
| Advanced AD queries | LDAP Query |
| OU migration comparison | Compare OUs |
| Privileged access audit | Privileged Accounts |
| Kerberoasting risk assessment | Service Accounts |
| Disabled account cleanup | Disabled Accounts |
| Password policy review | Password Policy |
| AD replication health | Replication Status |
| Site topology documentation | Sites & Subnets |
| Trust relationship inventory | Trust Relationships |
| GPO documentation | GPO Overview |
| Change audit trail | Recent Changes |
| Account lifecycle management | Account Expiration |
| Kerberos auth troubleshooting | Duplicate SPNs |
| Security compliance reports | Any tool → XLSX export |

---

## Error Handling

| Error | Cause | Solution |
|-------|-------|----------|
| `ActiveDirectory module is not installed` | RSAT not installed | Install RSAT (see Prerequisites) |
| `GroupPolicy module could not be loaded` | GPMC not installed or PS7 compat issue | Install GPMC (see Prerequisites §2) |
| `Invalid SearchBase` | Malformed Distinguished Name | Use proper DN format: `OU=Name,DC=domain,DC=com` |
| `Unable to contact the server` | No DC connectivity | Verify domain network access |
| `Access denied` | Insufficient permissions | Run xyOps with an account that has AD Read access |
| `The search filter cannot be recognized` | Invalid name filter | Use valid wildcard patterns (e.g., `*admin*`) |

## Performance Considerations

- **Default result limit** is 1,000 objects. Increase `maxResults` for larger environments, but be mindful of memory usage.
- **Subtree scope** with no search base queries the entire domain — this can be slow in large environments. Use a specific `searchBase` when possible.
- **Extended and All field sets** request more properties from AD, which may be slightly slower than Essential or Standard.
- **Group member counts** require fetching the Members attribute, which adds overhead for large groups.
- **XLSX export** auto-installs the ImportExcel module on first use (requires internet access).
- **Stale Accounts** tool performs client-side date filtering for null LastLogonDate values.
- **GPO Overview** generates an XML report per GPO to resolve link locations — can be slow with many GPOs.
- **Export files** are written to the job working directory and declared as workflow artifacts.

## Related Plugins

- **xyOps Network Diagnostic** — Network tools including DNS, ping, port scan (useful for verifying AD connectivity)
- **xyOps FTP List / Upload** — Export AD data and upload to file servers for archival

---

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

(c) 2026 Tim Alderweireldt