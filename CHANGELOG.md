# Changelog

All notable changes to the xyOps AD Info Plugin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0] - 2026-02-22

### Added

#### 12 New Tools (13 → 25 total)

**Security & Compliance:**
- **Privileged Accounts** — Audit members of high-privilege groups (Domain Admins, Enterprise Admins, Schema Admins, etc.) with password age and logon info
- **Service Accounts** — Find user accounts with SPNs (Kerberoasting risk assessment) with delegation settings
- **Disabled Accounts** — List disabled users and/or computers for cleanup review
- **Password Policy** — Show default domain policy and fine-grained password policies (FGPPs)

**Infrastructure:**
- **Replication Status** — AD replication health between DCs with failure tracking
- **Sites & Subnets** — AD site topology with associated subnets and site links
- **Trust Relationships** — Domain/forest trusts with direction, type, and transitivity
- **GPO Overview** — List all GPOs with status, versions, and link locations (requires GroupPolicy RSAT)

**Operational:**
- **User Detail** — Deep dive into a single user (identity, org, account status, groups, direct reports)
- **Recent Changes** — Find AD objects created or modified in the last N days
- **Account Expiration** — Find users whose account (not password) expires within N days
- **Duplicate SPNs** — Scan for duplicate Service Principal Names that break Kerberos

#### Module Helpers
- `Assert-GroupPolicyModule` — GroupPolicy module check for GPO Overview tool

### Technical Details
- **Script Size**: ~2,350 lines (up from ~1,380)
- **Tools**: 25 (13 v2.0 + 12 new)
- **Embedded Script**: 96K chars
- **New Dependencies**: GroupPolicy module (RSAT) for GPO Overview only

---

## [2.0.0] - 2026-02-22

### Changed
- **BREAKING:** Converted from flat param structure to **toolset** architecture with 13 dedicated tools
- Replaced single `objectType` selector with a toolset dropdown — each tool has its own tailored parameter set
- Upgraded `xyops.json` to use `"type": "toolset"` param structure (matching xyOps network plugin pattern)
- Bumped xyOps version requirement to `1.0.0`

### Added

#### 9 New Tools
- **Group Membership** — Look up all groups a user belongs to (recursive)
- **Group Members** — List all members of a group with optional recursive expansion
- **Stale Accounts** — Find user and/or computer accounts with no logon in N days
- **Password Expiry** — Find users with passwords expiring within N days
- **Locked Accounts** — Find all currently locked-out user accounts with lockout details
- **Empty Groups** — Find groups with zero members for cleanup
- **Domain Info** — Display domain/forest details, FSMO roles, and domain controllers
- **LDAP Query** — Run custom LDAP filter queries with configurable properties
- **Compare OUs** — Compare objects between two OUs and show differences

#### Export Enhancements
- **HTML export** — Styled inline-CSS tables with xyOps purple branding
- **Excel (XLSX) export** — Auto-formatted spreadsheets via ImportExcel module (auto-installed on first use)
- Export support added to all tools (except Domain Info)

#### Architecture
- Toolset dispatch in main entry point: `$Params.tool` routes to dedicated `Invoke-*` functions
- Shared `Get-CommonQueryOpts` helper for consistent parameter handling across tools
- Shared `Emit-ListResults` helper for consistent table output from list tools
- Each list tool (Users, Groups, Computers, OUs) is now self-contained with its own `Invoke-*` function

### Technical Details
- **Script Size**: ~1,380 lines (up from ~730)
- **Tools**: 13 (4 original list tools + 9 new tools)
- **Functions**: 25+ helper, query, and export functions
- **Export Formats**: CSV, Markdown, HTML, XLSX (up from 2)
- **Dependencies**: ActiveDirectory module (RSAT), ImportExcel (auto-installed for XLSX)

---

## [1.0.0] - 2026-02-22

### Added
- Initial release of Active Directory Info Plugin
- Support for querying four AD object types: Users, Groups, Computers, Organizational Units
- Four field set presets (Essential, Standard, Extended, All) with curated fields per object type
- OU-scoped search with configurable search base and scope (Base, OneLevel, Subtree)
- Wildcard name filtering for targeted searches
- Enabled-only filtering for Users and Computers
- Sorting by Name, Created, or Modified (ascending/descending)
- Configurable maximum result count (1–10,000)
- Export to CSV file format with proper quoting
- Export to Markdown file format with formatted tables
- ActiveDirectory module detection with clear installation instructions
- Structured JSON output for workflow integration
- Output file declaration for downstream workflow steps
- Comprehensive documentation with 6 detailed examples

### Features by Category

#### Object Type Support
- **Users** — SamAccountName, email, department, title, manager, logon info, password status, account state
- **Groups** — Category, scope, member count, managed by, mail, description
- **Computers** — OS, IP address, DNS name, location, logon info, description
- **OUs** — Distinguished name, description, GP links, protection status, managed by

#### Field Set Presets
- **Essential** — Core identifying fields only (3–4 columns)
- **Standard** — Commonly needed operational fields (6–8 columns)
- **Extended** — Detailed administrative fields (8–12 columns)
- **All** — Every available field (12–20 columns)

#### Search & Filtering
- OU-based search scoping via Distinguished Name
- Search scope control: Base, OneLevel, Subtree
- Wildcard name filter (e.g., `*admin*`, `SRV-*`)
- Enabled-only toggle for Users and Computers
- Configurable result limit (default 1,000, max 10,000)

#### Display & Output
- Formatted table display with numbered rows
- Query summary statistics
- Human-readable value formatting (dates, booleans, DN references, arrays)
- CSV export with proper escaping and quoting
- Markdown export with formatted tables and metadata
- Structured JSON data output for automation

#### Value Formatting
- DateTime formatting with "Never" for epoch/null dates
- Boolean display as Yes/No
- DN references resolved to Common Name (Manager, ManagedBy)
- Array truncation with count indicator for long lists
- SID displayed as string representation
- Null/empty values shown as dash (-)

#### Error Handling
- ActiveDirectory module presence check with installation instructions
- Search base DN validation
- Graceful handling of missing properties
- Comprehensive error reporting with exit codes

### Technical Details
- **Script Size**: ~730 lines
- **Parameters**: 12 configurable options
- **Functions**: 14 helper and query functions
- **Object Types**: Users, Groups, Computers, OUs
- **Field Presets**: 4 levels (Essential, Standard, Extended, All)
- **Export Formats**: CSV, Markdown
- **Dependencies**: ActiveDirectory PowerShell module (RSAT)
- **PowerShell Version**: 7.0+
- **Exit Codes**: 0 (success), 1 (error)

### Prerequisites
- Windows machine with RSAT ActiveDirectory PowerShell module installed
- Domain-joined machine or connectivity to a domain controller
- Account running xyOps must have at least Read access to Active Directory objects
- PowerShell 7.0 or later

### Known Limitations
- MemberCount for groups counts direct members only (not nested/recursive)
- LastLogonDate may vary across domain controllers (not replicated in real-time)
- Maximum result set capped at 10,000 to prevent memory issues
- LinkedGroupPolicyObjects displays raw GP link DNs
- ServicePrincipalNames truncated to first 3 entries in display

### Future Enhancements (Planned)
- Nested group member count option
- Custom field selection (user-defined column list)
- LDAP filter support for advanced queries
- Group membership expansion (list members)
- User group membership lookup
- Excel (XLSX) export format
- HTML export with styling
- Comparison between two OUs
- Stale account detection (inactive for N days)
- Password expiration report
- Account lockout report

---

## Version History Summary

| Version | Date | Description |
|---------|------|-------------|
| 3.0.0 | 2026-02-22 | 12 new tools: security, infrastructure, operational |
| 2.0.0 | 2026-02-22 | Toolset architecture with 13 tools, HTML/XLSX export |
| 1.0.0 | 2026-02-22 | Initial release with full feature set |

---

For detailed information about features and usage, see [README.md](README.md).
