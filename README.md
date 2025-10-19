# Get-DefenderThreatSubmissionReport

PowerShell script to export and analyze Microsoft Defender for Office 365 threat submissions with an interactive HTML report.

## Overview

This tool retrieves user-reported threat submissions from Microsoft Defender for Office 365 and generates a comprehensive HTML report with filtering, search, and export capabilities.

## Features

- 📊 **Interactive HTML Report** - Visual dashboard with charts and statistics
- 🔍 **Advanced Filtering** - Filter by date range and search across all fields
- 📤 **Excel Export** - Export filtered results directly to CSV/Excel
- 🔐 **Message-ID Recovery** - Automatically retrieves missing Message IDs from user mailboxes
- 📈 **Rich Analytics** - Category breakdowns, top reporters, and submission trends
- 🎯 **Attack Simulation Detection** - Identifies test submissions from simulations

## Prerequisites

### 1. Azure App Registration (Optional - For Automated Scenarios)

> **Note:** This script uses interactive authentication by default. App registration is only needed for automated/unattended scenarios.

#### Step 1: Register Application in Azure AD

1. Navigate to [Azure Portal](https://portal.azure.com)
2. Go to **Azure Active Directory** → **App registrations** → **New registration**
3. Configure the application:
   - **Name:** `Defender Threat Submission Reporter`
   - **Supported account types:** `Accounts in this organizational directory only (Single tenant)`
   - **Redirect URI:** Leave blank for now
4. Click **Register**

#### Step 2: Configure API Permissions

1. In your app registration, go to **API permissions**
2. Click **Add a permission** → **Microsoft Graph** → **Application permissions**
3. Add the following permissions:
   - `ThreatSubmission.Read.All`
   - `Mail.ReadBasic.All`
4. Click **Add permissions**
5. Click **Grant admin consent for [Your Organization]** (requires admin)
6. Verify status shows green checkmarks

#### Step 3: Create Client Secret (Optional)

1. Go to **Certificates & secrets** → **Client secrets** → **New client secret**
2. Description: `Threat Submission Script`
3. Expires: Choose appropriate duration (recommended: 12-24 months)
4. Click **Add**
5. **IMPORTANT:** Copy the secret value immediately (you won't see it again)

#### Step 4: Note Your Application Details

Copy these values for later use:
- **Application (client) ID:** Found on Overview page
- **Directory (tenant) ID:** Found on Overview page
- **Client Secret Value:** Copied from step 3

#### Using App Registration with the Script

If you want to use app-based authentication instead of interactive:

```powershell
# Connect using app credentials (modify script or use this approach)
$ClientId = "your-app-id-here"
$TenantId = "your-tenant-id-here"
$ClientSecret = "your-secret-here"

$SecureSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential($ClientId, $SecureSecret)

Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $Credential
```

> **Security Note:** The current script uses interactive authentication with delegated permissions, which is more secure for manual execution. App-based authentication is recommended only for automation scenarios.

### 2. Microsoft Graph PowerShell Module

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser -Force
```

### 3. Microsoft Defender Configuration (CRITICAL)

#### Configure User Reported Settings

1. Navigate to [Microsoft 365 Defender portal](https://security.microsoft.com)
2. Go to **Settings** → **Email & collaboration** → **User reported settings**
3. Under **Microsoft Outlook Report Message button**, select one of:
   - ✅ **Send reported messages to Microsoft only**
   - ✅ **Send reported messages to Microsoft and my reporting mailbox**
4. Click **Save**

⚠️ **WARNING:** If user reports only go to a mailbox and NOT to Microsoft, this API will return ZERO results!

#### Enable User Reporting in Outlook

Ensure users have one of these reporting methods:
- **Built-in Outlook Report button** (Microsoft 365 Apps)
- **Report Message add-in** (available from Microsoft)
- **Report Phishing add-in** (available from Microsoft)

To deploy add-ins organization-wide:
1. Go to [Microsoft 365 Admin Center](https://admin.microsoft.com)
2. Navigate to **Settings** → **Integrated apps**
3. Click **Get apps** → Search for "Report Message" or "Report Phishing"
4. Deploy to users/groups

### 4. Required Permissions

#### For Interactive Authentication (Default)
The script uses Microsoft's built-in consent flow. On first run, you'll be prompted to consent to:
- `ThreatSubmission.Read.All` - Read threat submissions
- `Mail.ReadBasic` - For Message-ID recovery from user mailboxes

#### Required Azure AD Roles
Your user account needs one of these roles:
- **Security Administrator**
- **Security Reader**
- **Global Administrator**
- **Global Reader**

#### Verifying Your Roles
```powershell
# Check your current roles
Connect-MgGraph
Get-MgUserMemberOf -UserId (Get-MgContext).Account | Select-Object AdditionalProperties
```

### 5. Supported Environments

- Microsoft 365 Global cloud (Commercial)
- PowerShell 5.1 or PowerShell 7+
- Microsoft Graph /beta endpoint

## Installation

1. Download the script:
   ```powershell
   # Clone or download Get-DefenderThreatSubmissionReport.ps1
   ```

2. Unblock the script (if downloaded from internet):
   ```powershell
   Unblock-File -Path .\Get-DefenderThreatSubmissionReport.ps1
   ```

## Usage

### Basic Usage

```powershell
# Default: Last 180 days, all categories, user submissions only
.\Get-DefenderThreatSubmissionReport.ps1
```

### Advanced Examples

```powershell
# Last 30 days only
.\Get-DefenderThreatSubmissionReport.ps1 -DaysBack 30

# Filter by category (phishing only)
.\Get-DefenderThreatSubmissionReport.ps1 -Category "phishing"

# Include admin submissions
.\Get-DefenderThreatSubmissionReport.ps1 -IncludeAdminSubmissions

# Combine parameters
.\Get-DefenderThreatSubmissionReport.ps1 -DaysBack 90 -Category "malware" -IncludeAdminSubmissions
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-DaysBack` | int | 180 | Number of days to look back for submissions |
| `-Category` | string | "" | Filter by category: spam, phishing, malware, notJunk |
| `-IncludeAdminSubmissions` | switch | false | Include admin submissions in addition to user submissions |

## HTML Report Features

### Dashboard Statistics
- Total submission counts
- Category breakdown with visual charts
- Top 10 reporters by submission count

### Interactive Table
- **Search** - Real-time search across all columns
- **Date Filter** - Slider to filter by date range
- **Export to Excel** - Download filtered results as CSV

### Columns Included
- Created Date
- Sender
- Recipient  
- Subject
- Category (Phishing, Spam, Malware, Not Junk)
- Verdict (Analysis result)
- Status
- Simulation (Attack simulation flag)
- Admin Review
- Source (User/Admin)
- Message ID

## Output

The script generates an HTML report in the same directory:

```
Defender_Threat_Submissions_2025-10-19_14-30.html
```

The report automatically opens in your default browser.

## Troubleshooting

### Empty Results?

**Most common causes:**

1. ❌ User reported settings not configured to send to Microsoft
2. ❌ No user reports in the specified time range
3. ❌ Wrong tenant or insufficient permissions
4. ❌ Filters excluding all data

**Quick diagnostic test:**

```powershell
Connect-MgGraph -Scopes "ThreatSubmission.Read.All"
Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/security/threatSubmission/emailThreats?`$top=5"
```

### Permission Errors

Ensure you have granted admin consent for the required permissions in Azure AD.

### Connection Issues

```powershell
# Disconnect and reconnect
Disconnect-MgGraph
Connect-MgGraph -Scopes "ThreatSubmission.Read.All","Mail.ReadBasic"
```

## Message-ID Recovery

The script automatically attempts to recover missing Message IDs by:

1. Querying the recipient's mailbox via Graph API
2. Matching by sender, subject, and timestamp (±60 minutes)
3. Creating alternative identifiers when recovery is not possible

**Message ID prefixes:**
- `RETRIEVED:` - Successfully recovered from mailbox
- `ALT-ID:` - Alternative identifier created
- No prefix - Original ID from Threat Submission API

## Security & Privacy

- ✅ No credentials stored in the script
- ✅ Uses interactive authentication via Microsoft Graph
- ✅ Requires user sign-in on each execution
- ✅ Data stays local - only HTML report is generated

## Requirements Summary

| Component | Requirement |
|-----------|-------------|
| PowerShell | 5.1 or higher |
| Graph Module | Microsoft.Graph |
| Permissions | ThreatSubmission.Read.All, Mail.ReadBasic |
| Defender Config | User reports sent to Microsoft |
| Role | Security Admin/Reader or Global Admin |

## Author

**Muataz Awad**  
Email: muataz.awad@microsoft.com  
Version: 1.0  
Created: October 2025

## Links

- [Microsoft Graph PowerShell](https://learn.microsoft.com/en-us/powershell/microsoftgraph/)
- [Threat Submissions API](https://learn.microsoft.com/en-us/graph/api/resources/security-threatsubmission)
- [App Registration Guide](https://learn.microsoft.com/en-us/graph/auth-register-app-v2)

## License

This script is provided as-is for use within Microsoft 365 environments.

---

**💡 Tip:** For best results, ensure users are actively reporting suspicious emails through Outlook's built-in reporting features or the Report Message add-in.
