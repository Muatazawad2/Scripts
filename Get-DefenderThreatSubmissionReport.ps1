<#
.SYNOPSIS
    Microsoft Defender Threat Submission Export Script with Enhanced Message ID Recovery

.DESCRIPTION
    Exports comprehensive threat submission data from Microsoft Defender for Office 365 to CSV and JSON files.
    Features include:
    - Complete threat submission metadata export (30+ fields)
    - Automatic Message-ID recovery from user mailboxes when available
    - Alternative composite identifiers for tracking
    - Comprehensive threat analysis results
    - Admin review and tenant policy information
    - Attack simulation detection

.DEVELOPER
    Muataz Awad
    Contact: muataz.awad@microsoft.com
    Date: October 2025

.PREREQUISITES
    1. MICROSOFT GRAPH POWERSHELL MODULE
       Install-Module Microsoft.Graph -Scope CurrentUser -Force

    2. AZURE APP REGISTRATION (Required for Production/Automated Scenarios)
       - Register app in Azure AD: https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps
       - API Permissions: Microsoft Graph -> Application permissions -> ThreatSubmission.Read.All
       - Grant admin consent for the organization
       - Note: Interactive auth (used by this script) uses built-in Microsoft Graph Command Line Tools app

    3. MICROSOFT DEFENDER CONFIGURATION (CRITICAL - Most common cause of empty results)
       Navigate to: Microsoft 365 Defender portal -> Settings -> Email & collaboration -> User reported settings
       Configure: "Send reported messages to: Microsoft" (or "Microsoft and my reporting mailbox")
       
       ⚠️  WARNING: If user reports only go to a mailbox and NOT to Microsoft, this API will return ZERO results!
       
    4. PERMISSIONS REQUIRED
       - ThreatSubmission.Read.All (Application permission with admin consent)
       - Mail.ReadBasic (for Message-ID recovery from user mailboxes)
       - User must have appropriate roles (Security Admin, Security Reader, or Global Admin)

    5. SUPPORTED ENVIRONMENTS
       - Microsoft 365 Global cloud (Commercial)
       - Microsoft Graph /beta endpoint required
       - PowerShell 5.1 or PowerShell 7+ recommended

.TROUBLESHOOTING
    Empty CSV file? Most common causes:
    1. User reported settings not configured to send to Microsoft
    2. No user reports in the specified time range
    3. Wrong tenant or insufficient permissions
    4. Using filters that exclude all data (try without filters first)

    Quick diagnostic test:
    Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/security/threatSubmission/emailThreats?`$top=5"

.EXAMPLES
    # Default: Last 90 days, all categories, user submissions only
    .\Get-DefenderThreatSubmissionReport.ps1

    # Last 30 days, phishing only
    .\Get-DefenderThreatSubmissionReport.ps1 -DaysBack 30 -Category "phishing"

    # Include admin submissions
    .\Get-DefenderThreatSubmissionReport.ps1 -IncludeAdminSubmissions

.NOTES
    Author: Muataz Awad
    Version: 1.0
    Created: September 2025
    Updated: October 2025
    
    Requirements:
    - Microsoft.Graph PowerShell module
    - ThreatSubmission.Read.All permission
    - Mail.ReadBasic permission (for Message-ID recovery)
    - Microsoft Defender for Office 365
    - User reported settings configured to send to Microsoft
    
    Links:
    - Microsoft Graph PowerShell: https://learn.microsoft.com/en-us/powershell/microsoftgraph/
    - App Registration: https://learn.microsoft.com/en-us/graph/auth-register-app-v2
    - Threat Submissions API: https://learn.microsoft.com/en-us/graph/api/resources/security-threatsubmission
#>

[CmdletBinding()]
param(
    [Parameter(HelpMessage="Number of days to look back for submissions")]
    [int]$DaysBack = 180,
    
    [Parameter(HelpMessage="Filter by category (spam, phishing, malware, notJunk)")]
    [string]$Category = "",
    
    [Parameter(HelpMessage="Include admin submissions as well as user submissions")]
    [switch]$IncludeAdminSubmissions,
    
    [Parameter(HelpMessage="Generate and open HTML report")]
    [switch]$ExportHtml
)

# ===============================================
# PREREQUISITES CHECK
# ===============================================

function Test-Prerequisites {
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-Error "PowerShell 5.1 or higher is required. Current version: $($PSVersionTable.PSVersion)"
        return $false
    }
    
    # Check Microsoft Graph module
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        Write-Host "Installing Microsoft Graph module..." -ForegroundColor Yellow
        try {
            Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber
        } catch {
            Write-Error "Failed to install Microsoft Graph module: $($_.Exception.Message)"
            Write-Host "Manual installation: Install-Module Microsoft.Graph -Scope CurrentUser -Force" -ForegroundColor Yellow
            return $false
        }
    }
    
    return $true
}

function Export-HtmlReport {
    param(
        [Parameter(Mandatory=$true)]
        [array]$Submissions,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputPath
    )
    
    $timestamp = Get-Date -Format "MMMM dd, yyyy HH:mm:ss"
    $categoryStats = $Submissions | Group-Object Category | Sort-Object Count -Descending
    
    # Group by reporter - use display name if available, otherwise use email
    $recipientStats = $Submissions | ForEach-Object {
        $_ | Add-Member -NotePropertyName 'ReporterName' -NotePropertyValue $(if ($_.CreatedByDisplayName) { $_.CreatedByDisplayName } else { $_.CreatedByEmail }) -PassThru
    } | Group-Object ReporterName | Sort-Object Count -Descending | Select-Object -First 10
    
    $retrievedIds = $Submissions | Where-Object { $_.InternetMessageId -like "RETRIEVED:*" }
    $alternativeIds = $Submissions | Where-Object { $_.InternetMessageId -like "ALT-ID:*" }
    $originalIds = $Submissions | Where-Object { $_.InternetMessageId -notlike "RETRIEVED:*" -and $_.InternetMessageId -notlike "ALT-ID:*" -and -not [string]::IsNullOrEmpty($_.InternetMessageId) }
    
    $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Microsoft Defender Threat Submissions Report</title>
    <style>
        :root {
            --primary-color: #0078d4;
            --success-color: #107c10;
            --warning-color: #ff8c00;
            --danger-color: #d13438;
            --background: #f3f2f1;
            --card-bg: #ffffff;
            --text-primary: #323130;
            --text-secondary: #605e5c;
            --border-color: #edebe9;
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--background);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #0078d4 0%, #005a9e 100%);
            color: white;
            padding: 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .header-content {
            flex: 1;
        }
        
        .header h1 {
            font-size: 28px;
            font-weight: 600;
            margin-bottom: 10px;
        }
        
        .header p {
            opacity: 0.9;
            font-size: 14px;
        }
        
        .header-export-btn {
            padding: 12px 24px;
            background: white;
            color: #0078d4;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 15px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.2);
            transition: all 0.2s;
        }
        
        .header-export-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #fafafa;
        }
        
        .stat-card {
            background: var(--card-bg);
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid var(--primary-color);
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        
        .stat-card.success { border-left-color: var(--success-color); }
        .stat-card.warning { border-left-color: var(--warning-color); }
        .stat-card.danger { border-left-color: var(--danger-color); }
        
        .stat-value {
            font-size: 32px;
            font-weight: 700;
            color: var(--primary-color);
            margin-bottom: 5px;
        }
        
        .stat-card.success .stat-value { color: var(--success-color); }
        .stat-card.warning .stat-value { color: var(--warning-color); }
        .stat-card.danger .stat-value { color: var(--danger-color); }
        
        .stat-label {
            font-size: 13px;
            color: var(--text-secondary);
            font-weight: 500;
        }
        
        .content {
            padding: 30px;
        }
        
        .section {
            margin-bottom: 40px;
        }
        
        .section h2 {
            font-size: 20px;
            margin-bottom: 20px;
            color: var(--text-primary);
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 10px;
        }
        
        .stats-header {
            display: grid;
            grid-template-columns: auto 1fr 1fr;
            gap: 20px;
            align-items: start;
            margin-bottom: 30px;
        }
        
        .stats-header .stat-card {
            margin: 0;
        }
        
        .chart-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .chart-card {
            background: var(--card-bg);
            padding: 20px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
        }
        
        .chart-card h3 {
            font-size: 16px;
            margin-bottom: 15px;
            color: var(--text-primary);
        }
        
        .chart-item {
            display: flex;
            align-items: center;
            margin-bottom: 10px;
        }
        
        .chart-label {
            flex: 1;
            font-size: 14px;
            color: var(--text-secondary);
        }
        
        .chart-bar {
            flex: 2;
            height: 24px;
            background: linear-gradient(90deg, var(--primary-color), #5a9fd4);
            border-radius: 4px;
            margin: 0 10px;
            position: relative;
        }
        
        .chart-value {
            font-size: 14px;
            font-weight: 600;
            color: var(--text-primary);
            min-width: 40px;
            text-align: right;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            font-size: 13px;
        }
        
        thead {
            background: #f3f2f1;
        }
        
        th {
            padding: 12px;
            text-align: left;
            font-weight: 600;
            color: var(--text-primary);
            border-bottom: 2px solid var(--border-color);
        }
        
        td {
            padding: 12px;
            border-bottom: 1px solid var(--border-color);
        }
        
        tbody tr:hover {
            background: #fafafa;
        }
        
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .badge-phishing { background: #fff4ce; color: #8a6116; }
        .badge-spam { background: #fde7e9; color: #a4262c; }
        .badge-malware { background: #fed9cc; color: #bc4b09; }
        .badge-notjunk { background: #dff6dd; color: #0b6a0b; }
        .badge-user { background: #e1dfdd; color: #323130; }
        .badge-admin { background: #cfe4fa; color: #004578; }
        
        .footer {
            text-align: center;
            padding: 20px;
            background: #f3f2f1;
            color: var(--text-secondary);
            font-size: 12px;
        }
        
        .search-box {
            margin-bottom: 20px;
            padding: 10px;
            width: 100%;
            max-width: 400px;
            border: 2px solid var(--border-color);
            border-radius: 4px;
            font-size: 14px;
        }
        
        .search-box:focus {
            outline: none;
            border-color: var(--primary-color);
        }
        
        .date-filter {
            background: var(--card-bg);
            padding: 20px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
            margin-bottom: 20px;
        }
        
        .date-filter h3 {
            font-size: 16px;
            margin-bottom: 15px;
            color: var(--text-primary);
        }
        
        .slider-container {
            margin: 20px 0;
        }
        
        .slider-labels {
            display: flex;
            justify-content: space-between;
            font-size: 12px;
            color: var(--text-secondary);
            margin-top: 5px;
        }
        
        .date-range-slider {
            width: 100%;
            height: 8px;
            border-radius: 4px;
            background: linear-gradient(90deg, var(--primary-color) 0%, var(--success-color) 100%);
            outline: none;
            -webkit-appearance: none;
            appearance: none;
        }
        
        .date-range-slider::-webkit-slider-thumb {
            -webkit-appearance: none;
            appearance: none;
            width: 20px;
            height: 20px;
            border-radius: 50%;
            background: var(--primary-color);
            cursor: pointer;
            box-shadow: 0 2px 4px rgba(0,0,0,0.2);
        }
        
        .date-range-slider::-moz-range-thumb {
            width: 20px;
            height: 20px;
            border-radius: 50%;
            background: var(--primary-color);
            cursor: pointer;
            border: none;
            box-shadow: 0 2px 4px rgba(0,0,0,0.2);
        }
        
        .date-display {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px;
            background: #f3f2f1;
            border-radius: 4px;
            margin-top: 10px;
        }
        
        .date-display span {
            font-weight: 600;
            color: var(--text-primary);
        }
        
        .reset-btn {
            padding: 8px 16px;
            background: var(--primary-color);
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 600;
        }
        
        .reset-btn:hover {
            background: #005a9e;
        }
        
        .export-controls {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            align-items: center;
        }
        
        .export-btn {
            padding: 10px 20px;
            background: var(--success-color);
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .export-btn:hover {
            background: #0e6b0e;
        }
        
        .export-btn:disabled {
            background: #a19f9d;
            cursor: not-allowed;
        }
        
        .export-count {
            color: var(--text-secondary);
            font-size: 13px;
        }
        
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-content">
                <h1>🛡️ Microsoft Defender Threat Submissions Report</h1>
                <p>Generated: $timestamp | Total Submissions: $($Submissions.Count)</p>
            </div>
            <button class="header-export-btn" onclick="exportToExcel()" title="Export visible results to Excel">
                📊 Export to Excel
            </button>
        </div>
        
        <div class="content">
            <div class="section">
                <h2>📊 Submission Statistics</h2>
                
                <div class="stats-header">
                    <div class="stat-card">
                        <div class="stat-value">$($Submissions.Count)</div>
                        <div class="stat-label">Total Submissions</div>
                    </div>
                    
                    <div class="chart-card">
                        <h3>By Category</h3>
"@

    # Add category chart
    foreach ($stat in $categoryStats) {
        $percentage = [math]::Round(($stat.Count / $Submissions.Count) * 100)
        $htmlContent += @"
                        <div class="chart-item">
                            <div class="chart-label">$($stat.Name)</div>
                            <div class="chart-bar" style="width: $percentage%;"></div>
                            <div class="chart-value">$($stat.Count)</div>
                        </div>
"@
    }

    $htmlContent += @"
                    </div>
                    
                    <div class="chart-card">
                        <h3>Top Reporters (By User)</h3>
"@

    # Add recipient chart (top 10 users who reported)
    foreach ($stat in $recipientStats) {
        $percentage = [math]::Round(($stat.Count / $Submissions.Count) * 100)
        $userName = if ($stat.Name) { $stat.Name } else { "Unknown" }
        $htmlContent += @"
                        <div class="chart-item">
                            <div class="chart-label" title="$userName">$userName</div>
                            <div class="chart-bar" style="width: $percentage%;"></div>
                            <div class="chart-value">$($stat.Count)</div>
                        </div>
"@
    }

    $htmlContent += @"
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h2>📋 Detailed Submissions</h2>
                
                <div class="export-controls">
                    <span class="export-count">
                        <span id="visibleCount">$($Submissions.Count)</span> of $($Submissions.Count) submissions shown
                    </span>
                </div>
                
                <div class="date-filter">
                    <h3>📅 Filter by Date Range</h3>
                    <div class="slider-container">
                        <input type="range" min="0" max="180" value="180" class="date-range-slider" id="dateSlider">
                        <div class="slider-labels">
                            <span id="minDateLabel"></span>
                            <span id="maxDateLabel"></span>
                        </div>
                    </div>
                    <div class="date-display">
                        <span>Showing last <span id="daysDisplay">180</span> days</span>
                        <button class="reset-btn" onclick="resetDateFilter()">Reset to All</button>
                    </div>
                </div>
                
                <input type="text" class="search-box" id="searchBox" placeholder="Search submissions..." onkeyup="filterTable()">
                
                <table id="submissionsTable">
                    <thead>
                        <tr>
                            <th>Created Date</th>
                            <th>Sender</th>
                            <th>Recipient</th>
                            <th>Subject</th>
                            <th>Category</th>
                            <th>Verdict</th>
                            <th>Status</th>
                            <th>Simulation</th>
                            <th>Admin Review</th>
                            <th>Source</th>
                            <th>Message ID</th>
                        </tr>
                    </thead>
                    <tbody>
"@

    # Add table rows
    foreach ($submission in $Submissions) {
        $createdDate = if ($submission.CreatedDateTime) { 
            ([DateTime]$submission.CreatedDateTime).ToString("yyyy-MM-dd HH:mm") 
        } else { "N/A" }
        
        $categoryBadge = "badge-" + $submission.Category.ToLower()
        $sourceBadge = if ($submission.Source -eq "user") { "badge-user" } else { "badge-admin" }
        
        # Get verdict (result category)
        $verdict = if ($submission.ResultCategory) { $submission.ResultCategory } else { "-" }
        
        # Get status
        $status = if ($submission.Status) { $submission.Status } else { "-" }
        
        # Get simulation status
        $simulation = if ($submission.IsAttackSimulation -eq "Yes") { "Yes" } else { "No" }
        
        # Get admin review
        $adminReview = if ($submission.AdminReviewResult) { $submission.AdminReviewResult } else { "-" }
        
        $htmlContent += @"
                        <tr>
                            <td>$createdDate</td>
                            <td>$($submission.Sender)</td>
                            <td>$($submission.Recipient)</td>
                            <td>$($submission.Subject)</td>
                            <td><span class="badge $categoryBadge">$($submission.Category)</span></td>
                            <td>$verdict</td>
                            <td>$status</td>
                            <td>$simulation</td>
                            <td>$adminReview</td>
                            <td><span class="badge $sourceBadge">$($submission.Source)</span></td>
                            <td style="font-size: 11px;">$($submission.InternetMessageId)</td>
                        </tr>
"@
    }

    $htmlContent += @"
                    </tbody>
                </table>
            </div>
        </div>
        
        <div class="footer">
            <p>Microsoft Defender Threat Submissions Export Tool v1.0</p>
            <p>Developer: Muataz Awad | muataz.awad@microsoft.com</p>
        </div>
    </div>
    
    <script>
        // Store all submissions with their dates
        const allSubmissions = [];
        const tableRows = document.getElementById('submissionsTable').getElementsByTagName('tbody')[0].getElementsByTagName('tr');
        
        // Parse dates from table
        for (let i = 0; i < tableRows.length; i++) {
            const dateCell = tableRows[i].getElementsByTagName('td')[0];
            const dateStr = dateCell.textContent.trim();
            if (dateStr !== 'N/A') {
                const submissionDate = new Date(dateStr);
                allSubmissions.push({
                    row: tableRows[i],
                    date: submissionDate
                });
            }
        }
        
        // Find oldest and newest dates
        const dates = allSubmissions.map(s => s.date).sort((a, b) => a - b);
        const oldestDate = dates[0];
        const newestDate = dates[dates.length - 1];
        
        // Initialize date labels
        document.getElementById('minDateLabel').textContent = oldestDate.toLocaleDateString();
        document.getElementById('maxDateLabel').textContent = newestDate.toLocaleDateString();
        
        // Date slider functionality
        const dateSlider = document.getElementById('dateSlider');
        const daysDisplay = document.getElementById('daysDisplay');
        
        dateSlider.addEventListener('input', function() {
            const daysBack = parseInt(this.value);
            daysDisplay.textContent = daysBack;
            filterByDateRange(daysBack);
        });
        
        function filterByDateRange(daysBack) {
            const cutoffDate = new Date();
            cutoffDate.setDate(cutoffDate.getDate() - daysBack);
            
            let visibleCount = 0;
            allSubmissions.forEach(submission => {
                if (submission.date >= cutoffDate) {
                    submission.row.style.display = '';
                    visibleCount++;
                } else {
                    submission.row.style.display = 'none';
                }
            });
            
            // Update stats
            updateVisibleStats(visibleCount);
        }
        
        function resetDateFilter() {
            dateSlider.value = 180;
            daysDisplay.textContent = '180';
            allSubmissions.forEach(submission => {
                submission.row.style.display = '';
            });
            updateVisibleStats(allSubmissions.length);
        }
        
        function updateVisibleStats(count) {
            document.getElementById('visibleCount').textContent = count;
        }
        
        function filterTable() {
            const input = document.getElementById('searchBox');
            const filter = input.value.toUpperCase();
            const table = document.getElementById('submissionsTable');
            const rows = table.getElementsByTagName('tr');
            
            let visibleCount = 0;
            
            for (let i = 1; i < rows.length; i++) {
                const row = rows[i];
                
                // Skip if hidden by date filter
                if (row.style.display === 'none') continue;
                
                const cells = row.getElementsByTagName('td');
                let found = false;
                
                for (let j = 0; j < cells.length; j++) {
                    const cell = cells[j];
                    if (cell) {
                        const textValue = cell.textContent || cell.innerText;
                        if (textValue.toUpperCase().indexOf(filter) > -1) {
                            found = true;
                            break;
                        }
                    }
                }
                
                if (found) {
                    row.classList.remove('search-hidden');
                    visibleCount++;
                } else {
                    row.classList.add('search-hidden');
                }
            }
            
            // Apply visibility based on both filters
            for (let i = 1; i < rows.length; i++) {
                const row = rows[i];
                if (row.classList.contains('search-hidden')) {
                    row.style.display = 'none';
                }
            }
            
            updateVisibleStats(visibleCount);
        }
        
        // Get visible rows from table
        function getVisibleRows() {
            const table = document.getElementById('submissionsTable');
            const rows = table.getElementsByTagName('tr');
            const visibleData = [];
            
            // Get headers
            const headers = [];
            const headerCells = rows[0].getElementsByTagName('th');
            for (let i = 0; i < headerCells.length; i++) {
                headers.push(headerCells[i].textContent.trim());
            }
            
            // Get visible data rows
            for (let i = 1; i < rows.length; i++) {
                const row = rows[i];
                
                // Check if row is visible
                const computedStyle = window.getComputedStyle(row);
                if (computedStyle.display === 'none' || row.classList.contains('search-hidden')) {
                    continue;
                }
                
                const cells = row.getElementsByTagName('td');
                const rowData = {};
                
                for (let j = 0; j < cells.length; j++) {
                    const header = headers[j];
                    const value = cells[j].textContent.trim();
                    rowData[header] = value;
                }
                
                visibleData.push(rowData);
            }
            
            return { headers, data: visibleData };
        }
        
        // Export to Excel (CSV format)
        function exportToExcel() {
            const { headers, data } = getVisibleRows();
            
            if (data.length === 0) {
                alert('No visible submissions to export. Please adjust your filters.');
                return;
            }
            
            // Build CSV content with BOM for proper Excel UTF-8 support
            let csvContent = '\uFEFF'; // UTF-8 BOM for Excel
            
            // Add title row
            csvContent += 'Microsoft Defender Threat Submissions Report\n';
            const now = new Date();
            csvContent += 'Generated: ' + now.toLocaleString() + '\n';
            csvContent += 'Total Records: ' + data.length + '\n';
            csvContent += '\n'; // Empty line
            
            // Add headers
            csvContent += headers.join(',') + '\n';
            
            // Add data rows
            data.forEach(row => {
                const values = headers.map(header => {
                    let value = row[header] || '';
                    // Escape commas, quotes, and newlines for CSV
                    if (value.includes(',') || value.includes('"') || value.includes('\n')) {
                        value = '"' + value.replace(/"/g, '""') + '"';
                    }
                    return value;
                });
                csvContent += values.join(',') + '\n';
            });
            
            // Download CSV with descriptive filename
            const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
            const link = document.createElement('a');
            const url = URL.createObjectURL(blob);
            
            const now2 = new Date();
            const dateStr = now2.getFullYear() + '-' + 
                           String(now2.getMonth() + 1).padStart(2, '0') + '-' + 
                           String(now2.getDate()).padStart(2, '0');
            const timeStr = String(now2.getHours()).padStart(2, '0') + '-' + 
                           String(now2.getMinutes()).padStart(2, '0');
            
            const filename = 'Threat_Submissions_Report_' + dateStr + '_' + timeStr + '.csv';
            
            link.setAttribute('href', url);
            link.setAttribute('download', filename);
            link.style.visibility = 'hidden';
            
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            
            console.log('Exported ' + data.length + ' submissions to Excel: ' + filename);
        }
    </script>
</body>
</html>
"@

    $htmlContent | Out-File -FilePath $OutputPath -Encoding UTF8
}

function Show-ConfigurationGuidance {
    # Silent function - guidance removed from console
}

# ===============================================
# INITIALIZATION
# ===============================================

Write-Host "Microsoft Defender Threat Submission Export Tool v1.0" -ForegroundColor Green

# Run prerequisites check
if (-not (Test-Prerequisites)) {
    Write-Error "Prerequisites check failed. Please resolve the issues above and try again."
    exit 1
}

# Show configuration guidance
Show-ConfigurationGuidance

# Import required module
Import-Module Microsoft.Graph.Authentication -Force

# Connect to Microsoft Graph
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
try {
    Connect-MgGraph -Scopes "ThreatSubmission.Read.All","Mail.ReadBasic" -NoWelcome
    Write-Host "Connected successfully" -ForegroundColor Green
} catch {
    Write-Error "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
    exit 1
}

# ===============================================
# CONFIGURATION
# ===============================================

# Output file paths with timestamp
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$timestamp = (Get-Date).ToString("yyyy-MM-dd_HH-mm")
$OutCsv = Join-Path $ScriptDir "Defender_User_Submissions_$timestamp.csv"
$OutJson = Join-Path $ScriptDir "Defender_User_Submissions_$timestamp.json"

# Date filter
$startDate = (Get-Date).AddDays(-$DaysBack).ToString("yyyy-MM-ddTHH:mm:ssZ")
$dateFilter = "and createdDateTime ge $startDate"

# Category filter
$categoryFilter = if ($Category) { "and category eq '$Category'" } else { "" }

# ===============================================
# DATA RETRIEVAL
# ===============================================

$baseUri = "https://graph.microsoft.com/beta/security/threatSubmission/emailThreats"
$submissions = New-Object System.Collections.Generic.List[object]

# Build source filter
$sourceFilter = if ($IncludeAdminSubmissions) {
    "(source eq 'user' or source eq 'administrator')"
} else {
    "source eq 'user'"
}

$filterQuery = "`$filter=$sourceFilter $dateFilter $categoryFilter"
$uri = "$baseUri`?$filterQuery&`$top=100"

Write-Host "`nRetrieving threat submissions..." -ForegroundColor Yellow

# ===============================================
# HELPER FUNCTIONS
# ===============================================



# Function to retrieve Message-ID from Graph Mail API
function Get-MessageIdFromMail {
    param(
        [string]$recipientEmail,
        [string]$subject, 
        [string]$receivedDateTime,
        [string]$sender
    )
    
    try {
        # Format datetime for Graph API with better parsing
        $dateTime = [DateTime]::Parse($receivedDateTime)
        $startDate = $dateTime.AddMinutes(-60).ToString("yyyy-MM-ddTHH:mm:ssZ")
        $endDate = $dateTime.AddMinutes(60).ToString("yyyy-MM-ddTHH:mm:ssZ")
        
        # Escape single quotes in filter
        $escapedSender = $sender -replace "'", "''"
        
        $filter = "receivedDateTime ge $startDate and receivedDateTime le $endDate and from/emailAddress/address eq '$escapedSender'"
        $uri = "https://graph.microsoft.com/v1.0/users/$recipientEmail/messages?`$filter=$filter&`$select=internetMessageId,subject&`$top=20"
        
        $mailResponse = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction SilentlyContinue
        
        # Find exact subject match
        $matchingMail = $mailResponse.value | Where-Object { $_.subject -eq $subject } | Select-Object -First 1
        
        if ($matchingMail -and $matchingMail.internetMessageId) {
            return $matchingMail.internetMessageId
        }
    } catch {
        Write-Verbose "Mail API error for $recipientEmail : $($_.Exception.Message)"
    }
    
    return $null
}

# Function to create submission object with all fields
function New-SubmissionObject {
    param($submission, $internetMsgId)
    
    return [PSCustomObject]@{
        Id = $submission.id
        CreatedDateTime = $submission.createdDateTime
        Source = $submission.source
        Category = $submission.category
        ContentType = $submission.contentType
        RecipientEmail = $submission.recipientEmailAddress
        Sender = $submission.sender
        InternetMessageId = $internetMsgId
        ReceivedDateTime = $submission.receivedDateTime
        Subject = $submission.subject
        OriginalCategory = $submission.originalCategory
        Status = $submission.status
        ResultCategory = $submission.result?.category
        ResultDetail = $submission.result?.detail
        SenderIP = $submission.senderIP
        ClientSource = $submission.clientSource
        TenantId = $submission.tenantId
        CreatedByEmail = $submission.createdBy?.email
        CreatedByDisplayName = $submission.createdBy?.displayName
        DetectedUrls = if ($submission.result?.detectedUrls) { ($submission.result.detectedUrls -join "; ") } else { "" }
        DetectedFileNames = if ($submission.result?.detectedFiles) { ($submission.result.detectedFiles | ForEach-Object { $_.fileName } | Where-Object { $_ }) -join "; " } else { "" }
        DetectedFileHashes = if ($submission.result?.detectedFiles) { ($submission.result.detectedFiles | ForEach-Object { $_.fileHash } | Where-Object { $_ }) -join "; " } else { "" }
        UserMailboxSetting = $submission.result?.userMailboxSetting
        AdminReviewBy = $submission.adminReview?.reviewBy
        AdminReviewResult = $submission.adminReview?.reviewResult
        AdminReviewDateTime = $submission.adminReview?.reviewDateTime
        IsAttackSimulation = if ($submission.attackSimulationInfo) { "Yes" } else { "No" }
        AttackSimId = $submission.attackSimulationInfo?.attackSimId
        AttackSimDateTime = $submission.attackSimulationInfo?.attackSimDateTime
        TenantAllowBlockAction = $submission.tenantAllowOrBlockListAction?.action
        TenantAllowBlockNote = $submission.tenantAllowOrBlockListAction?.note
    }
}

$pageCount = 0
$totalRetrieved = 0
Write-Host "Retrieving threat submissions..." -ForegroundColor Yellow

do {
    try {
        $pageCount++
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri
        $batchCount = $response.value.Count
        $totalRetrieved += $batchCount
        
        Write-Progress -Activity "Retrieving submissions" -Status "Retrieved $totalRetrieved submissions" -PercentComplete -1
        
        foreach ($submission in $response.value) {
            
            # Determine Internet Message ID with optimized logic
            $internetMsgId = if ([string]::IsNullOrEmpty($submission.internetMessageId)) {
                # Try to retrieve from Mail API (only if we have valid data)
                if ($submission.recipientEmailAddress -and $submission.sender -and $submission.subject) {
                    $realMessageId = Get-MessageIdFromMail -recipientEmail $submission.recipientEmailAddress -subject $submission.subject -receivedDateTime $submission.receivedDateTime -sender $submission.sender
                    
                    if ($realMessageId) {
                        "RETRIEVED: $realMessageId"
                    } else {
                        # Generate alternative ID
                        "ALT-ID: $($submission.sender)-$($submission.subject)-$($submission.receivedDateTime)"
                    }
                } else {
                    "ALT-ID: $($submission.id)-$($submission.createdDateTime)"
                }
            } else { 
                $submission.internetMessageId 
            }
            
            # Create and add submission object
            $submissionObj = New-SubmissionObject -submission $submission -internetMsgId $internetMsgId
            $submissions.Add($submissionObj)
        }
        
        $uri = $response.'@odata.nextLink'
    } catch {
        Write-Error "Error retrieving submissions: $($_.Exception.Message)"
        break
    }
} while ($uri)

# ===============================================
# EXPORT RESULTS
# ===============================================

Write-Host "Processing complete. Retrieved $($submissions.Count) submissions" -ForegroundColor Green

if ($submissions.Count -gt 0) {
    # Sort by creation date
    $sortedSubmissions = $submissions | Sort-Object CreatedDateTime -Descending
    
    # Generate HTML report
    Write-Host "Generating HTML report..." -ForegroundColor Yellow
    $OutHtml = Join-Path $ScriptDir "Defender_Threat_Submissions_$(Get-Date -Format 'yyyy-MM-dd_HH-mm').html"
    
    try {
        Export-HtmlReport -Submissions $sortedSubmissions -OutputPath $OutHtml
        
        if (Test-Path $OutHtml) {
            Write-Host "Report generated: $OutHtml" -ForegroundColor Green
            Start-Process $OutHtml
        }
    } catch {
        Write-Warning "Failed to generate HTML report: $($_.Exception.Message)"
    }
} else {
    Write-Warning "No threat submissions found matching the specified criteria."
}

Write-Host "Script completed successfully!" -ForegroundColor Green