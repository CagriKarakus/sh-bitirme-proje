# Windows CIS Benchmark Audit Script Template
# PowerShell 5.1+ Required

#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    CIS Benchmark Audit Script for Windows

.DESCRIPTION
    Performs security audit checks based on CIS Benchmark recommendations
    for Windows operating systems.

.PARAMETER GenerateReport
    Generate HTML report of audit results

.PARAMETER ReportPath
    Path where report will be saved (default: C:\temp\cis_report)

.EXAMPLE
    .\audit_template.ps1 -GenerateReport -ReportPath "C:\Reports"
#>

param(
    [switch]$GenerateReport,
    [string]$ReportPath = "C:\temp\cis_report_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
)

# Script variables
$Script:AuditResults = @()
$Script:PassCount = 0
$Script:FailCount = 0

# Initialize logging
function Write-AuditLog {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $color = switch ($Level) {
        'Success' { 'Green' }
        'Warning' { 'Yellow' }
        'Error'   { 'Red' }
        default   { 'White' }
    }

    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

# Function to record audit result
function Add-AuditResult {
    param(
        [string]$RuleId,
        [string]$Title,
        [string]$Status,  # PASS or FAIL
        [string]$Description,
        [string]$Output
    )

    $Script:AuditResults += [PSCustomObject]@{
        RuleId      = $RuleId
        Title       = $Title
        Status      = $Status
        Description = $Description
        Output      = $Output
        Timestamp   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    }

    if ($Status -eq 'PASS') {
        $Script:PassCount++
        Write-AuditLog "✓ $RuleId - $Title" -Level Success
    } else {
        $Script:FailCount++
        Write-AuditLog "✗ $RuleId - $Title" -Level Warning
    }
}

# Audit rule functions will be inserted here

# Main execution
Write-AuditLog "Starting CIS Benchmark Audit for Windows" -Level Info
Write-AuditLog "Platform: $($PSVersionTable.PSVersion)" -Level Info

# Execute audit rules
# Rule executions will be inserted here by compose script

# Generate summary
Write-Host "`n" + ("=" * 80)
Write-Host "AUDIT SUMMARY"
Write-Host ("=" * 80)
Write-Host "Total Rules Checked: $($Script:PassCount + $Script:FailCount)"
Write-Host "Passed: $Script:PassCount" -ForegroundColor Green
Write-Host "Failed: $Script:FailCount" -ForegroundColor Red
Write-Host ("=" * 80)

# Generate report if requested
if ($GenerateReport) {
    Write-AuditLog "Generating HTML report..." -Level Info

    if (-not (Test-Path $ReportPath)) {
        New-Item -ItemType Directory -Path $ReportPath -Force | Out-Null
    }

    $reportFile = Join-Path $ReportPath "cis_audit_report.html"

    # Generate HTML report (simplified version)
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>CIS Benchmark Audit Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #2c3e50; color: white; padding: 20px; }
        .summary { margin: 20px 0; padding: 15px; background-color: #ecf0f1; }
        .pass { color: green; font-weight: bold; }
        .fail { color: red; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #34495e; color: white; }
    </style>
</head>
<body>
    <div class="header">
        <h1>CIS Benchmark Audit Report</h1>
        <p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        <p>Computer: $env:COMPUTERNAME</p>
    </div>

    <div class="summary">
        <h2>Summary</h2>
        <p>Total Rules: $($Script:PassCount + $Script:FailCount)</p>
        <p class="pass">Passed: $Script:PassCount</p>
        <p class="fail">Failed: $Script:FailCount</p>
    </div>

    <h2>Detailed Results</h2>
    <table>
        <tr>
            <th>Rule ID</th>
            <th>Title</th>
            <th>Status</th>
            <th>Description</th>
        </tr>
"@

    foreach ($result in $Script:AuditResults) {
        $statusClass = if ($result.Status -eq 'PASS') { 'pass' } else { 'fail' }
        $html += @"
        <tr>
            <td>$($result.RuleId)</td>
            <td>$($result.Title)</td>
            <td class="$statusClass">$($result.Status)</td>
            <td>$($result.Description)</td>
        </tr>
"@
    }

    $html += @"
    </table>
</body>
</html>
"@

    $html | Out-File -FilePath $reportFile -Encoding UTF8
    Write-AuditLog "Report saved to: $reportFile" -Level Success
}

# Export results to CSV
$csvFile = Join-Path $ReportPath "cis_audit_results.csv"
$Script:AuditResults | Export-Csv -Path $csvFile -NoTypeInformation
Write-AuditLog "Results exported to: $csvFile" -Level Info

Write-AuditLog "Audit completed" -Level Success
