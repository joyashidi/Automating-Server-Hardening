#Security Policy Configuration

function Security-Policy {
    # Set password policy
    secedit /export /cfg C:\SecConfig.cfg
    (Get-Content C:\SecConfig.cfg).replace("MinimumPasswordLength = 0", "MinimumPasswordLength = 12") | Set-Content C:\SecConfig.cfg
    (Get-Content C:\SecConfig.cfg).replace("MaximumPasswordAge = 42", "MaximumPasswordAge = 30") | Set-Content C:\SecConfig.cfg
    (Get-Content C:\SecConfig.cfg).replace("PasswordComplexity = 0", "PasswordComplexity = 1") | Set-Content C:\SecConfig.cfg
    secedit /configure /db secedit.sdb /cfg C:\SecConfig.cfg

    # Set account lockout policy
    (Get-Content C:\SecConfig.cfg).replace("LockoutBadCount = 0", "LockoutBadCount = 5") | Set-Content C:\SecConfig.cfg
    (Get-Content C:\SecConfig.cfg).replace("ResetLockoutCount = 30", "ResetLockoutCount = 15") | Set-Content C:\SecConfig.cfg
    (Get-Content C:\SecConfig.cfg).replace("LockoutDuration = 30", "LockoutDuration = 15") | Set-Content C:\SecConfig.cfg
    secedit /configure /db secedit.sdb /cfg C:\SecConfig.cfg

    # Set user rights assignment
    (Get-Content C:\SecConfig.cfg).replace("SeDenyInteractiveLogonRight = ", "SeDenyInteractiveLogonRight = *S-1-5-32-546") | Set-Content C:\SecConfig.cfg
    secedit /configure /db secedit.sdb /cfg C:\SecConfig.cfg

    # Set audit policy
    Auditpol.exe /set /subcategory:"Logon" /success:enable /failure:enable
    Auditpol.exe /set /subcategory:"Credential Validation" /success:enable /failure:enable
}

# Windows Server Update Script

$logFilePath = "C:\Logs\WindowsUpdate.log"
$inactiveStartHour = 19 # Start of inactive hours (7 PM)
$inactiveEndHour = 8    # End of inactive hours (8 AM)

# Ensure the log directory exists
$logDir = Split-Path -Path $logFilePath -Parent
if (-not (Test-Path -Path $logDir)) {
    Write-Output "Creating log directory at $logDir"
    New-Item -Path $logDir -ItemType Directory -Force
}

# Function to Log messages for this script
function Log-Message {
    param (
        [string]$message
    )
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $LogEntry = "$timestamp - $message"
    Add-Content -Path $logFilePath -Value $LogEntry
}

# Function to check if current time is within inactive hours
function Is-InactiveHours {
    $currentHour = (Get-Date).Hour
    if ($inactiveStartHour -lt $inactiveEndHour) {
        return ($currentHour -ge $inactiveStartHour -or $currentHour -lt $inactiveEndHour)
    } else {
        return ($currentHour -ge $inactiveStartHour -or $currentHour -lt $inactiveEndHour)
    }
}

# Inform the user that logs are being saved
Write-Host "Logs for this script are stored at C:\Logs\WindowsUpdate"

# Checking for updates
$updates = Get-WindowsUpdate -AcceptAll -IgnoreReboot -Verbose

if ($updates) {
    Log-Message "Updates found, installing updates..."
    Write-Host "Updates found, installing updates..."

    Install-WindowsUpdate -AcceptAll -AutoReboot
} else {
    Log-Message "No updates found."
    Write-Host "No updates found."
}

# Check if a reboot is required and schedule it during inactive hours
if (Is-InactiveHours) {
    Log-Message "System is in inactive hours. Rebooting now."
    Write-Host "System is in inactive hours. Rebooting now."
} else {
    Log-Message "System is not in inactive hours. Reboot will be scheduled."
    Write-Host "System is not in inactive hours. Scheduling reboot."

    # Schedule reboot at the start of the next inactive period
    $rebootTime = [datetime]::Now.Date.AddHours($inactiveStartHour)
    if ([datetime]::Now.Hour -ge $inactiveStartHour) {
        $rebootTime = $rebootTime.AddDays(1)
    }
    $rebootTime = $rebootTime.ToString("yyyy-MM-ddTHH:mm:ss")
    Log-Message "Scheduled reboot at $rebootTime."
    Write-Host "Scheduled reboot at $rebootTime."

    # Add scheduled task for reboot
    $rebootTime = "2:00AM"
    $action = New-ScheduledTaskAction -Execute "shutdown.exe" -Argument "/r /t 0"
    $trigger = New-ScheduledTaskTrigger -Once -At $rebootTime
    Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "ScheduledReboot" -RunLevel Highest
}

# After reboot, add a log entry indicating update completion
if ($env:COMPUTERNAME -eq $env:COMPUTERNAME) {
    Log-Message "Update done after reboot."
    Write-Host "Update done after reboot."
}

# Function to configure the firewall
function Configure-Firewall {
    Write-Output "Configuring firewall rules..."

    # Clear existing rules
    Write-Output "Clearing existing firewall rules..."
    Get-NetFirewallRule | Remove-NetFirewallRule

    #Turn on Windows Firewall for all network profiles
    Set-NetFirewallProfile -All -Enabled True
    Write-Output "Firewall turned on"

    # Block all incoming and outgoing connections by default
    Write-Output "Blocking all incoming and outgoing connections by default..."
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Block

    # Detect active connections and allow them
    Write-Output "Allowing active connections..."
    $activeConnections = Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' } | Select-Object -Property LocalPort

    foreach ($connection in $activeConnections) {
        $port = $connection.LocalPort
        Write-Output "Allowing active connection on port $port"
        New-NetFirewallRule -DisplayName "Allow Active Connection on Port $port" -Direction Outbound -Protocol TCP -LocalPort $port -Action Allow
    }

    # Enable firewall logging (Optional)
    Write-Output "Enabling firewall logging..."
    Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed True -LogBlocked True -LogFileName "C:\Logs\Firewall.log" -LogMaxSizeKilobytes 32767

    # Allow necessary inbound connections
    Write-Output "Allowing necessary inbound connections..."

    # List of inbound rules
    $inboundRules = @{
        "Allow RDP"              = @{ Protocol = 'TCP'; Port = 3389 }
        "Allow HTTPS"            = @{ Protocol = 'TCP'; Port = 443 }
        "Allow DNS"              = @{ Protocol = 'UDP'; Port = 53 }
        "Allow SMTP"             = @{ Protocol = 'TCP'; Port = 25 }        
        "Allow NTP"              = @{ Protocol = 'UDP'; Port = 123 }
    }

    foreach ($rule in $inboundRules.GetEnumerator()) {
        $name = $rule.Key
        $params = $rule.Value
        Write-Output "Creating inbound rule: $name"
        New-NetFirewallRule -DisplayName $name -Direction Inbound -Protocol $params.Protocol -LocalPort $params.Port -Action Allow
    }

    # Allow necessary outbound connections
    Write-Output "Allowing necessary outbound connections..."

    # List of outbound rules
    $outboundRules = @{
        "Allow Outbound DNS"     = @{ Protocol = 'UDP'; Port = 53 }
        "Allow Outbound HTTPS"   = @{ Protocol = 'TCP'; Port = 443 }
        "Allow Outbound SMTP"    = @{ Protocol = 'TCP'; Port = 25 }
        "Allow NTP Outbound"     = @{ Protocol = 'UDP'; Port = 123 }
    }

    foreach ($rule in $outboundRules.GetEnumerator()) {
        $name = $rule.Key
        $params = $rule.Value
        Write-Output "Creating outbound rule: $name"
        New-NetFirewallRule -DisplayName $name -Direction Outbound -Protocol $params.Protocol -RemotePort $params.Port -Action Allow
    }

    Write-Output "Firewall configuration completed. The logs are in C:\Logs\Firewall.log"
}

# Run the function
Configure-Firewall

#Now configure the IDS

# Define the output file with timestamp
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputFile = "C:\Logs\audit_results_$timestamp.txt"

# Create directory if it doesn't exist
$outputDir = [System.IO.Path]::GetDirectoryName($outputFile)
if (-not (Test-Path $outputDir)) {
    New-Item -Path $outputDir -ItemType Directory
}

# Function to log results
function Log-Result {
    param (
        [string]$message
    )
    Add-Content -Path $outputFile -Value $message
}

# Log the date and time the script ran
Log-Result "Security audit started on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

# 1. Detect Unusual Login Times
$loginThreshold = 6  # Set threshold for early morning logins (6 AM)
$logonEvents = Get-EventLog -LogName Security -InstanceId 4624 -ErrorAction SilentlyContinue | 
    Where-Object { $_.TimeGenerated.Hour -lt $loginThreshold -or $_.TimeGenerated.Hour -gt 20 }

if ($logonEvents.Count -gt 0) {
    Log-Result "`nUnusual login times detected:"
    foreach ($event in $logonEvents) {
        Log-Result "User: $($event.ReplacementStrings[5]), Time: $($event.TimeGenerated)"
    }
} else {
    Log-Result "`nNo unusual login times detected."
}

# 2. Detect High CPU Usage
$cpuThreshold = 80  # Set CPU usage threshold
$highCpuProcesses = Get-Process | Where-Object { $_.CPU -gt $cpuThreshold }

if ($highCpuProcesses.Count -gt 0) {
    Log-Result "`nHigh CPU usage detected:"
    foreach ($process in $highCpuProcesses) {
        Log-Result "Process: $($process.Name), CPU: $($process.CPU)%"
    }
} else {
    Log-Result "`nNo high CPU usage detected."
}

# 3. Detect Unknown Executables
$knownExecutables = @("cmd.exe", "powershell.exe", "wmic.exe", "mshta.exe")  # Add known safe executables
$runningProcesses = Get-Process | Where-Object { $_.Name -in $knownExecutables }

if ($runningProcesses.Count -gt 0) {
    Log-Result "`nUnknown executables detected:"
    foreach ($process in $runningProcesses) {
        Log-Result "Executable: $($process.Path)"
    }
} else {
    Log-Result "`nNo unknown executables detected."
}

# 4. Detect Privilege Escalation Attempts
$privilegeEscalationEvents = Get-EventLog -LogName Security -InstanceId 4672 -ErrorAction SilentlyContinue

if ($privilegeEscalationEvents.Count -gt 0) {
    Log-Result "`nPrivilege escalation attempts detected:"
    foreach ($event in $privilegeEscalationEvents) {
        Log-Result "User: $($event.ReplacementStrings[1]), Time: $($event.TimeGenerated)"
    }
} else {
    Log-Result "`nNo privilege escalation attempts detected."
}

# Final output check
if ((Get-Content -Path $outputFile).Trim().Length -eq 0) {
    Log-Result "`nNo issues detected."
} else {
    Log-Result "`nSecurity audit completed."
}

# Log the completion time
Log-Result "`nSecurity audit completed on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

# Output the file location to the console
Write-Host "Intrusion Detection audit results have been saved to: $outputFile"
