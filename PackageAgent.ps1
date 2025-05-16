#Requires -Version 5.1

# Configuration
$config = @{
    ApiPostEndpoint = "https://n8n.chezjf.com/webhook/report"  # Replace with your actual API endpoint for reporting
    #ApiPostEndpoint = "https://n8n.chezjf.com/webhook-test/report"  # Replace with your actual API endpoint for reporting
    LogPath = ".\logs"
    LogFile = "package_agent.log"
}

# Ensure log directory exists
if (-not (Test-Path $config.LogPath)) {
    New-Item -ItemType Directory -Path $config.LogPath -Force | Out-Null
}

# Function to write to log file
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Add-Content -Path (Join-Path $config.LogPath $config.LogFile) -Value $logMessage
    Write-Host $logMessage
}

# Function to check and install Chocolatey if needed
function Install-ChocolateyIfNeeded {
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-Log "Chocolatey not found. Installing..."
        try {
            Set-ExecutionPolicy Bypass -Scope Process -Force
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
            Write-Log "Chocolatey installed successfully"
        }
        catch {
            Write-Log "Failed to install Chocolatey: $_" -Level "ERROR"
            throw
        }
    }
    else {
        Write-Log "Chocolatey is already installed"
    }
}

# Function to get installed packages
function Get-InstalledPackages {
    try {
        $packages = choco list --local-only -r
        $packageList = @()
        
        foreach ($package in $packages) {
            $parts = $package -split '\|'
            if ($parts.Count -ge 2) {
                $packageList += @{
                    name = $parts[0]
                    version = $parts[1]
                }
            }
        }
        
        return $packageList
    }
    catch {
        Write-Log "Failed to get installed packages: $_" -Level "ERROR"
        return $null
    }
}

# Function to install or update packages
function Install-UpdatePackages {
    param(
        [array]$Packages
    )
    
    foreach ($package in $Packages) {
        try {
            if (-not (choco list --local-only $package.name -r)) {
                Write-Log "Installing package: $($package.name)"
                choco install $package.name -y
            }
            else {
                Write-Log "Updating package: $($package.name)"
                choco upgrade $package.name -y
            }
        }
        catch {
            Write-Log "Failed to process package $($package.name): $_" -Level "ERROR"
        }
    }
}

# Function to get disk space information
function Get-DiskSpaceInfo {
    try {
        $drive = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'"
        if ($drive) {
            $totalSize = [int64]$drive.Size
            $freeSpace = [int64]$drive.FreeSpace
            
            # Validate that we have valid size values
            if ($totalSize -gt 0 -and $freeSpace -ge 0) {
                $usedSpace = $totalSize - $freeSpace
                $freeSpacePercent = [math]::Round(($freeSpace / $totalSize) * 100, 2)
                
                $diskInfo = @{
                    totalSize = $totalSize
                    freeSpace = $freeSpace
                    usedSpace = $usedSpace
                    freeSpacePercent = $freeSpacePercent
                    driveLetter = $drive.DeviceID
                    fileSystem = $drive.FileSystem
                    volumeName = $drive.VolumeName
                }
                Write-Log "Disk space info retrieved: $($diskInfo | ConvertTo-Json)" -Level "DEBUG"
                return $diskInfo
            }
            else {
                Write-Log "Invalid disk size values detected: TotalSize=$totalSize, FreeSpace=$freeSpace" -Level "WARNING"
                return $null
            }
        }
        Write-Log "Could not get valid disk space information for C: drive" -Level "WARNING"
        return $null
    }
    catch {
        Write-Log "Failed to get disk space information: $_" -Level "ERROR"
        return $null
    }
}

# Function to get Windows version information
function Get-WindowsVersionInfo {
    try {
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
        $versionInfo = @{
            caption = $osInfo.Caption
            version = $osInfo.Version
            buildNumber = $osInfo.BuildNumber
            osArchitecture = $osInfo.OSArchitecture
            lastBootUpTime = $osInfo.LastBootUpTime.ToString("o")
            installDate = $osInfo.InstallDate.ToString("o")
        }
        Write-Log "Windows version info retrieved: $($versionInfo | ConvertTo-Json)" -Level "DEBUG"
        return $versionInfo
    }
    catch {
        Write-Log "Failed to get Windows version information: $_" -Level "ERROR"
        return $null
    }
}

# Function to get hardening information
function Get-HardeningInfo {
    try {
        # Check SMB1 status
        $smb1Status = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "AllowInsecureGuestAuth" -ErrorAction SilentlyContinue).AllowInsecureGuestAuth
        $smb1Enabled = $false
        
        if ($smb1Status -ne $null) {
            $smb1Enabled = ($smb1Status -eq 1)
        }

        # Check TLS protocols
        $tls10Enabled = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
        $tls11Enabled = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
        $tls12Enabled = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
        $tls13Enabled = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled

        # Check cipher suites
        $weakCiphers = @(
            "RC4",
            "DES",
            "3DES",
            "NULL"
        )
        
        $enabledCiphers = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\*" -ErrorAction SilentlyContinue | 
            Where-Object { $_.Enabled -eq 1 } | 
            Select-Object -ExpandProperty PSChildName

        $weakCiphersEnabled = $false
        foreach ($cipher in $enabledCiphers) {
            if ($weakCiphers -contains $cipher) {
                $weakCiphersEnabled = $true
                break
            }
        }
        
        $hardeningInfo = @{
            "smb1Enabled" = $smb1Enabled
            "smb1Status" = if ($smb1Enabled) { "Enabled" } else { "Disabled" }
            "tlsProtocols" = @{
                "tls10" = if ($tls10Enabled -eq 1) { "Enabled" } else { "Disabled" }
                "tls11" = if ($tls11Enabled -eq 1) { "Enabled" } else { "Disabled" }
                "tls12" = if ($tls12Enabled -eq 1) { "Enabled" } else { "Disabled" }
                "tls13" = if ($tls13Enabled -eq 1) { "Enabled" } else { "Disabled" }
            }
            "cipherSuites" = @{
                "weakCiphersEnabled" = $weakCiphersEnabled
                "enabledCiphers" = $enabledCiphers
            }
        }
        
        Write-Log "Hardening info retrieved: $($hardeningInfo | ConvertTo-Json)" "DEBUG"
        return $hardeningInfo
    }
    catch {
        Write-Log "Failed to get hardening information: $_" "ERROR"
        return $null
    }
}

# Function to send package report to API and get packages to install
function Send-PackageReport {
    try {
        $hostname = [System.Net.Dns]::GetHostName()
        $installedPackages = Get-InstalledPackages
        $diskInfo = Get-DiskSpaceInfo
        $windowsInfo = Get-WindowsVersionInfo
        $hardeningInfo = Get-HardeningInfo
        
        if ($installedPackages) {
            $report = @{
                hostname = $hostname
                timestamp = (Get-Date).ToString("o")
                packages = $installedPackages
                windowsInfo = $windowsInfo
                hardening = $hardeningInfo
            }
            
            # Add disk space info if available
            if ($diskInfo) {
                $report.diskSpace = $diskInfo
            }
            
            $jsonBody = $report | ConvertTo-Json -Depth 10
            Write-Log "Sending report to API: $jsonBody" -Level "DEBUG"
            
            $response = Invoke-RestMethod -Uri $config.ApiPostEndpoint -Method Post -Body $jsonBody -ContentType "application/json"
            Write-Log "API Response received: $($response | ConvertTo-Json)" -Level "DEBUG"
            Write-Log "Successfully sent package report to API"
            
            # Check if response contains packages to install
            if ($response -and $response.packages) {
                Write-Log "Retrieved $($response.packages.Count) packages to process from API response"
                Write-Log "Packages to process: $($response.packages | ConvertTo-Json)" -Level "DEBUG"
                Install-UpdatePackages -Packages $response.packages
            }
            else {
                Write-Log "No packages to process in API response" -Level "INFO"
                Write-Log "Response structure: $($response | Get-Member | ConvertTo-Json)" -Level "DEBUG"
            }
            
            return $true
        }
        else {
            Write-Log "No installed packages found to report" -Level "WARNING"
            return $false
        }
    }
    catch {
        Write-Log "Failed to send package report to API: $_" -Level "ERROR"
        if ($_.Exception.Response) {
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd()
            Write-Log "API Error Response: $responseBody" -Level "DEBUG"
        }
        return $false
    }
}

# Main execution
try {
    Write-Log "Starting Package Agent"
    
    # Ensure Chocolatey is installed
    Install-ChocolateyIfNeeded
    
    # Send package report and process any packages from the response
    Send-PackageReport
    
    Write-Log "Package Agent completed successfully"
}
catch {
    Write-Log "Package Agent failed: $_" -Level "ERROR"
    exit 1
} 