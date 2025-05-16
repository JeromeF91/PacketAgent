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

# Function to remediate WinVerifyTrust certificate padding
function Enable-WinVerifyTrustPadding {
    try {
        $winVerifyTrustPath = "HKLM:\SOFTWARE\Microsoft\Cryptography\Wintrust\Config"
        
        # Create the registry key if it doesn't exist
        if (-not (Test-Path $winVerifyTrustPath)) {
            New-Item -Path $winVerifyTrustPath -Force | Out-Null
        }
        
        # Set the EnableCertPaddingCheck value to 1 (enabled)
        Set-ItemProperty -Path $winVerifyTrustPath -Name "EnableCertPaddingCheck" -Value 1 -Type DWord -Force
        
        Write-Log "Successfully enabled WinVerifyTrust certificate padding check" "INFO"
        return $true
    }
    catch {
        Write-Log "Failed to enable WinVerifyTrust certificate padding check: $_" "ERROR"
        return $false
    }
}

# Function to check if running with administrator privileges
function Test-Administrator {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Function to remediate SMB1
function Disable-SMB1 {
    if (-not (Test-Administrator)) {
        Write-Log "SMB1 remediation requires administrator privileges. Please run the script as administrator." "ERROR"
        return $false
    }

    try {
        # Disable SMB1 in Windows Features
        $smb1Feature = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction Stop
        if ($smb1Feature.State -eq "Enabled") {
            Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction Stop
            Write-Log "Successfully disabled SMB1 protocol" "INFO"
        }

        # Disable SMB1 in registry
        $smb1Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
        if (-not (Test-Path $smb1Path)) {
            New-Item -Path $smb1Path -Force | Out-Null
        }
        Set-ItemProperty -Path $smb1Path -Name "AllowInsecureGuestAuth" -Value 0 -Type DWord -Force
        
        Write-Log "Successfully disabled SMB1 in registry" "INFO"
        return $true
    }
    catch {
        Write-Log "Failed to disable SMB1: $_" "ERROR"
        return $false
    }
}

# Function to check and remediate Spectre and Meltdown vulnerabilities
function Get-SpectreMeltdownStatus {
    try {
        $status = @{
            "spectreV2" = @{
                "enabled" = $true
                "status" = "Protected"
            }
            "meltdown" = @{
                "enabled" = $true
                "status" = "Protected"
            }
            "ssb" = @{
                "enabled" = $true
                "status" = "Protected"
                "cve" = "CVE-2018-3639"
            }
        }

        # Check registry settings for Spectre V2
        $spectreV2Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
        $spectreV2Value = (Get-ItemProperty -Path $spectreV2Path -Name "FeatureSettingsOverride" -ErrorAction SilentlyContinue).FeatureSettingsOverride
        $spectreV2Mask = (Get-ItemProperty -Path $spectreV2Path -Name "FeatureSettingsOverrideMask" -ErrorAction SilentlyContinue).FeatureSettingsOverrideMask

        if ($spectreV2Value -ne $null -and $spectreV2Mask -ne $null) {
            # Check if Spectre V2 protection is disabled
            if (($spectreV2Value -band $spectreV2Mask) -eq 0) {
                $status.spectreV2.enabled = $false
                $status.spectreV2.status = "Vulnerable"
            }
        }

        # Check registry settings for Meltdown
        $meltdownPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
        $meltdownValue = (Get-ItemProperty -Path $meltdownPath -Name "FeatureSettingsOverride" -ErrorAction SilentlyContinue).FeatureSettingsOverride
        $meltdownMask = (Get-ItemProperty -Path $meltdownPath -Name "FeatureSettingsOverrideMask" -ErrorAction SilentlyContinue).FeatureSettingsOverrideMask

        if ($meltdownValue -ne $null -and $meltdownMask -ne $null) {
            # Check if Meltdown protection is disabled
            if (($meltdownValue -band $meltdownMask) -eq 0) {
                $status.meltdown.enabled = $false
                $status.meltdown.status = "Vulnerable"
            }
        }

        # Check registry settings for SSB (CVE-2018-3639)
        $ssbPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
        $ssbValue = (Get-ItemProperty -Path $ssbPath -Name "FeatureSettingsOverride" -ErrorAction SilentlyContinue).FeatureSettingsOverride
        $ssbMask = (Get-ItemProperty -Path $ssbPath -Name "FeatureSettingsOverrideMask" -ErrorAction SilentlyContinue).FeatureSettingsOverrideMask

        if ($ssbValue -ne $null -and $ssbMask -ne $null) {
            # Check if SSB protection is disabled
            if (($ssbValue -band $ssbMask) -eq 0) {
                $status.ssb.enabled = $false
                $status.ssb.status = "Vulnerable"
            }
        }

        # Additional check for SSB using CPU information
        try {
            $cpuInfo = Get-CimInstance -ClassName Win32_Processor
            if ($cpuInfo) {
                # Check if CPU supports SSB mitigation
                $supportsSSBMitigation = $cpuInfo.Caption -match "Intel|AMD"
                if (-not $supportsSSBMitigation) {
                    $status.ssb.enabled = $false
                    $status.ssb.status = "Not Supported"
                }
            }
        }
        catch {
            Write-Log "Could not check CPU information for SSB: $_" "DEBUG"
        }

        return $status
    }
    catch {
        Write-Log "Failed to check Spectre/Meltdown/SSB status: $_" "ERROR"
        return $null
    }
}

# Function to remediate Spectre and Meltdown vulnerabilities
function Enable-SpectreMeltdownProtection {
    if (-not (Test-Administrator)) {
        Write-Log "Spectre/Meltdown/SSB remediation requires administrator privileges. Please run the script as administrator." "ERROR"
        return $false
    }

    try {
        $memoryManagementPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
        
        # Create the registry key if it doesn't exist
        if (-not (Test-Path $memoryManagementPath)) {
            New-Item -Path $memoryManagementPath -Force | Out-Null
        }

        # Enable Spectre V2 protection
        Set-ItemProperty -Path $memoryManagementPath -Name "FeatureSettingsOverride" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $memoryManagementPath -Name "FeatureSettingsOverrideMask" -Value 3 -Type DWord -Force

        # Enable Meltdown protection
        Set-ItemProperty -Path $memoryManagementPath -Name "FeatureSettingsOverride" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $memoryManagementPath -Name "FeatureSettingsOverrideMask" -Value 3 -Type DWord -Force

        # Enable SSB protection (CVE-2018-3639)
        # The correct registry settings for SSB are:
        # - FeatureSettingsOverride = 0
        # - FeatureSettingsOverrideMask = 3
        # These are the same as Spectre/Meltdown as they control all speculative execution mitigations
        Set-ItemProperty -Path $memoryManagementPath -Name "FeatureSettingsOverride" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $memoryManagementPath -Name "FeatureSettingsOverrideMask" -Value 3 -Type DWord -Force

        Write-Log "Successfully enabled Spectre, Meltdown, and SSB protections" "INFO"
        return $true
    }
    catch {
        Write-Log "Failed to enable Spectre/Meltdown/SSB protections: $_" "ERROR"
        return $false
    }
}

# Function to check and remediate SMB signing
function Get-SMBSigningStatus {
    try {
        $status = @{
            "serverEnabled" = $true
            "serverRequired" = $false
            "clientEnabled" = $true
            "clientRequired" = $false
        }

        # Check server signing settings
        $serverSigningPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        $serverEnabled = (Get-ItemProperty -Path $serverSigningPath -Name "EnableSecuritySignature" -ErrorAction SilentlyContinue).EnableSecuritySignature
        $serverRequired = (Get-ItemProperty -Path $serverSigningPath -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue).RequireSecuritySignature

        if ($serverEnabled -ne $null) {
            $status.serverEnabled = ($serverEnabled -eq 1)
        }
        if ($serverRequired -ne $null) {
            $status.serverRequired = ($serverRequired -eq 1)
        }

        # Check client signing settings
        $clientSigningPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
        $clientEnabled = (Get-ItemProperty -Path $clientSigningPath -Name "EnableSecuritySignature" -ErrorAction SilentlyContinue).EnableSecuritySignature
        $clientRequired = (Get-ItemProperty -Path $clientSigningPath -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue).RequireSecuritySignature

        if ($clientEnabled -ne $null) {
            $status.clientEnabled = ($clientEnabled -eq 1)
        }
        if ($clientRequired -ne $null) {
            $status.clientRequired = ($clientRequired -eq 1)
        }

        return $status
    }
    catch {
        Write-Log "Failed to check SMB signing status: $_" "ERROR"
        return $null
    }
}

# Function to remediate SMB signing
function Enable-SMBSigning {
    if (-not (Test-Administrator)) {
        Write-Log "SMB signing remediation requires administrator privileges. Please run the script as administrator." "ERROR"
        return $false
    }

    try {
        # Server signing settings
        $serverSigningPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        if (-not (Test-Path $serverSigningPath)) {
            New-Item -Path $serverSigningPath -Force | Out-Null
        }
        Set-ItemProperty -Path $serverSigningPath -Name "EnableSecuritySignature" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $serverSigningPath -Name "RequireSecuritySignature" -Value 1 -Type DWord -Force

        # Client signing settings
        $clientSigningPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
        if (-not (Test-Path $clientSigningPath)) {
            New-Item -Path $clientSigningPath -Force | Out-Null
        }
        Set-ItemProperty -Path $clientSigningPath -Name "EnableSecuritySignature" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $clientSigningPath -Name "RequireSecuritySignature" -Value 1 -Type DWord -Force

        Write-Log "Successfully enabled SMB signing for both client and server" "INFO"
        return $true
    }
    catch {
        Write-Log "Failed to enable SMB signing: $_" "ERROR"
        return $false
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

        # Check if SMB1 is enabled in Windows Features (only if running as admin)
        if (Test-Administrator) {
            try {
                $smb1Feature = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction Stop
                if ($smb1Feature.State -eq "Enabled") {
                    $smb1Enabled = $true
                }
            }
            catch {
                Write-Log "Could not check SMB1 feature status: $_" "DEBUG"
            }
        }
        else {
            Write-Log "Skipping SMB1 feature check - requires administrator privileges" "DEBUG"
        }

        # Remediate SMB1 if enabled
        if ($smb1Enabled) {
            Write-Log "SMB1 is enabled. Attempting to disable..." "WARNING"
            Disable-SMB1
        }

        # Check SMB signing status
        $smbSigningStatus = Get-SMBSigningStatus
        if ($smbSigningStatus) {
            # Attempt remediation if signing is not enabled or required
            if (-not $smbSigningStatus.serverEnabled -or -not $smbSigningStatus.serverRequired -or 
                -not $smbSigningStatus.clientEnabled -or -not $smbSigningStatus.clientRequired) {
                Write-Log "SMB signing is not fully enabled. Attempting to enable..." "WARNING"
                Enable-SMBSigning
                # Refresh status after remediation
                $smbSigningStatus = Get-SMBSigningStatus
            }
        }

        # Check WinVerifyTrust Signature Validation
        $winVerifyTrustPath = "HKLM:\SOFTWARE\Microsoft\Cryptography\Wintrust\Config"
        $winVerifyTrustEnabled = $true  # Default is enabled
        try {
            $winVerifyTrustValue = (Get-ItemProperty -Path $winVerifyTrustPath -Name "EnableCertPaddingCheck" -ErrorAction Stop).EnableCertPaddingCheck
            if ($winVerifyTrustValue -eq 0) {
                $winVerifyTrustEnabled = $false
                # Attempt to remediate if disabled
                Write-Log "WinVerifyTrust certificate padding check is disabled. Attempting to enable..." "WARNING"
                Enable-WinVerifyTrustPadding
            }
        }
        catch {
            Write-Log "Could not read WinVerifyTrust status: $_" "DEBUG"
        }

        # Check Spectre and Meltdown status
        $spectreMeltdownStatus = Get-SpectreMeltdownStatus
        if ($spectreMeltdownStatus) {
            # Attempt remediation if vulnerable
            if (-not $spectreMeltdownStatus.spectreV2.enabled -or -not $spectreMeltdownStatus.meltdown.enabled) {
                Write-Log "Spectre/Meltdown vulnerabilities detected. Attempting to enable protections..." "WARNING"
                Enable-SpectreMeltdownProtection
                # Refresh status after remediation
                $spectreMeltdownStatus = Get-SpectreMeltdownStatus
            }
        }

        # Check TLS protocols (Server)
        $tls10ServerEnabled = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
        $tls11ServerEnabled = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
        $tls12ServerEnabled = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
        $tls13ServerEnabled = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled

        # Check TLS protocols (Client)
        $tls10ClientEnabled = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
        $tls11ClientEnabled = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
        $tls12ClientEnabled = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
        $tls13ClientEnabled = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled

        # Check cipher suites (Server)
        $weakCiphers = @(
            "RC4",
            "DES",
            "3DES",
            "NULL"
        )
        
        # Get server cipher suites from SCHANNEL
        $schannelCiphersPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers"
        $enabledServerCiphers = @()
        $weakServerCiphersEnabled = $false

        try {
            # Get all cipher subkeys
            $cipherKeys = Get-ChildItem -Path $schannelCiphersPath -ErrorAction Stop
            foreach ($key in $cipherKeys) {
                $cipherName = $key.PSChildName
                $enabled = (Get-ItemProperty -Path $key.PSPath -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
                
                # If Enabled is not explicitly set to 0, consider it enabled (default behavior)
                if ($enabled -ne 0) {
                    $enabledServerCiphers += $cipherName
                    # Check if this is a weak cipher
                    foreach ($weakCipher in $weakCiphers) {
                        if ($cipherName -like "*$weakCipher*") {
                            $weakServerCiphersEnabled = $true
                            break
                        }
                    }
                }
            }
        }
        catch {
            Write-Log "Could not read SCHANNEL cipher status: $_" "DEBUG"
        }

        # Get client cipher suites
        $clientCipherPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers"
        $enabledClientCiphers = @()
        $weakClientCiphersEnabled = $false

        try {
            # Get all cipher subkeys for client
            $clientCipherKeys = Get-ChildItem -Path $clientCipherPath -ErrorAction Stop
            foreach ($key in $clientCipherKeys) {
                $cipherName = $key.PSChildName
                $enabled = (Get-ItemProperty -Path $key.PSPath -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
                
                # If Enabled is not explicitly set to 0, consider it enabled (default behavior)
                if ($enabled -ne 0) {
                    $enabledClientCiphers += $cipherName
                    # Check if this is a weak cipher
                    foreach ($weakCipher in $weakCiphers) {
                        if ($cipherName -like "*$weakCipher*") {
                            $weakClientCiphersEnabled = $true
                            break
                        }
                    }
                }
            }
        }
        catch {
            Write-Log "Could not read client cipher status: $_" "DEBUG"
        }
        
        $hardeningInfo = @{
            "smb1Enabled" = $smb1Enabled
            "smb1Status" = if ($smb1Enabled) { "Enabled" } else { "Disabled" }
            "smbSigning" = $smbSigningStatus
            "winVerifyTrust" = @{
                "enabled" = $winVerifyTrustEnabled
                "status" = if ($winVerifyTrustEnabled) { "Enabled" } else { "Disabled" }
            }
            "spectreMeltdown" = $spectreMeltdownStatus
            "tlsProtocols" = @{
                "server" = @{
                    "tls10" = if ($tls10ServerEnabled -eq 1) { "Enabled" } else { "Disabled" }
                    "tls11" = if ($tls11ServerEnabled -eq 1) { "Enabled" } else { "Disabled" }
                    "tls12" = if ($tls12ServerEnabled -eq 1) { "Enabled" } else { "Disabled" }
                    "tls13" = if ($tls13ServerEnabled -eq 1) { "Enabled" } else { "Disabled" }
                }
                "client" = @{
                    "tls10" = if ($tls10ClientEnabled -eq 1) { "Enabled" } else { "Disabled" }
                    "tls11" = if ($tls11ClientEnabled -eq 1) { "Enabled" } else { "Disabled" }
                    "tls12" = if ($tls12ClientEnabled -eq 1) { "Enabled" } else { "Disabled" }
                    "tls13" = if ($tls13ClientEnabled -eq 1) { "Enabled" } else { "Disabled" }
                }
            }
            "cipherSuites" = @{
                "server" = @{
                    "weakCiphersEnabled" = $weakServerCiphersEnabled
                    "enabledCiphers" = $enabledServerCiphers
                }
                "client" = @{
                    "weakCiphersEnabled" = $weakClientCiphersEnabled
                    "enabledCiphers" = $enabledClientCiphers
                }
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