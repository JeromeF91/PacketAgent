# Package Agent

A PowerShell-based agent that manages software packages using Chocolatey and integrates with an API to check for new packages to install.

## Prerequisites

- Windows PowerShell 5.1 or later
- Administrator privileges (required for Chocolatey installation and package management)

## Configuration

Before running the agent, update the following configuration in `PackageAgent.ps1`:

```powershell
$config = @{
    ApiPostEndpoint = "https://n8n.chezjf.com/webhook/report"  # API endpoint for reporting
    LogPath = ".\logs"
    LogFile = "package_agent.log"
}
```

## API Endpoint

### POST /report
The agent sends package reports to this endpoint and expects a response with packages to install/update.

#### Request Format
```json
{
    "hostname": "computer-name",
    "timestamp": "2024-03-14T12:00:00.000Z",
    "packages": [
        {
            "name": "package-name",
            "version": "1.0.0"
        }
    ],
    "windowsInfo": {
        "caption": "Microsoft Windows 11 Pro",
        "version": "10.0.26100",
        "buildNumber": "26100",
        "osArchitecture": "64-bit",
        "lastBootUpTime": "2024-03-14T12:00:00.000Z",
        "installDate": "2024-03-14T12:00:00.000Z"
    },
    "diskSpace": {
        "totalSize": 256060514304,
        "freeSpace": 128030257152,
        "usedSpace": 128030257152,
        "freeSpacePercent": 50.0,
        "driveLetter": "C:",
        "fileSystem": "NTFS",
        "volumeName": "Windows"
    },
    "hardening": {
        "smb1Enabled": false,
        "smb1Status": "Disabled"
    }
}
```

The report includes:
- `hostname`: The computer's hostname
- `timestamp`: Current time in ISO 8601 format
- `packages`: List of installed packages with versions
- `windowsInfo`: Detailed Windows system information
- `diskSpace`: C: drive space information in bytes
- `hardening`: Security hardening status (currently SMB1 check)

#### Response Format
The API should return a response with packages to install/update in the following format:
```json
{
    "packages": [
        {
            "name": "package-name",
            "version": "1.0.0"
        }
    ]
}
```

## Usage

1. Open PowerShell as Administrator
2. Navigate to the script directory
3. Run the script:

```powershell
.\PackageAgent.ps1
```

## Workflow

1. The agent collects information about:
   - Currently installed packages
   - Windows system information (version, build, architecture, etc.)
   - Available disk space on C: drive
   - Security hardening status (SMB1)
2. Sends this information to the API endpoint
3. Processes any packages returned in the API response
4. Installs or updates packages as needed

## Logging

The agent creates a log file in the `logs` directory. Each run will append to the log file with timestamps and log levels (INFO, DEBUG, ERROR).

## Error Handling

The script includes comprehensive error handling and will:
- Log all errors to the log file
- Continue processing other packages if one fails
- Exit with code 1 if a critical error occurs
- Handle API communication errors gracefully
- Validate disk space information before calculations

## Security

- The script requires administrator privileges to install/update packages
- Chocolatey installation uses HTTPS
- API calls are made over HTTPS
- Security hardening checks are included (SMB1 status)
- Windows system information is collected for security assessment