# Package Agent

A PowerShell-based agent that manages software packages using Chocolatey and integrates with an API to check for new packages to install.

## Prerequisites

- Windows PowerShell 5.1 or later
- Administrator privileges (required for Chocolatey installation and package management)

## Configuration

Before running the agent, update the following configuration in `PackageAgent.ps1`:

```powershell
$config = @{
    ApiPostEndpoint = "https://n8n.chezjf.com/webhook/report"  # Replace with your actual API endpoint for reporting
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
    ]
}
```

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

1. The agent collects information about currently installed packages
2. Sends this information to the API endpoint
3. Processes any packages returned in the API response
4. Installs or updates packages as needed

## Logging

The agent creates a log file in the `logs` directory. Each run will append to the log file with timestamps and log levels.

## Error Handling

The script includes comprehensive error handling and will:
- Log all errors to the log file
- Continue processing other packages if one fails
- Exit with code 1 if a critical error occurs

## Security

- The script requires administrator privileges to install/update packages
- Chocolatey installation uses HTTPS
- API calls should be made over HTTPS