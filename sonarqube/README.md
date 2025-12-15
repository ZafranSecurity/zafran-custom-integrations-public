# SonarQube Cloud Integration

This integration collects projects and security vulnerabilities from SonarQube Cloud.

## Configuration

The integration requires:
- **api_url**: The SonarQube Cloud API URL (default: sonarcloud.io)
- **api_key**: Authentication token for SonarQube Cloud

## Features

- Fetches all projects accessible to the authenticated user
- Collects project metadata including:
  - Organization
  - Project type/qualifier
  - Visibility settings
  - Last analysis date
- Retrieves security vulnerabilities from two sources:
  - Security Hotspots API
  - Issues API (filtered for VULNERABILITY type)
- Maps SonarQube findings to CVE-like identifiers
- Assigns severity scores based on SonarQube ratings

## Usage

```bash
./starlark-runner -script sonarqube/sonarqube.star -params "api_url=sonarcloud.io,api_key=your-token-here"
```

## Notes

- Projects are treated as "instances" in the Zafran model
- Each vulnerability is linked to its parent project
- Security hotspots and vulnerability issues are both collected
- Severity mapping:
  - HIGH/BLOCKER/CRITICAL: 8.0-9.0
  - MEDIUM/MAJOR: 5.0-6.0  
  - LOW/MINOR: 3.0
  - INFO: 1.0
- All vulnerabilities are marked as static analysis findings (not runtime)

## API Endpoints Used

- `/api/projects/search` - List all projects
- `/api/hotspots/search` - Get security hotspots for a project
- `/api/issues/search` - Get vulnerability issues for a project