# Cycode Integration

This integration authenticates with the Cycode API and obtains an authentication token.

## Configuration

The integration requires three parameters:
- **cycode_url**: The base URL of your Cycode instance (e.g., `https://api.cycode.com`)
- **cycode_client_id**: OAuth2 client ID for API authentication
- **cycode_secret**: OAuth2 client secret for API authentication

## Features

- OAuth2 authentication with Cycode API
- Secure token generation
- Error handling and logging

## Usage

```bash
./starlark-runner -script cycode.star -params "cycode_url=https://api.cycode.com,cycode_client_id=your-client-id,cycode_secret=your-client-secret"
```

## Authentication Flow

The integration follows this authentication process:

1. Makes a POST request to `{cycode_url}/api/v1/auth/api-token`
2. Sends credentials as JSON payload: `{"clientId": "<client_id>", "secret": "<client_secret>"}`
3. Includes proper headers: `Content-Type: application/json` and `Accept: application/json`
4. Extracts and returns the `token` field from the response

## Notes

- The token is logged (first 20 characters only) for verification purposes
- All authentication errors are logged with appropriate error messages
- The integration validates that all required parameters are provided before attempting authentication

