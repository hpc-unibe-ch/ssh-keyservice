# OpenOnDemand Configuration

This SSH Key Service can be run in two authentication modes:

1. **Azure OIDC Mode** (default) - Uses Microsoft Azure Active Directory for authentication
2. **OpenOnDemand Mode** - Uses pre-authenticated OIDC tokens from files (for OpenOnDemand environments)

## OpenOnDemand Mode

When running this application in an OpenOnDemand environment, authentication is already handled by the OpenOnDemand platform. The application can be configured to read existing OIDC tokens from a file instead of performing its own authentication flow.

### Configuration

To enable OpenOnDemand mode, set the following environment variables:

```bash
# Enable OpenOnDemand mode
USE_OPENONDEMAND=true

# Path to the OIDC token file (default: /var/run/secrets/oidc/token)
OIDC_TOKEN_PATH=/path/to/your/oidc/token

# Flask secret key for session management (optional, auto-generated if not set)
FLASK_SECRET_KEY=your-secret-key-here

# API endpoint for the backend service
AZURE_API_BASE_URL=http://your-api-server:8000
```

### How It Works

In OpenOnDemand mode:

1. **No Azure Authentication**: The application skips the Azure AD login flow entirely
2. **Token from File**: OIDC tokens are read from the file specified in `OIDC_TOKEN_PATH`
3. **Automatic Forwarding**: The token is automatically included in all API requests to the backend
4. **No Azure Key Vault**: Configuration secrets are not fetched from Azure Key Vault

### Example Docker Compose Configuration

```yaml
version: '3.8'

services:
  ssh-keyservice:
    image: ssh-keyservice:latest
    environment:
      - USE_OPENONDEMAND=true
      - OIDC_TOKEN_PATH=/var/run/secrets/oidc/token
      - AZURE_API_BASE_URL=http://api:8000
      - FLASK_SECRET_KEY=${FLASK_SECRET_KEY}
    volumes:
      - /path/to/oidc/token:/var/run/secrets/oidc/token:ro
    ports:
      - "5000:5000"
```

### Example Kubernetes Configuration

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: ssh-keyservice
spec:
  containers:
  - name: app
    image: ssh-keyservice:latest
    env:
    - name: USE_OPENONDEMAND
      value: "true"
    - name: OIDC_TOKEN_PATH
      value: "/var/run/secrets/oidc/token"
    - name: AZURE_API_BASE_URL
      value: "http://api-service:8000"
    volumeMounts:
    - name: oidc-token
      mountPath: /var/run/secrets/oidc
      readOnly: true
  volumes:
  - name: oidc-token
    hostPath:
      path: /path/to/oidc/token
      type: File
```

### Running Locally for Testing

To test OpenOnDemand mode locally:

1. Create a test token file:
   ```bash
   echo "your-test-oidc-token-here" > /tmp/oidc-token
   ```

2. Set environment variables:
   ```bash
   export USE_OPENONDEMAND=true
   export OIDC_TOKEN_PATH=/tmp/oidc-token
   export AZURE_API_BASE_URL=http://localhost:8000
   ```

3. Run the application:
   ```bash
   poetry run python -m ssh_keyservice.main
   ```

### Switching Back to Azure OIDC Mode

To switch back to Azure OIDC mode, either:

1. Set `USE_OPENONDEMAND=false`, or
2. Unset/remove the `USE_OPENONDEMAND` environment variable

When Azure OIDC mode is active, the application will:
- Require Azure Key Vault configuration
- Fetch secrets from Azure Key Vault
- Use Microsoft Azure AD for authentication

## Security Considerations

### OpenOnDemand Mode
- Ensure the OIDC token file has appropriate permissions (readable only by the application)
- The token file path should be mounted read-only in containerized environments
- Tokens should be refreshed periodically by the OpenOnDemand platform

### Azure OIDC Mode
- Requires proper Azure Key Vault configuration
- Ensure Azure credentials are properly configured
- Follow Azure security best practices for service principals

## Troubleshooting

### Token Not Found
If you see "OIDC token not found or invalid":
- Verify the `OIDC_TOKEN_PATH` points to the correct file
- Check file permissions
- Ensure the file contains a valid token (not empty)

### API Authentication Errors
If API calls fail with authentication errors:
- Verify the OIDC token is valid and not expired
- Ensure the backend API is configured to accept the token
- Check that `AZURE_API_BASE_URL` is correct

### Still Using Azure Authentication
If the app still tries to use Azure authentication:
- Verify `USE_OPENONDEMAND=true` is set (case-sensitive)
- Check environment variables are properly loaded
- Restart the application after changing environment variables
