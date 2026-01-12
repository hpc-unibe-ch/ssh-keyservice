import os
import secrets

from cachelib.file import FileSystemCache

# OpenOnDemand configuration
# Authentication is handled by OpenOnDemand, OIDC token is read from a file

def load_config():
    """Load configuration for OpenOnDemand mode.
    
    OpenOnDemand handles authentication externally, and the OIDC token
    is provided in a file on the web server.
    """
    # Read configuration from environment variables
    secret_key = os.getenv("FLASK_SECRET_KEY", secrets.token_hex(32))
    api_base_url = os.getenv("API_BASE_URL", "http://localhost:8000")
    api_endpoint = api_base_url + "/api/v1"
    oidc_token_path = os.getenv("OIDC_TOKEN_PATH", "/var/run/secrets/oidc/token")

    return {
        "SECRET_KEY": secret_key,
        "API_BASE_URL": api_base_url,
        "API_ENDPOINT": api_endpoint,
        "OIDC_TOKEN_PATH": oidc_token_path,
        # Session configuration
        "SESSION_TYPE": "cachelib",
        "SESSION_PERMANENT": False,
        "SESSION_SERIALIZATION_FORMAT": 'json',
        "SESSION_CACHELIB": FileSystemCache(threshold=500, cache_dir="flask_session")
    }
