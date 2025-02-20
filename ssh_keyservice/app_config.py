import os

from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

# Configure Azure Key Vault
KEY_VAULT_URL = os.getenv("AZURE_KEY_VAULT_URL", "https://your-keyvault-name.vault.azure.net")
credential = DefaultAzureCredential()
client = SecretClient(vault_url=KEY_VAULT_URL, credential=credential)

def get_secret(secret_name: str) -> str:
    try:
        return client.get_secret(secret_name).value
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving secret {secret_name}: {str(e)}")

# Configure your authority via environment variable
# Defaults to a multi-tenant app in world-wide cloud
TENANT_ID = get_secret("TENANT-ID")
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
#AUTHORITY = os.getenv("AUTHORITY") or "https://login.microsoftonline.com/common"

# Application (client) ID of app registration
CLIENT_ID = get_secret("APP-CLIENT-ID")
#CLIENT_ID = os.getenv("CLIENT_ID")
# Application's generated client secret: never check this into source control!
CLIENT_SECRET = get_secret("APP-CLIENT-SECRET")
#CLIENT_SECRET = os.getenv("CLIENT_SECRET")

REDIRECT_PATH = "/getAToken"  # Used for forming an absolute URL to your redirect URI.
# The absolute URL must match the redirect URI you set
# in the app's registration in the Azure portal.

# You can find more Microsoft Graph API endpoints from Graph Explorer
# https://developer.microsoft.com/en-us/graph/graph-explorer
ENDPOINT = 'https://graph.microsoft.com/v1.0/me'  # This resource requires no admin consent

# You can find the proper permission names from this document
# https://docs.microsoft.com/en-us/graph/permissions-reference
api_client_id = CLIENT_ID or ""
SCOPE = ["api://" + api_client_id + "/user.read.profile"]

# API URLs
API_BASE_URL = os.getenv("AZURE_API_BASE_URL") or "http://localhost:8000"
API_ENDPOINT = API_BASE_URL + "/api/v1"

# Flask rate limiting settings
#LIMITS_DB_HOST = os.getenv("LIMITS_DB_HOST") or "localhost"
#LIMITS_DB_PORT = os.getenv("LIMITS_DB_PORT") or 6379

# Tells the Flask-session extension to store sessions in the filesystem
SESSION_TYPE = "filesystem"
# In production, your setup may use multiple web servers behind a load balancer,
# and the subsequent requests may not be routed to the same web server.
# In that case, you may either use a centralized database-backed session store,
# or configure your load balancer to route subsequent requests to the same web server
# by using sticky sessions also known as affinity cookie.
# [1] https://www.imperva.com/learn/availability/sticky-session-persistence-and-cookies/
# [2] https://azure.github.io/AppService/2016/05/16/Disable-Session-affinity-cookie-(ARR-cookie)-for-Azure-web-apps.html
# [3] https://learn.microsoft.com/en-us/azure/app-service/configure-common?tabs=portal#configure-general-settings
