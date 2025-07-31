import os

from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from cachelib.file import FileSystemCache

# Configure Azure Key Vault

def get_secret(secret_name: str) -> str:
    credential = DefaultAzureCredential()
    client = SecretClient(vault_url=os.getenv("AZURE_KEY_VAULT_URL", "https://your-keyvault-name.vault.azure.net"), credential=credential)
    try:
        return client.get_secret(secret_name).value
    except Exception as e:
        raise RuntimeError(f"Error retrieving secret {secret_name}: {str(e)}")

def load_config():
    tenant_id = get_secret("TENANT-ID")
    client_id = get_secret("APP-CLIENT-ID")
    client_secret = get_secret("APP-CLIENT-SECRET")
    secret_key = get_secret("FLASK-SECRET-KEY")

    authority = f"https://login.microsoftonline.com/{tenant_id}"
    api_base_url = os.getenv("AZURE_API_BASE_URL", "http://localhost:8000")
    api_endpoint = api_base_url + "/api/v1"
    redirect_path = "/getAToken"
    endpoint = 'https://graph.microsoft.com/v1.0/me'
    scope = [f"api://{client_id}/user.read.profile"]

    return {
        "TENANT_ID": tenant_id,
        "AUTHORITY": authority,
        "CLIENT_ID": client_id,
        "CLIENT_SECRET": client_secret,
        "SECRET_KEY": secret_key,
        "REDIRECT_PATH": redirect_path,
        "ENDPOINT": endpoint,
        "SCOPE": scope,
        "API_BASE_URL": api_base_url,
        "API_ENDPOINT": api_endpoint,
        # Tells the Flask-session extension to store sessions in the filesystem
        # In production, your setup may use multiple web servers behind a load balancer,
        # and the subsequent requests may not be routed to the same web server.
        # In that case, you may either use a centralized database-backed session store,
        # or configure your load balancer to route subsequent requests to the same web server
        # by using sticky sessions also known as affinity cookie.
        # [1] https://www.imperva.com/learn/availability/sticky-session-persistence-and-cookies/
        # [2] https://azure.github.io/AppService/2016/05/16/Disable-Session-affinity-cookie-(ARR-cookie)-for-Azure-web-apps.html
        # [3] https://learn.microsoft.com/en-us/azure/app-service/configure-common?tabs=portal#configure-general-settings
        "SESSION_TYPE": "cachelib",
        "SESSION_SERIALIZATION_FORMAT": 'json',
        "SESSION_CACHELIB": FileSystemCache(threshold=500, cache_dir="flask_session")
    }
