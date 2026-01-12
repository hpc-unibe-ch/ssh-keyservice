import pytest
import tempfile
import os
from unittest.mock import patch
from ssh_keyservice.app import create_app

@pytest.fixture(autouse=True)
def mock_oidc_token():
    """Automatically create a mock OIDC token file for all tests."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.token') as f:
        f.write("test_oidc_token_12345")
        f.flush()
        token_path = f.name
    
    # Set environment variable to use the test token
    with patch.dict(os.environ, {"OIDC_TOKEN_PATH": token_path}):
        yield token_path
    
    # Cleanup
    try:
        os.unlink(token_path)
    except:
        pass

@pytest.fixture
def app():
    """Create a Flask app instance for testing."""
    app = create_app()
    app.config.update({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,  # Optional: disable CSRF in tests
        # Add any test-specific config overrides here
    })
    yield app

@pytest.fixture
def client(app):
    """Create a test client for the Flask app."""
    return app.test_client()
