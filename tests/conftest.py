import pytest
from unittest.mock import patch
import ssh_keyservice.config as config
from ssh_keyservice.app import create_app

@pytest.fixture(autouse=True)
def patch_get_secret():
    """Automatically mock get_secret() in all tests."""
    with patch.object(config, "get_secret") as mock_secret:
        def secret_side_effect(name):
            mocked = f"mocked_{name.lower().replace('-', '_')}"
            print(f"[MOCK] get_secret({name}) → {mocked}")
            return mocked
        mock_secret.side_effect = secret_side_effect
        #mock_secret.side_effect = lambda name: f"mocked_{name.lower().replace('-', '_')}"
        yield

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

@pytest.fixture
def runner(app):
    """Create a CLI runner for Flask app (if needed)."""
    return app.test_cli_runner()

