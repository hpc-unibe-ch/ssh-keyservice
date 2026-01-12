import pytest
import os
import tempfile
from unittest.mock import patch, MagicMock
from ssh_keyservice.app import create_app
from ssh_keyservice.utils import read_oidc_token


class TestReadOIDCToken:
    """Test OIDC token reading functionality."""
    
    def test_read_valid_token(self):
        """Test reading a valid OIDC token from file."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("test_token_123")
            f.flush()
            token_path = f.name
        
        try:
            token = read_oidc_token(token_path)
            assert token == "test_token_123"
        finally:
            os.unlink(token_path)
    
    def test_read_token_with_whitespace(self):
        """Test reading a token with whitespace."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("  test_token_456  \n")
            f.flush()
            token_path = f.name
        
        try:
            token = read_oidc_token(token_path)
            assert token == "test_token_456"
        finally:
            os.unlink(token_path)
    
    def test_read_nonexistent_token(self):
        """Test reading from a non-existent file."""
        token = read_oidc_token("/nonexistent/path/to/token")
        assert token is None
    
    def test_read_empty_token_file(self):
        """Test reading from an empty file."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("")
            f.flush()
            token_path = f.name
        
        try:
            token = read_oidc_token(token_path)
            assert token is None
        finally:
            os.unlink(token_path)


class TestOpenOnDemandConfig:
    """Test OpenOnDemand configuration."""
    
    @patch.dict(os.environ, {"USE_OPENONDEMAND": "true", "OIDC_TOKEN_PATH": "/test/token"})
    @patch('ssh_keyservice.config.get_secret')
    def test_openondemand_config(self, mock_get_secret):
        """Test that OpenOnDemand mode loads correct config."""
        from ssh_keyservice.config import load_config
        
        config = load_config()
        
        assert config["USE_OPENONDEMAND"] is True
        assert config["OIDC_TOKEN_PATH"] == "/test/token"
        assert "SECRET_KEY" in config
        assert config["CLIENT_ID"] == ""
        assert config["CLIENT_SECRET"] == ""
        # get_secret should not be called in OpenOnDemand mode
        mock_get_secret.assert_not_called()
    
    @patch.dict(os.environ, {"USE_OPENONDEMAND": "false"}, clear=True)
    @patch('ssh_keyservice.config.get_secret')
    def test_azure_oidc_config(self, mock_get_secret):
        """Test that Azure OIDC mode loads secrets."""
        def secret_side_effect(name):
            return f"mocked_{name.lower().replace('-', '_')}"
        mock_get_secret.side_effect = secret_side_effect
        
        from ssh_keyservice.config import load_config
        
        config = load_config()
        
        assert config["USE_OPENONDEMAND"] is False
        assert config["CLIENT_ID"] == "mocked_app_client_id"
        assert config["CLIENT_SECRET"] == "mocked_app_client_secret"
        # get_secret should be called in Azure mode
        assert mock_get_secret.call_count == 4


@pytest.fixture
def ood_app():
    """Create a Flask app instance for OpenOnDemand testing."""
    with patch.dict(os.environ, {"USE_OPENONDEMAND": "true", "OIDC_TOKEN_PATH": "/test/token"}):
        app = create_app()
        app.config.update({
            "TESTING": True,
            "WTF_CSRF_ENABLED": False,
        })
        yield app


@pytest.fixture
def ood_client(ood_app):
    """Create a test client for OpenOnDemand mode."""
    return ood_app.test_client()


class TestOpenOnDemandRoutes:
    """Test routes when in OpenOnDemand mode."""
    
    def test_login_redirects_to_index(self, ood_client):
        """Test that login redirects to index in OpenOnDemand mode."""
        response = ood_client.get('/login')
        assert response.status_code == 302
        assert response.location.endswith('/')
    
    def test_logout_clears_session(self, ood_client):
        """Test that logout clears session in OpenOnDemand mode."""
        with ood_client.session_transaction() as sess:
            sess['oidc_token'] = 'test_token'
        
        response = ood_client.get('/logout')
        assert response.status_code == 302
        
        # Session should be cleared
        with ood_client.session_transaction() as sess:
            assert 'oidc_token' not in sess
    
    @patch('ssh_keyservice.routes.read_oidc_token')
    def test_index_without_token(self, mock_read_token, ood_client):
        """Test index page when token cannot be read."""
        mock_read_token.return_value = None
        
        response = ood_client.get('/')
        assert response.status_code == 200
        # Should render config_error template
        assert b'error' in response.data or b'Error' in response.data
    
    @patch('ssh_keyservice.routes.read_oidc_token')
    @patch('ssh_keyservice.routes.requests.get')
    def test_index_with_token(self, mock_get, mock_read_token, ood_client):
        """Test index page with valid token."""
        mock_read_token.return_value = "valid_token_123"
        
        # Mock API response
        mock_response = MagicMock()
        mock_response.status_code = 404  # No keys
        mock_get.return_value = mock_response
        
        response = ood_client.get('/')
        assert response.status_code == 200
        assert mock_read_token.called
    
    @patch('ssh_keyservice.routes.read_oidc_token')
    @patch('ssh_keyservice.routes.requests.get')
    def test_add_key_get_with_token(self, mock_get, mock_read_token, ood_client):
        """Test GET request to add_key in OpenOnDemand mode."""
        mock_read_token.return_value = "valid_token_123"
        
        response = ood_client.get('/add_key')
        assert response.status_code == 200
    
    @patch('ssh_keyservice.routes.read_oidc_token')
    def test_add_key_without_token(self, mock_read_token, ood_client):
        """Test add_key redirects to login when token is not available."""
        mock_read_token.return_value = None
        
        response = ood_client.get('/add_key')
        assert response.status_code == 302
        assert '/login' in response.location
    
    @patch('ssh_keyservice.routes.read_oidc_token')
    @patch('ssh_keyservice.routes.requests.delete')
    def test_delete_key_with_token(self, mock_delete, mock_read_token, ood_client):
        """Test deleting a key in OpenOnDemand mode."""
        mock_read_token.return_value = "valid_token_123"
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_delete.return_value = mock_response
        
        response = ood_client.post('/delete_key?public_key=ssh-rsa+AAAA...')
        assert response.status_code == 302
    
    @patch('ssh_keyservice.routes.read_oidc_token')
    @patch('ssh_keyservice.routes.requests.get')
    def test_token_used_in_api_calls(self, mock_get, mock_read_token, ood_client):
        """Test that OIDC token is used for API authentication."""
        test_token = "test_oidc_token_xyz"
        mock_read_token.return_value = test_token
        
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response
        
        response = ood_client.get('/')
        assert response.status_code == 200
        
        # Verify the token was used in the API call
        mock_get.assert_called_once()
        call_args = mock_get.call_args
        assert 'headers' in call_args.kwargs
        assert call_args.kwargs['headers']['Authorization'] == f'Bearer {test_token}'


class TestOpenOnDemandIntegration:
    """Test integration scenarios for OpenOnDemand mode."""
    
    @patch('ssh_keyservice.routes.read_oidc_token')
    def test_token_persistence_in_session(self, mock_read_token, ood_client):
        """Test that token is stored in session after first read."""
        mock_read_token.return_value = "persistent_token"
        
        with ood_client.session_transaction() as sess:
            assert 'oidc_token' not in sess
        
        # Make a request that reads the token
        with patch('ssh_keyservice.routes.requests.get') as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 404
            mock_get.return_value = mock_response
            
            ood_client.get('/')
        
        # Token should now be in session
        with ood_client.session_transaction() as sess:
            assert sess.get('oidc_token') == "persistent_token"
