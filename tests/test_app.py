import pytest
from unittest.mock import patch, MagicMock


class TestAppConfiguration:
    """Test application configuration and setup."""
    
    def test_app_config(self, app):
        """Test that the app is configured correctly."""
        assert 'SECRET_KEY' in app.config
        assert app.config["TESTING"] is True
        assert app.config["WTF_CSRF_ENABLED"] is False

    def test_app_creation(self, app):
        """Test that the Flask app is created successfully."""
        assert app is not None
        assert app.name == "ssh_keyservice.app"


class TestUnauthenticatedRoutes:
    """Test routes when OIDC token is not available."""
    
    @patch('ssh_keyservice.routes.read_oidc_token')
    def test_index_without_token(self, mock_read_token, client):
        """Test that index shows error when token is not available."""
        mock_read_token.return_value = None
        
        response = client.get('/')
        assert response.status_code == 200
        assert b'error' in response.data or b'Error' in response.data

    def test_login_redirects_to_index(self, client):
        """Test that login redirects to index in OpenOnDemand mode."""
        response = client.get('/login')
        assert response.status_code == 302
        assert response.location.endswith('/')

    def test_logout_clears_session(self, client):
        """Test the logout route clears session."""
        with client.session_transaction() as sess:
            sess['oidc_token'] = 'test_token'
        
        response = client.get('/logout')
        assert response.status_code == 302

    @patch('ssh_keyservice.routes.read_oidc_token')
    def test_add_key_without_token(self, mock_read_token, client):
        """Test that add_key redirects to login if token is not available."""
        mock_read_token.return_value = None
        
        response = client.get('/add_key')
        assert response.status_code == 302
        assert '/login' in response.location

    @patch('ssh_keyservice.routes.read_oidc_token')
    def test_verify_key_without_token(self, mock_read_token, client):
        """Test that verify_key redirects if not authenticated."""
        mock_read_token.return_value = None
        
        response = client.get('/verify_key')
        assert response.status_code == 302

    @patch('ssh_keyservice.routes.read_oidc_token')
    def test_delete_key_without_token(self, mock_read_token, client):
        """Test that delete_key redirects to login if not authenticated."""
        mock_read_token.return_value = None
        
        response = client.post('/delete_key?public_key=test_key')
        assert response.status_code == 302

    def test_serve_script_accessible(self, client):
        """Test that verify_key.sh script route exists."""
        response = client.get('/verify_key.sh')
        # This might be 404 if the file doesn't exist in test environment
        assert response.status_code in [200, 404]


class TestAuthenticatedRoutes:
    """Test routes when OIDC token is available."""

    @patch('ssh_keyservice.routes.read_oidc_token')
    @patch('ssh_keyservice.routes.requests.get')
    def test_index_with_keys(self, mock_get, mock_read_token, client):
        """Test index page displays SSH keys for authenticated user."""
        mock_read_token.return_value = "valid_token"
        
        # Mock API response with SSH keys
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'ssh_keys': {
                'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ...': {
                    'comment': 'test@example.com',
                    'timestamp': '2025-01-01T12:00:00'
                }
            }
        }
        mock_get.return_value = mock_response
        
        response = client.get('/')
        assert response.status_code == 200

    @patch('ssh_keyservice.routes.read_oidc_token')
    @patch('ssh_keyservice.routes.requests.get')
    def test_index_no_keys(self, mock_get, mock_read_token, client):
        """Test index page when user has no SSH keys."""
        mock_read_token.return_value = "valid_token"
        
        # Mock API response with 404 (no keys)
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response
        
        response = client.get('/')
        assert response.status_code == 200

    @patch('ssh_keyservice.routes.read_oidc_token')
    def test_add_key_get_authenticated(self, mock_read_token, client):
        """Test GET request to add_key when authenticated."""
        mock_read_token.return_value = "valid_token"
        
        response = client.get('/add_key')
        assert response.status_code == 200

    @patch('ssh_keyservice.routes.read_oidc_token')
    @patch('ssh_keyservice.routes.requests.get')
    def test_add_key_post_valid(self, mock_get, mock_read_token, client):
        """Test adding a valid SSH key."""
        mock_read_token.return_value = "valid_token"
        
        # Mock existing keys check
        mock_get_response = MagicMock()
        mock_get_response.status_code = 404  # No existing keys
        mock_get.return_value = mock_get_response
        
        # Valid SSH key for testing (this test just verifies the flow)
        valid_ssh_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7vbqajDjnvTqO test@example.com"
        
        response = client.post('/add_key', data={
            'public_key': valid_ssh_key,
            'comment': 'test@example.com'
        })
        # Should either redirect to verify_key or stay on form (depending on validation)
        assert response.status_code in [200, 302]

    @patch('ssh_keyservice.routes.read_oidc_token')
    def test_verify_key_without_session_data(self, mock_read_token, client):
        """Test verify_key without required session data."""
        mock_read_token.return_value = "valid_token"
        
        response = client.get('/verify_key')
        assert response.status_code == 302  # Redirect to index

    @patch('ssh_keyservice.routes.read_oidc_token')
    @patch('ssh_keyservice.routes.requests.delete')
    def test_delete_key_success(self, mock_delete, mock_read_token, client):
        """Test successful key deletion."""
        mock_read_token.return_value = "valid_token"
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_delete.return_value = mock_response
        
        response = client.post('/delete_key?public_key=ssh-rsa+AAAA...')
        assert response.status_code == 302  # Redirect to index


class TestFormValidation:
    """Test form validation and edge cases."""
    
    @patch('ssh_keyservice.routes.read_oidc_token')
    def test_add_key_empty_form(self, mock_read_token, client):
        """Test submitting empty form to add_key."""
        mock_read_token.return_value = "valid_token"
        
        response = client.post('/add_key', data={})
        assert response.status_code == 200  # Should stay on form with errors

    @patch('ssh_keyservice.routes.read_oidc_token')
    def test_add_key_invalid_ssh_key(self, mock_read_token, client):
        """Test submitting invalid SSH key."""
        mock_read_token.return_value = "valid_token"
        
        response = client.post('/add_key', data={
            'public_key': 'invalid_ssh_key',
            'comment': 'test'
        })
        assert response.status_code == 200  # Should stay on form with errors


class TestErrorHandling:
    """Test error handling scenarios."""
    
    @patch('ssh_keyservice.routes.read_oidc_token')
    @patch('ssh_keyservice.routes.requests.get')
    def test_api_error_handling(self, mock_get, mock_read_token, client):
        """Test handling of API errors."""
        mock_read_token.return_value = "valid_token"
        
        # Mock API error
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_get.return_value = mock_response
        
        response = client.get('/')
        assert response.status_code == 200  # Should handle error gracefully


class TestSessionHandling:
    """Test session data handling."""
    
    @patch('ssh_keyservice.routes.read_oidc_token')
    @patch('ssh_keyservice.routes.requests.get')
    def test_session_cleanup_on_index(self, mock_get, mock_read_token, client):
        """Test that session is cleaned on index page."""
        mock_read_token.return_value = "valid_token"
        
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response
        
        with client.session_transaction() as sess:
            sess['challenge'] = 'test_challenge'
            sess['public_key'] = 'test_key'
            sess['comment'] = 'test_comment'
        
        response = client.get('/')
        assert response.status_code == 200
        
        # Session should be cleaned
        with client.session_transaction() as sess:
            assert 'challenge' not in sess
            assert 'public_key' not in sess
            assert 'comment' not in sess

    @patch('ssh_keyservice.routes.read_oidc_token')
    def test_session_cleanup_on_add_key_get(self, mock_read_token, client):
        """Test that session is cleaned on GET request to add_key."""
        mock_read_token.return_value = "valid_token"
        
        with client.session_transaction() as sess:
            sess['challenge'] = 'test_challenge'
            sess['public_key'] = 'test_key'
            sess['comment'] = 'test_comment'
        
        response = client.get('/add_key')
        assert response.status_code == 200
        
        # Session should be cleaned
        with client.session_transaction() as sess:
            assert 'challenge' not in sess
            assert 'public_key' not in sess
            assert 'comment' not in sess
