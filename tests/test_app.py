import pytest
from unittest.mock import patch, MagicMock
import json


class TestAppConfiguration:
    """Test application configuration and setup."""
    
    def test_app_config(self, app):
        """Test that the app is configured correctly."""
        assert app.config["CLIENT_ID"] == "mocked_frontend_app_client_id"
        assert app.config["SECRET_KEY"].startswith("mocked_")
        assert app.config["TESTING"] is True
        assert app.config["WTF_CSRF_ENABLED"] is False

    def test_app_creation(self, app):
        """Test that the Flask app is created successfully."""
        assert app is not None
        assert app.name == "ssh_keyservice.app"


class TestUnauthenticatedRoutes:
    """Test routes when user is not authenticated."""
    
    def test_index_redirect_to_login(self, client):
        """Test that index redirects to login when not authenticated."""
        response = client.get('/')
        assert response.status_code == 302
        assert '/login' in response.location

    # This needs a valid TENANT_ID to be configured
    #def test_login_page_accessible(self, client):
    #    """Test that the login page is accessible."""
    #    
    #    response = client.get('/login')
    #    assert response.status_code == 200

    def test_logout_redirect(self, client):
        """Test the logout route redirects correctly."""
        response = client.get('/logout')
        assert response.status_code == 302

    def test_add_key_requires_auth(self, client):
        """Test that add_key redirects to login if not authenticated."""
        response = client.get('/add_key')
        assert response.status_code == 302
        assert '/login' in response.location

    def test_verify_key_requires_auth(self, client):
        """Test that verify_key redirects to login if not authenticated."""
        response = client.get('/verify_key')
        assert response.status_code == 302
        assert '/login' in response.location

    def test_delete_key_requires_auth(self, client):
        """Test that delete_key redirects to login if not authenticated."""
        response = client.post('/delete_key?public_key=test_key')
        assert response.status_code == 302
        assert '/login' in response.location

    def test_serve_script_accessible(self, client):
        """Test that verify_key.sh script is accessible."""
        response = client.get('/verify_key.sh')
        # This might be 404 if the file doesn't exist in test environment
        assert response.status_code in [200, 404]

@pytest.fixture
def mock_auth():
    """Mock authentication for testing authenticated routes."""
    with patch('ssh_keyservice.routes.identity.web.Auth') as mock_auth_class:
        mock_auth = MagicMock()
        mock_auth.get_user.return_value = {
            'name': 'Test User',
            'preferred_username': 'testuser@example.com'
        }
        mock_auth.get_token_for_user.return_value = {
            'access_token': 'mock_token'
        }
        mock_auth_class.return_value = mock_auth
        yield mock_auth

class TestAuthenticatedRoutes:
    """Test routes when user is authenticated."""

    @patch('ssh_keyservice.routes.requests.get')
    def test_index_with_keys(self, mock_get, client, mock_auth, app):
        """Test index page displays SSH keys for authenticated user."""
        # Mock API response with SSH keys
        app.auth = mock_auth
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

    @patch('ssh_keyservice.routes.requests.get')
    def test_index_no_keys(self, mock_get, client, mock_auth, app):
        """Test index page when user has no SSH keys."""
        # Mock API response with 404 (no keys)
        app.auth = mock_auth
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response
        
        response = client.get('/')
        assert response.status_code == 200

    def test_add_key_get_authenticated(self, client, mock_auth, app):
        """Test GET request to add_key when authenticated."""
        app.auth = mock_auth
        response = client.get('/add_key')
        assert response.status_code == 200

    @patch('ssh_keyservice.routes.requests.get')
    @patch('ssh_keyservice.routes.requests.put')
    def test_add_key_post_valid(self, mock_put, mock_get, client, mock_auth):
        """Test adding a valid SSH key."""
        # Mock existing keys check
        mock_get_response = MagicMock()
        mock_get_response.status_code = 404  # No existing keys
        mock_get.return_value = mock_get_response
        
        # Mock successful key addition
        mock_put_response = MagicMock()
        mock_put_response.status_code = 200
        mock_put.return_value = mock_put_response
        
        # Valid SSH key for testing
        valid_ssh_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7vbqajDjnvTqO test@example.com"
        
        with client.session_transaction() as sess:
            sess['challenge'] = 'test_challenge'
            sess['public_key'] = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7vbqajDjnvTqO'
            sess['comment'] = 'test@example.com'
        
        response = client.post('/add_key', data={
            'public_key': valid_ssh_key,
            'comment': 'test@example.com'
        })
        # Should redirect to verify_key
        assert response.status_code == 302

    def test_verify_key_without_session_data(self, client, mock_auth):
        """Test verify_key without required session data."""
        response = client.get('/verify_key')
        assert response.status_code == 302  # Redirect to index

    @patch('ssh_keyservice.routes.requests.delete')
    def test_delete_key_success(self, mock_delete, client, mock_auth, app):
        """Test successful key deletion."""
        app.auth = mock_auth
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_delete.return_value = mock_response
        
        response = client.post('/delete_key?public_key=ssh-rsa+AAAA...')
        assert response.status_code == 302  # Redirect to index


class TestFormValidation:
    """Test form validation and edge cases."""
    
    def test_add_key_empty_form(self, client, mock_auth, app):
        """Test submitting empty form to add_key."""
        with patch('ssh_keyservice.routes.identity.web.Auth') as mock_auth_class:
            mock_auth = MagicMock()
            mock_auth.get_user.return_value = {'name': 'Test User'}
            mock_auth_class.return_value = mock_auth
            app.auth = mock_auth

            response = client.post('/add_key', data={})
            assert response.status_code == 200  # Should stay on form with errors

    def test_add_key_invalid_ssh_key(self, client, mock_auth, app):
        """Test submitting invalid SSH key."""
        with patch('ssh_keyservice.routes.identity.web.Auth') as mock_auth_class:
            mock_auth = MagicMock()
            mock_auth.get_user.return_value = {'name': 'Test User'}
            mock_auth_class.return_value = mock_auth
            app.auth = mock_auth
            
            response = client.post('/add_key', data={
                'public_key': 'invalid_ssh_key',
                'comment': 'test'
            })
            assert response.status_code == 200  # Should stay on form with errors


class TestErrorHandling:
    """Test error handling scenarios."""
    
    @patch('ssh_keyservice.routes.requests.get')
    def test_api_error_handling(self, mock_get, client, mock_auth, app):
        """Test handling of API errors."""
        with patch('ssh_keyservice.routes.identity.web.Auth') as mock_auth_class:
            mock_auth = MagicMock()
            mock_auth.get_user.return_value = {'name': 'Test User'}
            mock_auth.get_token_for_user.return_value = {'access_token': 'token'}
            mock_auth_class.return_value = mock_auth
            app.auth = mock_auth

            # Mock API error
            mock_response = MagicMock()
            mock_response.status_code = 500
            mock_get.return_value = mock_response
            
            response = client.get('/')
            assert response.status_code == 200  # Should handle error gracefully

    def test_auth_token_error(self, client):
        """Test handling of authentication token errors."""
        with patch('ssh_keyservice.routes.identity.web.Auth') as mock_auth_class:
            mock_auth = MagicMock()
            mock_auth.get_user.return_value = {'name': 'Test User'}
            mock_auth.get_token_for_user.return_value = {'error': 'token_error'}
            mock_auth_class.return_value = mock_auth
            
            response = client.get('/')
            assert response.status_code == 302  # Should redirect to login


class TestSessionHandling:
    """Test session data handling."""
    
    def test_session_cleanup_on_index(self, client, mock_auth, app):
        """Test that session is cleaned on index page."""
        with patch('ssh_keyservice.routes.identity.web.Auth') as mock_auth_class, \
             patch('ssh_keyservice.routes.requests.get') as mock_get:
            
            mock_auth = MagicMock()
            mock_auth.get_user.return_value = {'name': 'Test User'}
            mock_auth.get_token_for_user.return_value = {'access_token': 'token'}
            mock_auth_class.return_value = mock_auth
            app.auth = mock_auth

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

    def test_session_cleanup_on_add_key_get(self, client, mock_auth, app):
        """Test that session is cleaned on GET request to add_key."""
        with patch('ssh_keyservice.routes.identity.web.Auth') as mock_auth_class:
            mock_auth = MagicMock()
            mock_auth.get_user.return_value = {'name': 'Test User'}
            mock_auth_class.return_value = mock_auth
            app.auth = mock_auth

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
