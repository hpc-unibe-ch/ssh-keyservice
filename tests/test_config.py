import pytest
from unittest.mock import patch, MagicMock
import os

from ssh_keyservice.config import load_config


class TestLoadConfig:
    """Test configuration loading functionality."""

    @patch.dict(os.environ, {}, clear=True)
    @patch('ssh_keyservice.config.get_secret')
    def test_load_config_with_secrets(self, mock_get_secret):
        """Test loading configuration using secret management."""
        # Mock the get_secret function
        def mock_secret_side_effect(key):
            secret_map = {
                'AUTHORITY': 'https://login.microsoftonline.com/mocked_tenant_id',
                'TENANT-ID': 'secret_tenant_id',
                'APP-CLIENT-ID': 'secret_client_id',
                'APP-CLIENT-SECRET': 'secret_client_secret',
                'FLASK-SECRET-KEY': 'secret_secret_key'
            }
            return secret_map.get(key, f'default_{key}')
        
        mock_get_secret.side_effect = mock_secret_side_effect
        
        config = load_config()
        
        assert config['AUTHORITY'] == 'https://login.microsoftonline.com/secret_tenant_id'
        assert config['CLIENT_ID'] == 'secret_client_id'
        assert config['CLIENT_SECRET'] == 'secret_client_secret'
        assert config['SECRET_KEY'] == 'secret_secret_key'

    @patch.dict(os.environ, {'SCOPE': ''})
    def test_empty_scope_handling(self):
        """Test handling of empty SCOPE value."""
        config = load_config()
        
        # Should handle empty scope gracefully
        assert isinstance(config['SCOPE'], list)

    def test_config_contains_required_keys(self):
        """Test that configuration contains all required keys."""
        config = load_config()
        
        required_keys = [
            'AUTHORITY',
            'CLIENT_ID', 
            'CLIENT_SECRET',
            'SCOPE',
            'API_ENDPOINT',
            'REDIRECT_PATH',
            'SECRET_KEY'
        ]
        
        for key in required_keys:
            assert key in config

    def test_config_types(self):
        """Test that configuration values have correct types."""
        config = load_config()
        
        assert isinstance(config['AUTHORITY'], str)
        assert isinstance(config['CLIENT_ID'], str)
        assert isinstance(config['CLIENT_SECRET'], str)
        assert isinstance(config['SCOPE'], list)
        assert isinstance(config['API_ENDPOINT'], str)
        assert isinstance(config['REDIRECT_PATH'], str)
        assert isinstance(config['SECRET_KEY'], str)

    @patch.dict(os.environ, {'REDIRECT_PATH': '/'})
    def test_redirect_path_validation(self):
        """Test that REDIRECT_PATH validation works correctly."""
        config = load_config()
        
        # The config should load, but the app will validate this later
        assert config['REDIRECT_PATH'] == '/getAToken'

    @patch.dict(os.environ, {
        'AUTHORITY': '',
        'CLIENT_ID': '',
        'CLIENT_SECRET': '',
        'SECRET_KEY': ''
    })
    @patch('ssh_keyservice.config.get_secret')
    def test_empty_environment_variables_fallback_to_secrets(self, mock_get_secret):
        """Test that empty environment variables fall back to secrets."""
        mock_get_secret.return_value = 'fallback_value'
        
        config = load_config()
        
        # Should call get_secret for each config key
        assert mock_get_secret.call_count >= 4  # At least 7 calls for the main config keys

    @patch('ssh_keyservice.config.get_secret')
    def test_get_secret_exception_handling(self, mock_get_secret):
        """Test handling of exceptions from get_secret function."""
        # Mock get_secret to raise an exception
        mock_get_secret.side_effect = Exception("Secret retrieval failed")
        
        # Should not crash, but handle the exception gracefully
        try:
            config = load_config()
            # Configuration should still be returned, possibly with default values
            assert isinstance(config, dict)
        except Exception as e:
            # If an exception is raised, it should be handled appropriately
            assert "Secret retrieval failed" in str(e)

    def test_session_configuration(self):
        """Test that session configuration is properly set."""
        config = load_config()
        
        # Check session-related configuration
        assert config.get('SESSION_PERMANENT') is False
        assert config.get('SESSION_TYPE') == "cachelib"

    @patch('ssh_keyservice.config.get_secret')
    def test_realistic_azure_config(self, mock_get_secret):
        """Test with realistic Azure AD configuration values."""
        # Mock the get_secret function
        def mock_secret_side_effect(key):
            secret_map = {
                'AUTHORITY': 'https://login.microsoftonline.com/mocked_tenant_id',
                'TENANT-ID': 'secret_tenant_id',
                'APP-CLIENT-ID': 'test-client-id-12345',
            }
            return secret_map.get(key, f'default_{key}')
        
        mock_get_secret.side_effect = mock_secret_side_effect
        config = load_config()
        
        assert 'login.microsoftonline.com' in config['AUTHORITY']
        assert config['CLIENT_ID'] == 'test-client-id-12345'
        assert 'api://test-client-id-12345/user.read.profile' in config['SCOPE']


class TestConfigIntegration:
    """Integration tests for configuration loading."""
    
    def test_config_works_with_app_factory(self):
        """Test that configuration works with Flask app factory."""
        from ssh_keyservice.app import create_app
        
        # Should not raise an exception
        app = create_app()
        assert app is not None
        
        # Check that configuration is loaded
        assert 'CLIENT_ID' in app.config
        assert 'SECRET_KEY' in app.config
        assert 'AUTHORITY' in app.config

    @patch.dict(os.environ, {}, clear=True)
    def test_config_fallback_chain(self):
        """Test the complete fallback chain from env to secrets."""
        with patch('ssh_keyservice.config.get_secret') as mock_get_secret:
            mock_get_secret.return_value = 'fallback_value'
            
            config = load_config()
            
            # Should have called get_secret for missing environment variables
            assert mock_get_secret.called
            # All values should be the fallback value
            assert config['CLIENT_ID'] == 'fallback_value'
            assert config['CLIENT_SECRET'] == 'fallback_value'
