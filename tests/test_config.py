import pytest
import os
import tempfile
from unittest.mock import patch

from ssh_keyservice.config import load_config


class TestLoadConfig:
    """Test configuration loading functionality for OpenOnDemand mode."""

    def test_load_config_defaults(self):
        """Test loading configuration with default values."""
        # Clear the env var set by conftest temporarily
        with patch.dict(os.environ, {}, clear=False):
            if 'OIDC_TOKEN_PATH' in os.environ:
                del os.environ['OIDC_TOKEN_PATH']
            
            config = load_config()
            
            # Should have default values
            assert config['API_BASE_URL'] == 'http://localhost:8000'
            assert config['API_ENDPOINT'] == 'http://localhost:8000/api/v1'
            assert config['OIDC_TOKEN_PATH'] == '/var/run/secrets/oidc/token'
            assert 'SECRET_KEY' in config
            assert config['SECRET_KEY']  # Should not be empty

    @patch.dict(os.environ, {
        'API_BASE_URL': 'http://test-api:9000',
        'OIDC_TOKEN_PATH': '/custom/token/path',
        'FLASK_SECRET_KEY': 'test-secret-key'
    })
    def test_load_config_with_env_vars(self):
        """Test loading configuration from environment variables."""
        config = load_config()
        
        assert config['API_BASE_URL'] == 'http://test-api:9000'
        assert config['API_ENDPOINT'] == 'http://test-api:9000/api/v1'
        assert config['OIDC_TOKEN_PATH'] == '/custom/token/path'
        assert config['SECRET_KEY'] == 'test-secret-key'

    def test_config_contains_required_keys(self):
        """Test that configuration contains all required keys."""
        config = load_config()
        
        required_keys = [
            'SECRET_KEY',
            'API_BASE_URL',
            'API_ENDPOINT',
            'OIDC_TOKEN_PATH',
            'SESSION_TYPE',
            'SESSION_PERMANENT',
            'SESSION_SERIALIZATION_FORMAT',
            'SESSION_CACHELIB'
        ]
        
        for key in required_keys:
            assert key in config, f"Missing required config key: {key}"

    def test_config_types(self):
        """Test that config values have correct types."""
        config = load_config()
        
        assert isinstance(config['SECRET_KEY'], str)
        assert isinstance(config['API_BASE_URL'], str)
        assert isinstance(config['API_ENDPOINT'], str)
        assert isinstance(config['OIDC_TOKEN_PATH'], str)
        assert isinstance(config['SESSION_PERMANENT'], bool)
        assert config['SESSION_TYPE'] == 'cachelib'

    def test_session_configuration(self):
        """Test session configuration."""
        config = load_config()
        
        assert config['SESSION_TYPE'] == 'cachelib'
        assert config['SESSION_PERMANENT'] is False
        assert config['SESSION_SERIALIZATION_FORMAT'] == 'json'
        assert config['SESSION_CACHELIB'] is not None


class TestConfigIntegration:
    """Test configuration integration with app."""
    
    def test_config_works_with_app_factory(self):
        """Test that config works with Flask app factory."""
        from ssh_keyservice.app import create_app
        
        app = create_app()
        
        assert app is not None
        assert 'SECRET_KEY' in app.config
        assert 'API_BASE_URL' in app.config
        assert 'OIDC_TOKEN_PATH' in app.config
    
    @patch.dict(os.environ, {'API_BASE_URL': 'http://custom-api:8080'})
    def test_config_env_vars_propagate_to_app(self):
        """Test that environment variables propagate to app config."""
        from ssh_keyservice.app import create_app
        
        app = create_app()
        
        assert app.config['API_BASE_URL'] == 'http://custom-api:8080'
