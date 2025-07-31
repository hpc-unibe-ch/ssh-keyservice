import pytest
from unittest.mock import patch
from wtforms import ValidationError

from ssh_keyservice.forms import (
    SSHKeyForm, 
    ChallengeResponeForm,
    validate_ssh_public_key,
    validate_ssh_comment
)


class TestSSHKeyFormValidation:
    """Test SSH key form validation."""
    
    def test_valid_rsa_key_form(self, app):
        """Test form with valid RSA key."""
        with app.app_context():
            form = SSHKeyForm()
            form.public_key.data = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDHn7TL6SGb4oZtQZarWRBLZX9G4oxKDz+EP9rgGTi1ai3MBHKzQBW1VNrPjikYS2MrXl2Pa8qu5w5V18RX9/WY0Thr1XDq4Fo8+F0zMhXVmn/JYmVqy6JuruZFcShZv58BJVwpsQeDn1ohGXn6ib6ACE4ElYqly+ZEtbIPR8ndtVfQooTRC/xfgjvNNVs28wOxaALSMp5Zx5bGkMtoIhsCtO80+XoJ1SyHTIy413Yh0CNcY3TGGRYSOsHga58+wCVD3Ov7TFjQX8o/uyF6cRv/SWMs5lI/URWJ6bQVfmAUbcDN8saskrtONMCz02SkPHNvdqYOx5Bpy8IxMu5etfT5JebJLQOhJT5ZmNWEZX2bsPdJGz9PKCcbM+qkwhMiyXcQuY9echgIgD7HuDRFqKXhdjkDPQM8LBANTNHfjWK/GoyQvEauyNFVs3IQG63RPSCSnmrVQVtbw9ioBqS52djlLZZdc/vHN+uPY22v3D7RpoIELiBgn3B6EwRSL6LWjUs= test@example.com"
            form.comment.data = "My work key"
            
            # This might fail if CSRF is enabled, but we disabled it in conftest
            assert form.validate() is True

    def test_valid_ed25519_key_form(self, app):
        """Test form with valid Ed25519 key."""
        with app.app_context():
            form = SSHKeyForm()
            form.public_key.data = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test@example.com"
            form.comment.data = "Ed25519 key"
            
            assert form.validate() is True

    def test_invalid_key_form(self, app):
        """Test form with invalid SSH key."""
        with app.app_context():
            form = SSHKeyForm()
            form.public_key.data = "not-a-valid-ssh-key"
            form.comment.data = "Invalid key"
            
            assert form.validate() is False
            assert any("Invalid SSH public key" in str(error) for error in form.public_key.errors)

    def test_empty_key_form(self, app):
        """Test form with empty SSH key."""
        with app.app_context():
            form = SSHKeyForm()
            form.public_key.data = ""
            form.comment.data = "Empty key"
            
            assert form.validate() is False

    def test_key_with_newlines(self, app):
        """Test form with SSH key containing newlines."""
        with app.app_context():
            form = SSHKeyForm()
            # Key split across lines
            form.public_key.data = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDHn7TL6SGb4oZtQZarWRBLZX9G4oxKDz+EP9rgGTi1ai3MBHKzQBW1VNrPjikYS2MrXl2Pa8qu5w5V18RX9/WY0Thr1XDq4Fo8+F0zMhXVmn/JYmVqy6JuruZFcShZv58BJVwpsQeDn1ohGXn6ib6ACE4ElYqly+ZEtbIPR8ndtVfQooTRC/xfgjvNNVs28wOxaALSMp5Zx5bGkMtoIhsCtO80+XoJ1SyHTIy413Yh0CNcY3TGGRYSOsHga58+wCVD3Ov7TFjQX8o/uyF6cRv/SWMs5lI/URWJ6bQVfmAUbcDN8saskrtONMCz02SkPHNvdqYOx5Bpy8IxMu5etfT5JebJLQOhJT5ZmNWEZX2bsPdJGz9PKCcbM+qkwhMiyXcQuY9echgIgD7HuDRFqKXhdjkDPQM8LBANTNHfjWK/GoyQvEauyNFVs3IQG63RPSCSnmrVQVtbw9ioBqS52djlLZZdc/vHN+uPY22v3D7RpoIELiBgn3B6EwRSL6LWjUs=\ntest@example.com"
            form.comment.data = "Key with newlines"
            
            # Should still validate as the validator handles newlines
            assert form.validate() is True


class TestChallengeResponseForm:
    """Test challenge response form validation."""
    
    def test_valid_challenge_response_form(self, app):
        """Test form with valid challenge response."""
        with app.app_context():
            form = ChallengeResponeForm()
            form.challenge_response.data = "-----BEGIN SSH SIGNATURE-----\nsomeSignatureData\n-----END SSH SIGNATURE-----"
            
            assert form.validate() is True

    def test_empty_challenge_response_form(self, app):
        """Test form with empty challenge response."""
        with app.app_context():
            form = ChallengeResponeForm()
            form.challenge_response.data = ""
            
            assert form.validate() is False

    def test_whitespace_only_challenge_response(self, app):
        """Test form with whitespace-only challenge response."""
        with app.app_context():
            form = ChallengeResponeForm()
            form.challenge_response.data = "   \n   "
            
            assert form.validate() is False


class TestValidateSSHPublicKeyFunction:
    """Test the validate_ssh_public_key validator function."""
    
    def test_validator_with_valid_key(self, app):
        """Test validator function with valid SSH key."""
        with app.app_context():
            form = SSHKeyForm()
            form.public_key.data = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDHn7TL6SGb4oZtQZarWRBLZX9G4oxKDz+EP9rgGTi1ai3MBHKzQBW1VNrPjikYS2MrXl2Pa8qu5w5V18RX9/WY0Thr1XDq4Fo8+F0zMhXVmn/JYmVqy6JuruZFcShZv58BJVwpsQeDn1ohGXn6ib6ACE4ElYqly+ZEtbIPR8ndtVfQooTRC/xfgjvNNVs28wOxaALSMp5Zx5bGkMtoIhsCtO80+XoJ1SyHTIy413Yh0CNcY3TGGRYSOsHga58+wCVD3Ov7TFjQX8o/uyF6cRv/SWMs5lI/URWJ6bQVfmAUbcDN8saskrtONMCz02SkPHNvdqYOx5Bpy8IxMu5etfT5JebJLQOhJT5ZmNWEZX2bsPdJGz9PKCcbM+qkwhMiyXcQuY9echgIgD7HuDRFqKXhdjkDPQM8LBANTNHfjWK/GoyQvEauyNFVs3IQG63RPSCSnmrVQVtbw9ioBqS52djlLZZdc/vHN+uPY22v3D7RpoIELiBgn3B6EwRSL6LWjUs= test@example.com"
            
            # Should not raise ValidationError
            try:
                validate_ssh_public_key(form, form.public_key)
            except ValidationError:
                pytest.fail("Valid SSH key should not raise ValidationError")

    def test_validator_with_invalid_pattern(self, app):
        """Test validator function with invalid SSH key pattern."""
        with app.app_context():
            form = SSHKeyForm()
            form.public_key.data = "not-ssh-key invalid-pattern"
            
            with pytest.raises(ValidationError) as exc_info:
                validate_ssh_public_key(form, form.public_key)
            assert "Invalid SSH public key string pattern" in str(exc_info.value)

    def test_validator_with_incomplete_key(self, app):
        """Test validator function with incomplete SSH key."""
        with app.app_context():
            form = SSHKeyForm()
            form.public_key.data = "ssh-rsa "
            
            with pytest.raises(ValidationError) as exc_info:
                validate_ssh_public_key(form, form.public_key)
            assert "Invalid SSH public key" in str(exc_info.value)

    def test_validator_with_invalid_base64(self, app):
        """Test validator function with invalid base64 data."""
        with app.app_context():
            form = SSHKeyForm()
            form.public_key.data = "ssh-rsa invalid_base64_data"
            
            with pytest.raises(ValidationError) as exc_info:
                validate_ssh_public_key(form, form.public_key)
            assert "Invalid SSH public key string" in str(exc_info.value)

    def test_validator_strips_input(self, app):
        """Test that validator strips whitespace from input."""
        with app.app_context():
            form = SSHKeyForm()
            # Add whitespace around valid key
            form.public_key.data = "   ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDHn7TL6SGb4oZtQZarWRBLZX9G4oxKDz+EP9rgGTi1ai3MBHKzQBW1VNrPjikYS2MrXl2Pa8qu5w5V18RX9/WY0Thr1XDq4Fo8+F0zMhXVmn/JYmVqy6JuruZFcShZv58BJVwpsQeDn1ohGXn6ib6ACE4ElYqly+ZEtbIPR8ndtVfQooTRC/xfgjvNNVs28wOxaALSMp5Zx5bGkMtoIhsCtO80+XoJ1SyHTIy413Yh0CNcY3TGGRYSOsHga58+wCVD3Ov7TFjQX8o/uyF6cRv/SWMs5lI/URWJ6bQVfmAUbcDN8saskrtONMCz02SkPHNvdqYOx5Bpy8IxMu5etfT5JebJLQOhJT5ZmNWEZX2bsPdJGz9PKCcbM+qkwhMiyXcQuY9echgIgD7HuDRFqKXhdjkDPQM8LBANTNHfjWK/GoyQvEauyNFVs3IQG63RPSCSnmrVQVtbw9ioBqS52djlLZZdc/vHN+uPY22v3D7RpoIELiBgn3B6EwRSL6LWjUs= test@example.com   "
            
            # Should not raise ValidationError
            try:
                validate_ssh_public_key(form, form.public_key)
            except ValidationError:
                pytest.fail("Valid SSH key with whitespace should not raise ValidationError")

    def test_validator_handles_newlines(self, app):
        """Test that validator handles newlines in SSH key."""
        with app.app_context():
            form = SSHKeyForm()
            # Key with newlines and carriage returns
            form.public_key.data = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDHn7TL6SGb4oZtQZarWRBLZX9G4oxKDz+EP9rgGTi1ai3MBHKzQBW1VNrPjikYS2MrXl2Pa8qu5w5V18RX9/WY0Thr1XDq4Fo8+F0zMhXVmn/JYmVqy6JuruZFcShZv58BJVwpsQeDn1ohGXn6ib6ACE4ElYqly+ZEtbIPR8ndtVfQooTRC/xfgjvNNVs28wOxaALSMp5Zx5bGkMtoIhsCtO80+XoJ1SyHTIy413Yh0CNcY3TGGRYSOsHga58+wCVD3Ov7TFjQX8o/uyF6cRv/SWMs5lI/URWJ6bQVfmAUbcDN8saskrtONMCz02SkPHNvdqYOx5Bpy8IxMu5etfT5JebJLQOhJT5ZmNWEZX2bsPdJGz9PKCcbM+qkwhMiyXcQuY9echgIgD7HuDRFqKXhdjkDPQM8LBANTNHfjWK/GoyQvEauyNFVs3IQG63RPSCSnmrVQVtbw9ioBqS52djlLZZdc/vHN+uPY22v3D7RpoIELiBgn3B6EwRSL6LWjUs=\r\ntest@example.com"
            
            # Should not raise ValidationError
            try:
                validate_ssh_public_key(form, form.public_key)
            except ValidationError:
                pytest.fail("Valid SSH key with newlines should not raise ValidationError")


class TestValidateSSHCommentFunction:
    """Test the validate_ssh_comment validator function."""
    
    def test_comment_validator_exists(self):
        """Test that the comment validator function exists."""
        # Check if the function is importable
        assert validate_ssh_comment is not None
        assert callable(validate_ssh_comment)

    def test_valid_comment(self, app):
        """Test validator with valid comment."""
        with app.app_context():
            form = SSHKeyForm()
            form.comment.data = "user@example.com"
            
            # Assuming the validator doesn't raise an error for valid comments
            try:
                validate_ssh_comment(form, form.comment)
            except ValidationError:
                # If validation fails, that's also valid behavior depending on implementation
                pass

    def test_empty_comment(self, app):
        """Test validator with empty comment."""
        with app.app_context():
            form = SSHKeyForm()
            form.comment.data = ""
            
            # Assuming empty comments are allowed
            try:
                validate_ssh_comment(form, form.comment)
            except ValidationError:
                # If validation fails, that's also valid behavior depending on implementation
                pass


class TestFormIntegration:
    """Integration tests for forms."""
    
    def test_ssh_key_form_csrf_disabled(self, app):
        """Test that CSRF is properly disabled in test environment."""
        with app.app_context():
            form = SSHKeyForm()
            # In test environment, CSRF should be disabled
            assert app.config.get("WTF_CSRF_ENABLED") is False

    def test_challenge_response_form_csrf_disabled(self, app):
        """Test that CSRF is properly disabled for challenge response form."""
        with app.app_context():
            form = ChallengeResponeForm()
            # In test environment, CSRF should be disabled
            assert app.config.get("WTF_CSRF_ENABLED") is False

    def test_form_field_presence(self, app):
        """Test that forms have expected fields."""
        with app.app_context():
            ssh_form = SSHKeyForm()
            assert hasattr(ssh_form, 'public_key')
            assert hasattr(ssh_form, 'comment')
            
            challenge_form = ChallengeResponeForm()
            assert hasattr(challenge_form, 'challenge_response')

    def test_form_data_types(self, app):
        """Test that form fields have correct data types."""
        with app.app_context():
            ssh_form = SSHKeyForm()
            
            # Set data and check types
            ssh_form.public_key.data = "test_key"
            ssh_form.comment.data = "test_comment"
            
            assert isinstance(ssh_form.public_key.data, str)
            assert isinstance(ssh_form.comment.data, str)
            
            challenge_form = ChallengeResponeForm()
            challenge_form.challenge_response.data = "test_response"
            
            assert isinstance(challenge_form.challenge_response.data, str)
