import pytest
from unittest import mock
import subprocess
import tempfile

from ssh_keyservice.utils import (
    generate_challenge,
    validate_ssh_public_key,
    get_ssh_key_fingerprint,
    verify_challenge_response
)

VALID_RSA_KEY = """ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDHn7TL6SGb4oZtQZarWRBLZX9G4oxKDz+EP9rgGTi1ai3MBHKzQBW1VNrPjikYS2MrXl2Pa8qu5w5V18RX9/WY0Thr1XDq4Fo8+F0zMhXVmn/JYmVqy6JuruZFcShZv58BJVwpsQeDn1ohGXn6ib6ACE4ElYqly+ZEtbIPR8ndtVfQooTRC/xfgjvNNVs28wOxaALSMp5Zx5bGkMtoIhsCtO80+XoJ1SyHTIy413Yh0CNcY3TGGRYSOsHga58+wCVD3Ov7TFjQX8o/uyF6cRv/SWMs5lI/URWJ6bQVfmAUbcDN8saskrtONMCz02SkPHNvdqYOx5Bpy8IxMu5etfT5JebJLQOhJT5ZmNWEZX2bsPdJGz9PKCcbM+qkwhMiyXcQuY9echgIgD7HuDRFqKXhdjkDPQM8LBANTNHfjWK/GoyQvEauyNFVs3IQG63RPSCSnmrVQVtbw9ioBqS52djlLZZdc/vHN+uPY22v3D7RpoIELiBgn3B6EwRSL6LWjUs= example@local"""

INVALID_KEY = "not-a-real-key ABCDEFGHIJ=="

VALID_ED25519_KEY = """ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test@example.com"""

VALID_ECDSA_KEY = """ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg= test@example.com"""


class TestGenerateChallenge:
    """Test challenge generation functionality."""
    
    def test_generate_challenge_length(self):
        """Test that generated challenge has correct length."""
        challenge = generate_challenge()
        assert len(challenge) == 32  # 16 bytes = 32 hex characters

    def test_generate_challenge_uniqueness(self):
        """Test that multiple challenges are unique."""
        challenges = [generate_challenge() for _ in range(10)]
        assert len(set(challenges)) == 10  # All should be unique

    def test_generate_challenge_format(self):
        """Test that challenge contains only hex characters."""
        challenge = generate_challenge()
        assert all(c in '0123456789abcdef' for c in challenge.lower())

    def test_generate_challenge_type(self):
        """Test that challenge is returned as string."""
        challenge = generate_challenge()
        assert isinstance(challenge, str)


class TestValidateSSHPublicKey:
    """Test SSH public key validation."""
    
    def test_validate_valid_rsa_key(self):
        """Test validation of a valid RSA public key."""
        assert validate_ssh_public_key(VALID_RSA_KEY)

    def test_validate_valid_ed25519_key(self):
        """Test validation of a valid Ed25519 public key."""
        assert validate_ssh_public_key(VALID_ED25519_KEY)

    def test_validate_valid_ecdsa_key(self):
        """Test validation of a valid ECDSA public key."""
        assert validate_ssh_public_key(VALID_ECDSA_KEY)

    def test_validate_invalid_ssh_key(self):
        """Test validation of invalid SSH key."""
        assert not validate_ssh_public_key(INVALID_KEY)

    def test_validate_empty_key(self):
        """Test validation of empty key."""
        assert not validate_ssh_public_key("")

    def test_validate_malformed_key(self):
        """Test validation of malformed key."""
        malformed_key = "ssh-rsa invalid_base64_data"
        assert not validate_ssh_public_key(malformed_key)

    def test_validate_incomplete_key(self):
        """Test validation of incomplete key."""
        incomplete_key = "ssh-rsa"
        assert not validate_ssh_public_key(incomplete_key)

    def test_validate_wrong_key_type(self):
        """Test validation of wrong key type."""
        wrong_type = "ssh-unknown AAAAB3NzaC1yc2EAAAADAQABAAABAQ"
        assert not validate_ssh_public_key(wrong_type)


class TestGetSSHKeyFingerprint:
    """Test SSH key fingerprint generation."""
    
    def test_get_fingerprint_valid_rsa_key(self):
        """Test fingerprint generation for valid RSA key."""
        result = get_ssh_key_fingerprint(VALID_RSA_KEY)
        assert result.startswith("ssh-rsa - SHA256:")
        assert "(2048-bit)" in result or "(3072-bit)" in result or "(4096-bit)" in result

    def test_get_fingerprint_valid_ed25519_key(self):
        """Test fingerprint generation for valid Ed25519 key."""
        result = get_ssh_key_fingerprint(VALID_ED25519_KEY)
        assert result.startswith("ssh-ed25519 - SHA256:")
        assert "(256-bit)" in result

    def test_get_fingerprint_valid_ecdsa_key(self):
        """Test fingerprint generation for valid ECDSA key."""
        result = get_ssh_key_fingerprint(VALID_ECDSA_KEY)
        assert result.startswith("ecdsa-sha2-nistp256 - SHA256:")
        assert "(256-bit)" in result

    def test_get_fingerprint_invalid_key(self):
        """Test fingerprint generation for invalid key."""
        result = get_ssh_key_fingerprint(INVALID_KEY)
        assert "Invalid SSH public key" in result

    def test_get_fingerprint_empty_key(self):
        """Test fingerprint generation for empty key."""
        result = get_ssh_key_fingerprint("")
        assert "Invalid SSH public key" in result

    def test_get_fingerprint_malformed_key(self):
        """Test fingerprint generation for malformed key."""
        malformed_key = "ssh-rsa"  # Incomplete key
        result = get_ssh_key_fingerprint(malformed_key)
        assert "Invalid SSH public key" in result

    def test_get_fingerprint_key_with_insufficient_parts(self):
        """Test fingerprint generation for key with insufficient parts."""
        insufficient_key = "ssh-rsa incomplete"
        result = get_ssh_key_fingerprint(insufficient_key)
        assert "Invalid SSH public key" in result or "Error:" in result


class TestVerifyChallengeResponse:
    """Test challenge response verification."""
    
    @mock.patch("ssh_keyservice.utils.subprocess.run")
    def test_verify_challenge_response_success(self, mock_run):
        """Test successful challenge response verification."""
        # Mock successful ssh-keygen execution
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "Good signature"
        mock_run.return_value.stderr = ""

        result = verify_challenge_response("testchallenge", "signedresponse", VALID_RSA_KEY)
        assert result is True
        assert mock_run.called

    @mock.patch("ssh_keyservice.utils.subprocess.run")
    def test_verify_challenge_response_failure(self, mock_run):
        """Test failed challenge response verification."""
        # Mock failed ssh-keygen execution
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = "Bad signature"

        result = verify_challenge_response("testchallenge", "badsignature", VALID_RSA_KEY)
        assert result is False

    @mock.patch("ssh_keyservice.utils.subprocess.run")
    def test_verify_challenge_response_subprocess_error(self, mock_run):
        """Test challenge response verification with subprocess error."""
        # Mock subprocess error
        mock_run.side_effect = subprocess.SubprocessError("Command failed")

        result = verify_challenge_response("testchallenge", "response", VALID_RSA_KEY)
        assert result is False

    @mock.patch("ssh_keyservice.utils.subprocess.run")
    def test_verify_challenge_response_general_exception(self, mock_run):
        """Test challenge response verification with general exception."""
        # Mock general exception
        mock_run.side_effect = Exception("Unexpected error")

        result = verify_challenge_response("testchallenge", "response", VALID_RSA_KEY)
        assert result is False

    @mock.patch("ssh_keyservice.utils.subprocess.run")
    def test_verify_challenge_response_line_endings(self, mock_run):
        """Test that different line endings are handled correctly."""
        # Mock successful verification for both Unix and Windows line endings
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "Good signature"
        mock_run.return_value.stderr = ""

        # Test with Unix line endings
        response_unix = "signature_data\n"
        result = verify_challenge_response("challenge", response_unix, VALID_RSA_KEY)
        assert mock_run.called

        # Test with Windows line endings
        response_windows = "signature_data\r\n"
        result = verify_challenge_response("challenge", response_windows, VALID_RSA_KEY)
        assert mock_run.called

        # Test with mixed line endings
        response_mixed = "signature_data\r\nmore_data\n"
        result = verify_challenge_response("challenge", response_mixed, VALID_RSA_KEY)
        assert mock_run.called

    @mock.patch("ssh_keyservice.utils.subprocess.run")
    def test_verify_challenge_response_tries_multiple_line_endings(self, mock_run):
        """Test that verification tries both Unix and Windows line endings."""
        # First call fails, second succeeds
        mock_run.side_effect = [
            mock.MagicMock(returncode=1, stdout="", stderr="Failed"),  # Unix attempt fails
            mock.MagicMock(returncode=0, stdout="Good signature", stderr="")  # Windows attempt succeeds
        ]

        result = verify_challenge_response("challenge", "response", VALID_RSA_KEY)
        assert result is True
        assert mock_run.call_count == 2

    @mock.patch("ssh_keyservice.utils.subprocess.run")
    def test_verify_challenge_response_both_attempts_fail(self, mock_run):
        """Test when both Unix and Windows line ending attempts fail."""
        # Both calls fail
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = "Failed"

        result = verify_challenge_response("challenge", "response", VALID_RSA_KEY)
        assert result is False
        assert mock_run.call_count == 2


class TestUtilsIntegration:
    """Integration tests for utility functions."""
    
    def test_challenge_flow_integration(self):
        """Test the complete challenge flow integration."""
        # Generate a challenge
        challenge = generate_challenge()
        assert isinstance(challenge, str)
        assert len(challenge) == 32
        
        # Validate a key
        assert validate_ssh_public_key(VALID_RSA_KEY)
        
        # Get fingerprint
        fingerprint = get_ssh_key_fingerprint(VALID_RSA_KEY)
        assert "SHA256:" in fingerprint
        
        # Verify challenge (will fail without real signature, but should not crash)
        with mock.patch("ssh_keyservice.utils.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 1
            result = verify_challenge_response(challenge, "fake_signature", VALID_RSA_KEY)
            assert result is False

    def test_multiple_key_types_validation(self):
        """Test validation of multiple key types."""
        keys = [VALID_RSA_KEY, VALID_ED25519_KEY, VALID_ECDSA_KEY]
        
        for key in keys:
            assert validate_ssh_public_key(key)
            fingerprint = get_ssh_key_fingerprint(key)
            assert "SHA256:" in fingerprint
            assert "bit)" in fingerprint

    def test_edge_cases_handling(self):
        """Test handling of various edge cases."""
        edge_cases = [
            "",  # Empty string
            "   ",  # Whitespace only
            "ssh-rsa",  # Incomplete
            "not-ssh-key",  # Wrong format
            INVALID_KEY,  # Invalid key
        ]
        
        for case in edge_cases:
            assert not validate_ssh_public_key(case)
            fingerprint = get_ssh_key_fingerprint(case)
            assert "Invalid SSH public key" in fingerprint or "Error:" in fingerprint

    def test_challenge_uniqueness_across_calls(self):
        """Test that challenges remain unique across multiple calls."""
        challenges = set()
        for _ in range(100):
            challenge = generate_challenge()
            assert challenge not in challenges
            challenges.add(challenge)
        
        assert len(challenges) == 100

