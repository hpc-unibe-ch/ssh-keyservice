import pytest
from unittest import mock


from ssh_keyservice.utils import (
    generate_challenge,
    validate_ssh_public_key,
    get_ssh_key_fingerprint,
    verify_challenge_response
)

VALID_RSA_KEY = """ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDHn7TL6SGb4oZtQZarWRBLZX9G4oxKDz+EP9rgGTi1ai3MBHKzQBW1VNrPjikYS2MrXl2Pa8qu5w5V18RX9/WY0Thr1XDq4Fo8+F0zMhXVmn/JYmVqy6JuruZFcShZv58BJVwpsQeDn1ohGXn6ib6ACE4ElYqly+ZEtbIPR8ndtVfQooTRC/xfgjvNNVs28wOxaALSMp5Zx5bGkMtoIhsCtO80+XoJ1SyHTIy413Yh0CNcY3TGGRYSOsHga58+wCVD3Ov7TFjQX8o/uyF6cRv/SWMs5lI/URWJ6bQVfmAUbcDN8saskrtONMCz02SkPHNvdqYOx5Bpy8IxMu5etfT5JebJLQOhJT5ZmNWEZX2bsPdJGz9PKCcbM+qkwhMiyXcQuY9echgIgD7HuDRFqKXhdjkDPQM8LBANTNHfjWK/GoyQvEauyNFVs3IQG63RPSCSnmrVQVtbw9ioBqS52djlLZZdc/vHN+uPY22v3D7RpoIELiBgn3B6EwRSL6LWjUs= example@local"""

INVALID_KEY = "not-a-real-key ABCDEFGHIJ=="

def test_generate_challenge():
    challenge = generate_challenge()
    assert isinstance(challenge, str)
    assert len(challenge) == 32  # 16 bytes hex

def test_validate_valid_ssh_key():
    assert validate_ssh_public_key(VALID_RSA_KEY)

def test_validate_invalid_ssh_key():
    assert not validate_ssh_public_key(INVALID_KEY)

def test_get_ssh_key_fingerprint_valid():
    result = get_ssh_key_fingerprint(VALID_RSA_KEY)
    assert result.startswith("ssh-rsa - SHA256:")

def test_get_ssh_key_fingerprint_invalid_format():
    bad_key = "ssh-rsa-onlyonepart"
    result = get_ssh_key_fingerprint(bad_key)
    assert "Invalid SSH public key" in result

def test_get_ssh_key_fingerprint_invalid_key():
    result = get_ssh_key_fingerprint(INVALID_KEY)
    assert "Invalid SSH public key" in result

@mock.patch("ssh_keyservice.utils.subprocess.run")
def test_verify_challenge_response_valid(mock_run):
    # simulate successful subprocess return
    mock_run.return_value.returncode = 0
    mock_run.return_value.stdout = "OK"
    mock_run.return_value.stderr = ""

    result = verify_challenge_response("testchallenge", "signedresponse", VALID_RSA_KEY)
    assert result is True

@mock.patch("ssh_keyservice.utils.subprocess.run")
def test_verify_challenge_response_invalid(mock_run):
    # simulate failed subprocess return
    mock_run.return_value.returncode = 1
    mock_run.return_value.stdout = ""
    mock_run.return_value.stderr = "failed"

    result = verify_challenge_response("bad", "fail", INVALID_KEY)
    assert result is False

