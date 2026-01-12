import base64
import hashlib
import os

import subprocess
import secrets

import tempfile

from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.hazmat.primitives.serialization import load_ssh_public_key
from cryptography.exceptions import UnsupportedAlgorithm, InvalidKey

import logging

logger = logging.getLogger("ssh_keyservice")

def read_oidc_token(token_path):
    """
    Read OIDC token from file.
    
    Args:
        token_path: Path to the file containing the OIDC token
        
    Returns:
        The token string or None if file cannot be read
    """
    try:
        if not os.path.exists(token_path):
            logger.error(f"OIDC token file not found at {token_path}")
            return None
            
        with open(token_path, 'r') as f:
            token = f.read().strip()
            if not token:
                logger.error(f"OIDC token file at {token_path} is empty")
                return None
            return token
    except Exception as e:
        logger.error(f"Error reading OIDC token from {token_path}: {e}")
        return None

def generate_challenge():
    """Generate a random challenge string."""
    return secrets.token_hex(16)

def verify_challenge_response(challenge, response, public_key):
    """
    Verifies the challenge response using the provided public key.
    """
    try:
        # Normalize line endings and encode the response
        byte_str = response.encode("UTF-8")
        byte_str = byte_str.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
        response = byte_str.decode("UTF-8")

        # Create a temporary file to store the public key and response
        with tempfile.NamedTemporaryFile(mode="w", prefix="tmp_allowed_signers",
                                         newline='\n', delete_on_close=False) as f_allowed_signers, \
             tempfile.NamedTemporaryFile(mode="w", prefix='tmp_response', newline='\n', delete_on_close=False) as f_response:

            f_allowed_signers.write("keyservice@localhost" + " " + public_key)
            f_allowed_signers.close()

            f_response.write(response)
            f_response.close()

            # Try using both Unix and Windows line endings
            for candidate, client_os in [(challenge + "\n", "unix"), (challenge + "\r\n", "windows")]:
                # Execute ssh-keygen to verify the response
                result = subprocess.run(
                    ["/usr/bin/ssh-keygen", "-Y", "verify", "-f", f_allowed_signers.name , "-I", "keyservice@localhost", "-n", "file", "-s", f_response.name],
                    input=candidate,
                    text=True,
                    capture_output=True
                )
                logger.info(f"ssh-keygen output: {result.stdout} ({client_os})")
                if result.stderr:
                    logger.warning(f"ssh-keygen error: {result.stderr} ({client_os})")

                if result.returncode == 0:
                    return True

        return False
    except subprocess.SubprocessError as e:
        logger.error(f"Subprocess execution failed: {e}")
    except Exception as e:
        logger.exception("Unexpected error during challenge verification.")
    return False

def validate_ssh_public_key(key_data):
    """Check if the provided SSH key data is valid."""
    try:
        load_ssh_public_key(key_data.encode('utf-8'))
        return True
    except (ValueError, UnsupportedAlgorithm, InvalidKey):
        return False

def get_ssh_key_fingerprint(key_data: str):
    try:
        # Check if the key is valid
        if not validate_ssh_public_key(key_data):
            return "Invalid SSH public key."

        # Extract the base64-encoded key part
        key_parts = key_data.split()
        if len(key_parts) < 2:
            return "Invalid SSH public key format."

        key_type = key_parts[0]
        key_base64 = key_parts[1]

        # Decode the key
        key_bytes = base64.b64decode(key_base64)

        # Compute the fingerprint (SHA256 hash)
        fingerprint = hashlib.sha256(key_bytes).digest()
        fingerprint_base64 = base64.b64encode(fingerprint).decode()

        # Load the key to determine its length
        public_key = load_ssh_public_key(key_data.encode('utf-8'))
        key_length = None

        # Determine the key length based on the type
        if isinstance(public_key, rsa.RSAPublicKey):
            key_length = public_key.key_size
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            key_length = public_key.curve.key_size
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            key_length = 256

        return f"{key_type} - SHA256:{fingerprint_base64} ({key_length}-bit)"
    except Exception as e:
        return f"Error: {e}"
