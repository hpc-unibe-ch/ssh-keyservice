import re

from flask_wtf import FlaskForm

from wtforms import TextAreaField, StringField, SubmitField, ValidationError
from wtforms.validators import DataRequired, Optional, Length

from cryptography.hazmat.primitives.serialization import load_ssh_public_key
from cryptography.exceptions import UnsupportedAlgorithm, InvalidKey

def validate_ssh_public_key(form, field):
    """
    Custom validator to check if the input is a valid SSH public key string.

    Args:
        form: The form containing the field.
        field: The field to validate.

    Raises:
        ValidationError: If the input is not a valid SSH public key.
    """
    ssh_key_pattern = re.compile(
        r'^(ssh-(rsa|dss|ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521)) '  # key type
        r'[A-Za-z0-9+/=]+(?: [A-Za-z0-9+@.\-/=]+)*$'
    )

    # Strip the input
    key = field.data.strip()
    # Replace any newline characters with spaces
    key = key.replace('\n', ' ').replace('\r', '')

    # Check if the input matches the pattern
    if not ssh_key_pattern.match(key):
        raise ValidationError('Invalid SSH public key string pattern.')

    # Additional validation for the base64 part
    key_parts = key.split()
    if len(key_parts) < 2:
        raise ValidationError('SSH public key is incomplete.')

    try:
        # Try to load the SSH key
        load_ssh_public_key(key.encode('utf-8'))

    except (ValueError, UnsupportedAlgorithm, InvalidKey):
        raise ValidationError('Invalid SSH public key string.')

def validate_ssh_comment(form, field):
    """
    Custom validator to check if the input is a valid SSH comment string.

    Args:
        form: The form containing the field.
        field: The field to validate.

    Raises:
        ValidationError: If the input is not a valid SSH comment.
    """
    comment_pattern = re.compile(r'^[A-Za-z0-9@.\-/ ]+$')

    # Strip the input
    comment = field.data.strip()

    # Check if the input matches the pattern
    if not comment_pattern.match(comment):
        raise ValidationError('Invalid SSH comment string pattern. Only alphanumeric characters, @, ., -, and / are allowed.')

def validate_challenge_response(form, field):
    """
    Custom validator to check if the input is a valid challenge response string.

    Args:
        form: The form containing the field.
        field: The field to validate.

    Raises:
        ValidationError: If the input is not a valid challenge response.
    """
    challenge_response_pattern = re.compile(
            r"""
            ^-----BEGIN\ SSH\ SIGNATURE-----\n
            ([A-Za-z0-9+/=\n]+)
            \n?
            -----END\ SSH\ SIGNATURE-----$
            """, re.MULTILINE | re.VERBOSE
            )

    # Strip the input
    challenge_response = field.data.strip()
    challenge_response = challenge_response.replace("\r\n", "\n")

    # Check if the input matches the pattern
    if not challenge_response_pattern.fullmatch(challenge_response):
        raise ValidationError('Invalid challenge response string pattern. Must be a valid SSH signature.')

class SSHKeyForm(FlaskForm):
    public_key = TextAreaField("SSH Public Key", validators=[DataRequired(), validate_ssh_public_key])
    comment = StringField("Comment", validators=[Optional(), Length(max=50), validate_ssh_comment])
    submit = SubmitField("Submit")

class ChallengeResponeForm(FlaskForm):
    challenge_response = TextAreaField("Challenge Response", validators=[DataRequired(), validate_challenge_response])
    submit = SubmitField("Submit")

