from flask_wtf import FlaskForm
from wtforms import TextAreaField, StringField, SubmitField, ValidationError
from wtforms.validators import DataRequired, Optional, Length

from cryptography.hazmat.primitives.serialization import load_ssh_public_key
from cryptography.exceptions import UnsupportedAlgorithm, InvalidKey

import re

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
        r'[A-Za-z0-9+/=]+(?: [A-Za-z0-9+@/=]+)*$'
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


class SSHKeyForm(FlaskForm):
    public_key = TextAreaField("SSH Public Key", validators=[DataRequired(), validate_ssh_public_key])
    comment = StringField("Comment", validators=[Optional(), Length(max=50)])
    submit = SubmitField("Submit")

#TODO: Add a custom validator for the challenge response
class ChallengeResponeForm(FlaskForm):
    challenge_response = TextAreaField("Challenge Response", validators=[DataRequired()])
    submit = SubmitField("Submit")

