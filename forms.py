from flask_wtf import FlaskForm
from wtforms import TextAreaField, StringField, SubmitField
from wtforms.validators import DataRequired

class SSHKeyForm(FlaskForm):
    public_key = TextAreaField("Public Key", validators=[DataRequired()])
    challenge_response = TextAreaField("Challenge Response", validators=[DataRequired()])
    submit = SubmitField("Submit")

