#!/usr/bin/env python3
import os
import base64
import hashlib
import logging

import identity.web
import requests
import subprocess
import secrets

from datetime import datetime

from flask import Flask, redirect, render_template, request, session, url_for, flash, send_from_directory
from flask_session import Session
from flask_wtf import CSRFProtect
#from flask_limiter import Limiter
#from flask_limiter.util import get_remote_address

from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.hazmat.primitives.serialization import load_ssh_public_key
from cryptography.exceptions import UnsupportedAlgorithm, InvalidKey

from azure.monitor.opentelemetry import configure_azure_monitor

from forms import ChallengeResponeForm, SSHKeyForm

#from dotenv import load_dotenv
#load_dotenv()

import app_config

# Setup logger and Azure Monitor:
logger = logging.getLogger("ssh_keyservice")
logger.setLevel(logging.INFO)
if os.getenv("APPLICATIONINSIGHTS_CONNECTION_STRING"):
    configure_azure_monitor()

__version__ = "0.8.0"  # The version of this sample, for troubleshooting purpose

app = Flask(__name__)
app.config.from_object(app_config)
assert app.config["REDIRECT_PATH"] != "/", "REDIRECT_PATH must not be /"
Session(app)

#limiter = Limiter(
#  get_remote_address,
#  app=app,
#  default_limits=["200 per day", "50 per hour"],
#  storage_uri="redis://" + app_config.LIMITS_DB_HOST + ":" + str(app_config.LIMITS_DB_PORT),
#  storage_options={"socket_connect_timeout": 30},
#  strategy="fixed-window", # or "moving-window"
#)

app.secret_key = secrets.token_urlsafe(32)
csrf = CSRFProtect(app)
csrf.init_app(app)

# This section is needed for url_for("foo", _external=True) to automatically
# generate http scheme when this sample is running on localhost,
# and to generate https scheme when it is deployed behind reversed proxy.
# See also https://flask.palletsprojects.com/en/2.2.x/deploying/proxy_fix/
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

app.jinja_env.globals.update(Auth=identity.web.Auth)  # Useful in template for B2C
auth = identity.web.Auth(
    session=session,
    authority=app.config["AUTHORITY"],
    client_id=app.config["CLIENT_ID"],
    client_credential=app.config["CLIENT_SECRET"],
)

@app.route("/login")
def login():
    return render_template("login.html", version=__version__, **auth.log_in(
        scopes=app_config.SCOPE, # Have user consent to scopes during log-in
        redirect_uri=url_for("auth_response", _external=True), # Optional. If present, this absolute URL must match your app's redirect_uri registered in Azure Portal
        prompt="select_account",  # Optional. More values defined in  https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        ))


@app.route(app_config.REDIRECT_PATH)
def auth_response():
    result = auth.complete_log_in(request.args)
    if "error" in result:
        return render_template("auth_error.html", result=result)
    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    return redirect(auth.log_out(url_for("index", _external=True)))


@app.route("/")
def index():
    if not (app.config["CLIENT_ID"] and app.config["CLIENT_SECRET"]):
        # This check is not strictly necessary.
        # You can remove this check from your production code.
        return render_template('config_error.html')
    if not auth.get_user():
        return redirect(url_for("login"))

    token = auth.get_token_for_user(app_config.SCOPE)
    if "error" in token:
        return redirect(url_for("login"))
    # Use access token to call downstream api
    data = requests.get(
        app_config.API_ENDPOINT + "/users/me",
        headers={'Authorization': 'Bearer ' + token['access_token']},
        timeout=30,
    )
    if data.status_code == 200:
        data = data.json()
        print(data)
        keys = []
        for key, value in data['ssh_keys'].items():
            keys.append({
                    'ssh_key': key,
                    'fingerprint': get_ssh_key_fingerprint(key),
                    'comment': value['comment'],
                    'timestamp': f'(added on {datetime.fromisoformat(value['timestamp']).strftime("%B %m, %Y")})'
                    })

    elif data.status_code == 404:
        keys=[]
    else:
        flash("Error encountered during key retrieval.", "danger")
        keys=[]

    return render_template('index.html', user=auth.get_user(), version=__version__, keys=keys)

@app.route("/add_key", methods=["GET", "POST"])
def add_key():
    user = auth.get_user()
    if not user:
        return redirect(url_for("login"))

    form = SSHKeyForm()

    if request.method == "POST" and form.validate():
        # Handle Public Key Submission
        if "public_key" in request.form:
            public_key = form.public_key.data
            comment = form.comment.data

            if not public_key:
                flash("Please provide a valid public SSH key.", "danger")
                return render_template("manage_key.html", form=form, stage="add")

            # Strip comment from public key and keep only the key and type
            public_key = public_key.split(" ")[0] + " " + public_key.split(" ")[1]


            # Verify that the public key does not already exist
            token = auth.get_token_for_user(app_config.SCOPE)
            if "error" in token:
                return redirect(url_for("login"))

            data = requests.get(
                app_config.API_ENDPOINT + "/users/me",
                headers={'Authorization': 'Bearer ' + token['access_token']},
                timeout=30,
            )
            if data.status_code == 200:
                data = data.json()
                keys = []
                for key, _ in data['ssh_keys'].items():
                    keys.append(key)

            elif data.status_code == 404:
                keys=[]
            else:
                flash("Error encountered during key retrieval.", "danger")
                keys=[]

            if public_key in keys:
                flash("The SSH key already exists.", "danger")
                return render_template("manage_key.html", form=form, stage="add")

            # Generate a challenge
            challenge = generate_challenge()

            # Store the challenge and public key in the session
            session["challenge"] = challenge
            session["comment"] = comment
            session["public_key"] = public_key

            # Redirect to the verification page
            return redirect(url_for("verify_key"))

    # Default stage: show public key input
    stage = "add"
    return render_template("manage_key.html", form=form, stage=stage, user=auth.get_user())

@app.route("/verify_key", methods=["GET", "POST"])
def verify_key():
    user = auth.get_user()
    if not user:
        return redirect(url_for("login"))

    form = ChallengeResponeForm()

    if request.method == "POST" and form.validate():
        # Handle Challenge Response Submission
        if "challenge_response" in request.form and form.validate():
            challenge_response = form.challenge_response.data
            public_key = session.get("public_key")
            challenge = session.get("challenge")
            comment = session.get("comment")

            if not public_key or not challenge:
                flash("Session expired or invalid data. Please try again.", "danger")
                return redirect(url_for("manage_key"))

            # Verify the challenge response
            if not verify_challenge_response(challenge=challenge, response=challenge_response, public_key=public_key):
                flash("Challenge-response verification failed. Please try again.", "danger")
                return render_template("manage_key.html", form=form, stage="verify")

            # Add the SSH key
            print("comment: ", comment)
            print("ssh_key: ", public_key)
            token = auth.get_token_for_user(app_config.SCOPE)
            if "error" in token:
                return redirect(url_for("login"))

            # Headers
            headers = {
                "Authorization": f"Bearer {token['access_token']}",
            }

            data = {
                "ssh_key": public_key,
                "comment": comment
            }

            url = app_config.API_ENDPOINT + f"/users/me/keys"
            r = requests.put(url, json=data, headers=headers, timeout=10)

            # Clear session data
            session.pop("challenge", None)
            session.pop("public_key", None)
            session.pop("comment", None)

            if r.status_code != 200:
                flash("Error encountered during key addition.", "danger")
                return redirect(url_for("index"))
            else:
                flash("SSH key added successfully!", "success")
                return redirect(url_for("index"))

    # Default stage: show public key input
    stage = "verify"
    return render_template("manage_key.html", form=form, stage=stage, user=auth.get_user())

@app.route("/delete_key", methods=["POST"])
def delete_key():
    user = auth.get_user()
    if not user:
        return redirect(url_for("login"))

    public_key = request.args['public_key']

    # Delete the SSH key
    token = auth.get_token_for_user(app_config.SCOPE)
    if "error" in token:
        return redirect(url_for("login"))

    # Headers
    headers = {
        "Authorization": f"Bearer {token['access_token']}",
    }

    data = {
        "ssh_key": public_key
    }

    url = app_config.API_ENDPOINT + f"/users/me/keys"
    r = requests.delete(url, json=data, headers=headers, timeout=10)

    if r.status_code != 200:
        flash("Error encountered during key deletion.", "danger")
        return redirect(url_for("index"))
    else:
        flash("SSH key deleted successfully!", "success")
        return redirect(url_for("index"))

def generate_challenge():
    """Generate a random challenge string."""
    return secrets.token_hex(16)

def verify_challenge_response(challenge, response, public_key):
    """
    Verifies the challenge response using the provided public key.
    """
    try:

        # Write the public key and response to temporary files
        with open("allowed_signers.tmp", "w") as pub_file, open("response.tmp", "w") as resp_file:
            pub_file.write("keyservice@localhost" + " " + public_key)
            resp_file.write(response)

        # Add newline to the challenge
        challenge += "\n"

        # Use ssh-keygen to verify the response
        # ssh-keygen -Y verify -f allowed_signers.tmp -I keyservice@localhost -n file -s signature
        result = subprocess.run(
            ["/usr/bin/ssh-keygen", "-Y", "verify", "-f", "allowed_signers.tmp", "-I", "keyservice@localhost", "-n", "file", "-s", "response.tmp"],
            input=challenge,
            text=True,
            check=True,
            capture_output=True
        )

        # Clean up temporary files
        subprocess.run(["/bin/rm", "allowed_signers.tmp", "response.tmp"])

        # Check the result
        return result.returncode == 0
    except Exception as e:
        print(f"Error during verification: {e}")
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

@app.route("/verify_key.sh")
def serve_script():
    # Serve the `verify_key.sh` script
    return send_from_directory("assets/", "verify_key.sh", as_attachment=False)


if __name__ == "__main__":
    app.run()
