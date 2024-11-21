from os import walk
import identity.web
import requests
from flask import Flask, redirect, render_template, request, session, url_for, flash
from flask_session import Session
from flask_wtf import CSRFProtect

from dotenv import load_dotenv
load_dotenv()
import app_config

from forms import ChallengeResponeForm, SSHKeyForm

import subprocess
import sqlite3
import secrets

from DButils import add_user, add_ssh_key, user_exists, get_user_keys, delete_user_ssh_key


__version__ = "0.8.0"  # The version of this sample, for troubleshooting purpose

app = Flask(__name__)
app.config.from_object(app_config)
assert app.config["REDIRECT_PATH"] != "/", "REDIRECT_PATH must not be /"
Session(app)

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

    user = auth.get_user()
    print(user)
    # Fetch the user's SSH keys from the database
    add_user(user["preferred_username"])
    keys = get_user_keys(user["preferred_username"])

    return render_template('index.html', user=auth.get_user(), version=__version__, keys=keys)


@app.route("/call_downstream_api")
def call_downstream_api():
    token = auth.get_token_for_user(app_config.SCOPE)
    if "error" in token:
        return redirect(url_for("login"))
    # Use access token to call downstream api
    api_result = requests.get(
        app_config.ENDPOINT,
        headers={'Authorization': 'Bearer ' + token['access_token']},
        timeout=30,
    ).json()
    return render_template('display.html', result=api_result)

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

            print(comment)

            # Strip comment from public key and keep only the key and type
            public_key = public_key.split(" ")[0] + " " + public_key.split(" ")[1]

            if not public_key:
                flash("Please provide a valid public SSH key.", "danger")
                return render_template("manage_key.html", form=form, stage="add")

            # Generate a challenge
            challenge = generate_challenge()

            # Store the challenge and public key in the session
            session["challenge"] = challenge
            session["comment"] = comment
            session["public_key"] = public_key

            print("Got here")
            # Move to the verification stage
            #return render_template("manage_key.html", stage="verify")
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

    if request.method == "POST": # and form.validate():
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

            # Save the SSH key in the database
            user_record = user_exists(user["preferred_username"])
            if not user_record:
                # User record not created yet
                flash("User record not found. Please contact support.", "danger")
                return redirect(url_for("index"))

            # Add the SSH key

            print("comment: ", comment)
            add_ssh_key(user["preferred_username"], public_key, comment)

            # Clear session data
            session.pop("challenge", None)
            session.pop("public_key", None)
            session.pop("comment", None)

            flash("SSH key added successfully!", "success")
            return redirect(url_for("index"))

    # Default stage: show public key input
    stage = "verify"
    return render_template("manage_key.html", form=form, stage=stage, user=auth.get_user())

@app.route("/delete_key/<int:key_id>", methods=["POST"])
def delete_key(key_id):
    user = auth.get_user()
    if not user:
        return redirect(url_for("login"))

    # Delete the SSH key
    delete_user_ssh_key(user["preferred_username"], key_id)

    flash("SSH key deleted successfully.", "success")
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
            ["ssh-keygen", "-Y", "verify", "-f", "allowed_signers.tmp", "-I", "keyservice@localhost", "-n", "file", "-s", "response.tmp"],
            input=challenge,
            text=True,
            check=True,
            capture_output=True
        )

        # Clean up temporary files
        subprocess.run(["rm", "allowed_signers.tmp", "response.tmp"])

        # Check the result
        return result.returncode == 0
    except Exception as e:
        print(f"Error during verification: {e}")
        return False


if __name__ == "__main__":
    app.run()
