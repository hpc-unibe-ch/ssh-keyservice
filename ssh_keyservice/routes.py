import requests

from datetime import datetime
from flask import redirect, render_template, request, session, url_for, flash, send_from_directory

from .forms import ChallengeResponeForm, SSHKeyForm
from .utils import generate_challenge, verify_challenge_response, validate_ssh_public_key, get_ssh_key_fingerprint, read_oidc_token

__version__ = "0.8.0"  # The version of this sample, for troubleshooting purpose

def register_routes(app):
    """Register all routes for the OpenOnDemand application.
    
    Authentication is handled by OpenOnDemand externally. The OIDC token
    is read from a file and used for API authentication.
    """
    
    def get_oidc_token():
        """Get OIDC token from file or session."""
        # Check if token is already in session
        token = session.get('oidc_token')
        if token:
            return token
        
        # Read token from file
        token = read_oidc_token(app.config["OIDC_TOKEN_PATH"])
        if token:
            # Store token in session for subsequent requests
            session['oidc_token'] = token
        return token

    @app.route("/login")
    def login():
        """Login route - redirects to index since auth is handled by OpenOnDemand."""
        return redirect(url_for("index"))

    @app.route("/logout")
    def logout():
        """Logout route - clears session and redirects to index."""
        session.clear()
        return redirect(url_for("index"))

    @app.route("/")
    def index():
        """Main index page showing user's SSH keys."""
        # Get OIDC token
        token = get_oidc_token()
        if not token:
            return render_template('config_error.html', 
                                   error="OIDC token not found. Please ensure the token file exists at the configured path.")

        # Ensure that the session is clean
        session.pop("challenge", None)
        session.pop("public_key", None)
        session.pop("comment", None)

        # Use access token to call downstream api
        data = requests.get(
            app.config["API_ENDPOINT"] + "/users/me",
            headers={'Authorization': 'Bearer ' + token},
            timeout=30,
        )
        if data.status_code == 200:
            data = data.json()
            keys = []
            for key, value in data['ssh_keys'].items():
                keys.append({
                        'ssh_key': key,
                        'fingerprint': get_ssh_key_fingerprint(key),
                        'comment': value['comment'],
                        'timestamp': f'(added on {datetime.fromisoformat(value['timestamp']).strftime("%B %d, %Y")})'
                        })

        elif data.status_code == 404:
            keys=[]
        else:
            flash("Error encountered during key retrieval.", "danger")
            keys=[]

        # Return a minimal user object for display
        user = {'name': 'User', 'preferred_username': 'user'}
        return render_template('index.html', user=user, version=__version__, keys=keys)

    @app.route("/add_key", methods=["GET", "POST"])
    def add_key():
        """Add a new SSH key."""
        # Get OIDC token
        token = get_oidc_token()
        if not token:
            return redirect(url_for("login"))
        
        user = {'name': 'User', 'preferred_username': 'user'}
        form = SSHKeyForm()

        if request.method == "GET":
            session.pop("challenge", None)
            session.pop("public_key", None)
            session.pop("comment", None)

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

                # Strip the comment field
                if comment:
                    comment = comment.strip()

                # Verify that the public key does not already exist
                data = requests.get(
                    app.config["API_ENDPOINT"] + "/users/me",
                    headers={'Authorization': 'Bearer ' + token},
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
                if len(keys) >= 5:
                    flash("You have reached the maximum number of SSH keys per user.", "danger")
                    return redirect(url_for("index"))

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
        return render_template("manage_key.html", form=form, stage=stage, user=user)

    @app.route("/verify_key", methods=["GET", "POST"])
    def verify_key():
        """Verify SSH key ownership via challenge-response."""
        # Get OIDC token
        token = get_oidc_token()
        if not token:
            return redirect(url_for("login"))
        
        user = {'name': 'User', 'preferred_username': 'user'}

        if not session.get("public_key") or not session.get("challenge"):
            return redirect(url_for("index"))

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
                # Headers
                headers = {
                    "Authorization": f"Bearer {token}",
                }

                data = {
                    "ssh_key": public_key,
                    "comment": comment
                }

                url = app.config["API_ENDPOINT"] + f"/users/me/keys"
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
        return render_template("manage_key.html", form=form, stage=stage, user=user)

    @app.route("/delete_key", methods=["POST"])
    def delete_key():
        """Delete an SSH key."""
        # Get OIDC token
        token = get_oidc_token()
        if not token:
            return redirect(url_for("login"))

        public_key = request.args['public_key']

        # Delete the SSH key
        # Headers
        headers = {
            "Authorization": f"Bearer {token}",
        }

        data = {
            "ssh_key": public_key
        }

        url = app.config["API_ENDPOINT"] + f"/users/me/keys"
        r = requests.delete(url, json=data, headers=headers, timeout=10)

        if r.status_code != 200:
            flash("Error encountered during key deletion.", "danger")
            return redirect(url_for("index"))
        else:
            flash("SSH key deleted successfully!", "success")
            return redirect(url_for("index"))


    @app.route("/verify_key.sh")
    def serve_script():
        # Serve the `verify_key.sh` script
        return send_from_directory("assets/", "verify_key.sh", as_attachment=False)
