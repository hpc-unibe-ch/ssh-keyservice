import identity.web
import requests

from datetime import datetime
from flask import redirect, render_template, request, session, url_for, flash, send_from_directory

from .forms import ChallengeResponeForm, SSHKeyForm
from .utils import generate_challenge, verify_challenge_response, validate_ssh_public_key, get_ssh_key_fingerprint, read_oidc_token

__version__ = "0.8.0"  # The version of this sample, for troubleshooting purpose

def register_routes(app):
    use_openondemand = app.config.get("USE_OPENONDEMAND", False)
    
    if not use_openondemand:
        # Azure OIDC mode: set up identity.web.Auth
        app.jinja_env.globals.update(Auth=identity.web.Auth)  # Useful in template for B2C
        app.auth = identity.web.Auth(
            session=session,
            authority=app.config["AUTHORITY"],
            client_id=app.config["CLIENT_ID"],
            client_credential=app.config["CLIENT_SECRET"],
        )
    else:
        # OpenOnDemand mode: no identity.web.Auth needed
        app.auth = None

    def get_user_openondemand():
        """Get user information when in OpenOnDemand mode.
        
        In OpenOnDemand mode, user authentication is handled externally by the
        OpenOnDemand platform. The actual user identity is extracted and validated
        by the backend API when it receives the OIDC token. This function returns
        a minimal user object for frontend session management only.
        """
        # In OpenOnDemand mode, user info comes from the OIDC token
        # The API will validate the token and extract the actual user information
        token = read_oidc_token(app.config["OIDC_TOKEN_PATH"])
        if token:
            # Store token in session for subsequent requests
            session['oidc_token'] = token
            # Return a minimal user object for session management
            # The backend API will extract and validate the actual user from the token
            return {'name': 'OpenOnDemand User', 'preferred_username': 'ood_user'}
        return None

    def get_token_openondemand():
        """Get access token when in OpenOnDemand mode."""
        token = session.get('oidc_token') or read_oidc_token(app.config["OIDC_TOKEN_PATH"])
        if token:
            session['oidc_token'] = token
            return {'access_token': token}
        return {'error': 'no_token'}

    @app.route("/login")
    def login():
        if use_openondemand:
            # In OpenOnDemand mode, redirect directly to index
            # Authentication is handled by OpenOnDemand
            return redirect(url_for("index"))
        
        return render_template("login.html", version=__version__, **app.auth.log_in(
            scopes=app.config["SCOPE"], # Have user consent to scopes during log-in
            redirect_uri=url_for("auth_response", _external=True), # Optional. If present, this absolute URL must match your app's redirect_uri registered in Azure Portal
            prompt="select_account",  # Optional. More values defined in  https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
            ))


    @app.route(app.config["REDIRECT_PATH"])
    def auth_response():
        if use_openondemand:
            # In OpenOnDemand mode, redirect to index
            return redirect(url_for("index"))
        
        result = app.auth.complete_log_in(request.args)
        if "error" in result:
            return render_template("auth_error.html", result=result)
        return redirect(url_for("index"))


    @app.route("/logout")
    def logout():
        if use_openondemand:
            # In OpenOnDemand mode, just clear the session
            session.clear()
            return redirect(url_for("index"))
        
        return redirect(app.auth.log_out(url_for("index", _external=True)))


    @app.route("/")
    def index():
        if use_openondemand:
            # OpenOnDemand mode
            user = get_user_openondemand()
            if not user:
                return render_template('config_error.html', error="OIDC token not found or invalid")
            
            token = get_token_openondemand()
            if "error" in token:
                return render_template('config_error.html', error="Unable to read OIDC token")
        else:
            # Azure OIDC mode
            if not (app.config["CLIENT_ID"] and app.config["CLIENT_SECRET"]):
                # This check is not strictly necessary.
                # You can remove this check from your production code.
                print(f"[TEST] Missing CLIENT_ID or CLIENT_SECRET in config. Skipping authentication.")
                return render_template('config_error.html')
            if not app.auth.get_user():
                print(f"[TEST] User not authenticated. Redirecting to login.")
                return redirect(url_for("login"))

            user = app.auth.get_user()
            token = app.auth.get_token_for_user(app.config["SCOPE"])
            if "error" in token:
                print(f"[TEST] Error retrieving token: {token['error']}. Redirecting to login.")
                return redirect(url_for("login"))

        # Ensure that the session is clean
        session.pop("challenge", None)
        session.pop("public_key", None)
        session.pop("comment", None)

        # Use access token to call downstream api
        data = requests.get(
            app.config["API_ENDPOINT"] + "/users/me",
            headers={'Authorization': 'Bearer ' + token['access_token']},
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

        return render_template('index.html', user=user, version=__version__, keys=keys)

    @app.route("/add_key", methods=["GET", "POST"])
    def add_key():
        if use_openondemand:
            user = get_user_openondemand()
        else:
            user = app.auth.get_user()
        
        if not user:
            return redirect(url_for("login"))

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
                if use_openondemand:
                    token = get_token_openondemand()
                else:
                    token = app.auth.get_token_for_user(app.config["SCOPE"])
                
                if "error" in token:
                    return redirect(url_for("login"))

                data = requests.get(
                    app.config["API_ENDPOINT"] + "/users/me",
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
        if use_openondemand:
            user = get_user_openondemand()
        else:
            user = app.auth.get_user()
        
        if not user:
            return redirect(url_for("login"))

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
                if use_openondemand:
                    token = get_token_openondemand()
                else:
                    token = app.auth.get_token_for_user(app.config["SCOPE"])
                
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
        if use_openondemand:
            user = get_user_openondemand()
        else:
            user = app.auth.get_user()
        
        if not user:
            return redirect(url_for("login"))

        public_key = request.args['public_key']

        # Delete the SSH key
        if use_openondemand:
            token = get_token_openondemand()
        else:
            token = app.auth.get_token_for_user(app.config["SCOPE"])
        
        if "error" in token:
            return redirect(url_for("login"))

        # Headers
        headers = {
            "Authorization": f"Bearer {token['access_token']}",
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
