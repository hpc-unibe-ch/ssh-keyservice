#!/usr/bin/env python3

import os
import logging
from flask import Flask
from flask_session import Session
from flask_wtf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix

from .config import load_config
from .routes import register_routes

def create_app():
    logger = logging.getLogger("ssh_keyservice")
    logger.setLevel(logging.INFO)

    # Optional: Configure Azure Monitor if connection string is provided
    if os.getenv("APPLICATIONINSIGHTS_CONNECTION_STRING"):
        try:
            from azure.monitor.opentelemetry import configure_azure_monitor
            configure_azure_monitor()
        except ImportError:
            logger.warning("Azure Monitor OpenTelemetry not available")

    app = Flask(__name__)
    app.config.from_mapping(load_config())

    Session(app)
    CSRFProtect(app)

    # This section is needed for url_for("foo", _external=True) to automatically
    # generate http scheme when this sample is running on localhost,
    # and to generate https scheme when it is deployed behind reversed proxy.
    # See also https://flask.palletsprojects.com/en/2.2.x/deploying/proxy_fix/
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

    # Register all routes
    register_routes(app)

    return app
