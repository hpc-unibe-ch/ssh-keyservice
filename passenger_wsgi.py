# passenger_wsgi.py
import os
import sys

# Add the parent folder of ssh_keyservice package
sys.path.insert(0, os.path.dirname(__file__))

# Import the app via package
from ssh_keyservice.app import create_app

application = create_app()
