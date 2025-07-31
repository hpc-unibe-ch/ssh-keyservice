#!/bin/bash
set -e
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
python3 -m gunicorn ssh_keyservice.main:app  -c ssh_keyservice/gunicorn.conf.py
