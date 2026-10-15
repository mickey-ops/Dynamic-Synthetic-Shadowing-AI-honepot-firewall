#!/bin/bash
set -e
echo "Setting up Generative API Shadowing Demo..."
[ -d venv ] || { echo "Creating virtual environment..."; python3 -m venv venv; }
source venv/bin/activate
echo "Installing dependencies..."
pip install -q -r requirements.txt
echo "Starting server..."
echo "  Shop site : http://127.0.0.1:8000/"
echo "  Dashboard : http://127.0.0.1:8000/dashboard"
python3 app.py
