import os, sys
sys.path.insert(0, os.path.dirname(__file__))

from app import app
from flask import send_from_directory, send_file

# In Railway, static files are in same dir as serve.py
BASE = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(BASE, 'static_dist')

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_react(path):
    if path.startswith('api/'):
        return {'error': 'not found'}, 404
    if path and os.path.exists(os.path.join(DIST, path)):
        return send_from_directory(DIST, path)
    return send_file(os.path.join(DIST, 'index.html'))
