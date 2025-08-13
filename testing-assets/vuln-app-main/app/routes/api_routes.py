from flask import Blueprint, jsonify, request, current_app
from app import db
import requests
from functools import wraps
import os

# Create API blueprint
api = Blueprint('api', __name__, url_prefix='/api')

# Insecure API key for demonstration
API_KEYS = ['insecure_api_key_123']

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.args.get('api_key')
        if api_key in API_KEYS:
            return f(*args, **kwargs)
        return jsonify({"error": "Invalid API key"}), 403
    return decorated

@api.route('/fetch')
@require_api_key
def fetch_url():
    # Intentionally vulnerable to SSRF - no validation of target URL
    # This is UNSAFE - for demonstration only
    url = request.args.get('url')
    if not url:
        return jsonify({"error": "URL parameter is required"}), 400
    
    try:
        # No validation of the URL - this is the SSRF vulnerability
        response = requests.get(url, timeout=5, verify=False)  # Disabling SSL verification for demonstration
        
        # Return the response - this could leak internal network information
        return response.text, response.status_code
    except requests.exceptions.RequestException as e:
        # Don't expose internal error details in production
        current_app.logger.error(f"SSRF Request failed: {str(e)}")
        return jsonify({"error": "Failed to fetch URL"}), 500

@api.route('/admin/users')
@require_api_key
def list_users():
    # IDOR vulnerability - no proper authorization check
    from app.models import User
    users = User.query.all()
    return jsonify([{"id": u.id, "username": u.username, "email": u.email} for u in users])

@api.route('/admin/delete', methods=['POST'])
@require_api_key
def delete_user():
    # IDOR vulnerability - no proper authorization check
    user_id = request.json.get('user_id')
    from app.models import User
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"status": "success"})
    return jsonify({"error": "User not found"}), 404
