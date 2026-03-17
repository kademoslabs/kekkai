"""
Server-Side Request Forgery (SSRF) Vulnerabilities (CWE-918)
WARNING: This code is intentionally vulnerable for testing purposes.
DO NOT USE IN PRODUCTION.
"""

import requests
from flask import Flask, request


app = Flask(__name__)


@app.route("/fetch")
def fetch_url():
    """Vulnerable to SSRF."""
    url = request.args.get("url")
    
    # VULNERABLE: Fetching user-provided URL without validation
    response = requests.get(url)
    return response.text


@app.route("/proxy")
def proxy_request():
    """Vulnerable to SSRF via proxy."""
    target_url = request.args.get("target")
    
    # VULNERABLE: No URL validation, can access internal resources
    try:
        response = requests.get(target_url, timeout=5)
        return {
            "status": response.status_code,
            "content": response.text
        }
    except Exception as e:
        return {"error": str(e)}


def fetch_user_avatar(avatar_url):
    """Vulnerable to SSRF in avatar fetching."""
    # VULNERABLE: Can be used to scan internal network
    response = requests.get(avatar_url)
    return response.content


def webhook_callback(webhook_url, data):
    """Vulnerable to SSRF via webhook."""
    # VULNERABLE: Webhook URL not validated
    response = requests.post(webhook_url, json=data)
    return response.status_code


def fetch_external_data(api_endpoint):
    """Vulnerable to SSRF in API calls."""
    # VULNERABLE: Can access internal APIs and metadata endpoints
    headers = {"User-Agent": "MyApp/1.0"}
    response = requests.get(api_endpoint, headers=headers)
    return response.json()


class ImageProcessor:
    """Image processor with SSRF vulnerability."""
    
    def fetch_and_resize(self, image_url):
        """VULNERABLE: Fetches image from user-provided URL."""
        # Can be used to access internal resources or cloud metadata
        response = requests.get(image_url)
        return response.content
    
    def fetch_thumbnail(self, url):
        """VULNERABLE: No validation on URL scheme or domain."""
        # Attacker could use file://, gopher://, etc.
        response = requests.get(url, allow_redirects=True)
        return response.content
