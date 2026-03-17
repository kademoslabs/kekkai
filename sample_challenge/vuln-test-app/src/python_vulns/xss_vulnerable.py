"""
Cross-Site Scripting (XSS) Vulnerabilities (CWE-79)
WARNING: This code is intentionally vulnerable for testing purposes.
DO NOT USE IN PRODUCTION.
"""

from flask import Flask, request, render_template_string


app = Flask(__name__)


@app.route("/search")
def search():
    """Vulnerable to reflected XSS."""
    query = request.args.get("q", "")
    
    # VULNERABLE: Unescaped user input in HTML
    html = f"""
    <html>
        <body>
            <h1>Search Results</h1>
            <p>You searched for: {query}</p>
        </body>
    </html>
    """
    return html


@app.route("/profile")
def profile():
    """Vulnerable to DOM-based XSS."""
    username = request.args.get("name", "Guest")
    
    # VULNERABLE: Direct insertion into JavaScript
    return f"""
    <html>
        <body>
            <script>
                var username = "{username}";
                document.write("<h1>Welcome " + username + "</h1>");
            </script>
        </body>
    </html>
    """


@app.route("/comment", methods=["POST"])
def post_comment():
    """Vulnerable to stored XSS."""
    comment = request.form.get("comment", "")
    
    # VULNERABLE: Stored user input rendered without escaping
    html = f"""
    <div class="comment">
        <p>{comment}</p>
    </div>
    """
    return html


def generate_error_page(error_message):
    """Vulnerable to XSS in error messages."""
    # VULNERABLE: Error message from user input
    return f"""
    <html>
        <body>
            <h1>Error</h1>
            <p style="color: red;">{error_message}</p>
        </body>
    </html>
    """


def render_user_bio(bio_text):
    """Vulnerable to XSS in user-generated content."""
    # VULNERABLE: No HTML escaping
    template = f"""
    <div class="bio">
        <h2>About Me</h2>
        <div>{bio_text}</div>
    </div>
    """
    return template


@app.route("/redirect")
def unsafe_redirect():
    """Vulnerable to open redirect."""
    url = request.args.get("url", "/")
    
    # VULNERABLE: Unvalidated redirect
    return f"""
    <html>
        <head>
            <meta http-equiv="refresh" content="0; url={url}">
        </head>
    </html>
    """
