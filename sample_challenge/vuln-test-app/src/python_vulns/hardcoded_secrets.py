"""
Hardcoded Credentials and Secrets (CWE-798)
WARNING: This code contains intentionally exposed secrets for testing.
DO NOT USE IN PRODUCTION.
"""

# VULNERABLE: Hardcoded database credentials
DB_USERNAME = "admin"
DB_PASSWORD = "SuperSecret123!"
DB_HOST = "prod-db.internal.company.com"
DB_CONNECTION_STRING = "postgresql://admin:SuperSecret123!@prod-db.internal.company.com:5432/maindb"

# VULNERABLE: Hardcoded API keys
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
STRIPE_API_KEY = "sk_live_51AbCdEfGhIjKlMnOpQrStUvWxYz1234567890"
OPENAI_API_KEY = "sk-proj-1234567890abcdefghijklmnopqrstuvwxyz"

# VULNERABLE: Hardcoded JWT secret
JWT_SECRET = "my-super-secret-jwt-key-that-should-not-be-hardcoded"

# VULNERABLE: Hardcoded encryption key
ENCRYPTION_KEY = "0123456789abcdef0123456789abcdef"

# VULNERABLE: GitHub personal access token
GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz12"

# VULNERABLE: Private SSH key in code
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyz
-----END RSA PRIVATE KEY-----"""


class DatabaseConfig:
    """Configuration class with hardcoded credentials."""
    
    # VULNERABLE: Production credentials in code
    PROD_DB_USER = "root"
    PROD_DB_PASS = "ProductionPassword2024!"
    PROD_DB_NAME = "production_db"
    
    # VULNERABLE: Admin credentials
    ADMIN_USERNAME = "superadmin"
    ADMIN_PASSWORD = "Admin@12345"


def connect_to_database():
    """Connect with hardcoded credentials."""
    import psycopg2
    
    # VULNERABLE: Credentials in function
    connection = psycopg2.connect(
        host="database.example.com",
        database="users",
        user="db_admin",
        password="VerySecurePassword123!"
    )
    return connection


def send_email(recipient, subject, body):
    """Send email with hardcoded SMTP credentials."""
    import smtplib
    
    # VULNERABLE: Email credentials
    smtp_user = "notifications@company.com"
    smtp_password = "EmailPassword2024!"
    
    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.login(smtp_user, smtp_password)
    server.sendmail(smtp_user, recipient, f"Subject: {subject}\n\n{body}")
    server.quit()


# VULNERABLE: Slack webhook URL
SLACK_WEBHOOK = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX"

# VULNERABLE: Twilio credentials
TWILIO_ACCOUNT_SID = "AC1234567890abcdefghijklmnopqrstuvw"
TWILIO_AUTH_TOKEN = "1234567890abcdefghijklmnopqrstuvwx"

# VULNERABLE: Google API key
GOOGLE_API_KEY = "AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe"
