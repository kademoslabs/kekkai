"""
Application Settings with Hardcoded Secrets
WARNING: This file contains intentionally exposed secrets for testing.
DO NOT USE IN PRODUCTION.
"""

import os

# Application settings
DEBUG = True  # VULNERABLE: Debug mode in production
SECRET_KEY = "django-insecure-hardcoded-secret-key-12345"  # VULNERABLE

# Database configuration
DATABASE = {
    'ENGINE': 'django.db.backends.postgresql',
    'NAME': 'production_db',
    'USER': 'postgres',
    'PASSWORD': 'postgres123',  # VULNERABLE: Hardcoded password
    'HOST': 'prod-db.example.com',
    'PORT': '5432',
}

# AWS Credentials
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"  # VULNERABLE
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # VULNERABLE
AWS_STORAGE_BUCKET_NAME = "my-production-bucket"

# Email configuration
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_HOST_USER = 'app@company.com'
EMAIL_HOST_PASSWORD = 'EmailPass2024!'  # VULNERABLE
EMAIL_USE_TLS = True

# Third-party API keys
STRIPE_SECRET_KEY = "sk_live_51HxTy1234567890abcdefghijklmnopqrstuv"  # VULNERABLE
TWILIO_ACCOUNT_SID = "AC1234567890abcdefghijklmnopqrstuvw"  # VULNERABLE
TWILIO_AUTH_TOKEN = "auth_token_1234567890abcdefgh"  # VULNERABLE
SENDGRID_API_KEY = "SG.1234567890abcdefghijklmnopqrstuvwxyz"  # VULNERABLE

# OAuth Credentials
GOOGLE_OAUTH_CLIENT_ID = "123456789012-abcdefghijklmnopqrstuvwxyz.apps.googleusercontent.com"
GOOGLE_OAUTH_CLIENT_SECRET = "GOCSPX-1234567890abcdefghijklmnop"  # VULNERABLE

FACEBOOK_APP_ID = "1234567890123456"
FACEBOOK_APP_SECRET = "1234567890abcdef1234567890abcdef"  # VULNERABLE

# Redis configuration
REDIS_HOST = 'localhost'
REDIS_PORT = 6379
REDIS_PASSWORD = 'redis_password_123'  # VULNERABLE

# Celery configuration
CELERY_BROKER_URL = 'redis://:redis_password_123@localhost:6379/0'  # VULNERABLE

# JWT Configuration
JWT_SECRET_KEY = "jwt-secret-key-that-should-be-in-env"  # VULNERABLE
JWT_ALGORITHM = "HS256"

# API Keys
OPENAI_API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"  # VULNERABLE
ANTHROPIC_API_KEY = "sk-ant-1234567890abcdefghijklmnopqrstuvwxyz"  # VULNERABLE

# Private keys
PRIVATE_KEY_PATH = "/etc/ssl/private/server.key"
SSL_CERTIFICATE = """-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKL0UG+mRJKvMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
-----END CERTIFICATE-----"""  # VULNERABLE: Certificate in code

# Allow all hosts in production
ALLOWED_HOSTS = ['*']  # VULNERABLE: Too permissive

# CORS settings
CORS_ALLOW_ALL_ORIGINS = True  # VULNERABLE: Too permissive

# Security settings (disabled)
SECURE_SSL_REDIRECT = False  # VULNERABLE
SESSION_COOKIE_SECURE = False  # VULNERABLE
CSRF_COOKIE_SECURE = False  # VULNERABLE
