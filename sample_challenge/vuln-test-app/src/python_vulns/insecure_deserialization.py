"""
Insecure Deserialization Vulnerabilities (CWE-502)
WARNING: This code is intentionally vulnerable for testing purposes.
DO NOT USE IN PRODUCTION.
"""

import pickle
import yaml


def load_user_data(serialized_data):
    """Vulnerable to arbitrary code execution via pickle."""
    # VULNERABLE: pickle.loads can execute arbitrary code
    user_data = pickle.loads(serialized_data)
    return user_data


def save_session(session_obj):
    """Vulnerable: Serializing session with pickle."""
    # VULNERABLE: Pickling untrusted data
    return pickle.dumps(session_obj)


def load_config_unsafe(config_string):
    """Vulnerable to code execution via YAML."""
    # VULNERABLE: yaml.load without Loader parameter allows arbitrary code execution
    config = yaml.load(config_string)
    return config


def deserialize_object(data):
    """Vulnerable: Using eval for deserialization."""
    # VULNERABLE: eval() executes arbitrary code
    obj = eval(data)
    return obj


class SessionManager:
    """Session manager with deserialization vulnerabilities."""
    
    def restore_session(self, session_cookie):
        """VULNERABLE: Deserializing user-controlled data."""
        import base64
        
        decoded = base64.b64decode(session_cookie)
        session = pickle.loads(decoded)
        return session
    
    def load_user_preferences(self, prefs_data):
        """VULNERABLE: YAML deserialization without SafeLoader."""
        preferences = yaml.load(prefs_data)
        return preferences
