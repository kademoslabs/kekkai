"""
Path Traversal Vulnerabilities (CWE-22)
WARNING: This code is intentionally vulnerable for testing purposes.
DO NOT USE IN PRODUCTION.
"""

import os


def read_file_unsafe(filename):
    """Vulnerable to path traversal."""
    # VULNERABLE: No validation of filename
    with open(f"/var/www/uploads/{filename}", "r") as f:
        return f.read()


def serve_static_file(file_path):
    """Vulnerable to directory traversal."""
    # VULNERABLE: User-controlled path
    base_dir = "/var/www/static"
    full_path = base_dir + "/" + file_path
    
    with open(full_path, "rb") as f:
        return f.read()


def delete_user_file(user_id, filename):
    """Vulnerable to path traversal in file deletion."""
    # VULNERABLE: Filename not sanitized
    file_path = f"/home/users/{user_id}/{filename}"
    os.remove(file_path)


def read_log_file(log_name):
    """Vulnerable to path traversal in log reading."""
    # VULNERABLE: Direct path concatenation
    log_path = "/var/log/app/" + log_name
    
    if os.path.exists(log_path):
        with open(log_path, "r") as f:
            return f.read()
    return None


def save_uploaded_file(filename, content):
    """Vulnerable to path traversal in file upload."""
    # VULNERABLE: Filename from user without validation
    upload_dir = "/var/www/uploads"
    file_path = os.path.join(upload_dir, filename)
    
    with open(file_path, "wb") as f:
        f.write(content)


class FileManager:
    """File manager with path traversal vulnerabilities."""
    
    def __init__(self, base_dir="/var/data"):
        self.base_dir = base_dir
    
    def get_file_content(self, relative_path):
        """VULNERABLE: No path validation."""
        full_path = self.base_dir + "/" + relative_path
        with open(full_path, "r") as f:
            return f.read()
    
    def list_directory(self, dir_name):
        """VULNERABLE: User-controlled directory listing."""
        target_dir = os.path.join(self.base_dir, dir_name)
        return os.listdir(target_dir)
