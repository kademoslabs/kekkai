"""
OS Command Injection Vulnerabilities (CWE-78)
WARNING: This code is intentionally vulnerable for testing purposes.
DO NOT USE IN PRODUCTION.
"""

import os
import subprocess


def ping_host(hostname):
    """Vulnerable to command injection via os.system."""
    # VULNERABLE: Direct command execution with user input
    os.system(f"ping -c 4 {hostname}")


def list_files(directory):
    """Vulnerable to command injection via subprocess.call with shell=True."""
    # VULNERABLE: shell=True with user input
    subprocess.call(f"ls -la {directory}", shell=True)


def backup_file(filename):
    """Vulnerable to command injection via os.popen."""
    # VULNERABLE: os.popen with user input
    result = os.popen(f"tar -czf backup.tar.gz {filename}").read()
    return result


def get_disk_usage(path):
    """Vulnerable to command injection via subprocess.check_output."""
    # VULNERABLE: shell=True allows command chaining
    output = subprocess.check_output(f"du -sh {path}", shell=True)
    return output.decode()


def kill_process(pid):
    """Vulnerable to command injection."""
    # VULNERABLE: Direct string interpolation
    os.system("kill -9 " + pid)


def download_file(url):
    """Vulnerable to command injection via wget."""
    # VULNERABLE: Unvalidated URL in shell command
    command = f"wget {url} -O /tmp/downloaded_file"
    os.system(command)


def convert_image(input_file, output_file):
    """Vulnerable to command injection in ImageMagick-like command."""
    # VULNERABLE: User-controlled filenames in shell command
    cmd = f"convert {input_file} -resize 800x600 {output_file}"
    subprocess.run(cmd, shell=True)


def run_custom_script(script_name):
    """Vulnerable to arbitrary command execution."""
    # VULNERABLE: User controls entire command
    os.system(script_name)


class SystemManager:
    """System management class with command injection vulnerabilities."""
    
    def restart_service(self, service_name):
        """VULNERABLE: Service name not validated."""
        command = f"systemctl restart {service_name}"
        os.system(command)
    
    def add_user(self, username):
        """VULNERABLE: Username not sanitized."""
        os.system(f"useradd {username}")
    
    def check_port(self, port):
        """VULNERABLE: Port parameter not validated."""
        result = subprocess.check_output(f"netstat -an | grep {port}", shell=True)
        return result.decode()
