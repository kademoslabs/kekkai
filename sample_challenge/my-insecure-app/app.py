import os

# TODO: Remove before prod (Gitleaks targets)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7REALKEY"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYSECRETKEY"

# GitHub token (should be detected by gitleaks)
GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

def run_command(user_input):
    # DANGER: Command Injection (Semgrep target)
    os.system("echo " + user_input)

def main():
    print("Starting app...")
