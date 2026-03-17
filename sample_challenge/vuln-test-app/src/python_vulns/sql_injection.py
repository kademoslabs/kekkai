"""
SQL Injection Vulnerabilities (CWE-89)
WARNING: This code is intentionally vulnerable for testing purposes.
DO NOT USE IN PRODUCTION.
"""

import sqlite3


def unsafe_login(username, password):
    """Vulnerable to SQL injection - string concatenation."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    # VULNERABLE: Direct string concatenation
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    
    result = cursor.fetchone()
    conn.close()
    return result


def unsafe_search(search_term):
    """Vulnerable to SQL injection - format string."""
    conn = sqlite3.connect("products.db")
    cursor = conn.cursor()
    
    # VULNERABLE: Format string without parameterization
    query = "SELECT * FROM products WHERE name LIKE '%%{}%%'".format(search_term)
    cursor.execute(query)
    
    results = cursor.fetchall()
    conn.close()
    return results


def unsafe_delete_user(user_id):
    """Vulnerable to SQL injection - percent formatting."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    # VULNERABLE: Old-style string formatting
    query = "DELETE FROM users WHERE id = %s" % user_id
    cursor.execute(query)
    
    conn.commit()
    conn.close()


def unsafe_update_profile(user_id, bio):
    """Vulnerable to blind SQL injection."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    # VULNERABLE: String concatenation with user input
    query = "UPDATE users SET bio = '" + bio + "' WHERE id = " + str(user_id)
    cursor.execute(query)
    
    conn.commit()
    conn.close()


class UserRepository:
    """Database repository with multiple SQL injection vulnerabilities."""
    
    def __init__(self, db_path="app.db"):
        self.db_path = db_path
    
    def get_user_by_email(self, email):
        """VULNERABLE: SQL injection in WHERE clause."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        sql = f"SELECT id, username, email FROM users WHERE email = '{email}'"
        cursor.execute(sql)
        
        return cursor.fetchone()
    
    def search_users(self, name_filter):
        """VULNERABLE: SQL injection in LIKE clause."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = f"SELECT * FROM users WHERE name LIKE '%{name_filter}%'"
        cursor.execute(query)
        
        return cursor.fetchall()
