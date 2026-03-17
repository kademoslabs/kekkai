"""
Database Configuration with Security Issues
WARNING: This file contains intentionally insecure configurations.
DO NOT USE IN PRODUCTION.
"""

# VULNERABLE: Hardcoded production database credentials
PROD_DATABASE_CONFIG = {
    'host': 'prod-db-cluster.us-east-1.rds.amazonaws.com',
    'port': 5432,
    'database': 'production',
    'user': 'admin',
    'password': 'ProductionDBPass2024!',  # VULNERABLE
    'sslmode': 'disable'  # VULNERABLE: SSL disabled
}

# VULNERABLE: MongoDB connection string with credentials
MONGODB_URI = "mongodb://root:MongoRootPass123@mongodb.example.com:27017/admin?authSource=admin"

# VULNERABLE: MySQL connection details
MYSQL_CONFIG = {
    'host': 'mysql.internal.company.com',
    'user': 'root',
    'password': 'MySQLRootPassword!',  # VULNERABLE
    'database': 'users',
    'charset': 'utf8mb4'
}

# VULNERABLE: Redis connection with password
REDIS_CONNECTION_STRING = "redis://default:RedisPass123@redis.example.com:6379/0"

# VULNERABLE: Connection pool with default password
def get_db_connection():
    """Get database connection with hardcoded credentials."""
    import psycopg2
    
    # VULNERABLE: Credentials in code
    conn = psycopg2.connect(
        host="database.example.com",
        database="app_db",
        user="db_user",
        password="DbUserPassword123",
        port=5432
    )
    return conn


# VULNERABLE: SQLite database with sensitive data
SQLITE_DB_PATH = "/var/data/users.db"

# VULNERABLE: Elasticsearch credentials
ELASTICSEARCH_HOSTS = [
    {
        'host': 'elastic.example.com',
        'port': 9200,
        'http_auth': ('elastic', 'ElasticPassword123')  # VULNERABLE
    }
]

# VULNERABLE: Cassandra credentials
CASSANDRA_CONFIG = {
    'contact_points': ['cassandra1.example.com', 'cassandra2.example.com'],
    'port': 9042,
    'keyspace': 'production',
    'auth_provider': {
        'username': 'cassandra_user',
        'password': 'CassandraPass2024!'  # VULNERABLE
    }
}
