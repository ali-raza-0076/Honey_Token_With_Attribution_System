"""
Honey Token Generators Module
Generates fake API keys, database credentials, and SSH keys
"""

import secrets
import string
import random
from typing import Dict, List
from datetime import datetime


class APIKeyGenerator:
    """Generate fake API keys for various services"""
    
    @staticmethod
    def generate_google_api_key() -> str:
        """Generate a fake Google API key (AIza...)"""
        chars = string.ascii_letters + string.digits + '-_'
        random_part = ''.join(secrets.choice(chars) for _ in range(35))
        return f"AIza{random_part}"
    
    @staticmethod
    def generate_aws_access_key() -> str:
        """Generate a fake AWS access key (AKIA...)"""
        chars = string.ascii_uppercase + string.digits
        random_part = ''.join(secrets.choice(chars) for _ in range(16))
        return f"AKIA{random_part}"
    
    @staticmethod
    def generate_aws_secret_key() -> str:
        """Generate a fake AWS secret key"""
        chars = string.ascii_letters + string.digits + '+/'
        return ''.join(secrets.choice(chars) for _ in range(40))
    
    @staticmethod
    def generate_stripe_key(test: bool = False) -> str:
        """Generate a fake Stripe API key"""
        prefix = "sk_test_" if test else "sk_live_"
        chars = string.ascii_letters + string.digits
        random_part = ''.join(secrets.choice(chars) for _ in range(24))
        return f"{prefix}{random_part}"
    
    @staticmethod
    def generate_github_token() -> str:
        """Generate a fake GitHub personal access token"""
        chars = string.ascii_letters + string.digits + '_'
        random_part = ''.join(secrets.choice(chars) for _ in range(36))
        return f"ghp_{random_part}"
    
    @staticmethod
    def generate_slack_token() -> str:
        """Generate a fake Slack bot token"""
        part1 = ''.join(str(random.randint(0, 9)) for _ in range(10))
        part2 = ''.join(str(random.randint(0, 9)) for _ in range(10))
        chars = string.ascii_letters + string.digits
        part3 = ''.join(secrets.choice(chars) for _ in range(24))
        return f"xoxb-{part1}-{part2}-{part3}"
    
    @staticmethod
    def generate_openai_key() -> str:
        """Generate a fake OpenAI API key"""
        chars = string.ascii_letters + string.digits
        random_part = ''.join(secrets.choice(chars) for _ in range(48))
        return f"sk-{random_part}"
    
    @staticmethod
    def generate_all_api_keys() -> Dict[str, str]:
        """Generate all types of API keys"""
        return {
            "google_api_key": APIKeyGenerator.generate_google_api_key(),
            "aws_access_key_id": APIKeyGenerator.generate_aws_access_key(),
            "aws_secret_access_key": APIKeyGenerator.generate_aws_secret_key(),
            "stripe_live_key": APIKeyGenerator.generate_stripe_key(test=False),
            "stripe_test_key": APIKeyGenerator.generate_stripe_key(test=True),
            "github_token": APIKeyGenerator.generate_github_token(),
            "slack_bot_token": APIKeyGenerator.generate_slack_token(),
            "openai_api_key": APIKeyGenerator.generate_openai_key(),
        }


class DatabaseCredentialGenerator:
    """Generate fake database credentials"""
    
    HOSTS = {
        'postgresql': [
            'db.internal.company.com',
            'prod-db-01.region-a.cloud',
            'postgres-cluster.corp.local',
            'pg-primary.internal.net'
        ],
        'mssql': [
            'sql-server.corp.local',
            'mssql-prod.internal',
            'sqlserver-primary.region-b.cloud',
            'sql01.company.local'
        ],
        'mysql': [
            'mysql.internal.net',
            'db-cluster-01.local',
            'mysql-prod.region-c.cloud',
            'mariadb.corp.internal'
        ]
    }
    
    USERNAMES = {
        'postgresql': ['postgres', 'admin', 'dbuser', 'backup_user', 'replication'],
        'mssql': ['sa', 'sqladmin', 'app_user', 'reporting', 'etl_user'],
        'mysql': ['root', 'mysql', 'webapp', 'admin', 'readonly']
    }
    
    @staticmethod
    def generate_password(length: int = 16) -> str:
        """Generate a fake but realistic password"""
        chars = string.ascii_letters + string.digits + '!@#$%'
        password = ''.join(secrets.choice(chars) for _ in range(length))
        if not any(c.isupper() for c in password):
            password = password[:-1] + random.choice(string.ascii_uppercase)
        if not any(c.isdigit() for c in password):
            password = password[:-2] + str(random.randint(0, 9))
        if not any(c in '!@#$%' for c in password):
            password = password[:-3] + random.choice('!@#$%')
        return password
    
    @staticmethod
    def generate_postgresql_credentials() -> Dict[str, str]:
        """Generate PostgreSQL credentials"""
        return {
            "type": "postgresql",
            "host": random.choice(DatabaseCredentialGenerator.HOSTS['postgresql']),
            "port": "5432",
            "username": random.choice(DatabaseCredentialGenerator.USERNAMES['postgresql']),
            "password": DatabaseCredentialGenerator.generate_password(),
            "database": random.choice(['production', 'analytics', 'customers', 'orders']),
            "ssl_mode": "require"
        }
    
    @staticmethod
    def generate_mssql_credentials() -> Dict[str, str]:
        """Generate MS SQL Server credentials"""
        return {
            "type": "mssql",
            "host": random.choice(DatabaseCredentialGenerator.HOSTS['mssql']),
            "port": "1433",
            "username": random.choice(DatabaseCredentialGenerator.USERNAMES['mssql']),
            "password": DatabaseCredentialGenerator.generate_password(),
            "database": random.choice(['master', 'production', 'sales', 'inventory']),
            "encrypt": "true"
        }
    
    @staticmethod
    def generate_mysql_credentials() -> Dict[str, str]:
        """Generate MySQL credentials"""
        return {
            "type": "mysql",
            "host": random.choice(DatabaseCredentialGenerator.HOSTS['mysql']),
            "port": "3306",
            "username": random.choice(DatabaseCredentialGenerator.USERNAMES['mysql']),
            "password": DatabaseCredentialGenerator.generate_password(),
            "database": random.choice(['app_db', 'users', 'transactions', 'logs']),
            "ssl": "true"
        }
    
    @staticmethod
    def generate_all_db_credentials() -> List[Dict[str, str]]:
        """Generate credentials for all database types"""
        return [
            DatabaseCredentialGenerator.generate_postgresql_credentials(),
            DatabaseCredentialGenerator.generate_mssql_credentials(),
            DatabaseCredentialGenerator.generate_mysql_credentials()
        ]


if __name__ == "__main__":
    print("=== Generated API Keys ===")
    api_keys = APIKeyGenerator.generate_all_api_keys()
    for service, key in api_keys.items():
        print(f"{service}: {key}")
    
    print("\n=== Generated Database Credentials ===")
    db_creds = DatabaseCredentialGenerator.generate_all_db_credentials()
    for creds in db_creds:
        print(f"\n{creds['type'].upper()}:")
        for key, value in creds.items():
            print(f"  {key}: {value}")

