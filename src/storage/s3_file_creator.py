"""
AWS S3 File Creator
Creates realistic honey files and uploads to S3
"""

import os
import io
import csv
import json
import zipfile
from datetime import datetime
from faker import Faker
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import boto3
from botocore.exceptions import ClientError

fake = Faker()


class S3FileCreator:
    """Creates and uploads honey files to AWS S3"""
    
    def __init__(self, bucket_name=None, region=None):
        """Initialize S3 client"""
        self.bucket_name = bucket_name or os.getenv('S3_BUCKET_NAME', 'honey-tokens-storage')
        self.region = region or os.getenv('AWS_REGION', 'us-east-1')
        
        self.s3_client = boto3.client('s3', region_name=self.region)
        
        self._enable_bucket_logging()
    
    def _enable_bucket_logging(self):
        """Enable S3 access logging for the bucket"""
        try:
            log_bucket = f"{self.bucket_name}-logs"
            try:
                self.s3_client.head_bucket(Bucket=log_bucket)
            except ClientError:
                if self.region == 'us-east-1':
                    self.s3_client.create_bucket(Bucket=log_bucket)
                else:
                    self.s3_client.create_bucket(
                        Bucket=log_bucket,
                        CreateBucketConfiguration={'LocationConstraint': self.region}
                    )
            
            logging_config = {
                'LoggingEnabled': {
                    'TargetBucket': log_bucket,
                    'TargetPrefix': 'access-logs/'
                }
            }
            self.s3_client.put_bucket_logging(
                Bucket=self.bucket_name,
                BucketLoggingStatus=logging_config
            )
            print(f" S3 access logging enabled for bucket: {self.bucket_name}")
            
        except ClientError as e:
            print(f"Warning: Could not enable S3 logging: {e}")
    
    def create_csv_file(self, filename="financial_data_Q4_2024.csv"):
        """Create a CSV file with fake financial data"""
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        
        writer.writerow(['Date', 'Transaction_ID', 'Amount', 'Account_Number', 'Description'])
        
        for _ in range(100):
            writer.writerow([
                fake.date_this_year(),
                fake.uuid4(),
                f"${fake.random_int(100, 50000)}.{fake.random_int(0, 99):02d}",
                fake.bban(),
                fake.sentence()
            ])
        
        return filename, buffer.getvalue().encode('utf-8'), 'text/csv'
    
    def create_credentials_pdf(self, api_keys, db_creds, filename="credentials_backup.pdf"):
        """Create a PDF with fake credentials"""
        buffer = io.BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)
        
        c.setFont("Helvetica-Bold", 16)
        c.drawString(100, 750, "System Credentials - CONFIDENTIAL")
        
        y_position = 700
        c.setFont("Helvetica", 12)
        
        c.drawString(100, y_position, "API Keys:")
        y_position -= 20
        
        for key_type, key_value in list(api_keys.items())[:5]:
            c.setFont("Helvetica-Bold", 10)
            c.drawString(120, y_position, f"{key_type}:")
            y_position -= 15
            c.setFont("Courier", 9)
            c.drawString(120, y_position, str(key_value)[:60])
            y_position -= 25
        
        c.setFont("Helvetica", 12)
        c.drawString(100, y_position, "Database Credentials:")
        y_position -= 20
        
        for creds in db_creds[:2]:
            db_type = creds.get('type', 'unknown').upper()
            c.setFont("Helvetica-Bold", 10)
            c.drawString(120, y_position, f"{db_type}:")
            y_position -= 15
            c.setFont("Courier", 8)
            for key, value in creds.items():
                if key != 'type' and y_position > 50:
                    c.drawString(120, y_position, f"{key}: {value}")
                    y_position -= 12
            y_position -= 10
        
        c.save()
        return filename, buffer.getvalue(), 'application/pdf'
    
    def create_sql_dump(self, db_creds, filename="database_backup.sql"):
        """Create a fake SQL dump file"""
        creds = db_creds[0] if db_creds else {}
        
        sql_content = f"""-- Database Backup
-- Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
-- Database: production_db

-- Connection Info
-- Host: {creds.get('host', 'localhost')}
-- User: {creds.get('username', 'admin')}
-- Password: {creds.get('password', 'password123')}

CREATE DATABASE IF NOT EXISTS production_db;
USE production_db;

-- Users Table
CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert sample data
INSERT INTO users (username, email, password_hash) VALUES
"""
        
        for i in range(10):
            sql_content += f"('{fake.user_name()}', '{fake.email()}', '{fake.sha256()}'),\n"
        
        sql_content = sql_content.rstrip(',\n') + ';\n'
        
        return filename, sql_content.encode('utf-8'), 'application/sql'
    
    def create_env_file(self, api_keys, filename=".env.production"):
        """Create a fake .env file"""
        env_content = f"""

"""
        
        for key_type, key_value in api_keys.items():
            env_name = key_type.upper().replace(' ', '_').replace('-', '_')
            env_content += f"{env_name}={key_value}\n"
        
        env_content += f"""
DB_HOST=prod-db-cluster.us-east-1.rds.amazonaws.com
DB_PORT=5432
DB_NAME=production
DB_USER=admin
DB_PASSWORD={fake.password(length=20)}

AWS_ACCESS_KEY_ID={fake.sha256()[:20]}
AWS_SECRET_ACCESS_KEY={fake.sha256()}
"""
        
        return filename, env_content.encode('utf-8'), 'text/plain'
    
    def create_json_config(self, api_keys, filename="config.production.json"):
        """Create a fake JSON configuration file"""
        config = {
            "environment": "production",
            "version": "2.1.0",
            "last_updated": datetime.now().isoformat(),
            "api_keys": api_keys,
            "database": {
                "host": "prod-cluster.cluster-xyz.us-east-1.rds.amazonaws.com",
                "port": 5432,
                "username": "prod_user",
                "password": fake.password(length=16)
            },
            "aws": {
                "region": "us-east-1",
                "access_key": fake.sha256()[:20],
                "secret_key": fake.sha256()
            },
            "services": {
                "api_endpoint": "https://api.production.company.com",
                "admin_panel": "https://admin.production.company.com"
            }
        }
        
        json_content = json.dumps(config, indent=2)
        return filename, json_content.encode('utf-8'), 'application/json'
    
    def create_text_file(self, api_keys, filename="api_keys_backup.txt"):
        """Create a plain text file with credentials"""
        content = f"""API Keys and Credentials Backup
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{'=' * 60}

"""
        for key_type, key_value in api_keys.items():
            content += f"{key_type}:\n{key_value}\n\n"
        
        return filename, content.encode('utf-8'), 'text/plain'
    
    def create_zip_archive(self, api_keys, db_creds, ssh_keys, filename="credentials_archive.zip"):
        """Create a ZIP file with multiple credential files"""
        buffer = io.BytesIO()
        
        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            env_name, env_content, _ = self.create_env_file(api_keys)
            zip_file.writestr(env_name, env_content)
            
            json_name, json_content, _ = self.create_json_config(api_keys)
            zip_file.writestr(json_name, json_content)
            
            for i, key_data in enumerate(ssh_keys[:3]):
                key_type = key_data.get('type', f'key{i}')
                comment = key_data.get('comment', '')
                zip_file.writestr(f"{key_type}_private.pem", key_data.get('private_key', ''))
                zip_file.writestr(f"{key_type}_public.pem", key_data.get('public_key', ''))
            
            readme = f"""IMPORTANT: Production Credentials Archive

This archive contains sensitive production credentials.
DO NOT share or commit to version control.

Contents:
- .env.production: Environment variables
- config.production.json: Service configuration
- SSH keys: Server access keys

Last updated: {datetime.now().strftime('%Y-%m-%d')}
"""
            zip_file.writestr("README.txt", readme)
        
        return filename, buffer.getvalue(), 'application/zip'
    
    def upload_to_s3(self, filename, content, content_type):
        """Upload file to S3"""
        try:
            self.s3_client.put_object(
                Bucket=self.bucket_name,
                Key=filename,
                Body=content,
                ContentType=content_type,
                Metadata={
                    'honey-token': 'true',
                    'created-at': datetime.now().isoformat()
                }
            )
            
            s3_url = f"s3://{self.bucket_name}/{filename}"
            print(f" Uploaded to S3: {s3_url}")
            return s3_url
            
        except ClientError as e:
            print(f" Failed to upload {filename}: {e}")
            return None
    
    def create_all_honey_files(self, api_keys, db_creds, ssh_keys):
        """Create and upload all honey files"""
        uploaded_files = []
        
        print(f"\n{'='*60}")
        print(f"Creating and uploading honey files to S3...")
        print(f"{'='*60}\n")
        
        files_to_create = [
            self.create_csv_file(),
            self.create_credentials_pdf(api_keys, db_creds),
            self.create_sql_dump(db_creds),
            self.create_env_file(api_keys),
            self.create_json_config(api_keys),
            self.create_text_file(api_keys),
            self.create_zip_archive(api_keys, db_creds, ssh_keys),
        ]
        
        for filename, content, content_type in files_to_create:
            s3_url = self.upload_to_s3(filename, content, content_type)
            if s3_url:
                uploaded_files.append({
                    'filename': filename,
                    'url': s3_url,
                    'type': content_type
                })
        
        print(f"\n Successfully uploaded {len(uploaded_files)} honey files to S3")
        return uploaded_files

