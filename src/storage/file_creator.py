"""
File Creator for Cloud Storage
Creates realistic-looking honey files and uploads them to GCP Cloud Storage
"""

import os
import io
import json
import csv
import zipfile
from datetime import datetime
from typing import List, Dict
from faker import Faker
from google.cloud import storage
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

fake = Faker()


class FileCreator:
    """Create realistic honey files"""
    
    def __init__(self, bucket_name: str, project_id: str = None):
        """
        Initialize File Creator
        
        Args:
            bucket_name: GCS bucket name
            project_id: GCP project ID (optional)
        """
        self.bucket_name = bucket_name
        self.storage_client = storage.Client(project=project_id)
        self.bucket = self.storage_client.bucket(bucket_name)
    
    def create_csv_file(self, filename: str, rows: int = 5000) -> io.BytesIO:
        """
        Create a fake CSV file with financial data
        
        Args:
            filename: Name of the file
            rows: Number of rows to generate
            
        Returns:
            BytesIO object containing CSV data
        """
        output = io.StringIO()
        writer = csv.writer(output)
        
        writer.writerow([
            'transaction_id', 'date', 'customer_name', 'email', 
            'amount', 'currency', 'status', 'payment_method', 'country'
        ])
        
        for i in range(rows):
            writer.writerow([
                f"TXN{fake.random_number(digits=10)}",
                fake.date_between(start_date='-1y', end_date='today'),
                fake.name(),
                fake.email(),
                round(fake.random.uniform(10, 10000), 2),
                fake.random_element(['USD', 'EUR', 'GBP', 'JPY']),
                fake.random_element(['completed', 'pending', 'failed']),
                fake.random_element(['credit_card', 'debit_card', 'paypal', 'bank_transfer']),
                fake.country_code()
            ])
        
        output.seek(0)
        return io.BytesIO(output.getvalue().encode('utf-8'))
    
    def create_credentials_pdf(self, filename: str, credentials: Dict) -> io.BytesIO:
        """
        Create a fake PDF with credentials
        
        Args:
            filename: Name of the file
            credentials: Dictionary of credentials to include
            
        Returns:
            BytesIO object containing PDF data
        """
        buffer = io.BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)
        width, height = letter
        
        c.setFont("Helvetica-Bold", 16)
        c.drawString(50, height - 50, "CONFIDENTIAL - Production Credentials")
        
        c.setFont("Helvetica", 10)
        c.setFillColorRGB(1, 0, 0)
        c.drawString(50, height - 80, "️ DO NOT SHARE - Internal Use Only")
        c.setFillColorRGB(0, 0, 0)
        
        c.setFont("Helvetica", 12)
        y_position = height - 120
        
        for key, value in credentials.items():
            if y_position < 100:
                c.showPage()
                y_position = height - 50
            
            c.drawString(50, y_position, f"{key}:")
            c.setFont("Courier", 10)
            c.drawString(70, y_position - 15, str(value))
            c.setFont("Helvetica", 12)
            y_position -= 40
        
        c.setFont("Helvetica", 8)
        c.drawString(50, 30, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        c.drawString(50, 20, "© 2025 Company Internal - Classification: CONFIDENTIAL")
        
        c.save()
        buffer.seek(0)
        return buffer
    
    def create_sql_dump(self, filename: str) -> io.BytesIO:
        """
        Create a fake SQL dump file
        
        Args:
            filename: Name of the file
            
        Returns:
            BytesIO object containing SQL data
        """
        output = io.StringIO()
        
        output.write("-- MySQL dump 10.13  Distrib 8.0.35, for Linux (x86_64)\n")
        output.write(f"-- Host: prod-db-01.region-a.cloud    Database: production\n")
        output.write(f"-- Dump completed on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        output.write("-- Table structure for table `users`\n")
        output.write("DROP TABLE IF EXISTS `users`;\n")
        output.write("CREATE TABLE `users` (\n")
        output.write("  `id` int(11) NOT NULL AUTO_INCREMENT,\n")
        output.write("  `username` varchar(50) NOT NULL,\n")
        output.write("  `email` varchar(100) NOT NULL,\n")
        output.write("  `password_hash` varchar(255) NOT NULL,\n")
        output.write("  `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,\n")
        output.write("  PRIMARY KEY (`id`)\n")
        output.write(") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n\n")
        
        output.write("-- Dumping data for table `users`\n")
        output.write("INSERT INTO `users` VALUES\n")
        
        for i in range(100):
            comma = "," if i < 99 else ";"
            output.write(f"({i+1},'{fake.user_name()}','{fake.email()}','{fake.sha256()}','{fake.date_time_this_year()}'){comma}\n")
        
        output.seek(0)
        return io.BytesIO(output.getvalue().encode('utf-8'))
    
    def create_env_file(self, filename: str, config: Dict) -> io.BytesIO:
        """
        Create a fake .env file
        
        Args:
            filename: Name of the file
            config: Dictionary of environment variables
            
        Returns:
            BytesIO object containing .env data
        """
        output = io.StringIO()
        
        output.write("
        output.write(f"
        output.write("
        
        for key, value in config.items():
            output.write(f"{key}={value}\n")
        
        output.seek(0)
        return io.BytesIO(output.getvalue().encode('utf-8'))
    
    def create_json_credentials(self, filename: str, credentials: Dict) -> io.BytesIO:
        """
        Create a fake JSON credentials file
        
        Args:
            filename: Name of the file
            credentials: Dictionary of credentials
            
        Returns:
            BytesIO object containing JSON data
        """
        data = {
            "version": "1.0",
            "last_updated": datetime.now().isoformat(),
            "environment": "production",
            "credentials": credentials
        }
        
        json_str = json.dumps(data, indent=2)
        return io.BytesIO(json_str.encode('utf-8'))
    
    def create_zip_archive(self, filename: str, files_dict: Dict[str, io.BytesIO]) -> io.BytesIO:
        """
        Create a ZIP archive containing multiple files
        
        Args:
            filename: Name of the ZIP file
            files_dict: Dictionary of filename -> BytesIO content
            
        Returns:
            BytesIO object containing ZIP data
        """
        buffer = io.BytesIO()
        
        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            for name, content in files_dict.items():
                content.seek(0)
                zip_file.writestr(name, content.read())
        
        buffer.seek(0)
        return buffer
    
    def upload_to_gcs(self, filename: str, content: io.BytesIO, 
                      content_type: str = 'application/octet-stream',
                      metadata: Dict = None) -> str:
        """
        Upload file to Google Cloud Storage
        
        Args:
            filename: Name of the file in GCS
            content: File content as BytesIO
            content_type: MIME type of the file
            metadata: Optional metadata dictionary
            
        Returns:
            Public URL of the uploaded file
        """
        blob = self.bucket.blob(filename)
        
        if metadata:
            blob.metadata = metadata
        
        content.seek(0)
        blob.upload_from_file(content, content_type=content_type)
        
        print(f" Uploaded: {filename} to gs://{self.bucket_name}/{filename}")
        
        return f"gs://{self.bucket_name}/{filename}"
    
    def create_all_honey_files(self, api_keys: Dict, db_credentials: List[Dict], 
                                ssh_keys: List[Dict]) -> List[str]:
        """
        Create and upload all honey files
        
        Args:
            api_keys: Dictionary of API keys
            db_credentials: List of database credentials
            ssh_keys: List of SSH keys
            
        Returns:
            List of uploaded file URLs
        """
        uploaded_files = []
        
        print("\n Creating CSV files...")
        csv1 = self.create_csv_file("2025_financials_Q3.csv", rows=5000)
        uploaded_files.append(self.upload_to_gcs(
            "2025_financials_Q3.csv", csv1, "text/csv"
        ))
        
        csv2 = self.create_csv_file("2025_financials_Q4.csv", rows=4500)
        uploaded_files.append(self.upload_to_gcs(
            "2025_financials_Q4.csv", csv2, "text/csv"
        ))
        
        print("\n Creating PDF files...")
        pdf_creds = {**api_keys, **db_credentials[0]}
        pdf = self.create_credentials_pdf("backup_credentials.pdf", pdf_creds)
        uploaded_files.append(self.upload_to_gcs(
            "backup_credentials.pdf", pdf, "application/pdf"
        ))
        
        print("\n Creating SQL dump...")
        sql = self.create_sql_dump("database_backup_2025.sql")
        uploaded_files.append(self.upload_to_gcs(
            "database_backup_2025.sql", sql, "application/sql"
        ))
        
        print("\n️  Creating .env file...")
        env_config = {
            **{f"{k.upper()}": v for k, v in api_keys.items()},
            "DB_HOST": db_credentials[0]['host'],
            "DB_USER": db_credentials[0]['username'],
            "DB_PASS": db_credentials[0]['password'],
            "NODE_ENV": "production",
            "PORT": "3000"
        }
        env = self.create_env_file(".env.production", env_config)
        uploaded_files.append(self.upload_to_gcs(
            ".env.production", env, "text/plain"
        ))
        
        print("\n Creating JSON credentials...")
        json_creds = self.create_json_credentials("aws_credentials.json", {
            "aws_access_key_id": api_keys['aws_access_key_id'],
            "aws_secret_access_key": api_keys['aws_secret_access_key'],
            "region": "us-east-1"
        })
        uploaded_files.append(self.upload_to_gcs(
            "aws_credentials.json", json_creds, "application/json"
        ))
        
        print("\n Creating API keys file...")
        api_text = io.StringIO()
        api_text.write("
        for key, value in api_keys.items():
            api_text.write(f"{key}={value}\n")
        api_text.seek(0)
        api_bytes = io.BytesIO(api_text.getvalue().encode('utf-8'))
        uploaded_files.append(self.upload_to_gcs(
            "api_keys_production.txt", api_bytes, "text/plain"
        ))
        
        print("\n Creating SSH key files...")
        for i, key in enumerate(ssh_keys[:2]):
            ssh_file = io.BytesIO(key['private_key'].encode('utf-8'))
            filename = f"id_{key['type']}_{i+1}"
            uploaded_files.append(self.upload_to_gcs(
                filename, ssh_file, "text/plain"
            ))
        
        print("\n Creating ZIP archive...")
        zip_files = {
            "customers.csv": self.create_csv_file("customers.csv", 1000),
            "credentials.txt": io.BytesIO(f"DB_USER={db_credentials[1]['username']}\nDB_PASS={db_credentials[1]['password']}".encode()),
            "README.txt": io.BytesIO(b"Customer database dump for Region A")
        }
        zip_archive = self.create_zip_archive("customer_dump_region_A.zip", zip_files)
        uploaded_files.append(self.upload_to_gcs(
            "customer_dump_region_A.zip", zip_archive, "application/zip"
        ))
        
        print(f"\n Successfully uploaded {len(uploaded_files)} files!")
        return uploaded_files


if __name__ == "__main__":
    from src.generators import APIKeyGenerator, DatabaseCredentialGenerator, SSHKeyGenerator
    
    api_keys = APIKeyGenerator.generate_all_api_keys()
    db_creds = DatabaseCredentialGenerator.generate_all_db_credentials()
    ssh_keys = SSHKeyGenerator.generate_all_ssh_keys()
    
    creator = FileCreator(bucket_name="your-honey-tokens-bucket")
    uploaded = creator.create_all_honey_files(api_keys, db_creds, ssh_keys)
    
    print("\nUploaded files:")
    for url in uploaded:
        print(f"  - {url}")

