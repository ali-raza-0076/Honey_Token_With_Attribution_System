"""
AWS Lambda Function - Automatic Honey Token Detection
This runs every 5 minutes to detect attacks automatically
"""

import json
import os
import boto3
from datetime import datetime, timedelta
import pytz
from collections import defaultdict, Counter
from dataclasses import dataclass
import uuid

@dataclass
class SecurityEvent:
    event_type: str
    severity: str
    timestamp: datetime
    ip_address: str
    resource: str
    details: dict
    region: str

class CloudWatchAnalyzer:
    def __init__(self, region='us-east-1'):
        self.region = region
        self.s3 = boto3.client('s3', region_name=region)
        self.dynamodb = boto3.resource('dynamodb', region_name=region)
        self.logs = boto3.client('logs', region_name=region)
        self.table_name = os.environ.get('DYNAMODB_TABLE_NAME', 'honeypot_logs')
        self.bucket_name = os.environ.get('S3_BUCKET_NAME', 'honey-tokens-storage-us-east-1')
    
    def query_s3_access_logs(self, hours=1):
        """Query S3 access logs (Standard approach - 15-60 min delay)"""
        logs = []
        
        
        try:
            logs_bucket = f"{self.bucket_name}-logs"
            cutoff = datetime.now(pytz.UTC) - timedelta(hours=hours)
            
            print(f"Checking S3 access logs bucket: {logs_bucket}")
            
            response = self.s3.list_objects_v2(Bucket=logs_bucket, MaxKeys=100)
            
            log_files = response.get('Contents', [])
            print(f"Found {len(log_files)} log files")
            
            for obj in log_files:
                if obj['LastModified'] > cutoff:
                    try:
                        log_obj = self.s3.get_object(Bucket=logs_bucket, Key=obj['Key'])
                        log_content = log_obj['Body'].read().decode('utf-8')
                        
                        for line in log_content.split('\n'):
                            if line.strip() and not line.startswith('
                                parts = line.split()
                                if len(parts) > 10:
                                    logs.append({
                                        'timestamp': datetime.now(pytz.UTC).isoformat(),
                                        'remote_ip': parts[4] if len(parts) > 4 else 'unknown',
                                        'object_name': parts[7].split('/')[-1] if len(parts) > 7 else 'unknown',
                                        'user_agent': ' '.join(parts[10:]) if len(parts) > 10 else 'unknown',
                                        'http_status': parts[8] if len(parts) > 8 else '200',
                                        'operation': parts[5] if len(parts) > 5 else 'GET'
                                    })
                    except Exception as parse_error:
                        print(f"Error parsing log file {obj['Key']}: {parse_error}")
                        continue
            
            print(f"Parsed {len(logs)} access events from logs")
            
        except Exception as e:
            print(f"Could not read S3 access logs: {e}")
            print("Note: S3 access logs have 15-60 minute delay")
        
        return logs
    
    def detect_bulk_downloads(self, logs):
        """Detect bulk download attempts (5+ files)"""
        events = []
        ip_downloads = defaultdict(set)
        
        for log in logs:
            ip = log.get('remote_ip', 'unknown')
            resource = log.get('object_name', 'unknown')
            ip_downloads[ip].add(resource)
        
        for ip, files in ip_downloads.items():
            if len(files) >= 5:
                event = SecurityEvent(
                    event_type='bulk_download',
                    severity='critical',
                    timestamp=datetime.now(pytz.UTC),
                    ip_address=ip,
                    resource=f"{len(files)} files",
                    details={'files': list(files)[:10], 'total': len(files)},
                    region=self.region
                )
                events.append(event)
        
        return events
    
    def detect_rapid_access(self, logs):
        """Detect rapid successive access (10+ accesses in 5 minutes)"""
        events = []
        ip_access_times = defaultdict(list)
        
        for log in logs:
            try:
                timestamp_str = log.get('timestamp', '')
                if timestamp_str:
                    timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                    ip_access_times[log.get('remote_ip')].append(timestamp)
            except:
                continue
        
        for ip, times in ip_access_times.items():
            times.sort()
            
            for i in range(len(times) - 9):
                window_start = times[i]
                window_end = times[i + 9]
                
                if (window_end - window_start).total_seconds() <= 300:
                    event = SecurityEvent(
                        event_type='rapid_access',
                        severity='high',
                        timestamp=datetime.now(pytz.UTC),
                        ip_address=ip,
                        resource='multiple',
                        details={
                            'access_count': 10,
                            'time_window': '5 minutes',
                            'first_access': window_start.isoformat(),
                            'last_access': window_end.isoformat()
                        },
                        region=self.region
                    )
                    events.append(event)
                    break
        
        return events
    
    def detect_abnormal_hours(self, logs):
        """Detect access during off-hours (midnight to 6 AM)"""
        events = []
        abnormal_hours = range(0, 6)
        ip_abnormal_access = defaultdict(list)
        
        for log in logs:
            try:
                timestamp_str = log.get('timestamp', '')
                if timestamp_str:
                    timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                    if timestamp.hour in abnormal_hours:
                        ip = log.get('remote_ip')
                        ip_abnormal_access[ip].append(log)
            except:
                continue
        
        for ip, access_logs in ip_abnormal_access.items():
            if len(access_logs) >= 3:
                event = SecurityEvent(
                    event_type='abnormal_hours_access',
                    severity='medium',
                    timestamp=datetime.now(pytz.UTC),
                    ip_address=ip,
                    resource='multiple',
                    details={
                        'access_count': len(access_logs),
                        'time_range': '00:00-06:00 UTC',
                        'files_accessed': [log.get('object_name', 'unknown') for log in access_logs[:5]]
                    },
                    region=self.region
                )
                events.append(event)
        
        return events
    
    def detect_suspicious_user_agents(self, logs):
        """Detect automated tools and suspicious user agents"""
        events = []
        suspicious_patterns = ['curl', 'wget', 'python', 'bot', 'crawler', 'scanner', 'script']
        ip_suspicious = defaultdict(list)
        
        for log in logs:
            user_agent = log.get('user_agent', '').lower()
            if any(pattern in user_agent for pattern in suspicious_patterns):
                ip = log.get('remote_ip')
                ip_suspicious[ip].append(log)
        
        for ip, sus_logs in ip_suspicious.items():
            event = SecurityEvent(
                event_type='suspicious_user_agent',
                severity='medium',
                timestamp=datetime.now(pytz.UTC),
                ip_address=ip,
                resource=f"{len(sus_logs)} requests",
                details={
                    'user_agent': sus_logs[0].get('user_agent', 'Unknown'),
                    'request_count': len(sus_logs),
                    'reason': 'Automated tool detected'
                },
                region=self.region
            )
            events.append(event)
        
        return events
    
    def detect_failed_access_attempts(self, logs):
        """Detect multiple failed access attempts (403/404 errors)"""
        events = []
        ip_failures = defaultdict(list)
        
        for log in logs:
            status = log.get('http_status', '200')
            if status in ['403', '404', '401']:
                ip = log.get('remote_ip')
                ip_failures[ip].append(log)
        
        for ip, failure_logs in ip_failures.items():
            if len(failure_logs) >= 5:
                event = SecurityEvent(
                    event_type='failed_access_attempts',
                    severity='high',
                    timestamp=datetime.now(pytz.UTC),
                    ip_address=ip,
                    resource='multiple',
                    details={
                        'failure_count': len(failure_logs),
                        'status_codes': [log.get('http_status') for log in failure_logs[:10]],
                        'attempted_resources': [log.get('object_name', 'unknown') for log in failure_logs[:5]]
                    },
                    region=self.region
                )
                events.append(event)
        
        return events
    
    def store_event_in_dynamodb(self, event):
        """Store security event in DynamoDB"""
        try:
            table = self.dynamodb.Table(self.table_name)
            
            item = {
                'event_id': f"{event.event_type}_{datetime.now().timestamp()}_{event.ip_address}",
                'timestamp': event.timestamp.isoformat(),
                'event_type': event.event_type,
                'severity': event.severity,
                'ip_address': event.ip_address,
                'resource': event.resource,
                'region': event.region,
                'details': json.dumps(event.details)
            }
            
            table.put_item(Item=item)
            return True
        except Exception as e:
            print(f"Error storing event: {e}")
            return False
    
    def analyze_logs(self, hours=1):
        """Analyze logs for attacks - ALL DETECTION PATTERNS"""
        print(f"Analyzing logs for last {hours} hour(s)...")
        
        logs = self.query_s3_access_logs(hours)
        
        if not logs:
            print("No logs found")
            return {}
        
        print(f"Found {len(logs)} log entries to analyze")
        
        all_events = {
            'bulk_download': self.detect_bulk_downloads(logs),
            'rapid_access': self.detect_rapid_access(logs),
            'abnormal_hours': self.detect_abnormal_hours(logs),
            'suspicious_user_agent': self.detect_suspicious_user_agents(logs),
            'failed_access_attempts': self.detect_failed_access_attempts(logs)
        }
        
        total_stored = 0
        for event_type, events in all_events.items():
            print(f"  {event_type}: {len(events)} events")
            for event in events:
                if self.store_event_in_dynamodb(event):
                    total_stored += 1
        
        print(f"Total events stored: {total_stored}")
        
        return all_events


def lambda_handler(event, context):
    """
    AWS Lambda handler - automatically triggered by EventBridge
    This is the REAL AWS-native detection!
    """
    
    print(f" Lambda Function Started: {datetime.utcnow().isoformat()}")
    print(f"Event: {json.dumps(event)}")
    
    region = os.environ.get('HONEY_REGION', os.environ.get('AWS_REGION', 'us-east-1'))
    
    try:
        analyzer = CloudWatchAnalyzer(region=region)
        
        events = analyzer.analyze_logs(hours=1)
        
        total_events = sum(len(event_list) for event_list in events.values())
        
        if total_events > 0:
            print(f" DETECTED {total_events} security events!")
        else:
            print(" No security events detected")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Log analysis completed',
                'events_detected': total_events,
                'timestamp': datetime.utcnow().isoformat()
            })
        }
        
    except Exception as e:
        print(f" Error: {str(e)}")
        import traceback
        traceback.print_exc()
        
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            })
        }


if __name__ == "__main__":
    result = lambda_handler({}, None)
    print(json.dumps(result, indent=2))

