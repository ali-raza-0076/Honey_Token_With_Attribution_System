"""
CloudWatch Log Analyzer
Analyzes S3 access logs stored in CloudWatch for suspicious patterns
"""

import os
import json
from datetime import datetime, timedelta
from collections import defaultdict
import boto3
from dataclasses import dataclass
import pytz


@dataclass
class SecurityEvent:
    """Represents a security event"""
    event_type: str
    severity: str
    timestamp: datetime
    ip_address: str
    resource: str
    details: dict
    region: str


class CloudWatchAnalyzer:
    """Analyzes CloudWatch logs for suspicious patterns"""
    
    def __init__(self, region=None):
        """Initialize CloudWatch client"""
        self.region = region or os.getenv('AWS_REGION', 'us-east-1')
        self.cloudwatch_logs = boto3.client('logs', region_name=self.region)
        self.dynamodb = boto3.resource('dynamodb', region_name=self.region)
        self.log_group_name = '/aws/s3/access-logs'
        self.table_name = os.getenv('DYNAMODB_TABLE_NAME', 'honeypot_logs')
        
        self.bulk_download_threshold = int(os.getenv('BULK_DOWNLOAD_THRESHOLD', 10))
        self.rapid_access_threshold = int(os.getenv('RAPID_ACCESS_THRESHOLD', 5))
        self.rapid_access_window = int(os.getenv('RAPID_ACCESS_WINDOW', 60))
    
    def query_s3_access_logs(self, hours=24):
        """Query S3 access logs from CloudWatch Logs Insights"""
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=hours)
        
        query = """
        fields @timestamp, bucket, key, remoteip, useragent, operation, httpstatus
        | filter ispresent(remoteip)
        | sort @timestamp desc
        """
        
        try:
            response = self.cloudwatch_logs.start_query(
                logGroupName=self.log_group_name,
                startTime=int(start_time.timestamp()),
                endTime=int(end_time.timestamp()),
                queryString=query
            )
            
            query_id = response['queryId']
            
            status = 'Running'
            while status in ['Running', 'Scheduled']:
                response = self.cloudwatch_logs.get_query_results(queryId=query_id)
                status = response['status']
            
            if status == 'Complete':
                return self._parse_log_results(response['results'])
            else:
                print(f"Query failed with status: {status}")
                return []
                
        except Exception as e:
            print(f"Error querying CloudWatch logs: {e}")
            return []
    
    def _parse_log_results(self, results):
        """Parse CloudWatch Logs Insights results"""
        parsed_logs = []
        
        for result in results:
            log_entry = {}
            for field in result:
                log_entry[field['field']] = field['value']
            
            parsed_logs.append({
                'timestamp': log_entry.get('@timestamp'),
                'bucket_name': log_entry.get('bucket'),
                'object_name': log_entry.get('key'),
                'remote_ip': log_entry.get('remoteip'),
                'user_agent': log_entry.get('useragent'),
                'operation': log_entry.get('operation'),
                'http_status': log_entry.get('httpstatus'),
                'region': self.region
            })
        
        return parsed_logs
    
    def detect_bulk_downloads(self, logs):
        """Detect bulk download patterns"""
        events = []
        ip_downloads = defaultdict(list)
        
        for log in logs:
            if log.get('operation') == 'REST.GET.OBJECT':
                ip_downloads[log['remote_ip']].append(log)
        
        for ip, downloads in ip_downloads.items():
            if len(downloads) >= self.bulk_download_threshold:
                event = SecurityEvent(
                    event_type='bulk_download',
                    severity='high',
                    timestamp=datetime.now(pytz.UTC),
                    ip_address=ip,
                    resource=downloads[0]['bucket_name'],
                    details={
                        'download_count': len(downloads),
                        'files': [d['object_name'] for d in downloads[:10]],
                        'user_agent': downloads[0].get('user_agent', 'Unknown')
                    },
                    region=self.region
                )
                events.append(event)
        
        return events
    
    def detect_rapid_access(self, logs):
        """Detect rapid successive access patterns"""
        events = []
        ip_access_times = defaultdict(list)
        
        for log in logs:
            try:
                timestamp = datetime.fromisoformat(log['timestamp'].replace('Z', '+00:00'))
                ip_access_times[log['remote_ip']].append(timestamp)
            except:
                continue
        
        for ip, times in ip_access_times.items():
            times.sort()
            
            for i in range(len(times) - self.rapid_access_threshold + 1):
                window_start = times[i]
                window_end = times[i + self.rapid_access_threshold - 1]
                
                if (window_end - window_start).total_seconds() <= self.rapid_access_window:
                    event = SecurityEvent(
                        event_type='rapid_access',
                        severity='medium',
                        timestamp=datetime.now(pytz.UTC),
                        ip_address=ip,
                        resource='multiple',
                        details={
                            'access_count': self.rapid_access_threshold,
                            'time_window': f"{self.rapid_access_window} seconds",
                            'first_access': window_start.isoformat(),
                            'last_access': window_end.isoformat()
                        },
                        region=self.region
                    )
                    events.append(event)
                    break
        
        return events
    
    def detect_abnormal_hours_access(self, logs):
        """Detect access during abnormal hours (midnight to 6 AM)"""
        events = []
        abnormal_hours = range(0, 6)
        
        for log in logs:
            try:
                timestamp = datetime.fromisoformat(log['timestamp'].replace('Z', '+00:00'))
                if timestamp.hour in abnormal_hours:
                    event = SecurityEvent(
                        event_type='abnormal_hours_access',
                        severity='medium',
                        timestamp=timestamp,
                        ip_address=log['remote_ip'],
                        resource=log['object_name'],
                        details={
                            'access_time': timestamp.strftime('%Y-%m-%d %H:%M:%S UTC'),
                            'operation': log.get('operation', 'Unknown')
                        },
                        region=self.region
                    )
                    events.append(event)
            except:
                continue
        
        return events
    
    def detect_geolocation_anomaly(self, logs):
        """Detect access from unusual geographic locations"""
        events = []
        suspicious_patterns = ['curl', 'wget', 'python', 'bot', 'crawler', 'scanner']
        
        for log in logs:
            user_agent = log.get('user_agent', '').lower()
            if any(pattern in user_agent for pattern in suspicious_patterns):
                event = SecurityEvent(
                    event_type='suspicious_user_agent',
                    severity='medium',
                    timestamp=datetime.now(pytz.UTC),
                    ip_address=log['remote_ip'],
                    resource=log['object_name'],
                    details={
                        'user_agent': log.get('user_agent', 'Unknown'),
                        'reason': 'Automated tool detected'
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
                'event_id': f"{event.event_type}_{event.timestamp.timestamp()}_{event.ip_address}",
                'timestamp': event.timestamp.isoformat(),
                'event_type': event.event_type,
                'severity': event.severity,
                'ip_address': event.ip_address,
                'resource': event.resource,
                'region': event.region,
                'details': json.dumps(event.details)
            }
            
            table.put_item(Item=item)
            
        except Exception as e:
            print(f"Error storing event in DynamoDB: {e}")
    
    def analyze_logs(self, hours=24):
        """Run all detection patterns"""
        print(f"\n{'='*60}")
        print(f"Analyzing S3 access logs for the last {hours} hours")
        print(f"{'='*60}\n")
        
        logs = self.query_s3_access_logs(hours)
        print(f"Retrieved {len(logs)} log entries")
        
        if not logs:
            print("No logs found to analyze")
            return {}
        
        all_events = {
            'bulk_downloads': self.detect_bulk_downloads(logs),
            'rapid_access': self.detect_rapid_access(logs),
            'abnormal_hours': self.detect_abnormal_hours_access(logs),
            'suspicious_agents': self.detect_geolocation_anomaly(logs)
        }
        
        for event_type, events in all_events.items():
            print(f"\n{event_type}: {len(events)} events detected")
            for event in events:
                self.store_event_in_dynamodb(event)
        
        return all_events
    
    def get_recent_events(self, hours=24):
        """Get recent security events from DynamoDB"""
        try:
            table = self.dynamodb.Table(self.table_name)
            
            cutoff_time = (datetime.now(pytz.UTC) - timedelta(hours=hours)).isoformat()
            
            response = table.scan(
                FilterExpression='#ts >= :cutoff',
                ExpressionAttributeNames={'#ts': 'timestamp'},
                ExpressionAttributeValues={':cutoff': cutoff_time}
            )
            
            events = []
            for item in response.get('Items', []):
                details = item.get('details', {})
                if isinstance(details, str):
                    try:
                        details = json.loads(details)
                    except:
                        details = {}
                
                events.append({
                    'event_id': item['event_id'],
                    'timestamp': item['timestamp'],
                    'event_type': item['event_type'],
                    'severity': item['severity'],
                    'ip_address': item['ip_address'],
                    'resource': item['resource'],
                    'region': item['region'],
                    'details': details
                })
            
            return events
            
        except Exception as e:
            print(f"Error retrieving events from DynamoDB: {e}")
            return []


if __name__ == "__main__":
    analyzer = CloudWatchAnalyzer()
    events = analyzer.analyze_logs(hours=24)
    
    print("\n" + "="*60)
    print("ANALYSIS SUMMARY")
    print("="*60)
    
    total_events = sum(len(event_list) for event_list in events.values())
    print(f"\nTotal security events detected: {total_events}")
    
    for event_type, event_list in events.items():
        if event_list:
            print(f"\n{event_type}:")
            for event in event_list[:5]:
                print(f"  - {event.ip_address}: {event.details}")

