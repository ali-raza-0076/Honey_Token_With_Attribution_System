"""
Log Analyzer - Auto Attribution System
Analyzes GCP logs to detect suspicious activities and attack patterns
"""

import os
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from collections import defaultdict
import pytz
from google.cloud import bigquery, logging as cloud_logging
from dataclasses import dataclass


@dataclass
class SecurityEvent:
    """Represents a detected security event"""
    timestamp: datetime
    event_type: str
    severity: str
    source_ip: str
    user_agent: str
    resource: str
    details: Dict
    region: str = "unknown"


class LogAnalyzer:
    """Analyze logs for suspicious patterns"""
    
    def __init__(self, project_id: str, dataset_id: str = "honeypot_logs"):
        """
        Initialize Log Analyzer
        
        Args:
            project_id: GCP project ID
            dataset_id: BigQuery dataset ID
        """
        self.project_id = project_id
        self.dataset_id = dataset_id
        self.bq_client = bigquery.Client(project=project_id)
        self.logging_client = cloud_logging.Client(project=project_id)
        
        self.bulk_download_threshold = int(os.getenv('BULK_DOWNLOAD_THRESHOLD', 1000))
        self.rapid_access_threshold = int(os.getenv('RAPID_ACCESS_THRESHOLD', 10))
        self.rapid_access_window = int(os.getenv('RAPID_ACCESS_WINDOW', 300))
        self.abnormal_hours_start = int(os.getenv('ABNORMAL_HOURS_START', 0))
        self.abnormal_hours_end = int(os.getenv('ABNORMAL_HOURS_END', 6))
        
        self.suspicious_countries = ['RU', 'CN', 'KP', 'IR', 'SY']
        self.suspicious_user_agents = ['curl', 'wget', 'python-requests', 'scrapy', 'bot']
    
    def get_recent_access_logs(self, hours: int = 24) -> List[Dict]:
        """
        Retrieve recent access logs from BigQuery
        
        Args:
            hours: Number of hours to look back
            
        Returns:
            List of log entries
        """
        query = f"""
        SELECT
            timestamp,
            resource.labels.bucket_name,
            resource.labels.object_name,
            httpRequest.requestMethod,
            httpRequest.status,
            httpRequest.userAgent,
            httpRequest.remoteIp,
            httpRequest.requestUrl,
            labels.region
        FROM
            `{self.project_id}.{self.dataset_id}.storage_logs`
        WHERE
            timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {hours} HOUR)
        ORDER BY
            timestamp DESC
        """
        
        try:
            query_job = self.bq_client.query(query)
            results = query_job.result()
            
            logs = []
            for row in results:
                logs.append({
                    'timestamp': row.timestamp,
                    'bucket': row.bucket_name,
                    'object': row.object_name,
                    'method': row.requestMethod,
                    'status': row.status,
                    'user_agent': row.userAgent,
                    'ip': row.remoteIp,
                    'url': row.requestUrl,
                    'region': row.get('region', 'unknown')
                })
            
            return logs
        except Exception as e:
            print(f"Error fetching logs: {e}")
            return []
    
    def detect_bulk_downloads(self, logs: List[Dict]) -> List[SecurityEvent]:
        """
        Detect bulk download attempts
        
        Args:
            logs: List of log entries
            
        Returns:
            List of security events
        """
        events = []
        
        ip_downloads = defaultdict(int)
        ip_resources = defaultdict(set)
        ip_timestamps = defaultdict(list)
        
        for log in logs:
            ip = log['ip']
            if log['method'] == 'GET' and log['status'] == 200:
                ip_downloads[ip] += 1
                ip_resources[ip].add(log['object'])
                ip_timestamps[ip].append(log['timestamp'])
        
        for ip, count in ip_downloads.items():
            if count >= self.bulk_download_threshold:
                events.append(SecurityEvent(
                    timestamp=max(ip_timestamps[ip]),
                    event_type="bulk_download",
                    severity="high",
                    source_ip=ip,
                    user_agent=logs[0]['user_agent'],
                    resource=", ".join(list(ip_resources[ip])[:5]),
                    details={
                        'download_count': count,
                        'unique_resources': len(ip_resources[ip]),
                        'time_span': (max(ip_timestamps[ip]) - min(ip_timestamps[ip])).total_seconds()
                    }
                ))
        
        return events
    
    def detect_rapid_access(self, logs: List[Dict]) -> List[SecurityEvent]:
        """
        Detect rapid successive access from same source
        
        Args:
            logs: List of log entries
            
        Returns:
            List of security events
        """
        events = []
        
        ip_accesses = defaultdict(list)
        for log in logs:
            ip_accesses[log['ip']].append({
                'timestamp': log['timestamp'],
                'resource': log['object'],
                'user_agent': log['user_agent']
            })
        
        for ip, accesses in ip_accesses.items():
            accesses.sort(key=lambda x: x['timestamp'])
            
            for i in range(len(accesses)):
                window_end = accesses[i]['timestamp'] + timedelta(seconds=self.rapid_access_window)
                window_accesses = [
                    a for a in accesses[i:]
                    if a['timestamp'] <= window_end
                ]
                
                if len(window_accesses) >= self.rapid_access_threshold:
                    events.append(SecurityEvent(
                        timestamp=accesses[i]['timestamp'],
                        event_type="rapid_access",
                        severity="medium",
                        source_ip=ip,
                        user_agent=window_accesses[0]['user_agent'],
                        resource=window_accesses[0]['resource'],
                        details={
                            'access_count': len(window_accesses),
                            'time_window': self.rapid_access_window,
                            'requests_per_second': len(window_accesses) / self.rapid_access_window
                        }
                    ))
                    break
        
        return events
    
    def detect_abnormal_hours_access(self, logs: List[Dict]) -> List[SecurityEvent]:
        """
        Detect access during abnormal hours (e.g., 0-6 AM)
        
        Args:
            logs: List of log entries
            
        Returns:
            List of security events
        """
        events = []
        
        ip_abnormal_accesses = defaultdict(list)
        
        for log in logs:
            timestamp = log['timestamp']
            if isinstance(timestamp, str):
                timestamp = datetime.fromisoformat(timestamp)
            
            hour = timestamp.hour
            
            if self.abnormal_hours_start <= hour < self.abnormal_hours_end:
                ip_abnormal_accesses[log['ip']].append({
                    'timestamp': timestamp,
                    'resource': log['object'],
                    'user_agent': log['user_agent']
                })
        
        for ip, accesses in ip_abnormal_accesses.items():
            if len(accesses) >= 5:
                events.append(SecurityEvent(
                    timestamp=max(a['timestamp'] for a in accesses),
                    event_type="abnormal_hours_access",
                    severity="medium",
                    source_ip=ip,
                    user_agent=accesses[0]['user_agent'],
                    resource=accesses[0]['resource'],
                    details={
                        'access_count': len(accesses),
                        'time_range': f"{self.abnormal_hours_start:02d}:00 - {self.abnormal_hours_end:02d}:00",
                        'unique_resources': len(set(a['resource'] for a in accesses))
                    }
                ))
        
        return events
    
    def detect_geolocation_anomaly(self, logs: List[Dict]) -> List[SecurityEvent]:
        """
        Detect access from suspicious geolocations
        
        Args:
            logs: List of log entries
            
        Returns:
            List of security events
        """
        events = []
        
        
        for log in logs:
            ip = log['ip']
            
            if any(country in str(ip) for country in self.suspicious_countries):
                events.append(SecurityEvent(
                    timestamp=log['timestamp'],
                    event_type="geolocation_anomaly",
                    severity="high",
                    source_ip=ip,
                    user_agent=log['user_agent'],
                    resource=log['object'],
                    details={
                        'reason': 'Access from suspicious country',
                        'ip_address': ip
                    }
                ))
        
        return events
    
    def detect_user_agent_anomaly(self, logs: List[Dict]) -> List[SecurityEvent]:
        """
        Detect automated tools or suspicious user agents
        
        Args:
            logs: List of log entries
            
        Returns:
            List of security events
        """
        events = []
        
        for log in logs:
            user_agent = log['user_agent'].lower()
            
            if any(suspicious in user_agent for suspicious in self.suspicious_user_agents):
                events.append(SecurityEvent(
                    timestamp=log['timestamp'],
                    event_type="user_agent_anomaly",
                    severity="medium",
                    source_ip=log['ip'],
                    user_agent=log['user_agent'],
                    resource=log['object'],
                    details={
                        'reason': 'Automated tool detected',
                        'user_agent': log['user_agent']
                    }
                ))
        
        return events
    
    def analyze_logs(self, hours: int = 24) -> Dict[str, List[SecurityEvent]]:
        """
        Run all detection patterns on recent logs
        
        Args:
            hours: Number of hours to analyze
            
        Returns:
            Dictionary of event_type -> list of events
        """
        print(f" Analyzing logs from the last {hours} hours...")
        
        logs = self.get_recent_access_logs(hours)
        print(f" Found {len(logs)} log entries")
        
        if not logs:
            print("️  No logs found")
            return {}
        
        all_events = {
            'bulk_download': self.detect_bulk_downloads(logs),
            'rapid_access': self.detect_rapid_access(logs),
            'abnormal_hours': self.detect_abnormal_hours_access(logs),
            'geolocation_anomaly': self.detect_geolocation_anomaly(logs),
            'user_agent_anomaly': self.detect_user_agent_anomaly(logs)
        }
        
        total_events = sum(len(events) for events in all_events.values())
        print(f"\n Detected {total_events} security events:")
        for event_type, events in all_events.items():
            if events:
                print(f"  - {event_type}: {len(events)} events")
        
        return all_events


if __name__ == "__main__":
    import os
    from dotenv import load_dotenv
    
    load_dotenv()
    
    project_id = os.getenv('GCP_PROJECT_ID')
    analyzer = LogAnalyzer(project_id)
    
    events = analyzer.analyze_logs(hours=24)
    
    for event_type, event_list in events.items():
        if event_list:
            print(f"\n=== {event_type.upper()} ===")
            for event in event_list:
                print(f"  Time: {event.timestamp}")
                print(f"  IP: {event.source_ip}")
                print(f"  Severity: {event.severity}")
                print(f"  Details: {event.details}")
                print()

