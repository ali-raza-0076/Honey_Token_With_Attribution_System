"""
Pattern Detector - Extended detection patterns for various attack types
"""

from typing import List, Dict
from collections import defaultdict
from datetime import datetime, timedelta
from .cloudwatch_analyzer import SecurityEvent

class PatternDetector:
    """Detect advanced attack patterns"""
    
    @staticmethod
    def detect_credential_stuffing(logs: List[Dict]) -> List[SecurityEvent]:
        """
        Detect credential stuffing attacks (multiple failed auth attempts)
        
        Args:
            logs: List of log entries
            
        Returns:
            List of security events
        """
        events = []
        
        ip_failed_auth = defaultdict(list)
        
        for log in logs:
            if log.get('status') in [401, 403]:
                ip_failed_auth[log['ip']].append({
                    'timestamp': log['timestamp'],
                    'resource': log['object'],
                    'user_agent': log['user_agent']
                })
        
        for ip, failures in ip_failed_auth.items():
            if len(failures) >= 5:
                failures.sort(key=lambda x: x['timestamp'])
                first = failures[0]['timestamp']
                last = failures[-1]['timestamp']
                
                if isinstance(first, str):
                    first = datetime.fromisoformat(first)
                if isinstance(last, str):
                    last = datetime.fromisoformat(last)
                
                if (last - first).total_seconds() <= 60:
                    events.append(SecurityEvent(
                        timestamp=last,
                        event_type="credential_stuffing",
                        severity="high",
                        source_ip=ip,
                        user_agent=failures[0]['user_agent'],
                        resource=failures[0]['resource'],
                        details={
                            'failed_attempts': len(failures),
                            'time_span': (last - first).total_seconds(),
                            'attack_rate': len(failures) / max((last - first).total_seconds(), 1)
                        }
                    ))
        
        return events
    
    @staticmethod
    def detect_data_exfiltration(logs: List[Dict]) -> List[SecurityEvent]:
        """
        Detect unusual data download patterns (data exfiltration)
        
        Args:
            logs: List of log entries
            
        Returns:
            List of security events
        """
        events = []
        
        ip_data_transfer = defaultdict(lambda: {'bytes': 0, 'files': 0, 'timestamps': []})
        
        for log in logs:
            if log['method'] == 'GET' and log['status'] == 200:
                ip = log['ip']
                estimated_size = 1024 * 1024
                ip_data_transfer[ip]['bytes'] += estimated_size
                ip_data_transfer[ip]['files'] += 1
                ip_data_transfer[ip]['timestamps'].append(log['timestamp'])
        
        threshold_mb = 100
        for ip, data in ip_data_transfer.items():
            size_mb = data['bytes'] / (1024 * 1024)
            
            if size_mb >= threshold_mb:
                timestamps = data['timestamps']
                first = min(timestamps)
                last = max(timestamps)
                
                if isinstance(first, str):
                    first = datetime.fromisoformat(first)
                if isinstance(last, str):
                    last = datetime.fromisoformat(last)
                
                events.append(SecurityEvent(
                    timestamp=last,
                    event_type="data_exfiltration",
                    severity="critical",
                    source_ip=ip,
                    user_agent="",
                    resource=f"{data['files']} files",
                    details={
                        'total_size_mb': round(size_mb, 2),
                        'file_count': data['files'],
                        'duration_seconds': (last - first).total_seconds(),
                        'transfer_rate_mbps': round(size_mb / max((last - first).total_seconds(), 1), 2)
                    }
                ))
        
        return events
    
    @staticmethod
    def detect_port_scanning(logs: List[Dict]) -> List[SecurityEvent]:
        """
        Detect port scanning behavior (sequential access patterns)
        
        Args:
            logs: List of log entries
            
        Returns:
            List of security events
        """
        events = []
        
        ip_resources = defaultdict(list)
        
        for log in logs:
            ip_resources[log['ip']].append({
                'timestamp': log['timestamp'],
                'resource': log['object'],
                'status': log['status']
            })
        
        for ip, accesses in ip_resources.items():
            accesses.sort(key=lambda x: x['timestamp'])
            
            unique_resources = set(a['resource'] for a in accesses)
            
            if len(unique_resources) >= 20:
                first = accesses[0]['timestamp']
                last = accesses[-1]['timestamp']
                
                if isinstance(first, str):
                    first = datetime.fromisoformat(first)
                if isinstance(last, str):
                    last = datetime.fromisoformat(last)
                
                if (last - first).total_seconds() <= 120:
                    events.append(SecurityEvent(
                        timestamp=last,
                        event_type="port_scanning",
                        severity="medium",
                        source_ip=ip,
                        user_agent="",
                        resource=f"{len(unique_resources)} resources",
                        details={
                            'unique_resources': len(unique_resources),
                            'total_requests': len(accesses),
                            'time_span': (last - first).total_seconds(),
                            'scan_rate': len(accesses) / max((last - first).total_seconds(), 1)
                        }
                    ))
        
        return events
    
    @staticmethod
    def detect_time_based_pattern(logs: List[Dict]) -> List[SecurityEvent]:
        """
        Detect time-based patterns (scheduled/automated attacks)
        
        Args:
            logs: List of log entries
            
        Returns:
            List of security events
        """
        events = []
        
        ip_intervals = defaultdict(list)
        
        for log in logs:
            ip = log['ip']
            timestamp = log['timestamp']
            if isinstance(timestamp, str):
                timestamp = datetime.fromisoformat(timestamp)
            
            ip_intervals[ip].append(timestamp)
        
        for ip, timestamps in ip_intervals.items():
            if len(timestamps) < 5:
                continue
            
            timestamps.sort()
            intervals = []
            for i in range(1, len(timestamps)):
                interval = (timestamps[i] - timestamps[i-1]).total_seconds()
                intervals.append(interval)
            
            if intervals:
                avg_interval = sum(intervals) / len(intervals)
                variance = sum(abs(i - avg_interval) for i in intervals) / len(intervals)
                
                if variance / avg_interval < 0.1:
                    events.append(SecurityEvent(
                        timestamp=timestamps[-1],
                        event_type="time_based_pattern",
                        severity="medium",
                        source_ip=ip,
                        user_agent="",
                        resource="",
                        details={
                            'average_interval_seconds': round(avg_interval, 2),
                            'interval_variance': round(variance, 2),
                            'request_count': len(timestamps),
                            'pattern_type': 'automated_scheduled'
                        }
                    ))
        
        return events
    
    @staticmethod
    def detect_impossible_travel(logs: List[Dict]) -> List[SecurityEvent]:
        """
        Detect impossible travel (access from geographically distant locations in short time)
        Note: Requires IP geolocation data
        
        Args:
            logs: List of log entries
            
        Returns:
            List of security events
        """
        return []


if __name__ == "__main__":
    print("Pattern Detector module - Extended attack pattern detection")

