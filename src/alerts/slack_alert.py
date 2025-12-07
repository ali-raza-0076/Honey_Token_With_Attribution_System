"""
Slack Alert System
Sends security alerts to Slack channels
"""

import os
import json
from typing import List, Dict
from datetime import datetime
import requests
from src.analysis import SecurityEvent


class SlackAlertSystem:
    """Send Slack alerts for security events"""
    
    def __init__(self, webhook_url: str = None):
        """
        Initialize Slack Alert System
        
        Args:
            webhook_url: Slack webhook URL
        """
        self.webhook_url = webhook_url or os.getenv('SLACK_WEBHOOK_URL')
        
        if not self.webhook_url:
            print("️  Slack webhook URL not configured")
            self.enabled = False
        else:
            self.enabled = True
    
    def format_event_slack(self, event: SecurityEvent) -> Dict:
        """
        Format security event for Slack
        
        Args:
            event: Security event
            
        Returns:
            Slack message payload
        """
        severity_colors = {
            'critical': 'danger',
            'high': 'warning',
            'medium': '#ffc107',
            'low': 'good'
        }
        
        severity_emojis = {
            'critical': ':rotating_light:',
            'high': ':warning:',
            'medium': ':large_orange_diamond:',
            'low': ':information_source:'
        }
        
        color = severity_colors.get(event.severity, '#6c757d')
        emoji = severity_emojis.get(event.severity, ':bell:')
        
        fields = [
            {
                "title": "Severity",
                "value": f"{emoji} *{event.severity.upper()}*",
                "short": True
            },
            {
                "title": "Event Type",
                "value": event.event_type.replace('_', ' ').title(),
                "short": True
            },
            {
                "title": "Source IP",
                "value": f"`{event.source_ip}`",
                "short": True
            },
            {
                "title": "Region",
                "value": event.region,
                "short": True
            },
            {
                "title": "Timestamp",
                "value": event.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC'),
                "short": False
            },
            {
                "title": "Resource",
                "value": f"`{event.resource}`",
                "short": False
            },
            {
                "title": "User Agent",
                "value": f"`{event.user_agent[:100]}...`" if len(event.user_agent) > 100 else f"`{event.user_agent}`",
                "short": False
            }
        ]
        
        for key, value in event.details.items():
            fields.append({
                "title": key.replace('_', ' ').title(),
                "value": str(value),
                "short": True
            })
        
        payload = {
            "attachments": [
                {
                    "color": color,
                    "title": f" Security Alert: {event.event_type.replace('_', ' ').title()}",
                    "fields": fields,
                    "footer": "Cloud Honey Tokens Attribution System",
                    "footer_icon": "https://platform.slack-edge.com/img/default_application_icon.png",
                    "ts": int(datetime.now().timestamp())
                }
            ]
        }
        
        return payload
    
    def send_alert(self, event: SecurityEvent) -> bool:
        """
        Send Slack alert for security event
        
        Args:
            event: Security event
            
        Returns:
            True if sent successfully
        """
        if not self.enabled:
            print(f"️  Slack not configured, skipping alert for {event.event_type}")
            return False
        
        try:
            payload = self.format_event_slack(event)
            
            response = requests.post(
                self.webhook_url,
                data=json.dumps(payload),
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                print(f" Slack alert sent for {event.event_type} (IP: {event.source_ip})")
                return True
            else:
                print(f" Failed to send Slack alert: {response.status_code}")
                return False
                
        except Exception as e:
            print(f" Error sending Slack alert: {e}")
            return False
    
    def send_batch_alert(self, events: List[SecurityEvent]) -> bool:
        """
        Send a batch alert for multiple events
        
        Args:
            events: List of security events
            
        Returns:
            True if sent successfully
        """
        if not self.enabled or not events:
            return False
        
        severity_counts = {}
        for event in events:
            severity_counts[event.severity] = severity_counts.get(event.severity, 0) + 1
        
        summary_text = f"*Security Alert Summary*\n"
        summary_text += f"Detected *{len(events)}* security events:\n"
        
        for severity in ['critical', 'high', 'medium', 'low']:
            if severity in severity_counts:
                count = severity_counts[severity]
                emoji = {
                    'critical': ':rotating_light:',
                    'high': ':warning:',
                    'medium': ':large_orange_diamond:',
                    'low': ':information_source:'
                }.get(severity, ':bell:')
                summary_text += f"{emoji} {severity.upper()}: {count}\n"
        
        attachments = []
        for event in events[:10]:
            severity_color = {
                'critical': 'danger',
                'high': 'warning',
                'medium': '#ffc107',
                'low': 'good'
            }.get(event.severity, '#6c757d')
            
            attachments.append({
                "color": severity_color,
                "title": event.event_type.replace('_', ' ').title(),
                "fields": [
                    {
                        "title": "IP",
                        "value": event.source_ip,
                        "short": True
                    },
                    {
                        "title": "Time",
                        "value": event.timestamp.strftime('%H:%M:%S'),
                        "short": True
                    }
                ]
            })
        
        if len(events) > 10:
            summary_text += f"\n_... and {len(events) - 10} more events_"
        
        payload = {
            "text": summary_text,
            "attachments": attachments
        }
        
        try:
            response = requests.post(
                self.webhook_url,
                data=json.dumps(payload),
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                print(f" Batch Slack alert sent ({len(events)} events)")
                return True
            else:
                print(f" Failed to send batch Slack alert: {response.status_code}")
                return False
                
        except Exception as e:
            print(f" Error sending batch Slack alert: {e}")
            return False


if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv()
    
    test_event = SecurityEvent(
        timestamp=datetime.now(),
        event_type="rapid_access",
        severity="medium",
        source_ip="10.0.0.50",
        user_agent="python-requests/2.28.0",
        resource="api_keys_production.txt",
        region="europe-west1",
        details={
            'access_count': 15,
            'time_window': 300,
            'requests_per_second': 0.05
        }
    )
    
    slack_system = SlackAlertSystem()
    slack_system.send_alert(test_event)

