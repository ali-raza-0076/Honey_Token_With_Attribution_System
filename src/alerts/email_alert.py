"""
Email Alert System
Sends security alerts via email using SendGrid
"""

import os
from typing import List
from datetime import datetime
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Email, To, Content
from src.analysis import SecurityEvent


class EmailAlertSystem:
    """Send email alerts for security events"""
    
    def __init__(self, api_key: str = None, from_email: str = None, to_email: str = None):
        """
        Initialize Email Alert System
        
        Args:
            api_key: SendGrid API key
            from_email: Sender email address
            to_email: Recipient email address
        """
        self.api_key = api_key or os.getenv('SENDGRID_API_KEY')
        self.from_email = from_email or os.getenv('ALERT_EMAIL', 'security@company.com')
        self.to_email = to_email or os.getenv('ALERT_EMAIL')
        
        if not self.api_key:
            print("️  SendGrid API key not configured")
            self.enabled = False
        else:
            self.sg = SendGridAPIClient(self.api_key)
            self.enabled = True
    
    def format_event_html(self, event: SecurityEvent) -> str:
        """
        Format security event as HTML
        
        Args:
            event: Security event
            
        Returns:
            HTML string
        """
        severity_colors = {
            'critical': '#dc3545',
            'high': '#ff9800',
            'medium': '#ffc107',
            'low': '#28a745'
        }
        
        color = severity_colors.get(event.severity, '#6c757d')
        
        html = f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background-color: {color}; color: white; padding: 20px; border-radius: 5px 5px 0 0;">
                <h2 style="margin: 0;"> Security Alert: {event.event_type.replace('_', ' ').title()}</h2>
            </div>
            <div style="border: 1px solid
                <table style="width: 100%; border-collapse: collapse;">
                    <tr>
                        <td style="padding: 10px; font-weight: bold; width: 150px;">Severity:</td>
                        <td style="padding: 10px; color: {color}; font-weight: bold; text-transform: uppercase;">
                            {event.severity}
                        </td>
                    </tr>
                    <tr style="background-color:
                        <td style="padding: 10px; font-weight: bold;">Timestamp:</td>
                        <td style="padding: 10px;">{event.timestamp}</td>
                    </tr>
                    <tr>
                        <td style="padding: 10px; font-weight: bold;">Source IP:</td>
                        <td style="padding: 10px; font-family: monospace;">{event.source_ip}</td>
                    </tr>
                    <tr style="background-color:
                        <td style="padding: 10px; font-weight: bold;">User Agent:</td>
                        <td style="padding: 10px; font-size: 12px;">{event.user_agent}</td>
                    </tr>
                    <tr>
                        <td style="padding: 10px; font-weight: bold;">Resource:</td>
                        <td style="padding: 10px; font-family: monospace; font-size: 12px;">{event.resource}</td>
                    </tr>
                    <tr style="background-color:
                        <td style="padding: 10px; font-weight: bold;">Region:</td>
                        <td style="padding: 10px;">{event.region}</td>
                    </tr>
                </table>
                
                <h3 style="margin-top: 20px; color:
                <div style="background-color:
        """
        
        for key, value in event.details.items():
            html += f"<div><strong>{key.replace('_', ' ').title()}:</strong> {value}</div>"
        
        html += """
                </div>
                
                <div style="margin-top: 20px; padding: 15px; background-color:
                    <strong>️ Recommended Actions:</strong>
                    <ul style="margin: 10px 0 0 0; padding-left: 20px;">
                        <li>Review the source IP and block if necessary</li>
                        <li>Check for additional activity from this source</li>
                        <li>Verify no real credentials were exposed</li>
                        <li>Update honey token rotation schedule if needed</li>
                    </ul>
                </div>
                
                <p style="margin-top: 20px; color:
                    This is an automated alert from the Cloud Honey Tokens Attribution System.
                    <br>
                    Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
                </p>
            </div>
        </div>
        """
        
        return html
    
    def send_alert(self, event: SecurityEvent) -> bool:
        """
        Send email alert for security event
        
        Args:
            event: Security event
            
        Returns:
            True if sent successfully
        """
        if not self.enabled:
            print(f"️  Email not configured, skipping alert for {event.event_type}")
            return False
        
        try:
            subject = f" [{event.severity.upper()}] Security Alert: {event.event_type.replace('_', ' ').title()}"
            
            message = Mail(
                from_email=self.from_email,
                to_emails=self.to_email,
                subject=subject,
                html_content=self.format_event_html(event)
            )
            
            response = self.sg.send(message)
            
            if response.status_code == 202:
                print(f" Email alert sent for {event.event_type} (IP: {event.source_ip})")
                return True
            else:
                print(f" Failed to send email: {response.status_code}")
                return False
                
        except Exception as e:
            print(f" Error sending email alert: {e}")
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
        
        by_severity = {}
        for event in events:
            if event.severity not in by_severity:
                by_severity[event.severity] = []
            by_severity[event.severity].append(event)
        
        summary_html = f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background-color:
                <h2 style="margin: 0;"> Security Alert Summary</h2>
                <p style="margin: 10px 0 0 0;">Detected {len(events)} security events</p>
            </div>
            <div style="border: 1px solid
                <h3>Events by Severity</h3>
        """
        
        for severity in ['critical', 'high', 'medium', 'low']:
            if severity in by_severity:
                count = len(by_severity[severity])
                summary_html += f"<p><strong>{severity.upper()}:</strong> {count} events</p>"
        
        summary_html += "<hr><h3>Event Details</h3>"
        
        for event in events[:10]:
            summary_html += f"""
            <div style="border-left: 3px solid
                <strong>{event.event_type.replace('_', ' ').title()}</strong><br>
                <small>IP: {event.source_ip} | Time: {event.timestamp}</small>
            </div>
            """
        
        if len(events) > 10:
            summary_html += f"<p><em>... and {len(events) - 10} more events</em></p>"
        
        summary_html += f"""
                <p style="margin-top: 20px; color:
                    Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
                </p>
            </div>
        </div>
        """
        
        try:
            message = Mail(
                from_email=self.from_email,
                to_emails=self.to_email,
                subject=f" Security Alert Summary: {len(events)} Events Detected",
                html_content=summary_html
            )
            
            response = self.sg.send(message)
            
            if response.status_code == 202:
                print(f" Batch email alert sent ({len(events)} events)")
                return True
            else:
                print(f" Failed to send batch email: {response.status_code}")
                return False
                
        except Exception as e:
            print(f" Error sending batch email alert: {e}")
            return False


if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv()
    
    test_event = SecurityEvent(
        timestamp=datetime.now(),
        event_type="bulk_download",
        severity="high",
        source_ip="192.168.1.100",
        user_agent="curl/7.68.0",
        resource="2025_financials_Q3.csv",
        region="us-central1",
        details={
            'download_count': 1500,
            'unique_resources': 25,
            'time_span': 300
        }
    )
    
    alert_system = EmailAlertSystem()
    alert_system.send_alert(test_event)

