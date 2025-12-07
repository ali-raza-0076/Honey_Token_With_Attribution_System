"""
Main entry point for Cloud Honey Tokens Attribution System
"""

import os
import sys
import argparse
from datetime import datetime
from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.generators.api_keys import APIKeyGenerator, DatabaseCredentialGenerator
from src.generators.ssh_keys import SSHKeyGenerator
from src.storage.s3_file_creator import S3FileCreator
from src.analysis.cloudwatch_analyzer import CloudWatchAnalyzer
from src.analysis.pattern_detector import PatternDetector
from src.alerts.email_alert import EmailAlertSystem
from src.alerts.slack_alert import SlackAlertSystem


def generate_tokens(region: str = None, bucket_name: str = None):
    """Generate and upload honey tokens"""
    print("=" * 60)
    print(" GENERATING HONEY TOKENS")
    print("=" * 60)
    
    print("\n Generating API keys...")
    api_keys = APIKeyGenerator.generate_all_api_keys()
    print(f" Generated {len(api_keys)} API keys")
    
    print("\n Generating database credentials...")
    db_creds = DatabaseCredentialGenerator.generate_all_db_credentials()
    print(f" Generated {len(db_creds)} database credential sets")
    
    print("\n Generating SSH keys...")
    ssh_keys = SSHKeyGenerator.generate_all_ssh_keys()
    print(f" Generated {len(ssh_keys)} SSH key pairs")
    
    bucket = bucket_name or os.getenv('S3_BUCKET_NAME')
    region = region or os.getenv('AWS_REGION', 'us-east-1')
    
    if not bucket:
        print("\n️  Bucket name not configured. Set S3_BUCKET_NAME in .env")
        print("Tokens generated but not uploaded.")
        return
    
    print(f"\n Uploading to S3 bucket: {bucket}")
    file_creator = S3FileCreator(bucket_name=bucket, region=region)
    
    try:
        uploaded = file_creator.create_all_honey_files(api_keys, db_creds, ssh_keys)
        print(f"\n Successfully created and uploaded {len(uploaded)} honey files")
        print(f" Region: {region}")
    except Exception as e:
        print(f"\n Error uploading files: {e}")


def analyze_logs(hours: int = 24, send_alerts: bool = True):
    """Analyze logs for security events"""
    print("=" * 60)
    print(" ANALYZING LOGS")
    print("=" * 60)
    
    region = os.getenv('AWS_REGION', 'us-east-1')
    
    analyzer = CloudWatchAnalyzer(region=region)
    events = analyzer.analyze_logs(hours=hours)
    
    all_events = []
    for event_type, event_list in events.items():
        all_events.extend(event_list)
    
    if not all_events:
        print("\n No security events detected")
        return
    
    print(f"\n Total events detected: {len(all_events)}")
    
    critical = sum(1 for e in all_events if e.severity == 'critical')
    high = sum(1 for e in all_events if e.severity == 'high')
    medium = sum(1 for e in all_events if e.severity == 'medium')
    low = sum(1 for e in all_events if e.severity == 'low')
    
    if critical:
        print(f"    CRITICAL: {critical}")
    if high:
        print(f"   🟠 HIGH: {high}")
    if medium:
        print(f"   🟡 MEDIUM: {medium}")
    if low:
        print(f"   🟢 LOW: {low}")
    
    if send_alerts:
        print("\n Sending alerts...")
        
        email_system = EmailAlertSystem()
        slack_system = SlackAlertSystem()
        
        immediate_alerts = [e for e in all_events if e.severity in ['critical', 'high']]
        for event in immediate_alerts:
            email_system.send_alert(event)
            slack_system.send_alert(event)
        
        if len(all_events) > 1:
            email_system.send_batch_alert(all_events)
            slack_system.send_batch_alert(all_events)


def run_continuous_monitoring(interval_minutes: int = 5):
    """Run continuous log monitoring"""
    import time
    
    print("=" * 60)
    print(" CONTINUOUS MONITORING MODE")
    print("=" * 60)
    print(f"Checking every {interval_minutes} minutes...")
    print("Press Ctrl+C to stop\n")
    
    try:
        while True:
            analyze_logs(hours=1, send_alerts=True)
            print(f"\n Sleeping for {interval_minutes} minutes...")
            time.sleep(interval_minutes * 60)
    except KeyboardInterrupt:
        print("\n\n Monitoring stopped")


def show_stats():
    """Show system statistics"""
    print("=" * 60)
    print(" SYSTEM STATISTICS")
    print("=" * 60)
    
    region = os.getenv('AWS_REGION', 'us-east-1'); analyzer = CloudWatchAnalyzer(region=region)
    
    periods = [
        ('Last Hour', 1),
        ('Last 24 Hours', 24),
        ('Last Week', 168),
    ]
    
    for period_name, hours in periods:
        print(f"\n{period_name}:")
        events = analyzer.analyze_logs(hours=hours)
        total = sum(len(e) for e in events.values())
        print(f"  Total Events: {total}")
        for event_type, event_list in events.items():
            if event_list:
                print(f"  - {event_type}: {len(event_list)}")


def main():
    """Main CLI entry point"""
    load_dotenv()
    
    parser = argparse.ArgumentParser(
        description='Cloud Honey Tokens Attribution System',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python src/main.py generate-tokens --region us-central1
  python src/main.py analyze-logs --hours 24
  python src/main.py monitor --interval 5
  python src/main.py stats
        '''
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    gen_parser = subparsers.add_parser('generate-tokens', help='Generate honey tokens')
    gen_parser.add_argument('--region', type=str, help='GCP region')
    gen_parser.add_argument('--bucket', type=str, help='GCS bucket name')
    
    analyze_parser = subparsers.add_parser('analyze-logs', help='Analyze logs for threats')
    analyze_parser.add_argument('--hours', type=int, default=24, help='Hours to analyze (default: 24)')
    analyze_parser.add_argument('--no-alerts', action='store_true', help='Don\'t send alerts')
    
    monitor_parser = subparsers.add_parser('monitor', help='Continuous monitoring mode')
    monitor_parser.add_argument('--interval', type=int, default=5, help='Check interval in minutes (default: 5)')
    
    subparsers.add_parser('stats', help='Show system statistics')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    if args.command == 'generate-tokens':
        generate_tokens(region=args.region, bucket_name=args.bucket)
    
    elif args.command == 'analyze-logs':
        analyze_logs(hours=args.hours, send_alerts=not args.no_alerts)
    
    elif args.command == 'monitor':
        run_continuous_monitoring(interval_minutes=args.interval)
    
    elif args.command == 'stats':
        show_stats()


if __name__ == "__main__":
    main()

