"""
Deploy AWS Lambda Function - Automatic Detection Setup
Uses boto3 to deploy Lambda directly without AWS CLI
"""

import boto3
import os
import json
import zipfile
from dotenv import load_dotenv

load_dotenv()

def create_lambda_package():
    """Create Lambda deployment ZIP"""
    print("\n Creating Lambda deployment package...")
    
    zip_path = 'lambda_deployment.zip'
    
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        zipf.write('lambda_function.py')
        print(f"   Added lambda_function.py")
    
    file_size = os.path.getsize(zip_path)
    print(f"   Package size: {file_size / 1024:.1f} KB")
    
    return zip_path

def deploy_lambda():
    """Deploy Lambda function"""
    print("\n Deploying Lambda function...")
    
    region = os.getenv('AWS_REGION', 'us-east-1')
    account_id = os.getenv('AWS_ACCOUNT_ID')
    
    lambda_client = boto3.client('lambda', region_name=region)
    
    function_name = 'HoneyTokenLogMonitor'
    role_arn = f'arn:aws:iam::{account_id}:role/HoneyTokenLambdaRole'
    
    zip_path = create_lambda_package()
    with open(zip_path, 'rb') as f:
        zip_content = f.read()
    
    try:
        response = lambda_client.create_function(
            FunctionName=function_name,
            Runtime='python3.11',
            Role=role_arn,
            Handler='lambda_function.lambda_handler',
            Code={'ZipFile': zip_content},
            Description='Automatically detects honey token access patterns every 5 minutes',
            Timeout=60,
            MemorySize=256,
            Environment={
                'Variables': {
                    'HONEY_REGION': region,
                    'S3_BUCKET_NAME': os.getenv('S3_BUCKET_NAME'),
                    'DYNAMODB_TABLE_NAME': os.getenv('DYNAMODB_TABLE_NAME')
                }
            }
        )
        
        function_arn = response['FunctionArn']
        print(f"   Lambda created: {function_arn}")
        return function_arn
        
    except lambda_client.exceptions.ResourceConflictException:
        print(f"   Function exists, updating...")
        
        lambda_client.update_function_code(
            FunctionName=function_name,
            ZipFile=zip_content
        )
        
        response = lambda_client.update_function_configuration(
            FunctionName=function_name,
            Environment={
                'Variables': {
                    'HONEY_REGION': region,
                    'S3_BUCKET_NAME': os.getenv('S3_BUCKET_NAME'),
                    'DYNAMODB_TABLE_NAME': os.getenv('DYNAMODB_TABLE_NAME')
                }
            },
            Timeout=60,
            MemorySize=256
        )
        
        function_arn = response['FunctionArn']
        print(f"   Lambda updated: {function_arn}")
        return function_arn

def create_eventbridge_rule():
    """Create EventBridge rule for automatic triggers"""
    print("\n Setting up EventBridge scheduler...")
    
    region = os.getenv('AWS_REGION', 'us-east-1')
    account_id = os.getenv('AWS_ACCOUNT_ID')
    
    events_client = boto3.client('events', region_name=region)
    lambda_client = boto3.client('lambda', region_name=region)
    
    rule_name = 'HoneyTokenLogAnalysis'
    function_name = 'HoneyTokenLogMonitor'
    
    response = events_client.put_rule(
        Name=rule_name,
        ScheduleExpression='rate(5 minutes)',
        State='ENABLED',
        Description='Triggers honey token log analysis every 5 minutes'
    )
    
    rule_arn = response['RuleArn']
    print(f"   EventBridge rule: {rule_arn}")
    print(f"     Schedule: Every 5 minutes")
    
    try:
        lambda_client.add_permission(
            FunctionName=function_name,
            StatementId='AllowEventBridgeInvoke',
            Action='lambda:InvokeFunction',
            Principal='events.amazonaws.com',
            SourceArn=rule_arn
        )
        print(f"   Lambda permission granted")
    except lambda_client.exceptions.ResourceConflictException:
        print(f"  ℹ️  Permission already exists")
    
    function_arn = f'arn:aws:lambda:{region}:{account_id}:function:{function_name}'
    
    events_client.put_targets(
        Rule=rule_name,
        Targets=[
            {
                'Id': '1',
                'Arn': function_arn
            }
        ]
    )
    
    print(f"   Lambda added as target")
    
    return rule_arn

def test_lambda():
    """Test Lambda function"""
    print("\n Testing Lambda function...")
    
    region = os.getenv('AWS_REGION', 'us-east-1')
    lambda_client = boto3.client('lambda', region_name=region)
    
    response = lambda_client.invoke(
        FunctionName='HoneyTokenLogMonitor',
        InvocationType='RequestResponse',
        Payload=json.dumps({})
    )
    
    result = json.loads(response['Payload'].read())
    print(f"  Status Code: {response['StatusCode']}")
    print(f"  Result: {json.dumps(result, indent=2)}")
    
    return response['StatusCode'] == 200

def main():
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║       AWS Lambda Auto-Detection Deployment              ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    
    This will deploy TRUE AWS-native automatic detection!
    
    After this completes:
     Lambda runs every 5 minutes automatically
     Analyzes S3 access logs for attacks
     Stores events in DynamoDB
     Dashboard shows them automatically
    
    NO MANUAL SCRIPTS NEEDED!
    """)
    
    try:
        function_arn = deploy_lambda()
        
        rule_arn = create_eventbridge_rule()
        
        if test_lambda():
            print("\n" + "="*70)
            print(" DEPLOYMENT SUCCESSFUL!")
            print("="*70)
            print(f"""
     AWS-Native Automatic Detection is NOW ACTIVE!
    
     What was deployed:
       • Lambda Function: HoneyTokenLogMonitor
       • EventBridge Rule: HoneyTokenLogAnalysis
       • Schedule: Every 5 minutes
       • Status: ENABLED
    
     How it works:
       1. EventBridge triggers Lambda every 5 minutes
       2. Lambda analyzes S3 access logs
       3. Detects attack patterns automatically
       4. Stores events in DynamoDB
       5. Dashboard shows them (auto-refresh every 60s)
    
     Test it:
       1. Run: python scripts/live_attack_demo.py
       2. Wait 5 minutes for next Lambda execution
       3. Check dashboard: http://localhost:8050
    
     Monitor Lambda:
       - CloudWatch Logs: /aws/lambda/HoneyTokenLogMonitor
       - Next execution: Within 5 minutes
    
     YOU'RE DONE! AWS now detects attacks automatically!
            """)
        else:
            print("\n️  Lambda test failed, check CloudWatch logs")
        
    except Exception as e:
        print(f"\n Deployment failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()

