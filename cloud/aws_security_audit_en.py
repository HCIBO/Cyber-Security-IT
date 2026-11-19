import boto3
import subprocess
import json

def run_aws_command(command, no_sign=False, description=""):
    if no_sign:
        command.append("--no-sign-request")
    print(f"[+] Executing: {' '.join(command)}")
    print(f"Description: {description}")
    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout if result.returncode == 0 else f"[!] Error: {result.stderr}"

def check_iam():
    print("\nPerforming IAM Checks...")
    print(run_aws_command(["aws", "iam", "list-users"], description="Lists all IAM users in the AWS account."))
    print(run_aws_command(["aws", "iam", "list-roles"], description="Lists all IAM roles available in the AWS account."))
    print(run_aws_command(["aws", "iam", "list-policies"], description="Lists all IAM policies applied in the account."))
    print(run_aws_command(["aws", "iam", "list-mfa-devices"], description="Checks if Multi-Factor Authentication (MFA) is enabled for IAM users."))
    print(run_aws_command(["aws", "iam", "get-account-summary"], description="Provides an overview of IAM resource limits and usage."))
    print(run_aws_command(["aws", "iam", "list-account-aliases"], description="Lists the alias associated with the AWS account."))

def check_s3():
    print("\nPerforming S3 Checks...")
    print(run_aws_command(["aws", "s3api", "list-buckets"], description="Lists all S3 buckets in the AWS account."))
    print(run_aws_command(["aws", "s3api", "get-public-access-block", "--bucket", "example-bucket"], description="Checks if public access is blocked for a given S3 bucket."))
    print(run_aws_command(["aws", "s3api", "get-bucket-encryption", "--bucket", "example-bucket"], description="Verifies if encryption is enabled for an S3 bucket."))
    print(run_aws_command(["aws", "s3api", "get-bucket-lifecycle-configuration", "--bucket", "example-bucket"], description="Checks if lifecycle policies are configured for an S3 bucket."))
    print(run_aws_command(["aws", "s3api", "get-bucket-policy-status", "--bucket", "example-bucket"], description="Determines if a bucket policy is making the bucket publicly accessible."))

def check_cloudtrail():
    print("\nPerforming CloudTrail Log Checks...")
    print(run_aws_command(["aws", "cloudtrail", "describe-trails"], description="Lists all CloudTrail trails configured in the AWS account."))
    print(run_aws_command(["aws", "cloudtrail", "get-trail-status", "--name", "Default"], description="Checks the logging status of a specific CloudTrail trail."))

def check_guardduty():
    print("\nPerforming AWS GuardDuty Checks...")
    print(run_aws_command(["aws", "guardduty", "list-detectors"], description="Checks if AWS GuardDuty is enabled and active for threat detection."))

def check_securityhub():
    print("\nPerforming AWS Security Hub Checks...")
    print(run_aws_command(["aws", "securityhub", "get-findings"], description="Lists all security findings detected by AWS Security Hub."))

def check_rds():
    print("\nPerforming RDS Checks...")
    print(run_aws_command(["aws", "rds", "describe-db-instances"], description="Lists all RDS database instances in the AWS account."))
    print(run_aws_command(["aws", "rds", "describe-db-snapshots"], description="Lists all RDS snapshots and their encryption status."))
    print(run_aws_command(["aws", "rds", "describe-db-clusters"], description="Lists all RDS clusters and their security settings."))

def check_ec2():
    print("\nPerforming EC2 Checks...")
    print(run_aws_command(["aws", "ec2", "describe-instances"], description="Lists all running EC2 instances along with their security groups."))
    print(run_aws_command(["aws", "ec2", "describe-security-groups"], description="Lists all security groups and their associated rules."))

def check_cloudfront():
    print("\nPerforming CloudFront Checks...")
    print(run_aws_command(["aws", "cloudfront", "list-distributions"], description="Lists all CloudFront distributions and their security settings."))

def check_route53():
    print("\nPerforming Route 53 Checks...")
    print(run_aws_command(["aws", "route53", "list-hosted-zones"], description="Lists all hosted zones in Route 53 and their configurations."))

def check_dynamodb():
    print("\nPerforming DynamoDB Checks...")
    print(run_aws_command(["aws", "dynamodb", "list-tables"], description="Lists all DynamoDB tables in the AWS account."))

def check_elasticsearch():
    print("\nPerforming ElasticSearch Checks...")
    print(run_aws_command(["aws", "es", "list-domain-names"], description="Lists all ElasticSearch domains and their configurations."))

def check_elb():
    print("\nPerforming ELB Checks...")
    print(run_aws_command(["aws", "elbv2", "describe-load-balancers"], description="Lists all ELB load balancers and their security settings."))

def main():
    print("Starting AWS Security Audit...")
    check_iam()
    check_s3()
    check_cloudtrail()
    check_guardduty()
    check_securityhub()
    check_rds()
    check_ec2()
    check_cloudfront()
    check_route53()
    check_dynamodb()
    check_elasticsearch()
    check_elb()
    print("Audit Completed!")

if __name__ == "__main__":
    main()
