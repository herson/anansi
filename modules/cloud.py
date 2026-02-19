import boto3
import logging
from botocore.exceptions import NoCredentialsError, ClientError

class CloudScanner:
    def __init__(self):
        self.s3 = boto3.client('s3')

    def scan_bucket(self, bucket_name):
        """
        Checks if an S3 bucket is publicly accessible.
        """
        results = {"bucket": bucket_name, "issues": []}
        
        try:
            # Check for public access block
            try:
                public_access_block = self.s3.get_public_access_block(Bucket=bucket_name)
                conf = public_access_block['PublicAccessBlockConfiguration']
                if not conf.get('BlockPublicAcls') or not conf.get('BlockPublicPolicy'):
                     results['issues'].append("Bucket might allow public ACLs or Policies")
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                    results['issues'].append("No Public Access Block configuration found (High Risk)")
                else:
                    logging.error(f"Error checking bucket {bucket_name}: {e}")

            # Check ACLs
            try:
                acl = self.s3.get_bucket_acl(Bucket=bucket_name)
                for grant in acl['Grants']:
                    grantee = grant.get('Grantee', {})
                    if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                        permission = grant.get('Permission')
                        results['issues'].append(f"Public Access Allowed: {permission}")
            except ClientError as e:
                 logging.error(f"Error checking ACLs for {bucket_name}: {e}")

        except NoCredentialsError:
            return {"error": "AWS Credentials not found"}
        except Exception as e:
            return {"error": str(e)}

        return results
