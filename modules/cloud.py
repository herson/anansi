from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

PUBLIC_ACCESS_BLOCK_FLAGS = ('BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets')
PUBLIC_GRANTEES = {
    'http://acs.amazonaws.com/groups/global/AllUsers': 'everyone (AllUsers)',
    'http://acs.amazonaws.com/groups/global/AuthenticatedUsers': 'any AWS account (AuthenticatedUsers)',
}


@dataclass
class BucketReport:
    """Issues found on the bucket, and the checks that could not run.

    A bucket is only clean when every check ran and found nothing.
    """
    bucket: str
    issues: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not self.issues and not self.errors


class CloudScanner:
    def __init__(self) -> None:
        self.s3: Any = boto3.client('s3')

    def scan_bucket(self, bucket_name: str) -> BucketReport:
        """Check whether an S3 bucket is, or could be made, publicly accessible."""
        report = BucketReport(bucket_name)
        checks: list[tuple[str, Callable[[str], list[str]]]] = [
            ('the public access block', self._check_public_access_block),
            ('the bucket ACL', self._check_acl),
            ('the bucket policy', self._check_policy_status),
        ]
        for name, check in checks:
            try:
                report.issues.extend(check(bucket_name))
            except NoCredentialsError:
                report.errors.append('AWS credentials not found')
                break
            except ClientError as e:
                report.errors.append(f"Could not check {name}: {e.response['Error']['Code']}")
            except BotoCoreError as e:
                report.errors.append(f"Could not check {name}: {type(e).__name__}: {e}")
        return report

    def _check_public_access_block(self, bucket: str) -> list[str]:
        try:
            conf = self.s3.get_public_access_block(Bucket=bucket)['PublicAccessBlockConfiguration']
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                return ['No public access block is configured on the bucket']
            raise
        disabled = [flag for flag in PUBLIC_ACCESS_BLOCK_FLAGS if not conf.get(flag)]
        return [f"Public access block does not enable: {', '.join(disabled)}"] if disabled else []

    def _check_acl(self, bucket: str) -> list[str]:
        issues = []
        for grant in self.s3.get_bucket_acl(Bucket=bucket)['Grants']:
            who = PUBLIC_GRANTEES.get(grant.get('Grantee', {}).get('URI', ''))
            if who:
                issues.append(f"ACL grants {grant.get('Permission')} to {who}")
        return issues

    def _check_policy_status(self, bucket: str) -> list[str]:
        try:
            status = self.s3.get_bucket_policy_status(Bucket=bucket)['PolicyStatus']
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                return []
            raise
        return ['Bucket policy makes the bucket public'] if status.get('IsPublic') else []
