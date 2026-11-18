import unittest
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError, EndpointConnectionError, NoCredentialsError

from modules.cloud import CloudScanner

ALL_BLOCKED = {
    'BlockPublicAcls': True, 'IgnorePublicAcls': True,
    'BlockPublicPolicy': True, 'RestrictPublicBuckets': True,
}
ALL_USERS = 'http://acs.amazonaws.com/groups/global/AllUsers'
AUTHENTICATED_USERS = 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'


def _client_error(code, operation):
    return ClientError({'Error': {'Code': code, 'Message': ''}}, operation)


def _locked_down_s3():
    s3 = MagicMock()
    s3.get_public_access_block.return_value = {'PublicAccessBlockConfiguration': dict(ALL_BLOCKED)}
    s3.get_bucket_acl.return_value = {'Grants': []}
    s3.get_bucket_policy_status.return_value = {'PolicyStatus': {'IsPublic': False}}
    return s3


class TestCloudScanner(unittest.TestCase):

    def _scan(self, s3):
        with patch('modules.cloud.boto3.client', return_value=s3):
            return CloudScanner().scan_bucket('my-bucket')

    def test_locked_down_bucket_is_clean(self):
        report = self._scan(_locked_down_s3())
        self.assertEqual(report.issues, [])
        self.assertEqual(report.errors, [])
        self.assertTrue(report.clean)

    def test_each_disabled_public_access_block_flag_is_reported(self):
        s3 = _locked_down_s3()
        s3.get_public_access_block.return_value = {'PublicAccessBlockConfiguration': {
            **ALL_BLOCKED, 'IgnorePublicAcls': False, 'RestrictPublicBuckets': False,
        }}
        report = self._scan(s3)
        self.assertEqual(report.issues, [
            'Public access block does not enable: IgnorePublicAcls, RestrictPublicBuckets',
        ])
        self.assertFalse(report.clean)

    def test_missing_public_access_block_is_reported(self):
        s3 = _locked_down_s3()
        s3.get_public_access_block.side_effect = _client_error(
            'NoSuchPublicAccessBlockConfiguration', 'GetPublicAccessBlock')
        self.assertEqual(self._scan(s3).issues, ['No public access block is configured on the bucket'])

    def test_acl_grant_to_everyone_is_reported(self):
        s3 = _locked_down_s3()
        s3.get_bucket_acl.return_value = {'Grants': [{'Grantee': {'URI': ALL_USERS}, 'Permission': 'READ'}]}
        self.assertEqual(self._scan(s3).issues, ['ACL grants READ to everyone (AllUsers)'])

    def test_acl_grant_to_any_aws_account_is_reported(self):
        s3 = _locked_down_s3()
        s3.get_bucket_acl.return_value = {
            'Grants': [{'Grantee': {'URI': AUTHENTICATED_USERS}, 'Permission': 'WRITE'}]}
        self.assertEqual(self._scan(s3).issues, ['ACL grants WRITE to any AWS account (AuthenticatedUsers)'])

    def test_public_bucket_policy_is_reported(self):
        s3 = _locked_down_s3()
        s3.get_bucket_policy_status.return_value = {'PolicyStatus': {'IsPublic': True}}
        self.assertEqual(self._scan(s3).issues, ['Bucket policy makes the bucket public'])

    def test_bucket_without_a_policy_is_not_an_error(self):
        s3 = _locked_down_s3()
        s3.get_bucket_policy_status.side_effect = _client_error('NoSuchBucketPolicy', 'GetBucketPolicyStatus')
        self.assertTrue(self._scan(s3).clean)

    def test_a_check_that_fails_is_an_error_not_a_clean_result(self):
        s3 = _locked_down_s3()
        s3.get_bucket_acl.side_effect = _client_error('AccessDenied', 'GetBucketAcl')
        report = self._scan(s3)
        self.assertEqual(report.issues, [])
        self.assertEqual(report.errors, ['Could not check the bucket ACL: AccessDenied'])
        self.assertFalse(report.clean)

    def test_other_checks_still_run_after_one_fails(self):
        s3 = _locked_down_s3()
        s3.get_public_access_block.side_effect = _client_error('AccessDenied', 'GetPublicAccessBlock')
        s3.get_bucket_policy_status.return_value = {'PolicyStatus': {'IsPublic': True}}
        report = self._scan(s3)
        self.assertEqual(report.errors, ['Could not check the public access block: AccessDenied'])
        self.assertEqual(report.issues, ['Bucket policy makes the bucket public'])

    def test_network_failure_is_an_error(self):
        s3 = _locked_down_s3()
        s3.get_bucket_policy_status.side_effect = EndpointConnectionError(endpoint_url='https://s3')
        report = self._scan(s3)
        self.assertEqual(len(report.errors), 1)
        self.assertTrue(report.errors[0].startswith('Could not check the bucket policy: EndpointConnectionError'))

    def test_missing_credentials_is_reported_once_and_stops_the_scan(self):
        s3 = _locked_down_s3()
        s3.get_public_access_block.side_effect = NoCredentialsError()
        report = self._scan(s3)
        self.assertEqual(report.errors, ['AWS credentials not found'])
        s3.get_bucket_acl.assert_not_called()
        self.assertFalse(report.clean)


if __name__ == '__main__':
    unittest.main()
