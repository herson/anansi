import unittest
from unittest.mock import patch, MagicMock
from botocore.exceptions import NoCredentialsError, ClientError


class TestCloudScanner(unittest.TestCase):

    def _make_scanner(self, mock_s3):
        with patch('boto3.client', return_value=mock_s3):
            from modules.cloud import CloudScanner
            return CloudScanner()

    def test_clean_bucket(self):
        mock_s3 = MagicMock()
        mock_s3.get_public_access_block.return_value = {
            'PublicAccessBlockConfiguration': {'BlockPublicAcls': True, 'BlockPublicPolicy': True}
        }
        mock_s3.get_bucket_acl.return_value = {'Grants': []}
        result = self._make_scanner(mock_s3).scan_bucket('my-bucket')
        self.assertEqual(result['issues'], [])

    def test_public_acl_flag_detected(self):
        mock_s3 = MagicMock()
        mock_s3.get_public_access_block.return_value = {
            'PublicAccessBlockConfiguration': {'BlockPublicAcls': False, 'BlockPublicPolicy': True}
        }
        mock_s3.get_bucket_acl.return_value = {'Grants': []}
        result = self._make_scanner(mock_s3).scan_bucket('my-bucket')
        self.assertIn("Bucket might allow public ACLs or Policies", result['issues'])

    def test_no_public_access_block_config(self):
        mock_s3 = MagicMock()
        err = {'Error': {'Code': 'NoSuchPublicAccessBlockConfiguration', 'Message': ''}}
        mock_s3.get_public_access_block.side_effect = ClientError(err, 'GetPublicAccessBlock')
        mock_s3.get_bucket_acl.return_value = {'Grants': []}
        result = self._make_scanner(mock_s3).scan_bucket('my-bucket')
        self.assertIn("No Public Access Block configuration found (High Risk)", result['issues'])

    def test_public_acl_grant(self):
        mock_s3 = MagicMock()
        mock_s3.get_public_access_block.return_value = {
            'PublicAccessBlockConfiguration': {'BlockPublicAcls': True, 'BlockPublicPolicy': True}
        }
        mock_s3.get_bucket_acl.return_value = {
            'Grants': [{
                'Grantee': {'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'},
                'Permission': 'READ',
            }]
        }
        result = self._make_scanner(mock_s3).scan_bucket('my-bucket')
        self.assertIn("Public Access Allowed: READ", result['issues'])

    def test_no_credentials_returns_error(self):
        mock_s3 = MagicMock()
        mock_s3.get_public_access_block.side_effect = NoCredentialsError()
        result = self._make_scanner(mock_s3).scan_bucket('my-bucket')
        self.assertIn('error', result)
        self.assertEqual(result['error'], 'AWS Credentials not found')


if __name__ == '__main__':
    unittest.main()
