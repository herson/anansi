"""The S3 scan's mocked tests can't see IAM: check the README grants every call it makes."""
import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# boto3 method -> IAM action it needs (they differ: get_public_access_block is
# authorised by s3:GetBucketPublicAccessBlock).
IAM_ACTIONS = {
    'get_public_access_block': 's3:GetBucketPublicAccessBlock',
    'get_bucket_acl': 's3:GetBucketAcl',
    'get_bucket_policy_status': 's3:GetBucketPolicyStatus',
}


def _s3_calls():
    tree = ast.parse((ROOT / 'modules' / 'cloud.py').read_text())
    return {
        node.func.attr for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Attribute) and node.func.value.attr == 's3'
    }


class TestS3PermissionsAreDocumented(unittest.TestCase):

    def test_every_s3_call_has_a_known_iam_action(self):
        self.assertEqual(_s3_calls() - IAM_ACTIONS.keys(), set(), 'add the IAM action for this call')

    def test_readme_lists_the_iam_action_of_every_s3_call(self):
        readme = (ROOT / 'README.md').read_text()
        missing = {IAM_ACTIONS[c] for c in _s3_calls() & IAM_ACTIONS.keys() if IAM_ACTIONS[c] not in readme}
        self.assertEqual(missing, set())


if __name__ == '__main__':
    unittest.main()
