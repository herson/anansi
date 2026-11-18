import unittest

from web.sessions import SessionStore


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class TestSessionStore(unittest.TestCase):

    def setUp(self):
        self.clock = FakeClock()
        self.store = SessionStore(ttl_seconds=60, clock=self.clock)

    def test_new_session_is_valid(self):
        token = self.store.create()
        self.assertTrue(self.store.is_valid(token))

    def test_tokens_are_unique_and_unguessable(self):
        tokens = {self.store.create() for _ in range(50)}
        self.assertEqual(len(tokens), 50)
        self.assertTrue(all(len(t) >= 43 for t in tokens))

    def test_unknown_token_is_rejected(self):
        self.assertFalse(self.store.is_valid("made-up-token"))

    def test_missing_token_is_rejected(self):
        self.assertFalse(self.store.is_valid(None))
        self.assertFalse(self.store.is_valid(""))

    def test_session_expires_after_ttl(self):
        token = self.store.create()
        self.clock.now += 59
        self.assertTrue(self.store.is_valid(token))
        self.clock.now += 1
        self.assertFalse(self.store.is_valid(token))

    def test_revoked_session_is_rejected(self):
        token = self.store.create()
        self.store.revoke(token)
        self.assertFalse(self.store.is_valid(token))

    def test_revoking_unknown_token_is_harmless(self):
        self.store.revoke("never-issued")
        self.store.revoke(None)

    def test_expired_sessions_are_purged_when_new_ones_are_created(self):
        self.store.create()
        self.clock.now += 61
        self.store.create()
        self.assertEqual(len(self.store), 1)


if __name__ == "__main__":
    unittest.main()
