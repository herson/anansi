import unittest
from itertools import count

import requests

from domain.findings import PathFinding
from modules.dir_scan import (DEFAULT_RATE, DEFAULT_WORDLIST, MAX_BODY_BYTES, MAX_RATE,
                              MAX_RETRY_AFTER, USER_AGENT, DirectoryScanner)

BASE = 'http://10.0.0.1/'


class FakeResponse:
    def __init__(self, status=404, body=b'', headers=None):
        self.status_code = status
        self.headers = headers or {}
        self._body = body
        self.read = 0
        self.closed = False

    def iter_content(self, chunk_size):
        for start in range(0, len(self._body), chunk_size):
            chunk = self._body[start:start + chunk_size]
            self.read += len(chunk)
            yield chunk

    def close(self):
        self.closed = True


class FakeSession:
    """Answers by path; a list answers successive requests for that path in turn."""

    def __init__(self, routes=None, default=None):
        self.routes = routes or {}
        self.default = default or (lambda: FakeResponse(404, b'Not Found'))
        self.headers = {}
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        path = url[len(BASE):]
        answer = self.routes.get(path, self.default)
        if isinstance(answer, list):
            answer = answer.pop(0)
        if callable(answer):
            answer = answer()
        if isinstance(answer, Exception):
            raise answer
        return answer


def _scanner(session, wordlist, **kwargs):
    names = (f'random{i}' for i in count())
    return DirectoryScanner(BASE, wordlist, session=session, sleep=kwargs.pop('sleep', lambda s: None),
                            random_path=lambda: next(names), **kwargs)


class TestFindsPaths(unittest.TestCase):

    def test_reports_paths_that_answer_differently_from_a_missing_page(self):
        session = FakeSession({'admin/': FakeResponse(200, b'<h1>Admin</h1>')})
        report = _scanner(session, ['admin/', 'nothing']).scan()
        self.assertEqual(report.found, [PathFinding(f'{BASE}admin/', 200, 14)])
        self.assertEqual(report.errors, [])

    def test_a_404_is_never_reported(self):
        session = FakeSession(default=lambda: FakeResponse(200, b'home page'),
                              routes={'gone': FakeResponse(404, b'x' * 500)})
        self.assertEqual(_scanner(session, ['gone']).scan().found, [])

    def test_ignores_pages_that_look_like_the_servers_answer_for_any_path(self):
        soft_404 = lambda: FakeResponse(200, b'Sorry, page not found' + b' ' * 300)  # noqa: E731
        session = FakeSession(default=soft_404,
                              routes={'nearly-the-same': FakeResponse(200, b'Sorry, page not found' + b' ' * 302),
                                      'real': FakeResponse(200, b'r' * 2000)})
        report = _scanner(session, ['nearly-the-same', 'real']).scan()
        self.assertEqual([f.url for f in report.found], [f'{BASE}real'])

    def test_a_different_status_counts_as_found_even_with_the_same_length(self):
        session = FakeSession(default=lambda: FakeResponse(200, b'x' * 100),
                              routes={'private/': FakeResponse(403, b'x' * 100)})
        self.assertEqual([f.status for f in _scanner(session, ['private/']).scan().found], [403])

    def test_redirects_are_reported_with_their_location_and_not_followed(self):
        session = FakeSession({'old': FakeResponse(301, b'', {'Location': 'https://elsewhere.example/'})})
        report = _scanner(session, ['old']).scan()
        self.assertEqual(report.found, [PathFinding(f'{BASE}old', 301, 0, 'https://elsewhere.example/')])
        for url, kwargs in session.calls:
            with self.subTest(url=url):
                self.assertIs(kwargs['allow_redirects'], False)
                self.assertTrue(url.startswith(BASE))

    def test_the_built_in_wordlist_is_used_by_default(self):
        session = FakeSession()
        DirectoryScanner(BASE, session=session, sleep=lambda s: None).scan()
        requested = {url[len(BASE):] for url, _ in session.calls}
        self.assertTrue(set(DEFAULT_WORDLIST) <= requested)
        self.assertGreaterEqual(len(DEFAULT_WORDLIST), 50)

    def test_paths_are_appended_to_the_url_given(self):
        session = FakeSession()
        DirectoryScanner('http://10.0.0.1/app', ['/login'], session=session, sleep=lambda s: None,
                         random_path=lambda: 'r').scan()
        self.assertEqual(session.calls[-1][0], 'http://10.0.0.1/app/login')


class TestStaysInScope(unittest.TestCase):

    def test_entries_that_climb_above_the_url_are_skipped(self):
        session = FakeSession()
        _scanner(session, ['../etc/passwd', 'a/../../b', '..', 'ok']).scan()
        requested = [url for url, _ in session.calls]
        self.assertIn(f'{BASE}ok', requested)
        self.assertFalse(any('..' in url for url in requested), requested)

    def test_blank_entries_and_comments_are_skipped(self):
        session = FakeSession()
        _scanner(session, ['', '   ', '# comment', 'ok']).scan()
        paths = [url[len(BASE):] for url, _ in session.calls]
        self.assertEqual(paths, ['random0', 'random1', 'ok'])


class TestIsGentleWithTheTarget(unittest.TestCase):

    def test_waits_between_requests_at_the_configured_rate(self):
        waits = []
        _scanner(FakeSession(), ['a', 'b', 'c'], rate=4, sleep=waits.append).scan()
        self.assertEqual(waits, [0.25] * 4)  # 2 baseline requests + 3 words, a wait before each but the first

    def test_default_rate_is_ten_requests_per_second(self):
        self.assertEqual(DEFAULT_RATE, 10)
        self.assertEqual(MAX_RATE, 50)

    def test_pauses_for_retry_after_then_retries_the_same_path(self):
        waits = []
        session = FakeSession({'admin/': [FakeResponse(429, b'', {'Retry-After': '7'}), FakeResponse(200, b'ok')]})
        report = _scanner(session, ['admin/'], sleep=waits.append).scan()
        self.assertIn(7, waits)
        self.assertEqual([f.url for f in report.found], [f'{BASE}admin/'])

    def test_retry_after_is_capped_so_a_server_cannot_stall_the_scan(self):
        waits = []
        session = FakeSession({'a': [FakeResponse(503, b'', {'Retry-After': '86400'}), FakeResponse(404)]})
        _scanner(session, ['a'], sleep=waits.append).scan()
        self.assertEqual(max(waits), MAX_RETRY_AFTER)
        self.assertLessEqual(MAX_RETRY_AFTER, 60)

    def test_a_path_still_throttled_after_three_tries_is_skipped_with_an_error(self):
        throttled = lambda: FakeResponse(429, b'', {'Retry-After': '1'})  # noqa: E731
        session = FakeSession({'a': throttled, 'b': FakeResponse(200, b'b')})
        report = _scanner(session, ['a', 'b']).scan()
        self.assertEqual(sum(url == f'{BASE}a' for url, _ in session.calls), 3)
        self.assertEqual([f.url for f in report.found], [f'{BASE}b'])
        self.assertEqual(len(report.errors), 1)
        self.assertIn(f'{BASE}a', report.errors[0])

    def test_stops_after_three_connection_errors_in_a_row(self):
        down = requests.ConnectionError('refused')
        session = FakeSession(default=lambda: down)
        report = _scanner(session, ['a', 'b', 'c', 'd', 'e']).scan()
        self.assertEqual(len(session.calls), 3)
        self.assertEqual(report.found, [])
        self.assertTrue(any('stopped' in e for e in report.errors), report.errors)

    def test_a_successful_request_resets_the_error_count(self):
        down = requests.ConnectionError('refused')
        session = FakeSession({'a': down, 'b': down, 'c': FakeResponse(404), 'd': down, 'e': down,
                               'f': FakeResponse(200, b'f')})
        report = _scanner(session, ['a', 'b', 'c', 'd', 'e', 'f']).scan()
        self.assertEqual([f.url for f in report.found], [f'{BASE}f'])
        self.assertEqual(len(report.errors), 4)

    def test_reads_at_most_a_capped_amount_of_each_body(self):
        big = FakeResponse(200, b'z' * (MAX_BODY_BYTES * 3))
        report = _scanner(FakeSession({'backup.zip': big}), ['backup.zip']).scan()
        self.assertLessEqual(big.read, MAX_BODY_BYTES + 65536)
        self.assertTrue(big.closed)
        self.assertEqual(report.found[0].length, MAX_BODY_BYTES)

    def test_identifies_itself_and_uses_a_timeout(self):
        session = FakeSession()
        _scanner(session, ['a']).scan()
        self.assertEqual(session.headers['User-Agent'], USER_AGENT)
        self.assertIn('Anansi', USER_AGENT)
        for _, kwargs in session.calls:
            self.assertEqual(kwargs['timeout'], 10)
            self.assertTrue(kwargs['stream'])

    def test_tls_certificates_are_verified_unless_turned_off(self):
        on, off = FakeSession(), FakeSession()
        _scanner(on, ['a']).scan()
        _scanner(off, ['a'], verify_tls=False).scan()
        self.assertTrue(all(kwargs['verify'] is True for _, kwargs in on.calls))
        self.assertTrue(all(kwargs['verify'] is False for _, kwargs in off.calls))


class TestRejectsInvalidSettings(unittest.TestCase):

    def test_rate_must_be_a_number_above_zero_and_at_most_the_cap(self):
        for rate in (0, -1, MAX_RATE + 1, True, '10', None):
            with self.subTest(rate=rate), self.assertRaisesRegex(ValueError, 'dirs_rate'):
                DirectoryScanner(BASE, rate=rate)

    def test_tls_verification_must_be_true_or_false(self):
        for verify in ('no', 0, None):
            with self.subTest(verify=verify), self.assertRaisesRegex(ValueError, 'dirs_verify_tls'):
                DirectoryScanner(BASE, verify_tls=verify)


if __name__ == '__main__':
    unittest.main()
