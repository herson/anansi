import unittest
from unittest.mock import patch, MagicMock


class TestIntelligentAnalyzer(unittest.TestCase):

    def _make_analyzer(self, mock_client, api_key='test-key'):
        with patch.dict('os.environ', {'OPENAI_API_KEY': api_key}):
            with patch('modules.intelligence.OpenAI', return_value=mock_client):
                from modules.intelligence import IntelligentAnalyzer
                return IntelligentAnalyzer({'ai_model': 'gpt-3.5-turbo'})

    def test_no_api_key_skips_analysis(self):
        with patch.dict('os.environ', {'OPENAI_API_KEY': ''}):
            from modules.intelligence import IntelligentAnalyzer
            analyzer = IntelligentAnalyzer({'ai_model': 'gpt-3.5-turbo'})
        self.assertIsNone(analyzer.client)
        result = analyzer.analyze({})
        self.assertIn("AI Analysis Skipped", result)

    def test_analyze_returns_content(self):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value.choices[0].message.content = "Looks risky"
        analyzer = self._make_analyzer(mock_client)
        scan = {'scan': {'192.168.1.1': {'tcp': {80: {'name': 'http', 'version': '2.4'}}}}}
        result = analyzer.analyze(scan)
        self.assertEqual(result, "Looks risky")

    def test_analyze_handles_openai_error(self):
        from openai import OpenAIError
        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = OpenAIError("rate limit")
        analyzer = self._make_analyzer(mock_client)
        result = analyzer.analyze({'scan': {}})
        self.assertIn("AI Analysis Failed", result)

    def test_construct_prompt_with_no_scan_data(self):
        mock_client = MagicMock()
        analyzer = self._make_analyzer(mock_client)
        prompt = analyzer._construct_prompt({})
        self.assertIn("No open ports", prompt)

    def test_construct_prompt_includes_host_and_port(self):
        mock_client = MagicMock()
        analyzer = self._make_analyzer(mock_client)
        scan = {'scan': {'10.0.0.1': {'tcp': {443: {'name': 'https', 'version': '1.2'}}}}}
        prompt = analyzer._construct_prompt(scan)
        self.assertIn("10.0.0.1", prompt)
        self.assertIn("443", prompt)


if __name__ == '__main__':
    unittest.main()
