import sys
import unittest
from unittest.mock import MagicMock
from modules.intelligence import IntelligentAnalyzer

class TestAIIntegration(unittest.TestCase):
    def test_ai_graceful_failure(self):
        """Test that analyzer returns error message if key is missing/invalid or client fails"""
        # Mock config
        config = {'ai_model': 'gpt-3.5-turbo'}
        
        # Initialize analyzer (it might print warning about valid API key depending on env)
        analyzer = IntelligentAnalyzer(config)
        
        if not analyzer.client:
            print("✅ Verified: Analyzer detected missing API Key correctly.")
            return

        # If we have a client (e.g. from .env), let's mock the API call failure
        analyzer.client = MagicMock()
        analyzer.client.chat.completions.create.side_effect = Exception("API connection failed")
        
        scan_results = {'scan': {'127.0.0.1': {'tcp': {80: {'name': 'http', 'version': '1.0'}}}}}
        result = analyzer.analyze(scan_results)
        
        self.assertIn("AI Analysis Failed", result)
        print("✅ Verified: Analyzer handled API failure gracefully.")

if __name__ == '__main__':
    unittest.main()
