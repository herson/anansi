import unittest
from unittest.mock import patch
from modules.utils import log_error, handle_network_timeout

class TestUtils(unittest.TestCase):

    @patch('modules.utils.logging.error')
    def test_log_error(self, mock_logging_error):
        """Test the log_error function."""
        error_message = "This is a test error message."
        log_error(error_message)
        mock_logging_error.assert_called_once_with(error_message)

    @patch('modules.utils.simulate_network_operation', return_value=True)
    def test_handle_network_timeout_success(self, mock_simulate):
        """Test handle_network_timeout when the operation succeeds."""
        try:
            handle_network_timeout(retries=3, delay=1)
        except ConnectionError:
            self.fail("handle_network_timeout raised ConnectionError unexpectedly!")

    @patch('modules.utils.simulate_network_operation', side_effect=ConnectionError("Simulated network failure."))
    @patch('modules.utils.time.sleep')  # Mock sleep to avoid delays
    def test_handle_network_timeout_failure(self, mock_sleep, mock_simulate):
        """Test handle_network_timeout when all attempts fail."""
        with self.assertRaises(ConnectionError):
            handle_network_timeout(retries=3, delay=1)

if __name__ == '__main__':
    unittest.main()

