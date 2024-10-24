import logging
import time
import random  # For simulating network operations

# Configure logging
logging.basicConfig(
    level=logging.ERROR,
    format='%(asctime)s - %(levelname)s - %(message)s',
)

def log_error(error_message):
    """Log an error message."""
    logging.error(error_message)

def simulate_network_operation():
    """Simulate a network operation that may fail."""
    # Simulate a random failure
    if random.choice([True, False]):  # Randomly succeed or fail
        return True  # Operation succeeded
    else:
        raise ConnectionError("Simulated network failure.")

def handle_network_timeout(retries=3, delay=2):
    """
    Handle network timeout with retry logic.

    Args:
        retries (int): Number of retry attempts.
        delay (int): Delay in seconds between retries.

    Raises:
        ConnectionError: If all retry attempts fail.
    """
    for attempt in range(1, retries + 1):
        try:
            print(f"Attempting network operation... (Attempt {attempt} of {retries})")
            if simulate_network_operation():  # Attempt the network operation
                print("Network operation succeeded.")
                return  # Exit if successful
        except ConnectionError as e:
            log_error(str(e))  # Log the error message
            print(f"Network timeout occurred. Retrying in {delay} seconds...")
            time.sleep(delay)  # Wait before retrying

    raise ConnectionError("All retry attempts failed. Please check your network connection.")
