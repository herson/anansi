import logging

def log_error(error_message):
    logging.error(error_message)

def handle_network_timeout():
    print("Network timeout occurred. Retrying...")
    # Retry logic or handling mechanism here