import logging
import yaml
import os

log_dir = os.path.join(os.getcwd(), "logs")
os.makedirs(log_dir, exist_ok=True)

logging.basicConfig(
    filename=os.path.join(log_dir, "anansi.log"),
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

try:
    with open(os.path.join(os.getcwd(), "config.yaml"), "r") as config_file:
        config = yaml.safe_load(config_file)
except FileNotFoundError:
    config = {}
    logging.warning("config.yaml not found; modules will use defaults")
except yaml.YAMLError as e:
    config = {}
    logging.error("Failed to parse config.yaml: %s", e)

__all__ = ["scanner", "enumerator", "exploiter", "reporter", "utils"]

logging.info("Anansi modules initialized.")
