import logging
import yaml
import os

# Set up logging for the entire modules package
logging.basicConfig(
    filename=os.path.join(os.getcwd(), "logs/anansi.log"),
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

# Load shared configuration for all modules
with open(os.path.join(os.getcwd(), "config.yaml"), "r") as config_file:
    config = yaml.safe_load(config_file)

# Ensure that any module that imports `modules` package can access the shared config
__all__ = ["scanner", "enumerator", "exploiter", "reporter", "utils"]

logging.info("Anansi modules initialized.")