import logging
import os
# import time
from datetime import datetime

def get_file_name():
    if os.path.exists("logs"):
        os.chdir("logs")
    else:
        os.mkdir("logs")
        os.chdir("logs")
        
    name = datetime.now().strftime("%Y-%m-%d") + ".log"
    if os.path.exists(name):
        return name
    else:
        with open(name, "w") as f:
            f.write("")
    
    return name

logging.basicConfig(filename=get_file_name(),level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def log_info(msg):
    logger.info(msg)

def log_error(msg):
    logger.error(msg)

def log_warning(msg):
    logger.warning(msg)
