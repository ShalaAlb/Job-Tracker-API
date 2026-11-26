import logging

LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {
            "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        },
    },
    "handlers":  {
        "console": {
            "class": "logging.StreamHandler",       
            "level": "DEBUG",                      
            "formatter": "standard",                  
            "stream": "ext://sys.stdout",           
        },
        "file": {
            "class": "logging.handlers.RotatingFileHandler",
            "formatter": "standard",
            "level": "DEBUG",
            "filename": "logs/app.log",
            "maxBytes": 10485760,
            "backupCount": 5
        },
    },
    "root": {
        "handlers": ["console", "file"],
        "level": "INFO",
    },
}

def logging_setup():
    logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("logs/app.log"),
        logging.StreamHandler()
    ]
    )