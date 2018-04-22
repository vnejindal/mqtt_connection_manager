"""

Logger Module

"""

import logging


import appconfig

def init_applog(logfile, loglevel):
    """
    """
    
    if loglevel == "INFO":
        level = logging.INFO
    elif loglevel == "DEBUG":
        level = logging.DEBUG
    elif loglevel == "WARNING":
        level = logging.WARN
    elif loglevel == "ERROR":
        level = logging.ERROR
    elif loglevel == "CRITICAL":
        level = logging.CRITICAL
    else:
        print "Invalid Log Level configured", loglevel
        return 0
        
    logger = logging.getLogger(__name__)
    logger.setLevel(level)

    # create a file handler
    handler = logging.FileHandler(logfile)
    handler.setLevel(level)

    # create a logging format
    formatter = logging.Formatter('%(asctime)s-%(name)s-%(levelname)s- %(message)s')
    handler.setFormatter(formatter)

    # add the handlers to the logger
    logger.addHandler(handler)

    return logger
