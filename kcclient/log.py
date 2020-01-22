import logging
import sys
import os
import glob
from os import path
from pathlib import Path

def mkdir(dir):
    path = Path(dir)
    path.mkdir(parents=True, exist_ok=True)

loggers = {}

def start_log(filename, level=logging.INFO, prtLogLevel=logging.WARNING, mode='w', loggerName=None):
    global logger
    if loggerName not in loggers:
        if loggerName is None:
            logger = logging.getLogger() # get root logger
        else:
            logger = logging.getLogger(loggerName)
        #print("Level: {0}".format(level))
        logger.setLevel(level)
        mkdir(path.dirname(filename))
        logfh = logging.FileHandler(filename, mode=mode)
        logfh.setLevel(level)
        logger.addHandler(logfh)
        logprt = logging.StreamHandler(sys.stdout)
        logprt.setLevel(prtLogLevel)
        logger.addHandler(logprt)
        loggers[loggerName] = logger
    return loggers[loggerName]

def get_logger(loggerName=None):
    return loggers[loggerName]

def delete_logs(searchFmt, numKeep=5):
    files = glob.glob(searchFmt)
    filesSorted = sorted(files, key=lambda f: -os.stat(f).st_mtime) # descending by time
    # keep newest
    for index in range(numKeep, len(filesSorted)):
        try:
            os.remove(filesSorted[index])
        except Exception:
            pass # don't care
