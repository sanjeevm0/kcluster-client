import logging
import logging.handlers
import sys
import os
import glob
from os import path
from pathlib import Path

def mkdir(dir):
    path = Path(dir)
    path.mkdir(parents=True, exist_ok=True)

loggers = {}

def start_log(filename, level=logging.INFO, prtLogLevel=logging.WARNING, mode='w', loggerName=None, backupCount=2, fmt=None, prtFmt=None) -> logging.Logger:
    global logger
    if loggerName not in loggers:
        if loggerName is None:
            logger = logging.getLogger() # get root logger
        else:
            logger = logging.getLogger(loggerName)
        #print("Level: {0}".format(level))
        logger.setLevel(level)
        mkdir(path.dirname(filename))
        if backupCount < 0:
            logfh = logging.FileHandler(filename, mode=mode)
        else:
            logfh = logging.handlers.RotatingFileHandler(filename, mode=mode, maxBytes=10*1024*1024, backupCount=backupCount)
        logfh.setLevel(level)
        if fmt is not None:
            if isinstance(fmt, str):
                fmt = logging.Formatter(fmt) # e.g. logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            logfh.setFormatter(fmt)
        logger.addHandler(logfh)
        logprt = logging.StreamHandler(sys.stdout)
        logprt.setLevel(prtLogLevel)
        if prtFmt is not None:
            if isinstance(prtFmt, str):
                prtFmt = logging.Formatter(prtFmt)
            logprt.setFormatter(prtFmt)
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
