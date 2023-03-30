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
logger = None

def start_log(filename, level=logging.INFO, prtLogLevel=logging.WARNING, mode='w', loggerName="logcommon-d3ab1c", backupCount=2,
              fmt=None, prtFmt=None, maxBytes=10*1024*1024, overwrite=False) -> logging.Logger:
    global logger
    if loggerName not in loggers or overwrite:
        logger = logging.getLogger(loggerName)
        for handler in logger.handlers: # if overwrite, remove old handlers
            handler.close()
            logger.removeHandler(handler)
        #logger.propagate = False # optional since not using root logger
        logger.setLevel(min(level, prtLogLevel))
        mkdir(path.dirname(filename))
        if backupCount < 0:
            logfh = logging.FileHandler(filename, mode=mode)
        else:
            # use mode='a' to rollover on start, otherwise 'w' would overwrite the file without rolling over
            # maxBytes=10*1024*1024, backupCount=2, use maxBytes=0 to grow without limit
            logfh = logging.handlers.RotatingFileHandler(filename, mode='a', maxBytes=maxBytes, backupCount=backupCount)
            if mode == 'w':
                logfh.doRollover()
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
