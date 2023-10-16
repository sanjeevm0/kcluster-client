import logging
import logging.handlers
import sys
import os
import glob
import uuid
from os import path
from pathlib import Path

def mkdir(dir):
    path = Path(dir)
    path.mkdir(parents=True, exist_ok=True)

loggers = {}
logger = None

# if seeing double print messages, set logger.propagate to False as someone may have added a handler to the root logger
def start_log(filename, level=logging.INFO, prtLogLevel=logging.WARNING, mode='w', loggerName="logcommon-d3ab1c", backupCount=2,
              fmt=None, prtFmt=None, maxBytes=10*1024*1024, overwrite=False, encoding='utf-8', propagate=True) -> logging.Logger:
    global logger
    if loggerName not in loggers or overwrite:
        logger = logging.getLogger(loggerName)
        for handler in logger.handlers: # if overwrite, remove old handlers
            handler.close()
            logger.removeHandler(handler)
        logger.propagate = propagate # set to False to prevent double printing
        logger.setLevel(min(level, prtLogLevel))
        mkdir(path.dirname(filename))
        if backupCount < 0:
            logfh = logging.FileHandler(filename, mode=mode, encoding=encoding)
        else:
            # use mode='a' to rollover on start, otherwise 'w' would overwrite the file without rolling over
            # maxBytes=10*1024*1024, backupCount=2, use maxBytes=0 to grow without limit
            try:
                logfh = logging.handlers.RotatingFileHandler(filename, mode='a', maxBytes=maxBytes, backupCount=backupCount, encoding=encoding)
                if mode == 'w':
                    logfh.doRollover()
            except Exception:
                base, ext = os.path.splitext(filename)
                filename = base + "-" + uuid.uuid4().hex + ext
                logfh = logging.handlers.RotatingFileHandler(filename, mode='a', maxBytes=maxBytes, backupCount=backupCount, encoding=encoding)
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
