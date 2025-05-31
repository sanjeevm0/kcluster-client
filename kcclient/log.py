import logging
import logging.handlers
import sys
import os
import glob
import uuid
from os import path
from pathlib import Path

def getLogDir():
    if os.path.exists("c:/logs"):
        return 'c:'
    elif 'HOME' in os.environ:
        return os.environ['HOME']
    elif 'USERPROFILE' in os.environ:
        return os.environ['USERPROFILE']
    else:
        return ''

def mkdir(dir):
    path = Path(dir)
    path.mkdir(parents=True, exist_ok=True)

loggers = {}
logger = None

# some default formats
fmt1 = logging.Formatter(fmt='%(asctime)s %(levelname)-8s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

def add_log_args(parser):
    logName = os.path.splitext(os.path.basename(sys.argv[0]))[0] + ".log"
    parser.add_argument('--log', '-log', default="{0}/logs/{1}".format(getLogDir(), logName), help="Log file name")
    parser.add_argument('--v', '-v', default=logging.DEBUG, type=int, help="Log Verbosity - fatal/critical 50, error 40, warn/warning 30, info 20, debug 10, notset 0")
    parser.add_argument('--vp', '-vp', default=logging.INFO, type=int, help="Log verbosity for printing")
    parser.add_argument('--logsize', '-logsize', default=0, type=int, help="Log file size in bytes")
    parser.add_argument('--backup', '-backup', default=2, type=int, help="Number of log file backups to keep")

def start_log_args(args):
    global logger
    logfmt = logging.Formatter(fmt='%(asctime)s %(levelname)-8s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    print("Starting log {0}".format(args.log))
    _, filename = start_log(args.log, level=args.v, prtLogLevel=args.vp, maxBytes=args.logsize, 
                            fmt=logfmt, backupCount=args.backup) # grow without limit
    return filename

# if seeing double print messages, set logger.propagate to False as someone may have added a handler to the root logger
def start_log(filename : str, level=logging.INFO, prtLogLevel=logging.WARNING, mode='w',
              loggerName="logcommon-d3ab1c", backupCount=2,
              fmt=None, prtFmt=None, maxBytes=10*1024*1024, overwrite=False, encoding='utf-8', propagate=True) -> \
                tuple[logging.Logger, str]:
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
                print("Starting log {0}".format(filename))
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
    return loggers[loggerName], filename

def flush_logs():
    for logger in loggers.values():
        for handler in logger.handlers:
            #print("Flush {0}".format(handler))
            handler.flush()

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
