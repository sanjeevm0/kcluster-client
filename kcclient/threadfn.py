import threading

class ThreadFn (threading.Thread):
    def __init__(self, threadID, name, sharedCtx, fn, *args):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.fn = fn
        self.args = args
        self.selfCtx = {}
        self.sharedCtx = sharedCtx
        if "finisher" in self.sharedCtx:
            self.sharedCtx["finisherLock"] = threading.Lock()
            self.sharedCtx["finisherRun"] = False
        if 'finisherType' not in self.sharedCtx:
            self.sharedCtx["finisherType"] = "ThreadFn"
        self.type = "ThreadFn"
        self.selfCtx['thread'] = self

    def run(self):
        print("Starting thread {0}".format(self.name))
        try:
            self.fn(self, *self.args)
        except Exception as e:
            self.sharedCtx['finished'] = True
            raise e
        self.sharedCtx['finished'] = True
        if self.type=="ThreadFn" and 'finisher' in self.selfCtx:
            self.selfCtx['finisher'](self.selfCtx)
        if self.sharedCtx["finisherType"]=="ThreadFn":
            self.runSharedFinisher()
        print("Exiting thread {0}".format(self.name))

    def stop(self):
        if 'finished' in self.sharedCtx and self.sharedCtx['finished']:
            return True
        else:
            return False

    # one run of shared finisher
    def runSharedFinisher(self):
        if 'finisher' in self.sharedCtx:
            with self.sharedCtx["finisherLock"]:
                if not self.sharedCtx["finisherRun"]:
                    self.sharedCtx["finisher"](self.sharedCtx)
                    self.sharedCtx["finisherRun"] = True

# Repeats fn if ret is True
class ThreadFnR (ThreadFn):
    def __init__(self, threadID, name, sharedCtx, fn, *args):
        super(ThreadFnR,self).__init__(threadID, name, sharedCtx, fn, *args)
        self.sharedCtx["finisherType"] = "ThreadFnR"
        self.type = "ThreadFnR"

    def run(self):
        print("Starting thread {0}".format(self.name))
        while True:
            self.selfCtx['repeat'] = False
            try:
                self.fn(self, *self.args)
            except Exception as e:
                self.sharedCtx['finished'] = True
                raise e # thread will exit due to exception raised
            if not self.selfCtx['repeat']:
                break
            else:
                print("REPEAT LOOP for {0}".format(self.name))
        self.sharedCtx['finished'] = True
        if 'finisher' in self.selfCtx:
            self.selfCtx['finisher'](self.selfCtx)
        self.runSharedFinisher()
        print("Exiting thread {0}".format(self.name))

    def getState(self, key=None):
        if 'state' in self.selfCtx:
            if key is None:
                return self.selfCtx['state']
            elif key in self.selfCtx['state']:
                return self.selfCtx['state'][key]
            else:
                return None
        else:
            return None

# for debugging
import sys, traceback
def PrintThreads():
    thread_names = {t.ident: t.name for t in threading.enumerate()}
    if thread_names is not None:
        for name in thread_names:
            print("ThreadName: {0}".format(name))
    for thread_id, frame in sys._current_frames().items():
        print("Thread %s:" % thread_names.get(thread_id, thread_id))
        traceback.print_stack(frame)
        print()
