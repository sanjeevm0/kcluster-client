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

    def run(self):
        print("Starting thread {0}".format(self.name))
        try:
            self.fn(self, *self.args)
        except Exception as e:
            self.sharedCtx['finished'] = True
            raise e
        self.sharedCtx['finished'] = True
        print("Exiting thread {0}".format(self.name))

    def stop(self):
        if 'finished' in self.sharedCtx and self.sharedCtx['finished']:
            return True
        else:
            return False

# Repeats fn if ret is True
class ThreadFnR (ThreadFn):
    def __init__(self, threadID, name, sharedCtx, fn, *args):
        super(ThreadFnR,self).__init__(threadID, name, sharedCtx, fn, *args)

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
        print("Exiting thread {0}".format(self.name))

    def getState(self):
        if 'state' in self.selfCtx:
            return self.selfCtx['state']
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
