import threading
import copy

class MLock():
    def __init__(self, reentrant=False):
        if reentrant:
            self.lock = threading.RLock()
        else:
            self.lock = threading.Lock()

    def acquire(self, *args, **kwargs):
        return self.lock.acquire(*args, **kwargs)

    def release(self):
        return self.lock.release()

    __enter__ = acquire

    def __exit__(self, exc_type, exc_val, exc_tb):
        return self.lock.release()

    def __deepcopy__(self, memo):
        return copy.copy(self) # shallow copy

    def __repr__(self):
        return self.lock.__repr__()

## ===========================

if __name__ == "__main__":
    import time
    import copy

    def work(lock, input, sleepTime):
        print("Start {0}".format(input))
        timeNow = time.time()
        with lock:
            time.sleep(sleepTime)
            print("End {0} Took {1}".format(input, time.time()-timeNow))

    class A:
        def __init__(self):
            self.lock = MLock()

    a = A()
    threading.Thread(target=work, args=(a.lock, "A", 4.0)).start()
    b = copy.deepcopy(a)
    threading.Thread(target=work, args=(b.lock, "B", 4.0)).start()
