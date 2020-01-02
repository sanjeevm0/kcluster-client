import math
import sys
import os
import copy
thisPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(thisPath)
from enum import Enum
from mlock import MLock
import utils

# Input.Cumulative means cumulative value is being input (e.g. total bytes)
# Input.Average means time average is being input (e.g. bytes/sec)
# Input Value means value is being given (e.g. bytes)
Input = Enum('Input', 'Value Counter NBitCounter')

def noneMax(x, y):
    if x is None:
        return y
    elif y is None:
        return x
    else:
        return max(x, y)

def noneMin(x, y):
    if x is None:
        return y
    elif y is None:
        return x
    else:
        return min(x, y)

class SlidingMetrics():
    # if input is avg, it is something like bytes/sec, etc., otherwise unit is bytes or seconds of latency, etc.
    def __init__(self, minWindow, maxWindow, inputType, bits=32):
        self.minWindow = minWindow
        self.maxWindow = maxWindow
        self.subWindow = maxWindow - minWindow
        self.maxWindows = math.ceil(minWindow / self.subWindow) + 1
        self.inputType = inputType
        self.winIndex = 0
        self.lock = MLock()

        # window statistics
        self.NWin = []
        self.ts1Win = []
        self.tsNWin = []
        self.minValWin = []
        self.maxValWin = []
        self.cumu1Win = []
        self.cumuNWin = []

        self.N = 0 # num samples (1 to N)
        self.ts0 = None # ts below lowest value (needed for left )
        self.ts1 = None
        self.tsN = None
        self.minVal = None
        self.maxVal = None
        self.cumu0 = 0
        self.cumu1 = None
        self.cumuNMinus1 = None
        self.cumuN = 0

        self.startTs = None
        self.prevTs = None
        self.prevData = 0 # raw data

        self.bits = bits

    def __dump__(self):
        o = copy.deepcopy(self.__dict__)
        o.pop("lock", None)
        o["inputType"] = str(o["inputType"])
        return o

    @staticmethod
    def __load__(o):
        x = SlidingMetrics(10, 20, Input.Value, bits=32)
        o = utils.smartLoad(o, True)
        for key, val in o.items():
            setattr(x, key, val)
        x.inputType = eval(x.inputType) # convert back
        return x

    def _resetCumu(self):
        amtToSub = self.cumu0
        if amtToSub==0:
            return

        for i in range(len(self.cumu1Win)):
            self.cumu1Win[i] -= amtToSub
            self.cumuNWin[i] -= amtToSub

        self.cumu0 -= amtToSub
        self.cumu1 -= amtToSub
        self.cumuNMinus1 -= amtToSub
        self.cumuN -= amtToSub

    # returns cumulative and value
    def _setCumuVal(self, data):
        if self.inputType==Input.NBitCounter:
            if data < self.prevData: # counter overflow
                data += (1 << self.bits)
            val = data - self.prevData
        elif self.inputType==Input.Counter:
            val = data - self.prevData
        elif self.inputType==Input.Value:
            val = data

        self.prevData = data
        cumu = self.cumuN + val

        return val, cumu

    def popWindow(self):
        N0 = self.NWin.pop(0)
        self.N -= N0
        self.ts1Win.pop(0)
        self.ts1 = self.ts1Win[0]
        self.ts0 = self.tsNWin.pop(0)
        self.minValWin.pop(0)
        self.minVal = min(self.minValWin)
        self.maxValWin.pop(0)
        self.maxVal = max(self.maxValWin)
        self.cumu1Win.pop(0)
        self.cumu1 = self.cumu1Win[0]
        self.cumu0 = self.cumuNWin.pop(0)

    def _addHelper(self, ts, data):
        if self.startTs is None:
            self.startTs = ts
        ts = ts - self.startTs # normalize to start at zero
        if self.prevTs is not None and ts < self.prevTs:
            return False
        self.prevTs = ts

        val, cumu = self._setCumuVal(data)

        if ts >= self.winIndex*self.subWindow:
            # new window
            self.winIndex += 1
            self.NWin.append(1)
            self.ts1Win.append(ts)
            self.tsNWin.append(ts)
            self.minValWin.append(val)
            self.maxValWin.append(val)
            self.cumu1Win.append(cumu)
            self.cumuNWin.append(cumu)
        else:
            # add to current window (last window)
            self.NWin[-1] += 1
            self.tsNWin[-1] = ts
            self.minValWin[-1] = min(self.minValWin[-1], val)
            self.maxValWin[-1] = max(self.maxValWin[-1], val)
            self.cumuNWin[-1] = cumu

        # pop oldest window as new window is added
        bWindowMoved = False
        if len(self.ts1Win) > self.maxWindows:
            self.popWindow()
            bWindowMoved = True

        if self.ts1 is None:
            self.ts1 = ts
        while ts-self.ts1 >= self.maxWindow:
            self.popWindow()
            bWindowMoved = True

        self.N += 1
        self.tsN = ts
        self.minVal = noneMin(self.minVal, val)
        self.maxVal = noneMax(self.maxVal, val)
        if self.cumu1 is None:
            self.cumu1 = cumu
        self.cumuNMinus1 = self.cumuN
        self.cumuN = cumu

        #print("Cumu: {0} {1} {2} {3}".format(self.cumu0, self.cumu1, self.cumuNMinus1, self.cumuN))

        if bWindowMoved:
            self._resetCumu()

        return True

    def add(self, ts, data):
        with self.lock:
            return self._addHelper(ts, data)

    def lockTryNan(self, fn):
        with self.lock:
            try:
                return fn()
            except ZeroDivisionError:
                return 0.0
            except Exception:
                return float('nan')

    # given data points have timestamp which is left end of interval
    def avgL(self):
        with self.lock:
            if (self.N-1)==0 or (self.tsN == self.ts1):
                return 0.0
            else:
                # N-1 points, N-1 intervals
                return (self.cumuNMinus1 - self.cumu0) / (self.tsN - self.ts1)

    def avgR(self):
        with self.lock:
            if self.ts0 is None:
                if (self.N-1)<=0 or (self.tsN == self.ts1):
                    return 0.0
                else:
                    # N-1 points, N-1 intervals
                    return (self.cumuN - self.cumu1) / (self.tsN - self.ts1)                    
            else:
                if self.N==0 or (self.tsN == self.ts0):
                    return 0.0
                else:
                    # N points, N intervals
                    return (self.cumuN - self.cumu0) / (self.tsN - self.ts0)

    def avgN(self):
        with self.lock:
            if self.N==0:
                return 0.0
            else:
                return (self.cumuN - self.cumu0) / self.N

    # number of measurements
    def avgNumL(self):
        with self.lock:
            if (self.N-1)==0 or (self.tsN == self.ts1):
                return 0.0
            else:        
                return (N-1) / (self.tsN - self.ts1)

    def avgNumR(self):
        with self.lock:
            if self.ts0 is None:
                if (self.N-1)<=0 or (self.tsN == self.ts1):
                    return 0.0
                else:
                    return (N-1) / (self.tsN - self.ts1)
            else:
                if self.N==0 or (self.tsN == self.ts0):
                    return 0.0
                else:
                    return N / (self.tsN - self.ts0)

    def windowL(self):
        return self.lockTryNan(lambda : self.tsN - self.ts1)

    def windowR(self):
        with self.lock:
            if self.ts0 is None:
                return self.tsN - self.ts1
            else:
                return self.tsN - self.ts0

utils.registerEval('SlidingMetrics', SlidingMetrics)
# ============================
# Testing

from numpy import random

if __name__ == "__main__":
    window = []
    N = 100000
    s = SlidingMetrics(9.0, 10.0, Input.Value)
    subWindow = 1.0
    numWindows = 10
    ts = 0
    r = random.RandomState(4532312)
    lastPopped = None
    valMin = 0
    valMax = 20
    tsDelta = 0.2
    tsDeltaRand = 0.03
    for i in range(N):
        val = r.uniform(valMin, valMax)
        s.add(ts, val)
        window.append((ts, val))
        # remove from window
        curWindow = math.floor(ts/subWindow)
        firstWindow = max(0, curWindow - numWindows + 1)
        firstTs = firstWindow * subWindow
        while len(window) > 0:
            (t, v) = window[0]
            if t < firstTs:
                lastPopped = window.pop(0)
            else:
                break
        #print("{0} {1}".format(len(window), window))
        # compare
        if lastPopped is not None:
            t0 = lastPopped[0]
            rStart = 0
        else:
            t0 = None
            rStart = 1
        sumL = 0
        for j in range(0, len(window)-1):
            sumL += window[j][1]
        if len(window)<=1:
            avgWinL = 0.0
        else:
            avgWinL = sumL / (window[-1][0] - window[0][0])
        sumR = 0
        for j in range(rStart, len(window)):
            sumR += window[j][1]
        if len(window)<=1:
            avgWinR = 0.0
        elif rStart==0:
            avgWinR = sumR / (window[-1][0] - t0)
        else:
            avgWinR = sumR / (window[-1][0] - window[0][0])
        avgWinN = (sumL + window[-1][1]) / len(window)
        maxWin = max(window, key=lambda x: x[1])[1]
        minWin = min(window, key=lambda x: x[1])[1]
        if False:
            print("T: {0} W: {1} V: {2}".format(ts, curWindow, val))
            print("L: {0} {1}".format(avgWinL, s.avgL()))
            print("R: {0} {1}".format(avgWinR, s.avgR()))
            print("N: {0} {1}".format(avgWinN, s.avgN()))

        error = abs(avgWinL-s.avgL()) + abs(avgWinR-s.avgR()) + abs(avgWinN-s.avgN())
        errorMinMax = abs(maxWin-s.maxVal) + abs(minWin-s.minVal)
        print("ERROR: {0:20.15f}\t ERRORMINMAX: {1:20.15f}".format(error, errorMinMax), end='\r')
        if (abs(avgWinL-s.avgL()) > abs(avgWinL)*0.0000001 or
            abs(avgWinR-s.avgR()) > abs(avgWinR)*0.0000001 or
            abs(avgWinN-s.avgN()) > abs(avgWinN)*0.0000001 or
            maxWin != s.maxVal or
            minWin != s.minVal):
            print("ERROR====")
            print("T: {0} W: {1} V: {2}".format(ts, curWindow, val))
            print("L: {0} {1}".format(avgWinL, s.avgL()))
            print("R: {0} {1}".format(avgWinR, s.avgR()))
            print("N: {0} {1}".format(avgWinN, s.avgN()))
            print("M: {0} {1}".format(maxWin, s.maxVal))
            print("m: {0} {1}".format(minWin, s.minVal))
        
        ts += r.uniform(tsDelta - tsDeltaRand, tsDelta + tsDeltaRand)


