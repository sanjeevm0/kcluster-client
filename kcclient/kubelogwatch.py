import utils, kubeutils
from datetime import datetime, timezone
import threading
import re
from kubeutils import ObjTracker
from functools import partial
import copy
import uuid
import base64
import time
import traceback
import logging

dateFormatStr = '%Y-%m-%dT%H:%M:%SZ'
logger: logging.Logger = kubeutils.logger

def getPodStartTime(pods, podKey):
    st = utils.getValDef(pods, [podKey, 'status', 'startTime'], None, None)
    if st is not None:
        #return st.replace(tzinfo=timezone.utc)
        return datetime.strptime(datetime.strftime(st, dateFormatStr), dateFormatStr)
    else:
        return None

def getPodActivationTime(pods, podKey) -> datetime:
    st = utils.getValDef(pods, [podKey, 'metadata', 'annotations', 'kube5g.io/pod-activate-time'], None, None)
    if st is not None:
        return datetime.strptime(st, dateFormatStr)
    else:
        return getPodStartTime(pods, podKey)
    
def getContActivationTime(pods, podKey, contName) -> datetime:
    st = utils.getValDef(pods, [podKey, 'metadata', 'annotations', 'kube5g.io/cont-activate-time-{0}'.format(contName)], None, None)
    if st is not None:
        return datetime.strptime(st, dateFormatStr)
    else:
        return None

def trackPodLabels(podsWithLabel, podLabels, podKey, pod, deleted):
    # handle labels and lable notifications
    labels = set()
    for k, v in pod['metadata'].get('labels', {}).items():
        labelVal = "{0}={1}".format(k, v)
        if deleted:
            if labelVal in podsWithLabel:
                podsWithLabel[labelVal].pop(podKey, None)
        else:
            utils.setVal(podsWithLabel, [labelVal, podKey], True, None)
            labels.add(labelVal)

    if deleted:
        podLabels.pop(podKey, None)
        return

    for prevLabel in podLabels.get(podKey, set()):
        if prevLabel not in labels: # label removed
            podsWithLabel[prevLabel].pop(podKey, None)

    podLabels[podKey] = labels

class ConditionsChecker():
    def __init__(self, cluster : kubeutils.Cluster, getPods=None, lock : threading.Lock = None):
        if getPods is None and lock is None:
            raise Exception("Either getPods or lock must be provided") # get pods will do self locking
        self.cluster = cluster
        self.lock = lock
        self.podLabels = {} # podKey -> set of labels for pod
        self.podsWithLabel = {} # label -> podKey -> True
        self.pods = {} # podKey -> pod
        self.allLogWatchers = {} # for external callers to use
        self.allStartWatchers = {}
        if getPods is None:
            self.podTracker = self.cluster.tracker({}, lambda : False, 'list_pod_for_all_namespaces',
                callback=partial(ObjTracker.TryCb, self.onPodCb, self.lock), timeout_seconds=0)
            self.podTracker.start()
            self.getPods = self.getPodSnapshot # use lock inside
        else:
            self.getPods = getPods

    def trackPodLabels(self, podKey, pod, deleted): # should call this in  pod callback if getPods being used
        trackPodLabels(self.podsWithLabel, self.podLabels, podKey, pod, deleted)

    def onPodCb(self, evType, pod, _, podPrev):
        # inside lock
        _, deleted, pod = ObjTracker.ProcessObj(lambda _ : True, evType, pod, self.pods, {'ip': 'IP'}, updateObj=True, useUid=False)
        if pod is None:
            return
        self.trackPodLabels(pod['key'], pod, deleted)

    def getPodSnapshot(self):
        with self.lock:
            return copy.deepcopy(self.pods), copy.deepcopy(self.podsWithLabel)

    def ensureWatcher(self, pods, waitId, podKeyToWatch, contNameToWatch, startCondIndex, regex, logWatchers):
        if podKeyToWatch not in pods:
            logger.info("{0} does not exist - skip watching".format(podKeyToWatch))
            return
        try:
            uid = pods[podKeyToWatch]['metadata']['uid'] # uid of pod being watched
            if contNameToWatch is None:
                contNameToWatch = uid # assume single container in pod being watched
            curWatch = utils.getValDef(logWatchers, [str(startCondIndex), uid, contNameToWatch], None, None)
            if curWatch is None: # start watcher if not present
                matcher = re.compile(regex)
                nsW, podNameW = podKeyToWatch.split('/')
                if contNameToWatch != uid:
                    kwargs = {'container' : contNameToWatch}
                else: # contName is None
                    kwargs = {}
                logger.info("waitid {0} creates watch on {1}/{2} - regex {3}".format(waitId, podKeyToWatch, contNameToWatch, regex))
                w = kubeutils.LogWatch(lambda line : matcher.match(line) is None, self.cluster, podNameW, nsW, **kwargs)
                utils.setVal(logWatchers, [str(startCondIndex), uid, contNameToWatch], {'watch': w, 'key': podKeyToWatch}, None)
        except Exception as ex:
            logger.error("EnsureWatcher encounters exception {0} {1}".format(ex, traceback.format_exc()))

    def ensureAllLabelWatchers(self, pods, podsWithLabel, waitId, labelToWatch, contNameToWatch, startCondIndex, regex, logWatchers):
        for podKeyToWatch, _ in podsWithLabel.get(labelToWatch, {}).items():
            self.ensureWatcher(pods, waitId, podKeyToWatch, contNameToWatch, startCondIndex, regex, logWatchers)

    def checkStartTime(self, pods, podKeyToWatch, contNameToWatch, startCondIndex, waitTime, startWatchers):
        if podKeyToWatch not in pods:
            logger.info("{0} does not exist - skip watching".format(podKeyToWatch))
            return False
        uid = pods[podKeyToWatch]['metadata']['uid'] # uid of pod being watched
        if contNameToWatch is None:
            utils.setVal(startWatchers, [str(startCondIndex), uid, uid], {'key': podKeyToWatch}, None)
        else:
            utils.setVal(startWatchers, [str(startCondIndex), uid, contNameToWatch], {'key': podKeyToWatch}, None)
        if contNameToWatch is None:
            activateTime = getPodActivationTime(pods, podKeyToWatch) # use own if not present
            logger.info("Pod {0} activate time: {1}".format(podKeyToWatch, activateTime))
        else:
            activateTime = getContActivationTime(pods, podKeyToWatch, contNameToWatch)
            logger.info("Pod {0} container {1} activate time: {2}".format(podKeyToWatch, contNameToWatch, activateTime))
        if activateTime is None:
            return False
        diff = datetime.utcnow() - activateTime
        logger.info("Diff: {0}".format(diff))
        return (datetime.utcnow() - activateTime).seconds > int(waitTime)
    
    def cleanAndCheckWatchers(self, pods, startCondIndex, watchers):
        deleted = False
        for uid, watchersCond in watchers.get(str(startCondIndex), {}).items():
            for contNameToWatch in list(watchersCond.keys()):
                # uid is of pod being watched, check if pod being watched exists and if uid matches
                w = watchersCond[contNameToWatch]
                # uid is of pod being watched, check if pod being watched exists and if uid matches
                # check if pod exists and if uid matches to make sure correct log is being checked
                podKeyToWatch: str = w['key']
                toDelete = False
                if not toDelete and podKeyToWatch not in pods:
                    logger.info("Pod {0} does not exist - delete old watcher".format(podKeyToWatch))
                    toDelete = True
                    deleted = True
                if not toDelete and pods[podKeyToWatch]['metadata']['uid'] != uid:
                    logger.info("Pod {0} has changed uid {1} -> {2} - delete old watcher".format(podKeyToWatch, uid, pods[podKeyToWatch]['metadata']['uid']))
                    toDelete = True
                    deleted = True
                if 'watch' in w and w['watch'].failed:
                    logger.info("Pod {0} watcher failed - delete old watcher".format(podKeyToWatch))
                    toDelete = True # failed watcher, but valid pod still exists
                if toDelete:
                    if 'watch' in w:
                        w['watch'].stop() # stop watcher if it exists
                    del watchersCond[contNameToWatch] # delete watcher
        #print(watchers)
        return deleted

    def startConditionMet(self, pods, podsWithLabel, waitId, startCondIndex, start, startWatchers, logWatchers):
        podBeingWatchedDeleted = self.cleanAndCheckWatchers(pods, startCondIndex, startWatchers)
        podBeingWatchedDeleted = podBeingWatchedDeleted or self.cleanAndCheckWatchers(pods, startCondIndex, logWatchers)

        if 'after' in start:
            for after in start['after']: # array
                if 'podLabel' in after:
                    for podKeyToWatch, _ in podsWithLabel.get(after['podLabel'], {}).items():
                        if self.checkStartTime(pods, podKeyToWatch, after.get('contName', None), startCondIndex, after['wait'], startWatchers):
                            return True, podKeyToWatch, podBeingWatchedDeleted  
                else:
                    if self.checkStartTime(pods, after['podKey'], after.get('contName', None), startCondIndex, after['wait'], startWatchers):
                        return True, after['podKey'], podBeingWatchedDeleted

        if 'logMatch' in start:
            for matchLog in start['logMatch']: # array
                if 'regexBase64' in matchLog and 'regex' not in matchLog:
                    matchLog['regex'] = base64.b64decode(matchLog['regexBase64'].encode()).decode() # back to string
                if 'regex' not in matchLog:
                    logger.warning("Skip {0} regex not present".format(matchLog))
                if 'podLabel' in matchLog:
                    self.ensureAllLabelWatchers(pods, podsWithLabel, waitId, matchLog['podLabel'], matchLog.get('contName', None), 
                                                startCondIndex, matchLog['regex'], logWatchers)
                else:
                    self.ensureWatcher(pods, waitId, matchLog['podKey'], matchLog.get('contName', None),
                                       startCondIndex, matchLog['regex'], logWatchers)

            logWatcherCount = 0
            for uid, watchers in logWatchers.get(str(startCondIndex), {}).items():
                for contNameToWatch in list(watchers.keys()):
                    logWatcherCount += 1
                    w = watchers[contNameToWatch]
                    if w['watch'].conditionMet:
                        return True, w['key'], podBeingWatchedDeleted

            if logWatcherCount==0:
                logger.info("WaitId {0} - startCondIndex {1} has no logwatchers".format(waitId, startCondIndex))

        return False, None, podBeingWatchedDeleted
    
    def initConditionChecker(self, waitId=None):
        if waitId is None:
            waitId = str(uuid.uuid4())
        if waitId not in self.allLogWatchers:
            logger.info("Add condition checker with waitId {0}".format(waitId))
            self.allLogWatchers[waitId] = {}
        if waitId not in self.allStartWatchers:
            self.allStartWatchers[waitId] = {}
        return waitId

    # can be repeatedly called
    def deleteConditionChecker(self, waitId):
        logger.info("Delete condition checker with waitId {0}".format(waitId))
        # stop the remaining logwatchers
        for startCondIndex, allCondWatchers in self.allLogWatchers.get(waitId, {}).items(): # iterate over startCondIndex
            for uid, watchers in allCondWatchers.items(): # iterate over uid of pod being watched
                for contNameToWatch, watcher in watchers.items(): # iterate over contNameToWatch
                    watcher['watch'].stop()

        if waitId in self.allLogWatchers:
            del self.allLogWatchers[waitId]
        if waitId in self.allStartWatchers:
            del self.allStartWatchers[waitId]

    def conditionsMetChecker(self, startConditions, waitId, getPods, failOnPodRemoval=True):
        pods, podsWithLabel = getPods()
        podKeysCondition = {}
        if waitId not in self.allLogWatchers or waitId not in self.allStartWatchers:
            self.initConditionChecker(waitId)
        logWatchers = self.allLogWatchers[waitId]
        startWatchers = self.allStartWatchers[waitId]
        for startCondIndex, startCondition in enumerate(startConditions):
            conditionMet, podKeyCondition, followedPodDeleted = self.startConditionMet(pods, podsWithLabel, waitId, startCondIndex, 
                                                                                       startCondition, startWatchers, logWatchers)
            if followedPodDeleted and failOnPodRemoval:
                logger.info("WaitId {0} pod being followed for condition {1} was deleted".format(waitId, startCondIndex))
                self.deleteConditionChecker(waitId)
                return False, None
            if not conditionMet:
                return True, None # success, but conditions not yet met
            podKeysCondition[podKeyCondition] = pods[podKeyCondition]['metadata']['uid']
        self.deleteConditionChecker(waitId)
        return True, podKeysCondition

    # synchronously wait for conditions to be met
    # failOnPodRemoval: if True, fail if pod being followed for condition meeting is removed
    # pollInterval: interval to poll for condition meeting
    def waitConditionsSync(self, startConditions, failOnPodRemoval=True, pollInterval=2, maxWait=None):
        waitId = self.initConditionChecker()
        logger.info("WaitId: {0} - startConditions: {1}".format(waitId, startConditions))
        startTime = time.time()
        while True:
            success, podKeysCondition = self.conditionsMetChecker(startConditions, waitId, self.getPods, failOnPodRemoval)
            if not success:
                break
            if podKeysCondition is not None:
                break
            time.sleep(pollInterval)
            if maxWait is not None and time.time()-startTime > maxWait:
                logger.info("WaitId {0} - maxWait {1} reached".format(waitId, maxWait))
                success = False
                break

        self.deleteConditionChecker(waitId)
        # if podKeysCondition is being used to establish dependencies, caller should lock and check to make sure pods still exist
        return success, podKeysCondition

def main():
    import argparse
    parser = argparse.ArgumentParser()
    kubeutils.Cluster.addCmdArgs(parser)
    args = parser.parse_args()

    cluster = kubeutils.Cluster.fromCmdArgs(args)
    lock = threading.RLock()

    cc = ConditionsChecker(cluster, lock=lock)
    # conditions = [{'after': [{
    #     'podLabel': 'name=testss',
    #     'contName': 'cont1',
    #     'wait': 10
    # }]}]
    conditions = [{'logMatch': [{
        'podLabel': 'name=testss',
        'contName': 'cont2',
        'regex': 'complete'
    }]}]
    success, podsUsed = cc.waitConditionsSync(conditions, failOnPodRemoval=False)
    logger.info(success)
    logger.info(podsUsed)

if __name__=="__main__":
    main()
