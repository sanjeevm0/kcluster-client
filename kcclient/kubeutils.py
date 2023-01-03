import os
import sys
from kubernetes import client as kclient, config as kcfg, watch, utils as kutils
#import kubewatch as watch
thisPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(thisPath)
import utils
import time
import yaml
import re
import copy
import threadfn
from threadfn import ThreadFn, ThreadFnR
import tempfile
import random
import glob
import hashlib
import threading
import urllib3
import atexit
import inflection
import traceback
import subprocess
import json
from collections import deque
from functools import partial
from typing import Dict, Tuple
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import log
import logging
logger = log.start_log("{0}/logs/kubeutils.log".format(utils.getHome()), logging.DEBUG, logging.INFO, 'w', 'kubelog')

methods = {}
clusters = {}
clusterLock = threading.RLock()
apiObjs = {}
cfgArgs = {}

def setLogger(_logger):
    global logger
    logger = _logger
    threadfn.setLogger(_logger)

def _findMethodElem(method):
    if method in methods:
        return methods[method]
    for elem in dir(kclient):
        if method in eval('dir(kclient.'+elem+')'):
            methods[method] = 'kclient.'+elem
            break
    return methods[method]

def getClientForMethod(clusterId, method, reloadConfig=True, loaderIn=None, waitForLive=True):
    with clusterLock:
        apiObj = utils.getValK(apiObjs, [clusterId, method])
        if apiObj is not None:
            return apiObj
        else:
            if reloadConfig:
                (_, loader, _) = waitForK8s(**cfgArgs[clusterId], waitForLive=waitForLive)
            else:
                loader = loaderIn
            elem = _findMethodElem(method)
            if loader is None:
                client = eval(elem+'()') # an instance of the class
            else:
                client = eval("{0}(loader)".format(elem))
            methodFn = eval('client.'+method) # a function in the instantiated class
            utils.setValK(apiObjs, [clusterId, method], (client, methodFn))
            return client, methodFn

def evalMethod(clusterId, method, **kwargs):
    _, methodFn = getClientForMethod(clusterId, method, True) # reload config to make sure it is correct
    return methodFn(**kwargs)

def replaceDir(x, field, newbase):
    file = x[field]
    x[field] = os.path.join(newbase, os.path.basename(file))

# Load CFG from admin config
def _loadCfg(deploydir, modssl_dir=False):
    kcfgfile = '{0}/kubecfg/admin.yaml'.format(deploydir)
    if modssl_dir:
        sslpath = os.path.abspath('{0}/ssl'.format(deploydir))
        cfg = utils.loadYaml(kcfgfile)
        replaceDir(cfg['clusters'][0]['cluster'], 'certificate-authority', sslpath)
        replaceDir(cfg['users'][0]['user'], 'client-certificate', sslpath)
        replaceDir(cfg['users'][0]['user'], 'client-key', sslpath)
        if "HOME" in os.environ:
            dir = os.environ['HOME']
        else:
            dir = '/'
        kcfgfile = os.path.join(dir, 'tmpkubeconfig.yaml')
        utils.dumpYaml(cfg, kcfgfile)
    kcfg.load_kube_config(kcfgfile)

# Load CFG from a TLS certificate - form a config dynamically
def _loadCfgCert(server, base, ca, cert, key):
    cfgtemplate = '{0}/../kube/kclientcfg.yaml'.format(thisPath)
    tmp = "tmpconfig-{0}.yaml".format(utils.random_string(32))
    utils.render_template(cfgtemplate, tmp, {
        "user": "cluster-admin",
        "api_servers": server,
        "ca": "{0}/{1}".format(base, ca),
        "cert": "{0}/{1}".format(base, cert),
        "key": "{0}/{1}".format(base, key)
    })
    try:
        kcfg.load_kube_config(tmp)
    finally:
        os.remove(tmp)

def rmtmp(fd, name):
    try:
        os.close(fd)
    except Exception:
        pass # already closed
    if os.path.exists(name):
        os.remove(name)

def rmtmp2(name):
    if os.path.exists(name):
        os.remove(name)

def createTmpKubeConfig(server, base, ca, cert, key):
    cfg = {
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [
            {
                "name": "local",
                "cluster": {
                    "certificate-authority": "{0}/{1}".format(base, ca),
                    "server": server,
                }
            }
        ],
        "users": [
            {
                "name": "cluster-admin",
                "user": {
                    "client-certificate": "{0}/{1}".format(base, cert),
                    "client-key": "{0}/{1}".format(base, key)
                }
            }
        ],
        "contexts": [
            {
                "name": "default",
                "context": {
                    "cluster": "local",
                    "user": "cluster-admin"
                }
            }
        ],
        "current-context": "default"
    }
    logger.debug("CFG:\n{0}".format(yaml.safe_dump(cfg)))
    try:
        (fd, tmp) = tempfile.mkstemp(suffix=".yaml")
        logger.info("Use temp file {0}".format(tmp))
        with open(tmp, 'w') as fp:
            yaml.dump(cfg, fp)
        return tmp
    finally:
        atexit.register(rmtmp, fd, tmp)

def _loadCfgCert2(server, base, ca, cert, key):
    tmp = createTmpKubeConfig(server, base, ca, cert, key)
    kcfg.load_kube_config(tmp)

# Load CFG from a Kcluster client
def _loadCfgKclient(id, user):
    home = utils.getHome()
    ctxdir = glob.glob('{0}/.kcluster/{1}*'.format(home, id))
    ctxdir = [c for c in ctxdir if os.path.isdir(c)]
    serverInfo = utils.loadYaml("{0}/servers.yaml".format(ctxdir[0]))
    servers = serverInfo["Servers"]
    servers = [re.sub('(.*):(.*)', '\g<1>:{0}'.format(serverInfo["k8sport"]), s) for s in servers]
    return _loadCfgCert(random.choice(servers), ctxdir[0], "ca-kube.pem", "{0}-kube.pem".format(user), "{0}-kube-key.pem".format(user))

def _loadCfgServiceAccount():
    with open('/var/run/secrets/kubernetes.io/serviceaccount/token') as fp:
        token = fp.read()
    cfg = kclient.Configuration()
    cfg.api_key['authorization'] = token
    cfg.api_key_prefix['authorization'] = 'Bearer'
    cfg.verify_ssl = False
    cfg.host = "https://{0}:{1}".format(os.environ["KUBERNETES_SERVICE_HOST"], os.environ["KUBERNETES_PORT_443_TCP_PORT"])
    return kclient.ApiClient(cfg)

def createApiClient(deploydir, modssl_dir=False):
    try:
        _loadCfg(deploydir, modssl_dir)
        return kclient.ApiClient()
    except Exception:
        return None

def createClient(deploydir, modssl_dir=False):
    try:
        _loadCfg(deploydir, modssl_dir)
        return kclient.CoreV1Api()
    except Exception:
        return None

def createAppClient(deploydir, modssl_dir=False):
    try:
        _loadCfg(deploydir, modssl_dir)
        return kclient.AppsV1Api()
    except Exception:
        return None

def createExtClient(deploydir, modssl_dir=False):
    try:
        _loadCfg(deploydir, modssl_dir)
        return kclient.ExtensionsV1beta1Api()
    except Exception:
        return None

def createBatchClient(deploydir, modssl_dir=False):
    try:
        _loadCfg(deploydir, modssl_dir)
        return kclient.BatchV1Api()
    except Exception:
        return None

def isAlive(client):
    try:
        return client is not None and client.list_node() is not None
    except kclient.rest.ApiException as ex:
        # check for forbidden
        try:
            ret = yaml.safe_load(ex.body)
            if 'message' in ret and "forbidden" in ret['message'].lower():
                return True
            else:
                return False
        except Exception:
            return False
    except Exception:
        return False

def waitForKube(deploydir, modssl_dir=False):
    kclient = None
    while True:
        kclient = createClient(deploydir, modssl_dir)
        if isAlive(kclient):
            break
        time.sleep(5.0)
    return kclient

def waitForK(loader, creator=None, waitForLive=True):
    loaderRet = None
    numTry = 0
    while True:
        logger.debug("waitForK - try {0}".format(numTry))
        try:
            ret = loader()
            if ret is None:
                kubeclient = kclient.CoreV1Api()
            else:
                loaderRet = ret
                kubeclient = kclient.CoreV1Api(ret)
        except Exception as ex:
            logger.debug("waitForK Encounter exception: {0}".format(ex))
            kubeclient = None
        if not waitForLive or isAlive(kubeclient):
            break
        logger.debug("waitForK no exception, but not alive.")
        time.sleep(5.0)
        numTry += 1
    if creator is None:
        return (loaderRet, None)
    else:
        return (loaderRet, creator(loaderRet))

def waitForKClient(id, user):
    #print("ID: {0} USER: {1}".format(id, user))
    (_, created) = waitForK(lambda : _loadCfgKclient(id, user), creator=kclient.CoreV1Api)
    return created

def _waitForK8sHelper(deploydir=None, modssl_dir=False, server=None, base=None, ca=None, cert=None, key=None, id=None, user=None, waitForLive=True):
    with clusterLock:
        if deploydir is not None:
            return waitForK(lambda : _loadCfg(deploydir, modssl_dir), waitForLive=waitForLive)
        elif server is not None:
            return waitForK(lambda : _loadCfgCert2(server, base, ca, cert, key), waitForLive=waitForLive)
        elif id is not None:
            return waitForK(lambda : _loadCfgKclient(id, user), waitForLive=waitForLive)
        else:
            return waitForK(lambda : _loadCfgServiceAccount(), waitForLive=waitForLive)

def getClusterArgs(**kwargs):
    clientArgs, _ = getClientArgs(**kwargs)
    clientArgs.pop('client', None)
    clientArgs.pop('cluster_id', None)
    return clientArgs

def waitForK8s(**kwargs):
    clusterId = getClusterId(**kwargs)
    clusterArgs = getClusterArgs(**kwargs)
    (loaderRet, creatorRet) = _waitForK8sHelper(**clusterArgs)
    return (clusterId, loaderRet, creatorRet)

def getClusterId(**kwargs):
    clusterArgs = getClusterArgs(**kwargs)
    clusterId = utils.kwargHash(**clusterArgs)
    if clusterId not in cfgArgs:
        cfgArgs[clusterId] = clusterArgs # save the mapping for waiting
    return clusterId

def deployAddon(deploydir, name):
    os.system("kubectl apply -f {0}/kubeaddons/{1} --validate=false".format(deploydir, name))

def getNodes(client):
    return client.list_node().to_dict()['items']

def getNodeMetadata(client):
    return [n['metadata'] for n in getNodes(client)]

def getNodeNames(client):
    return [n['name'] for n in getNodeMetadata(client)]

def getNamespaceNames(client):
    return [n['metadata']['name'] for n in client.list_namespace().to_dict()['items']]

def getNsPodNames(client, ns):
    return [p['metadata']['name'] for p in client.list_namespaced_pod(namespace=ns).to_dict()['items']]

def getNsDeploymentNames(appClient, ns):
    return [d['metadata']['name'] for d in appClient.list_namespaced_deployment(namespace=ns).to_dict()['items']]

def getNsServiceAccnts(client, ns):
    return {s['metadata']['name'] : s for s in client.list_namespaced_service_account(namespace=ns).to_dict()['items']}

def getNsSecrets(client, ns):
    return {s['metadata']['name'] : s for s in client.list_namespaced_secret(namespace=ns).to_dict()['items']}

def getServiceToken(client, ns, accntname):
    accnts = getNsServiceAccnts(client, ns)
    secretName = utils.getVal(accnts, accntname+'.secrets.[0].name')
    if secretName is not None:
        secrets = getNsSecrets(client, ns)
        secret = utils.getVal(secrets, secretName+'.data.token')
        if secret is not None:
            return utils.b64d(secret)
    return None

def usertons(client, user):
    # namespace only allows for lowercase letters + dashes
    ns = user.replace('.','-').replace('@','-').replace('_','-').lower()
    # check if namespace exists
    existNs = getNamespaceNames(client)
    nsOrig = ns
    while ns in existNs:
        ns = nsOrig + "-" + utils.random_string(6)
    return (ns, existNs)

#cnvtRe = re.compile(r'([+-.\d]+)(.*)')
# Allow e or E for exponent provided numbers come after it
cnvtRe = re.compile(r'([+-.\deE]+\d+|[+-.\d]+)(.*)')
cnvtMul = {
    '': 1,
    'm': 0.001,
    'K': 1000,
    'Ki': 1024,
    'M': 1000**2,
    'Mi': 1024**2,
    'G': 1000**3,
    'Gi': 1024**3,
    'T': 1000**4,
    'Ti': 1024**4,
    'P': 1000**5,
    'Pi': 1024**5,
    'E': 1000**6,
    'Ei': 1024**6
}

def _convertUnit(x):
    m = cnvtRe.match(x)
    if m is None or len(m.groups()) < 2:
        raise (Exception('Invalid value')) # invalid value
    #return float(m.group(1)) * cnvtMul[m.group(2)]
    if isinstance(cnvtMul[m.group(2)], int):
        try:
            i1 = int(m.group(1))
            return i1 * cnvtMul[m.group(2)]
        except Exception:
            pass

    return float(m.group(1)) * cnvtMul[m.group(2)]

def tryConvertUnit(x):
    try:
        return True, _convertUnit(str(x))
    except Exception:
        return False, 0

def getContainerReqs(container):
    reqs = {'cpu': 0, 'memory': 0, 'nvidia.com/gpu': 0, 'privileged': 0} # other requests may exist
    if utils.getVal(container, 'securityContext') is not None:
        reqs['privileged'] = 1 # any modification from default securityContext
    requests = utils.getVal(container, 'resources.requests')
    if requests is not None:
        for res in requests:
            (success, reqs[res]) = tryConvertUnit(requests[res])
            if not success:
                return False, reqs
    limits = utils.getVal(container, 'resources.limits')
    if limits is not None:
        for res in limits:
            if res in ['nvidia.com/gpu']: # for these resources, also look at limit
                (success, reqs[res]) = tryConvertUnit(limits[res])
                if not success:
                    return False, reqs
    return True, reqs

from collections import Counter
def combineReqs(a, b):
    output = {}
    keys = utils.unionKeys2(a, b)
    for key in keys:
        if key in a and key in b:
            if isinstance(a[key], bool):
                output[key] = a[key] or b[key]
            else:
                output[key] = a[key] + b[key]
        elif key in a:
            output[key] = a[key]
        else:
            output[key] = b[key]
    return output
    #return dict(Counter(a)+Counter(b))

def maxReqs(a, b):
    output = {}
    keys = utils.unionKeys2(a, b)
    for key in keys:
        if key in a and key in b:
            if isinstance(a[key], bool):
                output[key] = a[key] or b[key]
            else:
                output[key] = max(a[key], b[key])
        elif key in a:
            output[key] = a[key]
        else:
            output[key] = b[key]
    return output

def negVal(x):
    return {key: -x[key] for key in x}

def scaleVal(x, scale):
    output = {}
    for key in x:
        if isinstance(x[key], bool):
            output[key] = x[key]
        else:
            output[key] = scale*x[key]
    return output

def divVal(x, y):
    output = {}
    for key in x.keys():
        if key in y and y[key] != 0:
            if isinstance(y[key], bool): # assume True
                output[key] = x[key] / sys.maxsize
            else:
                output[key] = x[key] / y[key]
        elif x[key] == 0:
            output[key] = 0
        else:
            output[key] = None
    for key in y.keys():
        if key not in x:
            output[key] = 0
    return output

def maxDivVal(x, y):
    num = divVal(x, y)
    if None in num.values():
        return (False, 0)
    else:
        vals = list(num.values())
        if len(vals) > 0:
            return (True, max(vals))
        else:
            return (True, 0)

# xs is list of hashes
def addVals(xs):
    output = {}
    for x in xs:
        for key in x.keys():
            if key not in output:
                output[key] = x[key]
            else:
                if isinstance(x[key], bool):
                    output[key] = output[key] or x[key]
                else:
                    output[key] = output[key] + x[key]
    return output

def maxVals(xs):
    output = {}
    for x in xs:
        for key in x.keys():
            if key not in output:
                output[key] = x[key]
            else:
                output[key] = max(output[key], x[key])
    return output

def minVals(xs):
    output = {}
    for x in xs:
        for key in x.keys():
            if key not in output:
                output[key] = x[key]
            else:
                output[key] = min(output[key], x[key])
    return output

def nodeToDict(node):
    if not isinstance(node, dict):
        if isinstance(node, kclient.models.v1_node.V1Node):
            return node.to_dict()
        else:
            raise Exception("Invalid type")
    return node

def podToDict(pod):
    if not isinstance(pod, dict):
        if isinstance(pod, kclient.models.v1_pod.V1Pod):
            return pod.to_dict()
        else:
            raise Exception("Invalid type")
    return pod

def nodeCordoned(node):
    node = nodeToDict(node)
    return utils.getVal(node, 'spec.unschedulable') == True

def nodeSchedulable(node):
    node = nodeToDict(node)
    if utils.getVal(node, 'spec.unschedulable'):
        # node is cordoned
        return False
    else:
        # other reasons -
        # node is either unreachable or is master node most likely
        taints = utils.getVal(node, 'spec.taints')
        if taints is not None:
            for taint in taints:
                if utils.getVal(taint, 'effect').lower() == 'noschedule':
                    return False
        return True

def nodeIsMaster(node):
    node = nodeToDict(node)
    taints = utils.getVal(node, 'spec.taints')
    if taints is not None:
        for taint in taints:
            if utils.getVal(taint, 'effect').lower() == 'noschedule':
                if utils.getVal(taint, 'key').lower() == 'node-role.kubernetes.io/master':
                    return True
    return False

def getinfraNodes(client):
    nodes = getNodes(client)
    infraNodes = []
    for node in nodes:
        if nodeIsMaster(node):
            infraNodes.append(node)
    return infraNodes

def getNodeAvail(node, skipCordon=True):
    node = nodeToDict(node)
    if skipCordon and utils.getVal(node, 'spec.unschedulable'):
        return {}
    avail = utils.getVal(node, 'status.allocatable')
    for key in avail:
        success, avail[key] = tryConvertUnit(avail[key])
        if not success:
            avail[key] = 0
    try:
        maxpods = avail['pods']
    except Exception:
        maxpods = 4096
    avail.update({
        "hostnetwork": True,
        "hostpath": True,
        "privileged": True,
        "pods": maxpods
    })
    return avail

def getPodReqs(pod):
    reqs = None
    podC = utils.getVal(pod, 'spec.containers')
    if podC is not None:
        for c in podC:
            (success, reqC) = getContainerReqs(c)
            if not success:
                return False, reqs
            if reqs is None:
                reqs = reqC
            else:
                reqs = combineReqs(reqs, reqC)
    reqs.update({
        "hostnetwork": 0,
        "hostpath": 0,
        "pods": 1
    })
    if utils.getVal(pod, 'spec.hostNetwork'):
        reqs['hostnetwork'] = 1
    volumes = utils.getVal(pod, 'spec.volumes')
    if volumes is not None:
        for v in volumes:
            if 'hostPath' in v:
                reqs['hostpath'] = 1
                break
    return True, reqs

def convertAll(x, prevSuccess=True):
    if x is None:
        return prevSuccess, {}
    else:
        newSuccess = prevSuccess
        output = {}
        for xKey in x:
            (success, output[xKey]) = tryConvertUnit(x[xKey])
            if not success:
                newSuccess = False
        return newSuccess, output

# return requests and limits of pods, given 
def totalPodReqs(pod, includeInitContainers=True):
    reqs = {}
    limits = {}
    success = True
    podC = utils.getValDef(pod, 'spec.containers')
    for c in podC:
        (success, reqsC) = convertAll(utils.getValDef(c, 'resources.requests'), success)
        (success, limitsC) = convertAll(utils.getValDef(c, 'resources.limits'), success)
        limitsC = maxReqs(limitsC, reqsC) # limits is max
        reqs = combineReqs(reqs, reqsC)
        limits = combineReqs(limits, limitsC)

    if includeInitContainers:
        podC = utils.getValDef(pod, 'spec.initContainers')
        for c in podC:
            (success, reqsC) = convertAll(utils.getValDef(c, 'resources.requests'), success)
            (success, limitsC) = convertAll(utils.getValDef(c, 'resources.limits'), success)
            limitsC = maxReqs(limitsC, reqsC)
            reqs = maxReqs(reqs, reqsC)
            limits = maxReqs(limits, limitsC)

    return success, reqs, limits

# returns whether or not pod has been scheduled onto a node (e.g. assigned a node), and if assigned the hostIP, and nodeName
def podScheduled(pod):
    # don't use pod phase as it is inaccurate
    if pod.status is not None and pod.status.conditions is not None:
        for c in pod.status.conditions:
            if c.type == "PodScheduled" and c.status in [True, "True"]:
                return (True, pod.status.host_ip, pod.spec.node_name)
    return (False, None, None)

def podRunning(pod):
    if pod.status is None or pod.status.conditions is None:
        return False
    if pod.status.phase != "Running":
        return False
    for c in pod.status.conditions:
        if c.type == "Ready" and c.status in [True, "True"]:
            return True
    return False

def getDeploymentReqs(dep):
    replicas = utils.getVal(dep, 'spec.replicas')
    podTemplate = utils.getVal(dep, 'spec.template')
    if replicas is None or podTemplate is None:
        return False, None
    (success, reqs) = getPodReqs(podTemplate)
    if not success:
        return False, None
    return True, scaleVal(reqs, replicas)

def getReqs(spec):
    if spec['kind'] == 'Deployment':
        return getDeploymentReqs(spec)
    if spec['kind'] == 'Pod':
        return getPodReqs(spec)
    return True, None

specTypeCompile = re.compile(r'.*\.(v.*?)_(.*?)\.')
def getSpecFromObj(o):
    d = o.to_dict()
    if 'kind' not in d:
        d['kind'] = None
    if 'api_version' not in d:
        d['api_version'] = None
    if d['kind'] is None or d['api_version'] is None:
        m = specTypeCompile.match(str(type(o)))
        if m is not None:
            if d['api_version'] is None:
                d['api_version'] = m.group(1)
            if d['kind'] is None:
                d['kind'] = inflection.camelize(m.group(2), True)
    return d

def getReqsFromObj(o):
    return getReqs(getSpecFromObj(o))

def hasParent(o):
    if hasattr(o, 'metadata') and o.metadata.owner_references is not None and len(o.metadata.owner_references) > 0:
        if o.metadata.owner_references[0].controller:
            return True
    return False

def _getWatchCtx(lister, **kwargs):
    w = watch.Watch()
    expireTime = 60 # every minute restart watch, bugs in urllib prevent broken connection from terminating watch
    if 'resource_version' in kwargs and kwargs['resource_version'] is None:
        kwargs.pop('resource_version') # unset it
    if 'timeout_seconds' not in kwargs:
        # return a generator which can be iterated over        
        #watcher = w.stream(lister, timeout_seconds=0, **kwargs)
        watcher = w.stream(lister, timeout_seconds=expireTime, **kwargs) # expire after 60 seconds and restart
    else:
        #watcher = w.stream(lister, **kwargs) # return a generator (not a function)
        ts = kwargs.pop('timeout_seconds')
        if ts==0:
            ts = expireTime
        watcher = w.stream(lister, timeout_seconds=min(expireTime, ts), **kwargs)
    return w, watcher

def _watchAndDo(thread : ThreadFnR, listerFn, watcherFn, doFn, stopLoop = lambda : False):
    #print("IN WATCH AND DO")
    doinit = thread.selfCtx.get('doinit', True)
    maxResVer = thread.selfCtx.get('resource_version', None)
    init = {}
    if doinit:
        if stopLoop is None:
            stopLoop = lambda : False
        if stopLoop():
            return
        # Get initial obj list
        doFn('init', None, True) # every start calls this
        try:
            initobjs = listerFn() # keep resource_version unset so that it starts from scratch
            if isinstance(initobjs, dict):
                initobjs = utils.ToClass(initobjs, True, KubeYamlIgnore)
            maxResVer = initobjs.metadata.resource_version # opaque value for the lister function
        except Exception as ex:
            logger.error('_watchAndDo encounters exception:\n {0} {1} {2}'.format(ex, listerFn, watcherFn))
            return # don't set repeat to true, let it terminate
        for obj in initobjs.items:
            init[obj.metadata.uid] = obj
            if stopLoop():
                return
            done = doFn('added', obj, True)
            if done:
                return

        done = doFn("none", None, False) # once after initialization done
        if done:
            return

    w, watcher = watcherFn(maxResVer) # watcher is a generator
    thread.selfCtx['state'] = {'watcher': w}
    thread.selfCtx['doinit'] = True # do init again unless normal termination
    thread.selfCtx['resource_version'] = None # no resource version
    while True:
        try:
            e = next(watcher)
        except StopIteration:
            # normal termination
            logger.info("Normal termination")
            if maxResVer is not None:
                logger.info("Next watch starts at {0}".format(maxResVer))
                thread.selfCtx['doinit'] = False
                thread.selfCtx['resource_version'] = maxResVer
            else:
                logger.info("Next watch starts from scratch")
            break
        except Exception as e:
            logger.info("Generator encounters exception {0}".format(e))
            break # also break

        if e['type'] not in ["ADDED", "DELETED", "MODIFIED"]:
            logger.info("Unknown type {0} encountered -- stop loop".format(e['type'])) # e.g. "ERROR"
            break
        #print(e)
        #raw = e['raw_object'] # accessible as map
        if isinstance(e['object'], dict):
            obj = utils.ToClass(e['object'], True, KubeYamlIgnore)
        else:
            obj = e['object']
        maxResVer = obj.metadata.resource_version
        try:
            if e['type'].lower()=="added" and obj.metadata.uid in init and init[obj.metadata.uid].metadata.resource_version==obj.metadata.resource_version:
                logger.debug("Already processed: {0}".format(obj.metadata.uid))
                init.pop(obj.metadata.uid)
                continue
            # elif e['type'].lower()=="added":
            #     if obj.metadata.uid not in init:
            #         logger.debug("{0} not in init".format(obj.metadata.uid))
            #     elif init[obj.metadata.uid].metadata.resource_version != obj.metadata.resource_version:
            #         logger.debug("Res version no match {0} <> {1}".format(init[obj.metadata.uid].metadata.resource_version, obj.metadata.resource_version))                
        except Exception as ex:
            logger.error("_watchAndDo Encounter exception {0}".format(ex))
            pass
        if stopLoop():
            logger.info("WatchAndDoStopLoop")
            w.stop()
            return
        done = doFn(e['type'].lower(), obj, False)
        if done:
            logger.info("WatchAndDoStopLoopDone")
            w.stop()
            return
        #print("Start next watch")
    logger.info("WatchAndDoLoopExits")
    if ('timeout_seconds' not in thread.selfCtx or thread.selfCtx['timeout_seconds'] <= 0 or
        (time.time()-thread.selfCtx['thread_start_time']) < thread.selfCtx['timeout_seconds']):
        logger.info("WATCH THREAD {0}-{1} STOPS BYITSELF - REPEAT LOOP".format(thread.name, thread.threadID))
        thread.selfCtx['repeat'] = True
    #time.sleep(20) # sleep only for testing if trackObj correctly handles objects deleted during thread restarts

def _getListerAndWatcher(fn, **kwargs):
    listerFn = lambda : fn(**kwargs)
    watcherFn = lambda rv : _getWatchCtx(fn, resource_version=rv, **kwargs)
    return listerFn, watcherFn

def _getListerAndWatcherFromClient(lister, **kwargs):
    clientArgs, remArgs = getClientArgs(**kwargs)
    if 'client' in clientArgs:
        clientMethod = eval("clientArgs['client'].{0}".format(lister))
    elif len(clientArgs) > 0:
        with clusterLock:
            (clusterId, loaderRet, _) = waitForK8s(**clientArgs)
            _, clientMethod = getClientForMethod(clusterId, lister, False, loaderRet)
        clientArgs.pop('cluster_id', None) # ignore and remove if it exists
    else:
        clusterId = clientArgs.pop('cluster_id') # raise error if not found
        logger.debug("Start watch for cluster {0}".format(clusterId))
        _, clientMethod = getClientForMethod(clusterId, lister, True)
    listerFn, watcherFn = _getListerAndWatcher(clientMethod, **remArgs)
    return listerFn, watcherFn

def _watcherThreadStart(t, finisher=None, **kwargs):
    if finisher is not None:
        t.selfCtx['finisher'] = finisher
    if 'timeout_seconds' in kwargs:
        t.selfCtx['timeout_seconds'] = kwargs['timeout_seconds']
        t.selfCtx['thread_start_time'] = time.time()
    t.daemon = True
    t.start()

# returns clientArgs, remArgs
def getClientArgs(**kwargs):
    return utils.kwargFilter(['deploydir', 'modssl_dir', 'server', 'base', 'ca', 'cert', 'key', 'id', 'user', 'client', 'cluster_id', 'waitForLive'], **kwargs)

# To use - example:
#
# kubeutils.waitForK8s(id='3x',user='name@example.com')
# stop = False
# stopper = lambda : stop
# printer = lambda event,obj,init : print("{0}:{1}:{2}".format(event,obj,init))
# kubeutils.WatchObjThread(0, 'NodeWatcher', {}, printer, stopper, 'list_node', None, cluster_id=****)
# kubeutils.WatchObjThread(1, 'Kube-System Pod Watcher', {}, printer, stopper, 'list_namespaced_pod', None, 'cluster_id'=****, namespace='kube-system')
# stop = True # to stop watching
def WatchObjThread(threadId, name, sharedCtx, callback, stopLoop, lister, finisher=None, **kwargs):
    #print("IN WATCH OBJ")
    listerFn, watcherFn = _getListerAndWatcherFromClient(lister, **kwargs)
    t = ThreadFnR(threadId, name, sharedCtx, _watchAndDo, listerFn, watcherFn, callback, stopLoop)
    _watcherThreadStart(t, finisher, **kwargs)
    return t

threadIdLock = threading.Lock()
threadIdCnt = -1
def getThreadId():
    with threadIdLock:
        global threadIdCnt
        threadId = threadIdCnt + 1
        threadIdCnt += 1
    return threadId

def WatchObjOnCluster(cluster_id, threadName, sharedCtx, callback, stopLoop, lister, **kwargs):
    threadId = getThreadId()
    kwargs.update({'cluster_id': cluster_id})
    WatchObjThread(threadId, threadName, sharedCtx, callback, stopLoop, lister, **kwargs)

def GetHttpsPort(ports):
    for port in ports:
        if port.name=="https":
            return port

def GetApiServerList(clusterId, apiPodPrefix='kube-apiserver-', apiPodNs='kube-system'):
    try:
        pods = evalMethod(clusterId, 'list_namespaced_pod', namespace=apiPodNs)
        nodes = evalMethod(clusterId, 'list_node')
        servers = []
        for pod in pods.items:
            logger.debug("PodName: {0}".format(pod.metadata.name))
            if pod.metadata.name.startswith(apiPodPrefix):
                nodeName = pod.spec.node_name
                hostIp = pod.status.host_ip # internal IP
                hostPort = GetHttpsPort(pod.spec.containers[0].ports).host_port
                logger.info("APIServerPod: {0} {1} {2} - search for node {3}".format(nodeName, hostIp, hostPort, nodeName))
                for node in nodes.items:
                    if nodeName == node.metadata.name:
                        # order of precedence: externalIP -> fqdn in labels -> externalIP in labels
                        logger.info("RunningOnNode {0}".format(nodeName))
                        externalIPFound = False
                        for addr in node.status.addresses:
                            if addr.type == "ExternalIP":
                                serverName = "https://{0}:{1}".format(addr.address, hostPort)
                                servers.append(serverName)
                                logger.info("Using ExternalIP {0}".format(serverName))
                                externalIPFound = True
                                break
                        if externalIPFound:
                            break
                        if 'fqdn' in node.metadata.labels:
                            serverName = "https://{0}:{1}".format(node.metadata.labels['fqdn'], hostPort)
                            servers.append(serverName)
                            logger.info("Using fqdn from label {0}".format(serverName))
                            break
                        if 'externalIP' in node.metadata.labels:
                            serverName = "https://{0}:{1}".format(node.metadata.labels['externalIP'], hostPort)
                            servers.append(serverName)
                            logger.info("Using externalIP from annotation {0}".format(serverName))
                            break
                        logger.error("Unable to determine API server address for node {0}".format(nodeName))
                        #raise Exception("Unable to determine API server address")
                        # api server pod skipped
        return servers
    except Exception as ex:
        logger.error("Encounter exception {0}".format(ex))
        return None

def getServers(serverFile, servers):
    if servers is not None:
        return servers # servers overrides serverFile
    if serverFile is not None:
        with open(serverFile, 'r') as fp:
            return yaml.safe_load(fp)
    return None

def DoOnServers(doer, *args, **kwargs):
    serverArgs, remArgs = utils.kwargFilter(['servers', 'serverFile', 'resetTime', 'numTry'], **kwargs)
    servers = serverArgs.pop('servers', None)
    serverFile = serverArgs.pop('serverFile', None)
    numTry = serverArgs.pop('numTry', 1)
    resetTime = serverArgs.pop('resetTime', 5.0)
    lastTry = {}
    tryCnt = 0
    while tryCnt < numTry:
        #print("TryCnt: {0} {1}".format(tryCnt, numTry))
        numSkip = 0
        servers = getServers(serverFile, servers)
        random.shuffle(servers)
        for _, server in enumerate(servers):
            remArgs.update({'server': server})
            timeSinceLastTry = time.time() - lastTry.get(server, 0.0)
            if timeSinceLastTry < resetTime:
                numSkip += 1
                continue
            try:
                return True, 200, doer(*args, **remArgs)
            except kclient.rest.ApiException as ex:
                logger.info('Server found, but encounter API exception {0} {1} {2}'.format(ex, args, kwargs))
                return True, ex.status, None
            except Exception as ex:
                logger.warning('DoOnServers encounters exception {0} {1}'.format(type(ex), ex))
                pass # try a different server
            lastTry[server] = time.time() # last time tried on this server
        if numSkip==len(servers):
            time.sleep(resetTime)
        tryCnt += 1
    logger.warning('Server not found {} {}'.format(args, kwargs))
    return False, 0, None

# The following will get stuck in waitForK8s, better to use DoOnServers
def DoOnCluster(doer, **kwargs):
    def doFn(**remArgs):
        _, doArgs = getClientArgs(**remArgs)
        cluster_id = getClusterId(**remArgs)
        _, methodFn = getClientForMethod(cluster_id, doer, reloadConfig=True, loaderIn=None, waitForLive=False)
        return methodFn(**doArgs)
    return DoOnServers(doFn, **kwargs)

# infinite watch across multiple api servers (until termination)
def _watchObjOnACluster(_, threadName, sharedCtx, callback, stopLoop, lister, apiPodPrefix='kube-apiserver-', apiPodNs='kube-system', **kwargs):
    serverArgs, remArgs = utils.kwargFilter(['servers', 'serverFile', 'resetTime', 'writeServerFile', 'disconnect'], **kwargs)
    servers = copy.deepcopy(serverArgs.pop('servers', None))
    serverFile = serverArgs.pop('serverFile', None)
    writeServerFile = serverArgs.pop('writeServerFile', False)
    resetTime = serverArgs.pop('resetTime', 5.0) # resetTime defines how long to wait before server can be tried again, default 5.0
    lastTry = {}
    threadId = getThreadId()
    startTime = time.time()
    while True:
        numSkip = 0
        serverReadFromFile = (servers is None)
        servers = getServers(serverFile, servers)
        random.shuffle(servers)
        for _, server in enumerate(servers):
            logger.info("Use server {0}".format(server))
            remArgs.update({'server': server})
            cluster_id = getClusterId(**remArgs)
            #remArgs.update({'cluster_id': cluster_id})
            timeSinceLastTry = time.time() - lastTry.get(server, 0.0)
            if timeSinceLastTry < resetTime:
                numSkip += 1
                continue
            # update server list here if needed
            serversChanged = False
            if writeServerFile and serverFile is not None:
                logger.info("ClusterId: {0} ServerArgs: {1}".format(cluster_id, remArgs))
                newServers = GetApiServerList(cluster_id, apiPodPrefix, apiPodNs)
                logger.info("Servers: {0} ServerFile: {1}".format(newServers, serverFile))
                if newServers is not None:
                    serversChanged = (set(newServers) != set(servers))
                    if serversChanged or not serverReadFromFile:
                        logger.info("ServersDumped: Old: {0} New: {1} ReadFromFile: {2}".format(servers, newServers, serverReadFromFile))
                        with open(serverArgs['serverFile'], 'w') as fp:
                            yaml.dump(newServers, fp)
            #print("STARTING WATCHOBJ")
            t = WatchObjThread(threadId, threadName, sharedCtx, callback, stopLoop, lister, **remArgs)
            t.join()
            if stopLoop():
                return
            if 'timeout_seconds' in kwargs and kwargs['timeout_seconds'] > 0 and time.time()-startTime > kwargs['timeout_seconds']:
                return
            if serversChanged:
                break # break the enumeration over servers
            lastTry[server] = time.time()
        if numSkip==len(servers):
            if 'disconnect' in serverArgs:
                serverArgs['disconnect']() # call the disconnect callback
            time.sleep(resetTime)
        if serverFile is not None:
            servers = None # reread from file in next iteration

#Usage example
# import kubeutils
# cb = lambda e, o, i : print("{0}: {1}".format(e, o.metadata.name)) if o is not None else None
# lister = 'list_namespaced_pod'
# stopLoop = lambda : stopper
# ca = 'ca-kube.pem'
# cert = 'sanjeevm0@hotmail.com-kube.pem'
# key = 'sanjeevm0@hotmail.com-kube-key.pem'
# stopper = False
# base = 'g:/OneDrive/sanjeevm/.kcluster/jstl6q5a'
# kubeutils.WatchObjOnACluster('A', {}, cb, stopLoop, lister, servers=['https://sanjeevm4-infra-1.westus2.cloudapp.azure.com:6443'], \
#    serverFile="{0}/servers2.yaml".format(base), base=base, ca=ca, cert=cert, key=key, namespace='default', \
#    timeout_seconds=10)
def WatchObjOnACluster(*args, **kwargs):
    return _watchObjOnACluster(None, *args, **kwargs)

# same as for WatchObjOnACluster, except runs in thread
def WatchObjClusterThread(threadName, sharedCtx, *args, **kwargs):
    if 'finisher' in kwargs:
        finisher = kwargs.pop('finisher') # run finisher at end
    else:
        finisher = None
    t = ThreadFn(getThreadId(), threadName, sharedCtx, _watchObjOnACluster, threadName+"A", sharedCtx, *args, **kwargs)
    _watcherThreadStart(t, finisher, **kwargs)
    return t

def getKind(o):
    try:
        if o.kind is not None:
            return o.kind
        return re.match(r'.*\.V.(.*)\'\>', str(type(o))).group(1)
    except Exception:
        return str(type(o))     

# Object tracker
class ObjTracker:
    #(sharedCtx, stopLoop, callback, lister, apiPodPrefix='kube-apiserver-', apiPodNs='kube-system', **kwargs):
    # args encompasses: stopLoop, lister
    # callback is additional callback after trackObjs is called, finisher is additional finisher
    # kwargs includes: apiPodPrefix, apiPodNs, additional **kwargs
    def __init__(self, sharedCtx, *args, callback = lambda a,b,c,d : None, finisher = lambda : None, disconnect  = lambda : None, **kwargs):
        self.objs = {} # obj key is uid
        self.deletedObjQ = deque()
        self.deletedObjs = {} # garbage collected eventually - only track objs deleted since tracker started
        self.sharedCtx = sharedCtx
        self.callback = callback # Additional callback
        self.finisher = finisher # Additional callback on finish
        self.onDisconnect = disconnect # Additional callback on disconnect
        self.stopper = args[0]
        self.lister = args[1]
        self.clusterName = kwargs.pop('clusterName', "NONAME_PROVIDED")
        self.args = args
        self.kwargs = kwargs
        self.stop = False
        self.gcFreq = 10.0
        self.timeTillGc = 30.0
        self.started = False
        self.connected = True # connected unless told otherwise
        self.init = False
        self.lock = threading.RLock()

        # for standard callback, use setParams to set
        self.event = None
        self.predicate = None
        self.replacements = {}
        self.updaetObj = False
        self.addlCallback = None
        self.useUid = False
        self.trackedObjs = {}

    # try-catch callback with optional lock
    @staticmethod
    def TryCb(cb, lock, evType, obj, init, objPrev):
        try:
            if lock is None:
                cb(evType, obj, init, objPrev)
            else:
                with lock:
                    cb(evType, obj, init, objPrev)
        except Exception as ex:
            logger.error("ERROR: {0} {1}".format(ex, traceback.format_exc()))

    def setDefaultCallback(self, event : threading.Event=None, predicate=None, replacements={}, updateObj=False,
        addlCallback=None, callbackLock=None, useUid=False, setEventOnDelete=True):

        self.event = event
        self.predicate = predicate
        self.replacements = replacements
        self.updateObj = updateObj
        self.addlCallback = addlCallback
        self.useUid = useUid
        self.setEventOnDelete = setEventOnDelete
        # update the callback
        self.callback = partial(ObjTracker.TryCb, self.standardCallback, callbackLock)

    def standardCallback(self, evType, obj, init, objPrev):
        process, deleted, objD = ObjTracker.ProcessObj(self.predicate, evType, obj, self.trackedObjs,
            replacements=self.replacements, updateObj=self.updateObj, useUid=self.useUid)
        if not process and evType!="none":
            return # no need to process, predicate not met
        if self.addlCallback is not None:
            self.addlCallback(evType, deleted, objD)
        if self.event is not None and (evType=="none" or self.setEventOnDelete or not deleted):
            self.event.set()

    # A standard callback which keeps objects in "objs" by key (using toKey)
    # returns (processed, deleted) tuple
    @staticmethod
    def ProcessObj(predicate, evType, obj, objs, replacements={}, updateObj=False, useUid=False):
        if obj is None:
            return False, False, None

        objO = copy.deepcopy(obj)
        obj = ToYaml(obj, replacements) # replace _ip_ with _IP_ (e.g. for IP addresses)
        if obj['kind']=="Pod":
            obj['running'] = podRunning(objO)
        if 'key' in obj:
            raise Exception("Already has a field called key")
        obj['key'] = ToKey(obj)
        obj['typekey'] = obj['kind'] + "/" + obj['key']

        if useUid:
            key = obj['metadata']['uid']
        else:
            key = obj['key']

        if not predicate(obj):
            objs.pop(key, None)
            return False, False, obj

        if utils.getValDef(obj, ['metadata', 'deletionTimestamp'], None, None) is not None or evType=="deleted":
            objs.pop(key, None)
            return True, True, obj

        if updateObj:
            utils.updateToVal(objs, key, copy.deepcopy(obj))
        else:
            objs[key] = copy.deepcopy(obj)
        return True, False, obj

    # init=True implies performing init
    def trackObj(self, event, obj, init):
        with self.lock:
            if event == 'init':
                logger.info("Reinit trackObj")
                self.init = False # go back to uninit state
                self.seenInInit = {}
                return
            self.connected = True # any notification with message means we are connected
            # exit for duplicate add (e.g. watcher thread restarts) - no callback needed
            if event == 'added' and init:
                self.seenInInit[obj.metadata.uid] = True
            if event == 'added' and obj is not None and obj.metadata.uid in self.objs:
                if obj.metadata.resource_version==self.objs[obj.metadata.uid].metadata.resource_version:
                    return # no callback, already processed
            if event == 'none':
                assert(not init)
                # check seenInInit -> in case anything deleted in between thread restarts
                toPop = []
                #print(self.seenInInit)
                for objId, cachedObj in self.objs.items():
                    if objId not in self.seenInInit:
                        logger.info("Object deleted in between thread restarts {0} {1}".format(objId, cachedObj.metadata.name))
                        toPop.append(objId)
                for objId in toPop:
                    delObj = self.objs.pop(objId)
                    self.callback('deleted', delObj, True, None)
                self.init = True
            objPrev = None
            if obj is not None:
                objId = obj.metadata.uid
                logger.info("{0}: Cluster: {1} EvType: {2} Obj: {3}".format(getKind(obj), self.clusterName, event, obj.metadata.name))
                logger.debug("{0}:\n{1}".format(event, obj))
                if objId in self.objs:
                    objPrev = self.objs[objId]
                    objDiff = utils.diff(obj.to_dict(), self.objs[objId].to_dict(), False)
                    logger.debug("Diffs:{0}:\n{1}".format(event, objDiff))
                else:
                    logger.debug("Diffs: ObjectNotPresentBefore")
                if event=="deleted":
                    if objId not in self.objs:
                        logger.error('Not present object being deleted - {0}'.format(obj))
                    # get last prior to delete, or current
                    self.deletedObjs[objId] = self.objs.pop(objId, obj)
                    self.deletedObjQ.append((time.time(), objId))
                else:
                    self.objs[objId] = obj
            self.callback(event, obj, init, objPrev)

    def gc(self, _):
        while True:
            #print("GC Start")
            with self.lock:
                if self.stop:
                    return
                curTime = time.time()
                while (len(self.deletedObjQ) > 0) and (curTime - self.deletedObjQ[0][0] >= self.timeTillGc):
                    (_, idToDel) = self.deletedObjQ.popleft()
                    delObj = self.deletedObjs.pop(idToDel, None)
                    logger.info("GarbageCollect:{0}:{1}".format(idToDel, delObj.metadata.name))
            #print("GC End")
            time.sleep(self.gcFreq)

    def snapshot(self):
        with self.lock:
            if self.started:
                objs = copy.deepcopy(self.objs)
                delObjs = copy.deepcopy(self.deletedObjs)
                init = self.init
                connected = self.connected
                started = self.started
            else:
                objs = None
                delObjs = None
                init = False
                connected = False
                started = self.started
                #raise Exception("Object Tracker has stopped -- run start to restart")
        return objs, delObjs, init, connected, started

    def getObjName(self, o, addNamespace):
        if addNamespace and hasattr(o.metadata, 'namespace'):
            return "{}/{}".format(o.metadata.namespace, o.metadata.name)
        else:
            return o.metadata.name

    def snapshotByName(self, addNamespace=True):
        with self.lock:
            if self.started:
                objs = {}
                for _, o in self.objs.items():
                    objs[self.getObjName(o, addNamespace)] = copy.deepcopy(o)
                delObjs = {}
                for _, o in self.deletedObjs.items():
                    delObjs[self.getObjName(o, addNamespace)] = copy.deepcopy(o)
                init = self.init
                connected = self.connected
                started = self.started
            else:
                objs = None
                delObjs = None
                init = False
                connected = False
                started = self.started
                #raise Exception("Object Tracker has stopped -- run start to restart")
        return objs, delObjs, init, connected, started

    def finished(self, threadSelfCtx):
        with self.lock:
            self.stop = True # to stop gc thread
            self.finisher() # additional finisher
            self.started = False

    def disconnect(self):
        with self.lock:
            self.connected = False
            self.onDisconnect() # additional callback up on disconnect

    def start(self):
        with self.lock:
            if not self.started:
                t = ThreadFn(getThreadId(), "ObjTracker-GarbageCollect-{0}-{1}".format(self.clusterName, self.lister), {}, self.gc)
                t.daemon = True
                t.start()
                wt = WatchObjClusterThread("ObjTracker-{0}-{1}".format(self.clusterName, self.lister), self.sharedCtx, self.trackObj, *self.args, 
                    finisher=self.finished, disconnect=self.disconnect, **self.kwargs)
                self.started = True
                return wt
        return None

# Supports token (e.g. service token, and TLS certs for auth)
class Cluster():
    def __init__(self, name=None, api_key=None, base=None, ca=None, cert=None, key=None, servers=None, serverFile=None,
        kubeconfig=None, kubeconfigYaml=None, kubeconfiguser=None, forceOverwrite=True, inPodCluster=False):
        self.name = name
        self.api_key = api_key
        self.inPodCluster = inPodCluster
        if inPodCluster:
            with open('/var/run/secrets/kubernetes.io/serviceaccount/token') as fp:
                token = fp.read()
            self.name = "InPodCluster"
            self.api_key = token
            self.serverFileFixed =  None
            self.serversFixed = ["https://{0}:{1}".format(os.environ["KUBERNETES_SERVICE_HOST"], os.environ["KUBERNETES_PORT_443_TCP_PORT"])]
        elif kubeconfig is not None or kubeconfigYaml is not None:
            self.kubeconfig = kubeconfig
            self.kubeconfigYaml = kubeconfigYaml
            self.kubeconfiguser = kubeconfiguser
            self.forceOverwrite = forceOverwrite
            self.loadFromKubeConfig()
        else:
            self.base = base
            self.ca = ca
            self.cert = cert
            self.key = key
            self.serversFixed = servers
            self.serverFileFixed = serverFile
        if not inPodCluster and self.serversFixed is not None:
            self.kubeConfigFile = createTmpKubeConfig(self.serversFixed[0], self.base, self.ca, self.cert, self.key)
        else:
            self.kubeConfigFile = None
        self.useKubectl = False
        self.clients = {}
        self.methods = {}
        self.trackers : dict[str, Tuple[ObjTracker, dict]] = {} # options

    def setUseKubectl(self, useKubectl):
        self.useKubectl = useKubectl    

    @staticmethod
    def addCmdArgs(parser):
        parser.add_argument('--aksname', '-aksname', nargs='+', default=None, required=False, help="AKS cluster of form: <resourceGroup> <clusterName>")
        parser.add_argument('--kcfg', '-kcfg', nargs='+', default=None, required=False, help="Kube config cluster of form: <kubeConfigFile> <clusterName> <clusterUser>")
        parser.add_argument('--kcert', '-kcert', nargs='+', default=None, required=False, help="Kube certs of form: <Server> <Base> <CA> <Cert> <Key>")
        parser.add_argument('--kdef', '-kdef', action='store_true', help="Use default Kubeconfig file and current context")

    @staticmethod
    def defCluster():
        kubeconfig = os.path.join(os.environ['HOME'], '.kube', 'config')
        config = utils.loadYaml(kubeconfig)
        defConfig = [v for v in config['contexts'] if v['name']==config['current-context']][0]
        return Cluster(kubeconfig=kubeconfig, name=defConfig['context']['cluster'], kubeconfiguser=defConfig['context']['user'])

    @staticmethod
    def fromCmdArgs(args):
        if args.aksname is not None:
            return Cluster.aksname(args.aksname[0], args.aksname[1])
        elif args.kcfg is not None:
            return Cluster(kubeconfig=args.kcfg[0], name=args.kcfg[1], kubeconfiguser=args.kcfg[2])
        elif args.kcert is not None:
            return Cluster(servers=[args.kcert[0]], base=args.kcert[1], ca=args.kcert[2], cert=args.kcert[3], key=args.kcert[4])
        elif args.kdef:
            return Cluster.defCluster()
        else:
            return Cluster(inPodCluster=True) # run from within a pod

    @staticmethod
    def aksname(resgrp, name):
        kubeconfig = os.path.join(os.environ['HOME'], '.kube', 'config')
        kubeconfiguser = 'clusterUser_{0}_{1}'.format(resgrp, name)
        return Cluster(name=name, kubeconfig=kubeconfig, kubeconfiguser=kubeconfiguser)

    @staticmethod
    def fromconfig(name, resgrp=None, user=None):
        kubeconfig = os.path.join(os.environ['HOME'], '.kube', 'config')
        if resgrp is not None:
            kubeconfiguser = 'clusterUser_{0}_{1}'.format(resgrp, name)
        else:
            kubeconfiguser = user
        return Cluster(name=name, kubeconfig=kubeconfig, kubeconfiguser=kubeconfiguser)

    def loadFromKubeConfig(self):
        ncfg = {}
        if self.kubeconfig is not None:
            self.base, _ = os.path.split(self.kubeconfig)
        else:
            self.base = tempfile.gettempdir()
        if self.base=="":
            self.base = "." # otherwise loadCfgCert2 will try to load as "/file"
        self.ca = "{0}-5f4rvds1d3sa12-ca.pem".format(self.name)
        self.cert = "{0}-5f4rvds1d3sa12-cert.pem".format(self.name)
        self.key = "{0}-5f4rvds1d3sa12-key.pem".format(self.name)
        self.serverFileFixed = None
        caName = os.path.join(self.base, self.ca)
        certName = os.path.join(self.base, self.cert)
        keyName = os.path.join(self.base, self.key)
        if self.kubeconfig is not None:
            kconfig = utils.loadYaml(self.kubeconfig)
        else:
            kconfig = self.kubeconfigYaml
            self.forceOverwrite = True
        # try best to remove these at exit
        atexit.register(rmtmp2, caName)
        atexit.register(rmtmp2, certName)
        atexit.register(rmtmp2, keyName)
        for c in kconfig['clusters']:
            if c['name'] == self.name:
                if not os.path.exists(caName) or self.forceOverwrite:
                    with open(caName, "wt") as fp:
                        fp.write(utils.b64d(c['cluster']['certificate-authority-data']))
                self.serversFixed = [c['cluster']['server']]
                utils.setValK(ncfg, ['clusters', 0], c)
                break
        for u in kconfig['users']:
            if self.kubeconfiguser is None or u['name'] == self.kubeconfiguser: # if username is None, take first user
                if not os.path.exists(certName) or self.forceOverwrite:
                    with open(certName, "wt") as fp:
                        fp.write(utils.b64d(u['user']['client-certificate-data']))
                if not os.path.exists(keyName) or self.forceOverwrite:
                    with open(keyName, "wt") as fp:
                        fp.write(utils.b64d(u['user']['client-key-data']))
                utils.setValK(ncfg, ['users', 0], u)
                break
        return ncfg

    # args = (sharedCtx, toStop, listMethod)
    def tracker(self, *args, **kwargs):
        if self.inPodCluster:
            _, client, _ = self.getMethodAndClient(self.serversFixed[0], args[2])
            return ObjTracker(*args, **kwargs, clusterName=self.name, servers=self.serversFixed, serverFile=self.serverFileFixed,
                client=client)
        else:
            return ObjTracker(*args, **kwargs, clusterName=self.name, servers=self.serversFixed, serverFile=self.serverFileFixed,
                base=self.base, ca=self.ca, cert=self.cert, key=self.key)

    def addTracker(self, name, watchMethod, event : threading.Event=None, predicate=None, replacements={}, updateObj=False,
        addlCallback=None, callbackLock=None, useUid=False, setEventOnDelete=True, writeBackUpdates=False, 
        timeout_seconds=0, stopMethod = lambda : False, sharedCtx = {}, **kwargs):
 
        writeServerFile = (len(self.trackers)==0)
        t = self.tracker(sharedCtx, stopMethod, watchMethod, callback=None, writeServerFile=writeServerFile,
            timeout_seconds=timeout_seconds, **kwargs)
        t.setDefaultCallback(event, predicate, replacements, updateObj, addlCallback, callbackLock, useUid, setEventOnDelete)
        logger.info("Add tracker with name {0} for method {1}".format(name, watchMethod))
        self.trackers[name] = (t, {'writeBackUpdates': writeBackUpdates})
        return t

    def startTrackers(self):
        for _, (t, _) in self.trackers.items():
            t.start()

    # processOne gets snapshot dictionary of items
    def processLoop(self, processOne, event : threading.Event, loopLock : threading.RLock):
        while True:
            event.wait()
            writeBack = False
            with loopLock:
                event.clear()
                objs = {}
                init = True
                for tname, (t, opt) in self.trackers.items():
                    if not t.init:
                        init = False # not init yet
                        break
                    objs[tname] = copy.deepcopy(t.trackedObjs)
                    writeBack = writeBack or opt['writeBackUpdates']
                if not init:
                    continue

            processOne(objs)

            if writeBack:
                with loopLock:
                    for tname, (t, _) in self.trackers.items():
                        t.trackedObjs = copy.deepcopy(objs[tname]) # keep updates made intact

    def processLoopThread(self, processOne, event, loopLock):
        t = threading.Thread(target=self.processLoop, args=(processOne, event, loopLock))
        t.daemon = True
        return t

    def getApiClient(self, server):
        if server not in self.clients:
            cfg = kclient.Configuration()
            cfg.verify_ssl = False
            if self.api_key is not None:
                cfg.api_key['authorization'] = self.api_key # a token
                cfg.api_key_prefix['authorization'] = 'Bearer'
            else:
                cfg.ssl_ca_cert = "{0}/{1}".format(self.base, self.ca)
                cfg.cert_file = "{0}/{1}".format(self.base, self.cert)
                cfg.key_file = "{0}/{1}".format(self.base, self.key)
            cfg.host = server
            self.clients[server] = kclient.ApiClient(cfg)
        return self.clients[server]

    def getMethodAndClient(self, server, method):
        #print("Server={0} Method={1}".format(server, method))
        ret = utils.getValK(self.methods, [server, method])
        if ret is not None:
            (apiClient, client, methodFn) = ret
            #print("methodFn={0}".format(methodFn))
            if apiClient is not None and client is not None and methodFn is not None:
                return apiClient, client, methodFn
        elem = _findMethodElem(method)
        #print(elem)
        apiClient = self.getApiClient(server)
        #print(apiClient)
        client = eval("{0}(apiClient)".format(elem))
        #print(client)
        methodFn = eval('client.'+method) # a function in the instantiated class
        #print(methodFn)
        utils.setValK(self.methods, [server, method], (apiClient, client, methodFn))
        return apiClient, client, methodFn

    def getMethod(self, server, method):
        _, _, methodFn = self.getMethodAndClient(server, method)
        return methodFn

    def call_api_server(self, *args, **kwargs):
        server = kwargs.pop('server')
        apiClient = self.getApiClient(server)
        #print("Call API with: {0} {1}".format(args, kwargs))
        logger.info("Start API call to server {0} - path {1}".format(server, args[0]))
        return apiClient.call_api(*args, **kwargs)

    def call_api(self, *args,
                 auth_settings=['BearerToken'],
                 header_params={'Accept': 'application/json', 'Content-Type': 'application/json'},
                 response_type='object',
                 async_req=False,
                 _return_http_data_only=True,
                 _preload_content=True, **kwargs):
                 # body if needed, post_params, files, _request_timeout, collection_formats (if needed):
        if self.serverFileFixed:
            kwargs.update({'serverFile': self.serverFileFixed})
        if self.serversFixed:
            kwargs.update({'servers': self.serversFixed})
        return DoOnServers(self.call_api_server, *args, auth_settings=auth_settings, header_params=header_params,
            response_type=response_type, async_req=async_req, _return_http_data_only=_return_http_data_only,
            _preload_content=_preload_content, **kwargs)

    def call_method_server(self, method, *args, **kwargs):
        server = kwargs.pop('server')
        #print(server)
        methodFn = self.getMethod(server, method)
        logger.info("Start API server {0} - method {1}".format(server, method))
        return methodFn(*args, **kwargs)

    def call_method(self, method, *args, **kwargs):
        if self.useKubectl:
            return self.call_method_kubectl(method, *args, **kwargs)
        kwargs.pop('wait', None) # remaining does not suppoort "wait" option

        if self.serverFileFixed:
            kwargs.update({'serverFile': self.serverFileFixed})
        if self.serversFixed:
            kwargs.update({'servers': self.serversFixed})
        return DoOnServers(self.call_method_server, method, *args, **kwargs)

    def call_method_kubectl(self, method, *args, **kwargs):
        if method.endswith('_custom_object'):
            obj = "{0}.{1}".format(kwargs['plural'], kwargs['group'])
        elif method.endswith('_pod'):
            obj = "pod"
        elif method.endswith("_service"):
            obj = "service"
        elif method.endswith("_deployment"):
            obj = "deployment"
        elif method.endswith("_stateful_set"):
            obj = "statefulset"
        else:
            raise Exception("Not supported {0}".format(method))

        try:
            if method.startswith("create_namespaced_"):
                out = launchFromSpec2(kwargs['body'], kwargs['namespace'], self.kubeConfigFile).lower()
                return ('created' in out and 'error' not in out), 200, None
            elif method.startswith("delete_namespaced_"):
                cmdStr = "kubectl delete {0} {1} -n {2} --kubeconfig {3}".format(obj,
                    kwargs['name'], kwargs['namespace'], self.kubeConfigFile)
                if not kwargs.get('wait', False):
                    cmdStr += " --wait=false"
                logger.info(cmdStr)
                out = subprocess.check_output(cmdStr, shell=True).decode().lower()
                return ('deleted' in out and 'error' not in out), 200, None
            elif method.startswith("read_namespaced_") or method.startswith("get_namespaced_"):
                cmdStr = "kubectl get {0} {1} -n {2} --kubeconfig {3} -o yaml".format(obj, kwargs['name'],
                    kwargs['namespace'], self.kubeConfigFile)
                logger.info(cmdStr)
                out = subprocess.check_output(cmdStr, shell=True)
                if method.startswith("read_namespaced_"):
                    out = utils.ToClass(yaml.safe_load(out), True, KubeYamlIgnore)
                else:
                    out = yaml.safe_load(out)
                return True, 200, out
            else:
                if method.startswith("patch_namespaced_"):
                    patchType = "strategic"
                elif method.startswith("patchmerge_namespaced_"):
                    patchType = "merge"
                elif method.startswith("patchjson_namespaced_"):
                    patchType = "json"
                else:
                    raise Exception("Not supported {0}".format(method))
                patchStr = json.dumps(kwargs['body'])
                if "'" in patchStr:
                    out = patchFromSpec2(patchStr, obj, kwargs['namespace'], kwargs['name'], patchType, self.kubeConfigFile).lower()
                else:
                    cmdStr = "kubectl patch {0} {1} -n {2} --kubeconfig {3} -p '{4}' --type {5}".format(obj, kwargs['name'],
                        kwargs['namespace'], self.kubeConfigFile, patchStr, patchType)
                    logger.info(cmdStr)
                    out = subprocess.check_output(cmdStr, shell=True).decode().lower()
                # out = subprocess.check_output(['kubectl', 'patch', obj, kwargs['name'], '-n', kwargs['namespace'], '--kubeconfig',
                #     self.kubeConfigFile, '-p', json.dumps(kwargs['body']), '--type', patchType], shell=True).decode().lower()
                return 'patched' in out and 'error' not in out, 200, None

        except Exception as ex:
            logger.debug('kubectl encounters exception {0}\n{1}'.format(ex, traceback.format_exc()))
            return False, 200, None

    def call_method1(self, method, *args, **kwargs):
        servers = getServers(self.serverFileFixed, self.serversFixed)
        return self.call_method_server(method, *args, **kwargs, server=servers[0])

def getClusterNs(aks=None, ns=None, name=None, user=None):
    if aks is not None:
        return Cluster.aksname(aks[0], aks[1]), ns
    elif name is not None:
        return Cluster.fromconfig(name, user=user)
    else:
        return Cluster(inPodCluster=True), getPodNs()

def WatchNodesThread(id, name, sharedCtx, deploydir, doFn, stopLoop=None):
    client = waitForKube(deploydir, True)
    listerFn, watcherFn = _getListerAndWatcher(client.list_node)
    t = ThreadFnR(id, name, sharedCtx, _watchAndDo, listerFn, watcherFn, doFn, stopLoop)
    t.daemon = True
    t.start()
    return t

def WatchNodesThreadClient(id, name, sharedCtx, clientFn, doFn, stopLoop=None):
    client = clientFn()
    listerFn, watcherFn = _getListerAndWatcher(client.list_node)
    t = ThreadFnR(id, name, sharedCtx, _watchAndDo, listerFn, watcherFn, doFn, stopLoop)
    t.daemon = True
    t.start()
    return t

# To test:
# import kubeutils
# k = kubeutils.createClient('/home/core/deploy')
# ctx = {'reqs' : {}}
# kubeutils.watchNsPodsAndDo(k, 'sanjeevm0-hotmail-com', lambda type, pod, init : kubeutils.trackReqs(ctx, type, pod, init))
# def watchNsPodsAndDo(client, ns, doFn, stopLoop=None):
#     listerFn = lambda : client.list_namespaced_pod(namespace=ns)
#     watcherFn = lambda : _getWatchCtx(client.list_namespaced_pod, namespace=ns)
#     _watchAndDo({}, listerFn, watcherFn, doFn, stopLoop)

def WatchNsPodsThread(id, name, sharedCtx, deploydir, ns, doFn, stopLoop=None):
    client = waitForKube(deploydir, True)
    listerFn = lambda : client.list_namespaced_pod(namespace=ns)
    watcherFn = lambda rv : _getWatchCtx(client.list_namespaced_pod, namespace=ns, resource_version=rv)
    t = ThreadFnR(id, name, sharedCtx, _watchAndDo, listerFn, watcherFn, doFn, stopLoop)
    t.daemon = True # the stop mechanism does not work
    t.start()
    return t

# def watchAllPodsAndDo(client, doFn, stopLoop=None):
#     listerFn = lambda : client.list_pod_for_all_namespaces()
#     watcherFn = lambda : _getWatchCtx(client.list_pod_for_all_namespaces)
#     _watchAndDo({}, listerFn, watcherFn, doFn, stopLoop)

def WatchAllPodsThread(id, name, sharedCtx, deploydir, doFn, stopLoop=None):
    client = waitForKube(deploydir, True)
    listerFn = lambda : client.list_pod_for_all_namespaces()
    watcherFn = lambda rv : _getWatchCtx(client.list_pod_for_all_namespaces, resource_version=rv)
    t = ThreadFnR(id, name, sharedCtx, _watchAndDo, listerFn, watcherFn, doFn, stopLoop)
    t.daemon = True
    t.start()
    return t

def WatchAllPodsThreadClient(id, name, sharedCtx, clientFn, doFn, stopLoop=None):
    client = clientFn()
    listerFn, watcherFn = _getListerAndWatcher(client.list_pod_for_all_namespaces)
    t = ThreadFnR(id, name, sharedCtx, _watchAndDo, listerFn, watcherFn, doFn, stopLoop)
    t.daemon = True
    t.start()
    return t

# def watchAllDeploymentsAndDo(appClient, doFn, stopLoop=None):
#     listerFn = lambda : appClient.list_deployment_for_all_namespaces()
#     watcherFn = lambda : _getWatchCtx(appClient.list_deployment_for_all_namespaces)
#     _watchAndDo(listerFn, watcherFn, doFn, stopLoop)

def WatchAllDeploymentsThread(id, name, sharedCtx, deploydir, doFn, stopLoop=None):
    appClient = createAppClient(deploydir, True)
    listerFn = lambda : appClient.list_deployment_for_all_namespaces()
    watcherFn = lambda rv : _getWatchCtx(appClient.list_deployment_for_all_namespaces, resource_version=rv)
    t = ThreadFnR(id, name, sharedCtx, _watchAndDo, listerFn, watcherFn, doFn, stopLoop)
    t.daemon = True
    t.start()
    return t

# eventType is "Added", "Modified", or "Deleted"
# ctx is context to store state
def trackReqs(ctx, eventType, obj, init):
    success = False
    eventType = eventType.lower()
    if eventType in ["added", "deleted"]:
        (success, specreqs) = getReqsFromObj(obj)
        #print("N: {0} T: {1} SP: {2} I: {3}".format(obj.metadata.name, eventType, specreqs, init))
        if success:
            if eventType=="added":
                ctx['reqs'] = combineReqs(ctx['reqs'], specreqs)
            else:
                ctx['reqs'] = combineReqs(ctx['reqs'], negVal(specreqs))

            print("Init: {0} Reqs: {1}".format(init, ctx['reqs']))
        else:
            print("FAIL")

def resAvailable(required, available):
    for key in available:
        # every key in available must be satisfied
        if key in required:
            #print("Req: {0} Avail: {1}".format(required[key], available[key]))
            if isinstance(available[key], bool):
                if bool(required[key]) and not available[key]:
                    return False
            else:
                if float(required[key]) > float(available[key]):
                    return False
    for key in required:
        if key not in available and required[key] > 0:
            return False # something required is not in available
    return True

def launchFromSpec(spec, ns):
    (fd, tmp) = tempfile.mkstemp(suffix=".yaml")
    with open(tmp, 'w') as fp:
        yaml.dump(spec, fp)
    os.system("kubectl create -f {0} -n {1}".format(tmp, ns))
    rmtmp(fd, tmp)

def launchFromSpec2(spec, ns, kubeconfig):
    fd, tmp = tempfile.mkstemp(suffix=".yaml")
    with open(tmp, 'w') as fp:
        yaml.dump(spec, fp)
    cmdStr = "kubectl create --kubeconfig {0} -f {1} -n {2}".format(kubeconfig, tmp, ns)
    logger.info(cmdStr)
    ret = subprocess.check_output(cmdStr, shell=True).decode()
    rmtmp(fd, tmp)
    return ret

def patchFromSpec2(specJson, obj, ns, name, patchType, kubeconfig):
    fd, tmp = tempfile.mkstemp(suffix=".yaml")
    with open(tmp, 'w') as fp:
        fp.write(specJson) # dump json
    cmdStr = "kubectl patch {0} {1} -n {2} --kubeconfig {3} -p \"$(cat '{4}')\" --type {5}".format(obj, name, ns, 
        kubeconfig, tmp, patchType)
    logger.info(cmdStr)
    ret = subprocess.check_output(cmdStr, shell=True).decode()
    rmtmp(fd, tmp)
    return ret

def launchFromSpecApi(apiClient, spec, ns=None):
    specNs = copy.deepcopy(spec)
    if ns is not None:
        specNs['metadata']['namespace'] = ns
    (fd, tmp) = tempfile.mkstemp(suffix=".yaml")
    with open(tmp, 'w') as fp:
        yaml.dump(spec, fp)
        kutils.create_from_yaml(apiClient, tmp)
    rmtmp(fd, tmp)

# Tracker tests
# import kubeutils
# p = kubeutils.PodTracker.fromKClient({}, "r", "sanjeevm0@hotmail.com")
# n = kubeutils.NodeTracker.fromKClient({}, "r", "sanjeevm0@hotmail.com")

# import kubeutils
# sharedCtx = {}
# deploydir = '/home/core/deploy'
# stopLoop = lambda : 'finished' in sharedCtx and sharedCtx['finished']
# nodeTracker = kubeutils.NodeTracker.fromDeployDir(sharedCtx, deploydir, stopLoop)
# podTracker = kubeutils.PodTracker.fromDeployDir(sharedCtx, deploydir, stopLoop)
# waitingPodReqs = podTracker.getTotalWaitingPodReqsThatFitAgentNode(nodeTracker)
# canFit, numExtra = kubeutils.maxDivVal(waitingPodReqs, nodeTracker.getMaxAgentNodes())

# totalPodReqs = podTracker.getTotalAgentAndWaitingPodReqs(nodeTracker)
# canFit, numNodes = kubeutils.maxDivVal(totalPodReqs, nodeTracker.getAvgAgentNodes())

import threading

nodeIsAgent = lambda node : not nodeIsMaster(node)

class NodeTracker():
    def __init__(self, sharedCtx):
        self.nodes = {}
        self.t = None
        self.sharedCtx = sharedCtx
        self.tid = utils.random_string(16)
        self.callback = lambda : None # overwrite if you wish
        if sharedCtx is not None and 'lock' not in self.sharedCtx:
            self.sharedCtx['lock'] = threading.Lock()

    @classmethod
    def fromDeployDir(cls, sharedCtx, deploydir, stopLoop=None):
        tracker = cls(sharedCtx)
        tracker.t = WatchNodesThread(tracker.tid, "NodeTracker-"+tracker.tid, sharedCtx, 
            deploydir, tracker.trackNodes, stopLoop)
        return tracker

    @classmethod
    def fromKClient(cls, sharedCtx, id, user, stopLoop=None):
        tracker = cls(sharedCtx)
        tracker.t = WatchNodesThreadClient(tracker.tid, "NodeTracker-"+tracker.tid, sharedCtx, 
            lambda : waitForKClient(id, user), tracker.trackNodesLock, stopLoop)
        return tracker

    def snapshot(self):
        snap = NodeTracker(None)
        snap.nodes = copy.deepcopy(self.nodes)
        return snap

    def trackNodesLock(self, eventType, obj, init):
        self.sharedCtx['lock'].acquire()
        try:
            self.trackNodes(eventType, obj, init)
        finally:
            self.sharedCtx['lock'].release()
        self.callback()

    def trackNodes(self, eventType, obj, init):
        if eventType=="none":
            return
        if eventType=="deleted":
            self.nodes.pop(obj.metadata.name, None)
        elif obj is not None:
            self.nodes[obj.metadata.name] = obj

    def getAvail(self, nodename):
        return getNodeAvail(self.nodes[nodename])

    def getAvails(self, schedulable=True):
        avails = []
        nodes = copy.deepcopy(self.nodes)
        for nodename in nodes:
            if not schedulable or self.schedulable(nodename):
                avails.append(getNodeAvail(nodes[nodename]))
        return avails

    def getMaxAvail(self, schedulable=True):
        return maxVals(self.getAvails(schedulable))

    def getMinAvail(self, schedulable=True):
        return minVals(self.getAvails(schedulable))

    def getSumAvail(self, schedulable=True):
        return addVals(self.getAvails(schedulable))

    def getAvgAvail(self, schedulable=True):
        avails = self.getAvails(schedulable)
        if len(avails)==0:
            return {}
        else:
            return scaleVal(addVals(avails), 1.0/len(avails))

    def getAvailsLambda(self, expr):
        avails = []
        nodes = copy.deepcopy(self.nodes)
        for nodename in nodes:
            if expr(nodes[nodename]):
                avails.append(getNodeAvail(nodes[nodename], skipCordon=False))
        return avails

    def getAvgNodesLambda(self, expr):
        avails = self.getAvailsLambda(expr)
        if len(avails)==0:
            return {}
        else:
            return scaleVal(addVals(avails), 1.0/len(avails))

    def getAvgAgentNodes(self):
        return self.getAvgNodesLambda(nodeIsAgent)

    def getMaxAgentNodes(self):
        return maxVals(self.getAvailsLambda(nodeIsAgent))

    def getSumIfNodeRemoved(self, nodeToRemove, schedulable=True):
        avails = {}
        nodes = copy.deepcopy(self.nodes)
        for nodename in nodes:
            if not schedulable or self.schedulable(nodename):
                avails[nodename] = getNodeAvail(self.nodes[nodename])
        avails.pop(nodeToRemove, None) # remove specified nodename
        return addVals(list(avails.values()))

    def infraNode(self, nodename):
        if nodename not in self.nodes:
            return False
        return nodeIsMaster(self.nodes[nodename])

    def cordoned(self, nodename):
        if nodename not in self.nodes:
            return False
        return nodeCordoned(self.nodes[nodename])

    def schedulable(self, nodename):
        if nodename not in self.nodes:
            return False
        return nodeSchedulable(self.nodes[nodename])

# import kubeutils
# p = kubeutils.PodTracker.fromKClient({}, "", "sanjeevm0@hotmail.com")
# n = kubeutils.NodeTracker.fromKClient({}, "", "sanjeevm0@hotmail.com")

class PodTracker():
    def __init__(self, sharedCtx):
        self.pods = {} # podname: pod
        self.nodeForPod = {} # podname: nodename
        self.podsOnNode = {} # nodename: list of pods
        self.sharedCtx = sharedCtx
        self.tid = utils.random_string(16)
        self.callback = lambda : None # overwrite if you wish
        if sharedCtx is not None and 'lock' not in self.sharedCtx:
            self.sharedCtx['lock'] = threading.Lock()

    @classmethod
    def fromDeployDir(cls, sharedCtx, deploydir, stopLoop=None):
        tracker = cls(sharedCtx)
        tracker.t = WatchAllPodsThread(tracker.tid, "PodTracker-"+tracker.tid, sharedCtx,
            deploydir, tracker.trackPods, stopLoop)
        return tracker

    @classmethod
    def fromKClient(cls, sharedCtx, id, user, stopLoop=None):
        tracker = cls(sharedCtx)
        tracker.t = WatchAllPodsThreadClient(tracker.tid, "PodTracker-"+tracker.tid, sharedCtx,
            lambda : waitForKClient(id, user), tracker.trackPodsLock, stopLoop)
        return tracker

    def snapshot(self):
        snap = PodTracker(None)
        snap.pods = copy.deepcopy(self.pods)
        snap.nodeForPod = copy.deepcopy(self.nodeForPod)
        snap.podsOnNode = copy.deepcopy(self.podsOnNode)
        return snap

    def trackPodsLock(self, eventType, obj, init):
        self.sharedCtx['lock'].acquire()
        try:
            self.trackPods(eventType, obj, init)
        finally:
            self.sharedCtx['lock'].release()
        self.callback()

    def trackPods(self, eventType, obj, init):
        if eventType=="none" or obj is None:
            return
        podname = obj.metadata.namespace + "/" + obj.metadata.name
        if podname in self.nodeForPod:
            node = self.nodeForPod[podname]
            if node in self.podsOnNode:
                if podname in self.podsOnNode[node]:
                    self.podsOnNode[node].remove(podname)
        if eventType=="deleted":
            self.pods.pop(podname, None)
            self.nodeForPod.pop(podname, None)
        else:
            self.pods[podname] = obj
            try:
                nodename = obj.spec.node_name
            except Exception:
                nodename = None
            if nodename == '':
                nodename = None
            self.nodeForPod[podname] = nodename
            if nodename not in self.podsOnNode:
                self.podsOnNode[nodename] = []
            self.podsOnNode[nodename].append(podname)

    # requests of individual pods on node - returns list of hash
    def getPodReqOnNode(self, nodename):
        if nodename not in self.podsOnNode:
            return {}
        reqsOnNode = []
        for podname in self.podsOnNode[nodename]:
            success, podReqs = getPodReqs(self.pods[podname].to_dict())
            if not success:
                podReqs = {}
            reqsOnNode.append(podReqs)
        return reqsOnNode

    # total of all pods on node - returns hash
    def getTotalReqOnNode(self, nodename):
        return addVals(self.getPodReqOnNode(nodename))

    # total of all running pods in cluster
    def getTotalRunningPodReqs(self):
        reqs = []
        for nodename in self.podsOnNode:
            if nodename is not None and nodename != '':
                reqs.append(self.getTotalReqOnNode(nodename))
        return addVals(reqs)

    def getTotalPodReqs(self, expr=None):
        reqs = []
        for nodename in self.podsOnNode:
            if expr is None or expr(nodename):
                reqs.append(self.getTotalReqOnNode(nodename))
        return addVals(reqs)

    def getTotalAgentAndWaitingPodReqs(self, nodeTracker : NodeTracker):
        return self.getTotalPodReqs(lambda nodename : nodename is None or not nodeIsMaster(nodeTracker.nodes[nodename]))

    def fitOnNode(self, nodeTracker, nodename, podReqs):
        if nodename not in nodeTracker.nodes:
            return False
        if not nodeSchedulable(nodeTracker.nodes[nodename]):
            return False
        newReqs = addVals([self.getTotalReqOnNode(nodename), podReqs])
        return resAvailable(newReqs, nodeTracker.getAvail(nodename))

    def getWaitingPodReqs(self):
        if None not in self.podsOnNode:
            return {}
        waitingPodNames = copy.deepcopy(self.podsOnNode[None])
        #time.sleep(2.0) # wait in case scheduler schedules them
        waitReqs = []
        for podname in waitingPodNames:
            success, podReqs = getPodReqs(self.pods[podname].to_dict())
            if success:
                waitReqs.append(podReqs)
        return waitReqs

    def getTotalWaitingPodReqs(self):
        return addVals(self.getWaitingPodReqs())

    def getTotalWaitingPodReqsThatFitAgentNode(self, nodeTracker : NodeTracker):
        waitingPodReqs = self.getWaitingPodReqs()
        maxNodeAvail = nodeTracker.getMaxAgentNodes()
        podReqsThatFit = []
        for podReq in waitingPodReqs:
            if resAvailable(podReq, maxNodeAvail):
                podReqsThatFit.append(podReq)
        return addVals(podReqsThatFit)

    def getMaxWaitingPodReqs(self):
        return maxVals(self.getWaitingPodReqs())

    def isZeroPodNode(self, node):
        return node not in self.podsOnNode or len(self.podsOnNode[node])==0

    def getZeroPodNodes(self, nodeTracker):
        zeroPodNodes = []
        for node in nodeTracker.nodes:
            if node not in self.podsOnNode or len(self.podsOnNode[node])==0:
                zeroPodNodes.append(node)
        return zeroPodNodes

    def isNonSystemZeroPodNode(self, node):
        if node not in self.podsOnNode:
            return True
        podsOnNode = copy.deepcopy(self.podsOnNode[node])
        for pod in podsOnNode:
            if not pod.startswith("kube-system/"):
                return False
        return True

    def getNonSystemZeroPodNodes(self, nodeTracker):
        zeroPodNodes = []
        for node in nodeTracker.nodes:
            if self.isNonSystemZeroPodNode(node):
                zeroPodNodes.append(node)
        return zeroPodNodes

def trackerSnapshot(nodeTracker : NodeTracker, podTracker : PodTracker):
    with nodeTracker.sharedCtx['lock']:
        nodeSnap = nodeTracker.snapshot()
        podSnap = podTracker.snapshot()
    return nodeSnap, podSnap

def getAdminPwd(kube):
    return hashlib.md5(getServiceToken(kube, 'kube-system', 'default').encode()).hexdigest()

def getUserPwd(kube, ns):
    return hashlib.md5(getServiceToken(kube, ns, 'serviceaccount-'+ns).encode()).hexdigest()

# =======================================================================

# obtain a lock for the pod using configmaps
# resp=cc.patch_namespaced_config_map('testcmap', 'default', 
#                                    [{"op": "test", "path": "/metadata/resourceVersion", "value": "5900202"}, 
#                                     {"op": "replace", "path": "/data/podname", "value": "me400"}])
# resp=cc.list_namespaced_config_map('default', field_selector='metadata.name==testcmap')

def readConfigMap(client, configMapName, ns):
    try:
        resp = client.read_namespaced_config_map(configMapName, namespace=ns)
        return resp
    except Exception:
        return None

# returns True if successful in obtaining lock, otherwise False
def createLockConfigMap(client, configMapName, podName, ns):
    try:
        # create a configmap
        cm = kclient.V1ConfigMap()
        cm.api_version = 'v1'
        cm.kind = 'ConfigMap'
        cm.metadata = kclient.V1ObjectMeta()
        cm.metadata.namespace = ns
        cm.metadata.name = configMapName
        cm.data = {"lockholder": podName}
        resp = client.create_namespaced_config_map(ns, cm)
        return (True, resp) # this pod is now lock holder
    except Exception:
        return (False, readConfigMap(client, configMapName, ns))

def updateLockConfigMap(client, configMapName, podName, podNameToDelete, ns):
    try:
        # JSON merge as opposed to strategic patch or json merge patch, check if podName is empty prior to setting
        resp = client.patch_namespaced_config_map(configMapName, ns, [
            {"op": "test", "path": "/data/lockholder", "value": ""},
            {"op": "replace", "path": "/data/lockholder", "value": podName},
        ])
        return (True, resp)
    except Exception:
        if podNameToDelete is not None:
            try:
                resp = client.patch_namespaced_config_map(configMapName, ns, [
                    {"op": "test", "path": "/data/lockholder", "value": podNameToDelete},
                    {"op": "replace", "path": "/data/lockholder", "value": podName},
                ])
                return (True, resp)
            except Exception:
                return (False, readConfigMap(client, configMapName, ns))
        else:
            return (False, readConfigMap(client, configMapName, ns))

def deleteLockConfigMap(client, configMapName, podNameToDelete, ns):
    try:
        resp = client.patch_namespaced_config_map(configMapName, ns, [
            {"op": "test", "path": "/data/lockholder", "value": podNameToDelete},
            {"op": "replace", "path": "/data/lockholder", "value": ""}
        ])
        return (True, resp)
    except Exception:
        return (False, readConfigMap(client, configMapName, ns))

def configMapCallback(event, configMap, init, ctx):
    if event in ["modified", "deleted"] and configMap.metadata.name == ctx['configMap']:
        ctx['configMapChanged'] = True
        ctx['stop'] = True
        ctx['tryagain'].set()

def podCallback(event, pod, init, ctx):
    if event == "deleted" and pod.metadata.name == ctx['podName']:
        ctx['podDeleted'] = True
        ctx['stop'] = True
        ctx['tryagain'].set()

def stopCheck(ctx):
    return ctx['stop'] or ('finished' in ctx and ctx['finished'])

def finisher(ctx):
    ctx['tryagain'].set()

def kubeLockRelease1(client, lockName, podName, ns):
    configMapName = "locks-{0}".format(lockName)
    deleteLockConfigMap(client, configMapName, podName, ns)

def kubeLockAcquire1(client, lockName, podName, ns, numTry=0):
    configMapName = "locks-{0}".format(lockName)
    podNameToDelete = None
    cnt = 0

    # get config map
    while True:
        cnt += 1
        # first read
        resp = readConfigMap(client, configMapName, ns)
        if resp is not None:
            if resp.data['lockholder'] == podName:
                return True # already have lock
            else:
                (success, resp) = updateLockConfigMap(client, configMapName, podName, podNameToDelete, ns)
                if success:
                    return True
        else:
            (success, resp) = createLockConfigMap(client, configMapName, podName, ns)
            if success:
                return True

        if numTry > 0 and cnt >= numTry:
            return False # lock not acquired

        if resp is None or resp.data['lockholder']=="":
            podNameToDelete = None
            continue # next iteration

        try:
            curLockHolder = client.read_namespaced_pod(resp.data['lockholder'], namespace=ns)
        except kclient.rest.ApiException as ex:
            try:
                ret = yaml.safe_load(ex.body)
                if 'message' in ret and "not found" in ret['message'].lower():
                    # Pod has been deleted
                    podNameToDelete = resp.data['lockholder']
                    continue
                else:
                    # some other error
                    podNameToDelete = None
                    continue
            except Exception:
                podNameToDelete = None
                continue
        except Exception: # other error
            podNameToDelete = None
            continue

        # start a watch
        ctx = {
            'stop': False,
            'configMapChanged': False,
            'podDeleted': False,
            'configMap': resp.metadata.name,
            'podName': resp.data['lockholder'],
            'tryagain': threading.Event(),
            'finisher': finisher,
        }
        cmCb = lambda event, obj, init : configMapCallback(event, obj, init, ctx)
        podCb = lambda event, obj, init : podCallback(event, obj, init, ctx)
        stopFn = lambda : stopCheck(ctx)

        # to test thread:
        # t0 = kubeutils.WatchObjThread(0, "kubeLock-cm", {}, lambda event, o, init: print(o.metadata.name) if o is not None else print("None"), lambda : False, 'list_namespaced_pod', None, client=client, namespace=ns, field_selector='metadata.name=={0}'.format(podName), timeout_seconds=10)
        t0 = WatchObjThread(cnt, "kubeLock-cm", ctx, cmCb, stopFn, 'list_namespaced_config_map', None, client=client, namespace=ns,
            field_selector='metadata.name=={0}'.format(configMapName), 
            timeout_seconds=10) # resource_version=resp.metadata.resource_version) - using resource version has unexpected behavior
        t1 = WatchObjThread(cnt, "kubeLock-pod", ctx, podCb, stopFn, 'list_namespaced_pod', None, client=client, namespace=ns,
            field_selector='metadata.name=={0}'.format(curLockHolder.metadata.name), 
            timeout_seconds=10) # resource_version=curLockHolder.metadata.resource_version)

        ctx['tryagain'].wait()
        watcher = t0.getState('watcher')
        if watcher is not None:
            watcher.stop()
        watcher = t1.getState('watcher')
        if watcher is not None:
            watcher.stop()

        if ctx['podDeleted']:
            podNameToDelete = curLockHolder.metadata.name
        else:
            podNameToDelete = None

    #raise Exception("Invalid code path")
    #return False

def getPodNs():
    with open('/var/run/secrets/kubernetes.io/serviceaccount/namespace') as fp:
        return fp.read()

#KubeYamlIgnore = re.compile(r"\|metadata\|(labels|annotations)\|.*")
KubeYamlIgnore = utils.buildIgnorePattern(['*.labels.*', '*.annotations.*'])

def SetKubeYamlIgnore(ignore):
    global KubeYamlIgnore
    KubeYamlIgnore = ignore

def GetKubeYamlIgnore():
    return KubeYamlIgnore

def ToYaml(obj, replacements={}, ignore=None):
    if ignore is None:
        ignore = GetKubeYamlIgnore()
    if isinstance(obj, dict):
        return utils.camelizeKeys(obj, False, replacements, ignore)
    elif type(obj)==utils.ToClass or str(type(obj))=="<class 'kcclient.utils.ToClass'>":
        return obj.to_dict(True, replacements, ignore)
    else:
        return utils.camelizeKeys(getSpecFromObj(obj), False, replacements, ignore)

def ToKey(o):
    if type(o)==dict:
        if 'namespace' not in o['metadata'] or o['metadata']['namespace'] is None:
            return o['metadata']['name']
        else:
            return o['metadata']['namespace'] + "/" + o['metadata']['name']
    else:
        if o.metadata.namespace is None:
            return o.metadata.name
        else:
            return o.metadata.namespace + "/" + o.metadata.name

def ToTypeKey(o):
    if type(o)==dict:
        return o['kind'] + "/" + ToKey(o)
    else:
        return getKind(o) + "/" + ToKey(o)

def findDeploymentForPod(pod, deployments):
    # In, NotIn, Exists, and DoesNotExist. The values set must be non-empty in the case of In and NotIn. 
    # All of the requirements, from both matchLabels and matchExpressions are ANDed together -- 
    # they must all be satisfied in order to match - any violation returns in not matching
    podLabels = utils.getValDef(pod, ['metadata', 'labels'], {}, None)
    for deplKey, depl in deployments.items():
        if pod['metadata']['namespace'] != depl['metadata']['namespace']:
            continue
        match = True
        for k, v in utils.getValDef(depl, ['spec', 'selector', 'matchLabels'], {}, None).items():
            if k not in podLabels or podLabels[k] != v:
                match = False
                break
        if not match:
            continue
        for expr in utils.getValDef(depl, ['spec', 'selector', 'matchExpressions'], [], None):
            if expr['operator']=='In':
                if expr['key'] not in podLabels or podLabels[expr['key']] not in expr['values']:
                    match = False
                    break
            elif expr['operator']=='NotIn':
                if expr['key'] in podLabels and podLabels[expr['key']] in expr['values']:
                    match = False
                    break
            elif expr['operator']=='Exists':
                if expr['key'] not in podLabels:
                    match = False
                    break
            elif expr['operator']=='DoesNotExist':
                if expr['key'] in podLabels:
                    match = False
                    break
        if match:
            return deplKey, depl
    return None, None

# def getPodName(client):
#     ns = getPodNs()
#     pods = client.list_namespaced_pod(namespace=ns)
#     info = utils.getMachineInfo()
#     for pod in pods:
#         if pod.status.podIP==info['private_ip']:
#             return pod.metadata.name
#     raise Exception("Unable to find pod name")
#     #return None

def getPodName():
    return os.environ["HOSTNAME"]

def kubeLockAcquire(lockName, numTry=0):
    ns = getPodNs()
    podName = getPodName()
    clusterId = getClusterId() # no arg hash
    client, _ = getClientForMethod(clusterId, 'list_namespaced_pod')
    return kubeLockAcquire1(client, lockName, podName, ns, numTry)

def tryKubeLockAcquire(lockName):
    return kubeLockAcquire(lockName, numTry=1)

def kubeLockRelease(lockName):
    ns = getPodNs()
    podName = getPodName()
    clusterId = getClusterId()
    client, _ = getClientForMethod(clusterId, 'list_namespaced_pod')
    return kubeLockRelease1(client, lockName, podName, ns)

def kubeLoadTLS(tlscm=[], cluster=None, ns=None):
    if cluster is None:
        cluster = Cluster(inPodCluster=True)
    if ns is None:
        ns = getPodNs()
    certs = []
    try:
        _, _, cm = cluster.call_method('list_namespaced_config_map', namespace='kube-system', 
            field_selector='metadata.name==extension-apiserver-authentication')
        certs.append(str.encode(cm.items[0].data['requestheader-client-ca-file']))
    except Exception:
        print("Unable to load extension-apiserver-authentication")
    for cmn in tlscm:
        try:
            _, _, cm = cluster.call_method('list_namespaced_secret', namespace=ns, 
                field_selector='metadata.name=={0}'.format(cmn))
            certs.append(str.encode(utils.b64d(cm.items[0].data['tls.crt'])))
        except Exception:
            print("Unable to load {0}".format(cmn))
    return certs

# returns whether merge took place or not & updated value, merge is atomic
def mergeField(exist, new, failOnExist=False):
    if exist is not None:
        updated = copy.deepcopy(exist)
    else:
        updated = []
    if new is None:
        return True, updated
    for n in new:
        found = False
        for i, e in enumerate(exist):
            if e['name'] == n['name']:
                if failOnExist and (e != n):
                    return False, copy.deepcopy(exist)
                updated[i] = n
                found = True
                break
        if not found:
            updated.append(n)
    return True, updated

def mergeConfig(exist, new, failOnExist=False):
    updated = copy.deepcopy(exist)
    success1, updated['users'] = mergeField(exist.get('users', None), new.get('users', None), failOnExist)
    success2, updated['clusters'] = mergeField(exist.get('clusters', None), new.get('clusters', None), failOnExist)
    success3, updated['contexts'] = mergeField(exist.get('contexts', None), new.get('contexts', None), failOnExist)
    if success1 and success2 and success3:
        return True, updated
    else:
        return False, copy.deepcopy(exist)

def mergeInto(existFile, *args, failOnExist=True, newUser=None, newCluster=None, newContext=None):
    exist = utils.loadYaml(existFile)
    for a in args:
        new = utils.loadYaml(a)
        if newCluster is not None:
            new['clusters'][0]['name'] = newCluster
        if newUser is not None:
            new['users'][0]['name'] = newUser
        if newContext is not None:
            new['contexts'][0]['name'] = newContext
        new['contexts'][0]['context'].update({
            'cluster': new['clusters'][0]['name'],
            'user': new['users'][0]['name']
        })
        print("Merge {0} into kubeconfig {1} {2} {3}".format(
            a, new['clusters'][0]['name'], new['users'][0]['name'], new['contexts'][0]['name']))
        success, exist = mergeConfig(exist, new, failOnExist=failOnExist)
        if not success:
            raise Exception("Not successful in merging, perphaps already exists")
    #print(exist)
    (fd, tmp) = tempfile.mkstemp()
    utils.dumpYaml(exist, tmp)
    utils.replaceSave(existFile, tmp)
    return exist

# str read_namespaced_pod_log(name, namespace, container=container, follow=follow, 
#                             insecure_skip_tls_verify_backend=insecure_skip_tls_verify_backend, 
#                             limit_bytes=limit_bytes, pretty=pretty, previous=previous, since_seconds=since_seconds, 
#                             tail_lines=tail_lines, timestamps=timestamps)
class LogWatch():
    # cb takes in string, returns whether to continue watch
    def __init__(self, cb, cluster, podName, namespace, finisher=None, **kwargs):
        self.cluster = cluster
        self.cb = cb
        self.finisher = finisher
        self.namespace = namespace
        self.podName = podName
        client, api, method = cluster.getMethodAndClient(cluster.serversFixed[0], 'read_namespaced_pod_log')
        kwargs['follow'] = True  # else no need to watch
        self.w = watch.Watch()
        self.watcher = self.w.stream(method, namespace=namespace, name=podName, **kwargs)
        self.conditionMet = False
        self.stopped = False
        t = threading.Thread(target=self.doWatch)
        t.daemon = True
        t.start()

    def stop(self):
        self.stopped = True

    def doWatch(self):
        keepGoing = True
        while not self.stopped and keepGoing:
            try:
                e = next(self.watcher)
                keepGoing = self.cb(e)
                if not keepGoing:
                    self.conditionMet = True
                    logger.info("{0}/{1} meets condition".format(self.namespace, self.podName))
            except StopIteration:
                keepGoing = False # thread terminates but condition not met
                logger.info("{0}/{1} iteration stops - pod terminated".format(self.namespace, self.podName))
            except Exception as ex:
                keepGoing = False # thread terminates
                logger.error("{0}/{1} encounters exception {2}".format(self.namespace, self.podName, ex))
        try:
            self.w.stop()
        except Exception:
            pass
        if self.finisher is not None:
            self.finisher()
