import os
import sys
from kubernetes import client as kclient, config as kcfg, watch, utils as kutils
thisPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(thisPath)
import utils
import time
import yaml
import re
import copy
from threadfn import ThreadFnR
import tempfile
import random
import glob
import hashlib
import threading

methods = {}
clusters = {}
clusterLock = threading.RLock()
apiObjs = {}
cfgArgs = {}

def _findMethodElem(method):
    if method in methods:
        return methods[method]
    for elem in dir(kclient):
        if method in eval('dir(kclient.'+elem+')'):
            methods[method] = 'kclient.'+elem
            break
    return methods[method]

def getClientForMethod(clusterId, method, reloadConfig=True, loaderIn=None):
    with clusterLock:
        apiObj = utils.getValK(apiObjs, [clusterId, method])
        if apiObj is not None:
            return apiObj
        else:
            if reloadConfig:
                (_, loader, _) = waitForK8s(**cfgArgs[clusterId])
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
    kcfg.load_kube_config(tmp)
    os.remove(tmp)

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

def waitForK(loader, creator=None):
    loaderRet = None
    while True:
        try:
            ret = loader()
            if ret is None:
                kubeclient = kclient.CoreV1Api()
            else:
                loaderRet = ret
                kubeclient = kclient.CoreV1Api(ret)
        except Exception:
            kubeclient = None
        if isAlive(kubeclient):
            break
        time.sleep(5.0)
    if creator is None:
        return (loaderRet, None)
    else:
        return (loaderRet, creator(loaderRet))

def waitForKClient(id, user):
    #print("ID: {0} USER: {1}".format(id, user))
    (_, created) = waitForK(lambda : _loadCfgKclient(id, user), kclient.CoreV1Api)
    return created

def _waitForK8sHelper(deploydir=None, modssl_dir=False, server=None, base=None, ca=None, cert=None, key=None, id=None, user=None):
    with clusterLock:
        if deploydir is not None:
            return waitForK(lambda : _loadCfg(deploydir, modssl_dir))
        elif server is not None:
            return waitForK(lambda : _loadCfgCert(server, base, ca, cert, key))
        elif id is not None:
            return waitForK(lambda : _loadCfgKclient(id, user))
        else:
            return waitForK(lambda : _loadCfgServiceAccount())

def waitForK8s(**kwargs):
    clusterId = utils.kwargHash(**kwargs)
    if clusterId not in cfgArgs:
        cfgArgs[clusterId] = kwargs # save the mapping for waiting
    (loaderRet, creatorRet) = _waitForK8sHelper(**kwargs)
    return (clusterId, loaderRet, creatorRet)

def getClusterId(**kwargs):
    clusterId = utils.kwargHash(**kwargs)
    if clusterId not in cfgArgs:
        cfgArgs[clusterId] = kwargs
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

def getMasterNodes(client):
    nodes = getNodes(client)
    masterNodes = []
    for node in nodes:
        if nodeIsMaster(node):
            masterNodes.append(node)
    return masterNodes

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
def totalPodReqs(pod):
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
    podC = utils.getValDef(pod, 'spec.initContainers')
    for c in podC:
        (success, reqsC) = convertAll(utils.getValDef(c, 'resources.requests'), success)
        (success, limitsC) = convertAll(utils.getValDef(c, 'resources.limits'), success)
        limitsC = maxReqs(limitsC, reqsC)
        reqs = maxReqs(reqs, reqsC)
        limits = maxReqs(limits, limitsC)

    return success, reqs, limits

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

def getSpecFromObj(o):
    d = o.to_dict()
    if d['kind'] is None:
        d['kind'] = re.match(r'.*\.V.(.*)\'\>', str(type(o))).group(1)
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
    if 'timeout_seconds' not in kwargs:
        watcher = w.stream(lister, timeout_seconds=0, **kwargs)
    else:
        watcher = w.stream(lister, **kwargs)
    return w, watcher

def _watchAndDo(thread, listerFn, watcherFn, doFn, stopLoop = lambda : False):
    if stopLoop is None:
        stopLoop = lambda : False
    if stopLoop():
        return
    # Get initial obj list
    initobjs = listerFn()
    init = {}
    for obj in initobjs.items:
        init[obj.metadata.uid] = True
        if stopLoop():
            return
        done = doFn('added', obj, True)
        if done:
            return

    done = doFn("none", None, False) # once after initialization done
    if done:
        return

    w, watcher = watcherFn()
    thread.selfCtx['state'] = {'watcher': w}
    for e in watcher:
        #raw = e['raw_object'] # accessible as map
        obj = e['object']
        try:
            if obj.metadata.uid in init:
                #print("Already processed: {0}".format(obj.metadata.uid))
                init.pop(obj.metadata.uid)
                continue
        except Exception:
            pass
        if stopLoop():
            return
        done = doFn(e['type'].lower(), obj, False)
        if done:
            return
    print("WATCH STOPS BYITSELF")
    thread.selfCtx['repeat'] = True

def _getListerAndWatcher(fn, **kwargs):
    listerFn = lambda : fn(**kwargs)
    watcherFn = lambda : _getWatchCtx(fn, **kwargs)
    return listerFn, watcherFn

# To use - example:
#
# kubeutils.waitForK8s(id='3x',user='name@example.com')
# stop = False
# stopper = lambda : stop
# printer = lambda event,obj,init : print("{0}:{1}:{2}".format(event,obj,init))
# kubeutils.WatchObjThread(0, 'NodeWatcher', {}, printer, stopper, 'list_node', None, cluster_id=****)
# kubeutils.WatchObjThread(1, 'Kube-System Pod Watcher', {}, printer, stopper, 'list_namespaced_pod', None, 'cluster_id'=****, namespace='kube-system')
# stop = True # to stop watching
def WatchObjThread(threadId, name, sharedCtx, callback, stopLoop, lister, finisher, **kwargs):
    waitArgs, remArgs = utils.kwargFilter(['deploydir', 'modssl_dir', 'server', 'base', 'ca', 'cert', 'key', 'id', 'user', 'client'], **kwargs)
    if 'client' in waitArgs:
        clientMethod = eval("waitArgs['client'].{0}".format(lister))
    elif len(waitArgs) > 0:
        with clusterLock:
            (clusterId, loaderRet, _) = waitForK8s(**waitArgs)
            _, clientMethod = getClientForMethod(clusterId, lister, False, loaderRet)
        remArgs.pop('cluster_id', None) # ignore and remove if it exists
    else:
        clusterId = remArgs.pop('cluster_id') # raise error if not found
        print("Start watch for cluster {0}".format(clusterId))
        _, clientMethod = getClientForMethod(clusterId, lister, True)
    listerFn, watcherFn = _getListerAndWatcher(clientMethod, **remArgs)
    t = ThreadFnR(threadId, name, sharedCtx, _watchAndDo, listerFn, watcherFn, callback, stopLoop)
    if finisher is not None:
        t.selfCtx['finisher'] = finisher
    t.daemon = True
    t.start()
    return t

threadIdLock = threading.Lock()
threadIdCnt = -1
def WatchObjOnCluster(cluster_id, threadName, sharedCtx, callback, stopLoop, lister, **kwargs):
    with threadIdLock:
        threadId = threadIdCnt + 1
    kwargs.update({'cluster_id': cluster_id})
    WatchObjThread(threadId, threadName, sharedCtx, callback, stopLoop, lister, **kwargs)

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
def watchNsPodsAndDo(client, ns, doFn, stopLoop=None):
    listerFn = lambda : client.list_namespaced_pod(namespace=ns)
    watcherFn = lambda : _getWatchCtx(client.list_namespaced_pod, namespace=ns)
    _watchAndDo({}, listerFn, watcherFn, doFn, stopLoop)

def WatchNsPodsThread(id, name, sharedCtx, deploydir, ns, doFn, stopLoop=None):
    client = waitForKube(deploydir, True)
    listerFn = lambda : client.list_namespaced_pod(namespace=ns)
    watcherFn = lambda : _getWatchCtx(client.list_namespaced_pod, namespace=ns)
    t = ThreadFnR(id, name, sharedCtx, _watchAndDo, listerFn, watcherFn, doFn, stopLoop)
    t.daemon = True # the stop mechanism does not work
    t.start()
    return t

def watchAllPodsAndDo(client, doFn, stopLoop=None):
    listerFn = lambda : client.list_pod_for_all_namespaces()
    watcherFn = lambda : _getWatchCtx(client.list_pod_for_all_namespaces)
    _watchAndDo({}, listerFn, watcherFn, doFn, stopLoop)

def WatchAllPodsThread(id, name, sharedCtx, deploydir, doFn, stopLoop=None):
    client = waitForKube(deploydir, True)
    listerFn = lambda : client.list_pod_for_all_namespaces()
    watcherFn = lambda : _getWatchCtx(client.list_pod_for_all_namespaces)
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

def watchAllDeploymentsAndDo(extClient, doFn, stopLoop=None):
    listerFn = lambda : extClient.list_deployment_for_all_namespaces()
    watcherFn = lambda : _getWatchCtx(extClient.list_deployment_for_all_namespaces)
    _watchAndDo(listerFn, watcherFn, doFn, stopLoop)

def WatchAllDeploymentsThread(id, name, sharedCtx, deploydir, doFn, stopLoop=None):
    extClient = createExtClient(deploydir, True)
    listerFn = lambda : extClient.list_deployment_for_all_namespaces()
    watcherFn = lambda : _getWatchCtx(extClient.list_deployment_for_all_namespaces)
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
    (_, tmp) = tempfile.mkstemp(suffix=".yaml")
    with open(tmp, 'w') as fp:
        yaml.dump(spec, fp)
    os.system("kubectl create -f {0} -n {1}".format(tmp, ns))
    os.remove(tmp)

def launchFromSpecApi(apiClient, spec, ns=None):
    specNs = copy.deepcopy(spec)
    if ns is not None:
        specNs['metadata']['namespace'] = ns
    (_, tmp) = tempfile.mkstemp(suffix=".yaml")
    with open(tmp, 'w') as fp:
        yaml.dump(spec, fp)
        kutils.create_from_yaml(apiClient, tmp)
    os.remove(tmp)

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
        else:
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

    def masterNode(self, nodename):
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
        if eventType=="none":
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
        except:
            # Pod has been deleted
            podNameToDelete = resp.data['lockholder']
            continue

        # start a watch
        ctx = {
            'stop': False,
            'configMapChanged': False,
            'podDeleted': False,
            'tryagain': threading.Event(),
            'finisher': finisher,
        }
        cmCb = lambda event, obj, init : configMapCallback(event, obj, init, ctx)
        podCb = lambda event, obj, init : podCallback(event, obj, init, ctx)
        stopFn = lambda : stopCheck(ctx)

        t0 = WatchObjThread(cnt, "kubeLock-cm", ctx, cmCb, stopFn, 'list_namespaced_config_map', None, client=client, namespace=ns,
            field_selector='metadata.name=={0}'.format(configMapName), timeout_seconds=10)
        t1 = WatchObjThread(cnt, "kubeLock-pod", ctx, podCb, stopFn, 'list_namespaced_pod', None, client=client, namespace=ns,
            field_selector='metadata.name=={0}'.format(curLockHolder.metadata.name), timeout_seconds=10)

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
