import yaml
import json
import os
import sys
import requests
from functools import partial
import glob
thisPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(thisPath, '..', '..', 'utils'))
sys.path.append(thisPath)
import utils
import webutils
import re
import tempfile
import shutil

def getUser(id, user):
    if user is None:        
        cfgfile = "{0}/.{1}/{1}.users.yaml".format(utils.getHome(), "kcluster")
        if not os.path.exists(cfgfile) and id is not None:
            cfgfile = "{0}/.{1}/{2}/users.yaml".format(utils.getHome(), "kcluster", id)
        # if id is None:
        #     cfgfile = "{0}/.{1}/{1}.users.yaml".format(utils.getHome(), "kcluster")
        # else:
        #     cfgfile = "{0}/.{1}/{2}/users.yaml".format(utils.getHome(), "kcluster", id)
        cfg = utils.loadYaml(cfgfile)
        if len(list(cfg)) > 1:
            print("User must be specified - one of {0}".format(list(cfg)))
            exit()
        user = list(cfg)[0]
    return user

def getCtxId(id, server):
    ctxdir = None
    if id is not None:
        ctxdir = glob.glob('{0}/.kcluster/{1}*'.format(utils.getHome(), id))
    elif id is None and server is None:
        ctxdir = glob.glob('{0}/.kcluster/*'.format(utils.getHome()))
    if ctxdir is not None:
        ctxdir = [c for c in ctxdir if os.path.isdir(c)] # filter only dirs
        if len(ctxdir) != 1:
            print("ID not unique or not found {0}".format(ctxdir))
            exit()
        else:
            return os.path.basename(ctxdir[0])
    else:
        return None # id stays None

def getCtx(id, user, server, setcontext=False):
    ctxFile = '{0}/.kcluster/context.yaml'.format(utils.getHome())
    if os.path.exists(ctxFile) and not setcontext:
        ctx = utils.loadYaml(ctxFile)
        if id is None:
            id = ctx['ClusterID']
        else:
            id = getCtxId(id, server)
        if user is None:
            user = ctx['User']
        else:
            user = getUser(id, user)
    else:
        id = getCtxId(id, server)
        user = getUser(id, user)
    return id, user

def setCtx(id, user):
    if user is not None and id is not None:
        with open('{0}/.kcluster/context.yaml'.format(utils.getHome()), 'w') as fp:
            yaml.dump({'ClusterID': id, 'User': user}, fp)
    else:
        print("Unable to determine id or user")

def getKubeServers(cfgdir):
    serverInfo = utils.loadYaml("{0}/servers.yaml".format(cfgdir))
    servers = serverInfo["Servers"]
    servers = [re.sub('(.*):(.*)', '\g<1>:{0}'.format(serverInfo["k8sport"]), s) for s in servers]
    return servers

def createKubeConfig(cfgdir, resp,
    clustername='default-cluster', username='default-user', contextname='default-context'):

    return {
        'apiVersion': 'v1',
        'kind': 'Config',
        'clusters': [
            {
                'name': clustername,
                'cluster': {
                    'certificate-authority-data': utils.b64e(resp['CA']),
                    'server': getKubeServers(cfgdir)[0]
                }
            }
        ],
        'users': [
            {
                'name': username,
                'user': {
                    'client-certificate-data': utils.b64e(resp['Cert']),
                    'client-key-data':  utils.b64e(resp['Key']),
                    'token': resp['token']
                }
            }
        ],
        'contexts': [
            {
                'name': contextname,
                'context': {
                    'cluster': clustername,
                    'user': username
                }
            }
        ],
        'current-context': contextname
    }

def removeDups(old, name):
    new = []
    for i, x in enumerate(old):
        if x['name'] != name:
            new.append(x)
    return new

ctxName = None
def dumpKubeCreds(user, resp, id):
    cfgdir = utils.getHome()+"/.kcluster/{0}".format(id)
    print("Writing {0} to {1}".format(resp, cfgdir))
    with open('{0}/ca-kube.pem'.format(cfgdir), 'w') as fp:
        fp.write(resp['CA'])
    with open('{0}/{1}-kube.pem'.format(cfgdir, user), 'w') as fp:
        fp.write(resp['Cert'])
    with open('{0}/{1}-kube-key.pem'.format(cfgdir, user), 'w') as fp:
        fp.write(resp['Key'])
    with open('{0}/{1}-kube.config'.format(cfgdir, user), 'w') as fp:
        # create config file
        yaml.safe_dump(createKubeConfig(cfgdir, resp), fp)
    # also merge into kubeconfig
    if ctxName is None:
        cname = getKubeServers(cfgdir)[0].split('//')[1].split('.')[0].split('-infra')[0]
    else:
        cname = ctxName
    uname = cname+'-'+user
    kcfg = createKubeConfig(cfgdir, resp, clustername=cname, username=uname, contextname=uname)
    basecfg = utils.getHome()+'/.kube/config'
    if os.path.exists(basecfg):
        baseYaml = utils.loadYaml(basecfg)
        baseYaml['clusters'] = removeDups(baseYaml['clusters'], cname)
        baseYaml['users'] = removeDups(baseYaml['users'], uname)
        baseYaml['contexts'] = removeDups(baseYaml['contexts'], uname)
        newYaml = utils.deepmerge(kcfg, baseYaml)
        fd, name = tempfile.mkstemp()
        utils.dumpYaml(newYaml, name)
        print("merging configuration into {0}".format(basecfg))
        shutil.copy(name, basecfg)
        os.close(fd)
        os.remove(name)

def getServers(queryParams, server):
    resp = doAPIOper([server], None, "get", "servers", queryParams, None)
    id = resp.json()["ClusterID"]
    utils.mkdir("{0}/.{1}/{2}".format(utils.getHome(), "kcluster", id))
    return resp, "kcluster/{0}".format(id)

sslVerify = True
def doAPIOper(servers, id, verb, noun, queryParams, data):
    home = utils.getHome()
    if servers is None:
        with open('{0}/.{1}/{2}/servers.yaml'.format(home, "kcluster", id)) as fp:
            servers = yaml.safe_load(fp)["Servers"]
    elif noun != "servers":
        resp = doAPIOper(servers, id, "get", "servers", queryParams, data)
        if resp.status_code!=200:
            return resp
        id = resp.json()["ClusterID"]

    def getWithDebug(req):
        print("REQ: {0}".format(req))
        print("QUERYPARAMS: {0}".format(queryParams))
        resp = requests.get(req, params=queryParams, verify=sslVerify)
        print("RESP: {0}".format(resp))
        return resp

    #print("Verify={0}".format(sslVerify))

    if verb=="get":
        reqFn = lambda req : requests.get(req, params=queryParams, verify=sslVerify)
        #reqFn=getWithDebug
    elif verb=="create":
        reqFn = lambda req : requests.post(req, params=queryParams, json=data, verify=sslVerify)
    elif verb=="delete":
        reqFn = lambda req : requests.delete(req, params=queryParams, verify=sslVerify)
    elif verb=="put":
        reqFn = lambda req : requests.put(req, params=queryParams, json=data, verify=sslVerify)
    else:
        print("Unknown verb {0} - noun {1}".format(verb, noun))
        exit()
    #print("Verb: {0} Noun: {1} Servers: {2} QueryParams: {3} Data: {4}".format(verb, noun, servers, queryParams, data))
    resp = webutils.tryHttpServers("{0}".format(noun), servers, reqFn, partial(getServers, queryParams), verify=sslVerify)

    #if resp is not None:
    #    print(json.dumps(resp.json()))

    if resp is not None and resp.status_code==200 and verb=="get":
        if noun=="user":
            try:
                user = resp.json()['User']
                info = resp.json()['UserInfo']
                utils.merge2Yaml("{0}/.kcluster/{1}/users.yaml".format(home, id), {user: info})
            except Exception:
                print("Unable to get userinfo from {0}".format(resp.json()))
        elif noun=="servers":
            id = resp.json()["ClusterID"]
            utils.mkdir("{0}/.{1}/{2}".format(home, "kcluster", id))            
            webutils.dumpServers(resp, "kcluster/{0}".format(id))
        elif noun=="kubecred":
            dumpKubeCreds(resp.json()['user'], resp.json(), id)

    return resp

def argsToQuery(user=None, workspec=None, status=None, workcfg=None, workfile=None, origspec=None, workuser=None, dataPut=None):
    queryParams = {}
    data = dataPut
    if user is not None:
        home = utils.getHome()
        cfgfile = "{0}/.{1}/{1}.users.yaml".format(home, "kcluster")
        cfg = utils.loadYaml(cfgfile)
        queryParams['provider'] = cfg[user]['provider']
        queryParams['id_token'] = cfg[user]['tokens']['id_token']
    else: # worktoken
        queryParams['work_token'] = os.environ["KC_WORKTOKEN"]
    if status is not None:
        queryParams['status'] = status
    if workuser is not None:
        queryParams['workuser'] = workuser

    if workspec is not None:
        if data is None:
            data = {}
        data.update({
            'spec': workspec, # this work's spec - a map
            'origspec': origspec, # original spec without mods - a map
            'workfile': workfile # the raw file as string
        })
        if workcfg is not None:
            data['workcfg'] = workcfg # a map
  
    return queryParams, data

def serversWithPort(id, port, http=None):
    cfgdir = "{0}/.kcluster/{1}".format(utils.getHome(), id)
    serverInfo = utils.loadYaml("{0}/servers.yaml".format(cfgdir))
    servers = serverInfo["Servers"]
    if http is None:
        return [re.sub('(.*):(.*)', '\g<1>:{0}'.format(port), s) for s in servers]
    else:
        return [re.sub('(.*)://(.*):(.*)', '{0}://\g<2>:{1}'.format(http, port), s) for s in servers]
    return servers
