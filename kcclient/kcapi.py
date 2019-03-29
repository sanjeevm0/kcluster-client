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

def getCtx(id, user, server):
    ctxFile = '{0}/.kcluster/context.yaml'.format(utils.getHome())
    if os.path.exists(ctxFile):
        ctx = utils.loadYaml(ctxFile)
        return ctx['ClusterID'], ctx['User']
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

def dumpKubeCreds(user, resp, id):
    cfgdir = utils.getHome()+"/.kcluster/{0}".format(id)
    print("Writing {0} to {1}".format(resp, cfgdir))
    with open('{0}/ca-kube.pem'.format(cfgdir), 'w') as fp:
        fp.write(resp['CA'])
    with open('{0}/{1}-kube.pem'.format(cfgdir, user), 'w') as fp:
        fp.write(resp['Cert'])
    with open('{0}/{1}-kube-key.pem'.format(cfgdir, user), 'w') as fp:
        fp.write(resp['Key'])

def getServers(queryParams, server):
    resp = doAPIOper([server], None, "get", "servers", queryParams, None)
    id = resp.json()["ClusterID"]
    utils.mkdir("{0}/.{1}/{2}".format(utils.getHome(), "kcluster", id))
    return resp, "kcluster/{0}".format(id)

def doAPIOper(servers, id, verb, noun, queryParams, data):
    home = utils.getHome()
    if servers is None:
        with open('{0}/.{1}/{2}/servers.yaml'.format(home, "kcluster", id)) as fp:
            servers = yaml.load(fp)["Servers"]
    elif noun != "servers":
        resp = doAPIOper(servers, id, "get", "servers", queryParams, data)
        if resp.status_code!=200:
            return resp
        id = resp.json()["ClusterID"]

    def getWithDebug(req):
        print("REQ: {0}".format(req))
        print("QUERYPARAMS: {0}".format(queryParams))
        resp = requests.get(req, params=queryParams)
        print("RESP: {0}".format(resp))
        return resp

    if verb=="get":
        reqFn = lambda req : requests.get(req, params=queryParams)
        #reqFn=getWithDebug
    elif verb=="create":
        reqFn = lambda req : requests.post(req, params=queryParams, json=data)
    elif verb=="delete":
        reqFn = lambda req : requests.delete(req, params=queryParams)
    elif verb=="put":
        reqFn = lambda req : requests.put(req, params=queryParams, json=data)
    else:
        print("Unknown verb {0} - noun {1}".format(verb, noun))
        exit()
    #print("Verb: {0} Noun: {1} Servers: {2} QueryParams: {3} Data: {4}".format(verb, noun, servers, queryParams, data))
    resp = webutils.tryHttpServers("{0}".format(noun), servers, reqFn, partial(getServers, queryParams))

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

def argsToQuery(user=None, jobspec=None, status=None, jobcfg=None, jobfile=None, origspec=None, jobuser=None, dataPut=None):
    queryParams = {}
    data = dataPut
    if user is not None:
        home = utils.getHome()
        cfgfile = "{0}/.{1}/{1}.users.yaml".format(home, "kcluster")
        cfg = utils.loadYaml(cfgfile)
        queryParams['provider'] = cfg[user]['provider']
        queryParams['id_token'] = cfg[user]['tokens']['id_token']
    else: # jobtoken
        queryParams['job_token'] = os.environ["KC_JOBTOKEN"]
    if status is not None:
        queryParams['status'] = status
    if jobuser is not None:
        queryParams['jobuser'] = jobuser

    if jobspec is not None:
        if data is None:
            data = {}
        data.update({
            'spec': jobspec, # this job's spec - a map
            'origspec': origspec, # original spec without mods - a map
            'jobfile': jobfile # the raw file as string
        })
        if jobcfg is not None:
            data['jobcfg'] = jobcfg # a map
  
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
