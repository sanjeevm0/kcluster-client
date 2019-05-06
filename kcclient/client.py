#!/usr/bin/python
import argparse
import yaml
import json
import os
import sys
import requests
from functools import partial
import copy
from jinja2 import Template
import re
thisPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(thisPath, '..', '..', 'utils'))
sys.path.append(thisPath)
from kcapi import doAPIOper, getUser, getCtxId, argsToQuery, getCtx, setCtx
import kubeclient
import kcapi
import utils
import oidclogin
import webutils

def apiOperWork(verb, noun, queryParams=None, data=None):
    home = utils.getHome()
    if queryParams is None:
        (queryParams, _) = argsToQuery()
    id = os.environ["KC_CLUSTERID"]
    if os.path.exists('{0}/.{1}/{2}/servers.yaml'.format(home, "kcluster", id)):
        servers = None # read from file
    else:
        servers = os.environ["KC_APISERVERS"].split(",") # initial list of servers
    return doAPIOper(servers, id, verb, noun, queryParams, data)

def apiOperWithLogin(user, servers, id, verb, noun, queryParams, data):
    resp = doAPIOper(servers, id, verb, noun, queryParams, data)
    if resp is not None and resp.status_code == 401 and 'NeedLogin' in resp.json() and resp.json()['NeedLogin']:
        #print(json.dumps(resp.json()))
        cfg = utils.loadYaml("{0}/.{1}/{1}.users.yaml".format(utils.getHome(), "kcluster"))
        oidclogin.login(cfg[user]['provider'].lower(), "kcluster")
        # update token & try again
        cfg = utils.loadYaml("{0}/.{1}/{1}.users.yaml".format(utils.getHome(), "kcluster"))
        queryParams['id_token'] = cfg[user]['tokens']['id_token']
        return doAPIOper(servers, id, verb, noun, queryParams, data)
    else:
        return resp

def getServiceSelectors(specs):
    selectors = {}
    for spec in specs:
        if spec['kind']=="Service":
            selectors[utils.getVal(spec, 'metadata.name')] = utils.getVal(spec, 'spec.selector')
    return selectors

def modSpec(spec, serviceSelectors, suffix):
    if spec['kind'] in ['Pod', 'Deployment', 'Job']:
        labels = utils.getVal(spec, 'metadata.labels')
        key = None
        if labels is not None:
            for labelKey in labels:
                for selector in serviceSelectors:
                    for selectorKey in serviceSelectors[selector]:
                        if selectorKey==labelKey:
                            key = selectorKey
        #print("SelectorKey={0}".format(key))
        if key is not None:
            spec['metadata']['labels'][key] += suffix
        spec['metadata']['name'] += suffix
        if spec['kind'] in ['Deployment', 'Job']:
            if key is not None:
                spec['spec']['template']['metadata']['labels'][key] += suffix
            if 'name' in spec['spec']['template']['metadata']:
                spec['spec']['template']['metadata']['name'] += suffix
    elif spec['kind']=='Service':
        spec['metadata']['name'] += suffix
        key0 = list(spec['spec']['selector'])[0]
        spec['spec']['selector'][key0] += suffix
        exist = utils.getVal(spec, 'metadata.labels.{0}'.format(key0))
        if exist is not None:
            spec['metadata']['labels'][key0] += suffix

def specIter(user, status, workcfg, workfile, workuser):
    if workcfg is not None:
        template = Template(workfile)
        specC = template.render(cnf=workcfg)
    else:
        specC = workfile
    specs = utils.loadMYamlC(specC)
    #print(specC)
    selectors = getServiceSelectors(specs)
    suffix = "-" + utils.random_string(10)
    for spec in specs:
        origspec = copy.deepcopy(spec)
        modSpec(spec, selectors, suffix)
        (queryParams, data) = argsToQuery(user, spec, status, workcfg, workfile, origspec, workuser)
        yield (queryParams, data, spec)

def fileIter(workfile, user, status, workcfg, workuser, workcfgupdate=None):
    if workfile is not None:
        with open(workfile, 'r') as fp:
            workfilecontent = fp.read()
    else:
        workfilecontent = utils.b64d(os.environ["KC_WORKFILE"])
    if workcfg is not None:
        workcfgcontent = utils.loadYaml(workcfg) # a map
    elif "KC_WORKCFG" in os.environ:
        workcfgcontent = yaml.safe_load(utils.b64d(os.environ["KC_WORKCFG"])) # a map
    else:
        workcfgcontent = None
    if workcfgcontent is not None and workcfgupdate is not None:
        workcfgcontent.update(workcfgupdate)
    return specIter(user, status, workcfgcontent, workfilecontent, workuser)

def replicateAll(workcfgupdate=None):
    for (queryParams, data, _) in fileIter(None, None, None, None, None, workcfgupdate=workcfgupdate):
        apiOperWork("create", "work", queryParams, data)

def replicate(specupdate=None, workcfgupdate=None):
    (queryParams, data) = argsToQuery(None)
    suffix = "-" + utils.random_string(10)
    #spec = apiOperWork("get", "work/{0}".format(os.environ["KC_WORKNAME"]), queryParams, data).json()["spec"]
    #spec['metadata']['name'] += suffix
    origspec = yaml.safe_load(utils.b64d(os.environ["KC_ORIGSPEC"]))
    if specupdate is not None:
        origspec.update(specupdate) # modify original
    spec = copy.deepcopy(origspec)
    modSpec(spec, {}, suffix)
    workfilecontent = utils.b64d(os.environ["KC_WORKFILE"]) # raw
    if "KC_WORKCFG" in os.environ:
        workcfgcontent = yaml.safe_load(utils.b64d(os.environ["KC_WORKCFG"])) # a map
    else:
        workcfgcontent = None
    if workcfgcontent is not None and workcfgupdate is not None:
        workcfgcontent.update(workcfgupdate)
    (queryParams, data) = argsToQuery(None, spec, None, workcfgcontent, workfilecontent, origspec, None)
    apiOperWork("create", "work", queryParams, data)

def printResp(resp, verb, noun, output):
    if output is None:
        print(json.dumps(resp.json()))
    elif output=="simple" and verb=="get" and noun.split('/')[0] in ['work', 'worktree']:
        resp = resp.json()
        print("{0:<20}{1:<20}{2:<20}{3:<20}".format("WORKNAME", "STATUS", "AGE", "PARENT"))
        for workname in resp:
            respwork = resp[workname]
            ageStr = utils.msToTimeStr(utils.timeInMs()-respwork['time'], 2)
            if 'parent' in respwork:
                parentStr = respwork['parent'].split('/')[-1]
            else:
                parentStr = "None"
            print("{0:<20}{1:<20}{2:<20}{3:<20}".format(workname.split("/")[-1], respwork['status'], ageStr, parentStr))
    else:
        print(yaml.dump(resp.json()))

def getJupyterEndPt(args):
    jname = args.noun.split('/')[1]
    if args.jsvc is None:
        args.jsvc = jname
        args.jsvc = args.jsvc.replace("pod", "svc")
        args.jsvc = args.jsvc.replace("work", "svc")
    #print("WORK: {0}\nSVC: {1}".format(jname, args.jsvc))
    svcDesc, _ = kubeclient.doKubeOper(args.user, args.id, "get svc/{0} -o yaml".format(args.jsvc).split())
    #print(yaml.safe_load(svcDesc))
    port = utils.getVal(yaml.safe_load(svcDesc), 'spec.ports.[0].nodePort')
    if port is not None:
        endpt = kcapi.serversWithPort(args.id, port, "https")
        worklog, _ = kubeclient.doKubeOper(args.user, args.id, "logs pod/{0}".format(jname).split())
        #print(worklog)
        m = re.match('.*?http://.*(/\?token=.*?)(\s+|$)', " ".join(worklog.split()))
        if m is not None:
            endpt = [e+m.group(1) for e in endpt]
    print(endpt)
    return endpt

def workOper(args):
    if args.jsvc is None:
        args.jsvc = args.jname
        args.jsvc = args.jsvc.replace("pod", "svc")
        args.jsvc = args.jsvc.replace("work", "svc")
    opers = [args.verb]
    if args.output=='yaml':
        opers.extend(["-o", "yaml"])
    out, _ = kubeclient.doKubeOper(args.user, args.id, opers + ["pod", args.jname])
    print(out)
    out, _ = kubeclient.doKubeOper(args.user, args.id, opers + ["svc", args.jsvc])
    print(out)

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1]=='kube':
        kubeclient.main(sys.argv[2:])
        exit()
    parser = argparse.ArgumentParser("client.py", description="RestAPI Client for KubeCluster -- use with 'kube' as first argument to run 'kubectl' commands on cluster")
    parser.add_argument("verb", nargs='?', choices=['login', 'get', 'put', 'create', 'delete', 'describe', 'checktoken', 'browse'])
    parser.add_argument("noun", nargs='?', default='')
    parser.add_argument("noun2", nargs='?', default=None)
    parser.add_argument("-d", "--data", default=None)
    parser.add_argument("-s", "--server", default=None)
    parser.add_argument("-id", "--id", default=None)
    parser.add_argument("-u", "--user", default=None)
    parser.add_argument("-f", "--file", default=None, 
        help=("Workload submission file, currently support 'Secret', 'ConfigMap', 'Pod', 'Deployment', 'Service' -- may be template "
            "which is rendered using --cfg argument"))
    parser.add_argument("-workuser", "--workuser", default=None, help="Submit work on behalf of another user (for admins)")
    parser.add_argument("-status", "--status", choices=['approved', 'approvednq'], default=None,
        help="Change status of job to approved or approvednq automatically (for admins)")
    parser.add_argument("-cfg", "--cfg", default=None, help="Configuration to render file for submission - optional in case -f argument is template")
    parser.add_argument("-jname", "--jname", default=None, help="WorkloadName")
    parser.add_argument("-jsvc", "--jsvc", default=None, help="ServiceName")
    parser.add_argument("-o", "--output", choices=['yaml', 'simple'], default=None)
    parser.add_argument("-ctx", "--setcontext", action='store_true')
    args = parser.parse_args()
    args.noun = args.noun.lower()
    if args.noun2 is not None:
        args.noun += "/"+args.noun2
    if args.server is not None:
        args.server = args.server.split(",") # an array of servers
    if args.verb == "login":
        args.id = getCtxId(args.id, args.server)
    else:
        (args.id, args.user) = getCtx(args.id, args.user, args.server, args.setcontext)
    if args.verb != "login":
        args.user = getUser(args.id, args.user)
    if args.data is not None:
        args.data = yaml.safe_load(args.data)

    if args.setcontext:
        setCtx(args.id, args.user)
        exit()

    if args.verb == 'checktoken':
        print(webutils.decodeOIDCToken("kcluster", args.user))
        exit()

    if args.verb == "login":
        if args.noun == "google" or args.noun == "msft":
            (_, user) = oidclogin.login(args.noun, "kcluster")
            # after login, obtain userinfo and usercreds
            (queryParams, data) = argsToQuery(user=user)
            doAPIOper(args.server, args.id, "get", "user", queryParams, data)
            doAPIOper(args.server, args.id, "get", "kubecred", queryParams, data)
    else:
        if args.verb == "create":
            args.noun = "work"
        if args.verb == "get" and args.noun.startswith("endpt/"):
            #print("GETSVC: {0}".format(args.noun.split('/')[1]))
            svcDesc, _ = kubeclient.doKubeOper(args.user, args.id, "get svc {0} -o yaml".format(args.noun.split('/')[1]).split())
            #print(yaml.safe_load(svcDesc))
            port = utils.getVal(yaml.safe_load(svcDesc), 'spec.ports.[0].nodePort')
            if port is not None:
                print(kcapi.serversWithPort(args.id, port, "https"))
        elif args.verb in ["get", "browse"] and args.noun.startswith("jendpt/"):
            endpts = getJupyterEndPt(args)
            if args.verb == "browse":
                import webbrowser, random
                webbrowser.open(random.choice(endpts), new=2)
        elif args.verb in ['get', 'delete', 'describe'] and args.jname is not None:
            workOper(args)
        elif args.file is not None:
            for (queryParams, data, _) in fileIter(args.file, args.user, args.status, args.cfg, args.workuser):
                resp = apiOperWithLogin(args.user, args.server, args.id, args.verb, args.noun, queryParams, data)
                printResp(resp, args.verb, args.noun, args.output)
        else:
            (queryParams, data) = argsToQuery(user=args.user, workuser=args.workuser, dataPut=args.data)
            resp = apiOperWithLogin(args.user, args.server, args.id, args.verb, args.noun, queryParams, data)
            printResp(resp, args.verb, args.noun, args.output)
