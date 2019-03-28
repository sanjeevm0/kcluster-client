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
import kubeclient
import kcapi
import re
from kcapi import doAPIOper, getUser, getCtxId, argsToQuery
thisPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(thisPath, '..', '..', 'utils'))
import utils
import oidclogin
import webutils

def dumpKubeCreds(user, resp, id):
    cfgdir = utils.getHome()+"/.kcluster/{0}".format(id)
    print("Writing {0} to {1}".format(resp, cfgdir))
    with open('{0}/ca-kube.pem'.format(cfgdir), 'w') as fp:
        fp.write(resp['CA'])
    with open('{0}/{1}-kube.pem'.format(cfgdir, user), 'w') as fp:
        fp.write(resp['Cert'])
    with open('{0}/{1}-kube-key.pem'.format(cfgdir, user), 'w') as fp:
        fp.write(resp['Key'])

def apiOperJob(verb, noun, queryParams, data):
    home = utils.getHome()
    id = os.environ["KC_CLUSTERID"]
    if os.path.exists('{0}/.{1}/{2}/servers.yaml'.format(home, "kcluster", id)):
        servers = None # read from file
    else:
        servers = os.environ["KC_APISERVERS"] # initial
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

def specIter(user, status, jobcfg, jobfile, jobuser):
    if jobcfg is not None:
        template = Template(jobfile)
        specC = template.render(cnf=jobcfg)
    else:
        specC = jobfile
    specs = utils.loadMYamlC(specC)
    selectors = getServiceSelectors(specs)
    suffix = "-" + utils.random_string(10)
    for spec in specs:
        origspec = copy.deepcopy(spec)
        modSpec(spec, selectors, suffix)
        (queryParams, data) = argsToQuery(user, spec, status, jobcfg, jobfile, origspec, jobuser)
        yield (queryParams, data, spec)

def fileIter(file, user, status, jobcfg, jobfile, jobuser):
    if jobfile is not None:
        with open(file, 'r') as fp:
            jobfilecontent = fp.read()
    else:
        jobfilecontent = utils.b64d(os.environ["KC_JOBFILE"])
    if jobcfg is not None:
        jobcfgcontent = utils.loadYaml(jobcfg)
    elif "KC_JOBCFG" in os.environ:
        jobcfgcontent = utils.b64d(os.environ["KC_JOBCFG"])
    else:
        jobcfgcontent = None
    return specIter(user, status, jobcfgcontent, jobfilecontent, jobuser)

def replicateAll():
    for (queryParams, data, _) in fileIter(None, None, None, None, None):
        apiOperJob("create", "job", queryParams, data)

def replicate():
    (queryParams, data) = argsToQuery(None)
    suffix = "-" + utils.random_string(10)
    #spec = apiOperJob("get", "job/{0}".format(os.environ["KC_JOBNAME"]), queryParams, data).json()["spec"]
    #spec['metadata']['name'] += suffix
    origspec = yaml.load(utils.b64d(os.environ["KC_ORIGSPEC"]))
    spec = copy.deepcopy(origspec)
    modSpec(spec, {}, suffix)
    jobfilecontent = utils.b64d(os.environ["KC_JOBFILE"])
    jobcfgcontent = utils.b64d(os.environ["KC_JOBCFG"])
    (queryParams, data) = argsToQuery(None, spec, None, jobcfgcontent, jobfilecontent, origspec, None)
    apiOperJob("create", "job", queryParams, data)

def printResp(resp, output):
    if output is None:
        print(json.dumps(resp.json()))
    elif output=="yaml":
        print(yaml.dump(resp.json()))

def getJupyterEndPt(args):
    svcDesc, _ = kubeclient.doKubeOper(args.user, args.id, "get svc/{0} -o yaml".format(args.jsvc).split())
    #print(yaml.load(svcDesc))
    port = utils.getVal(yaml.load(svcDesc), 'spec.ports.[0].nodePort')
    if port is not None:
        endpt = kcapi.serversWithPort(args.id, port, "http")
        joblog, _ = kubeclient.doKubeOper(args.user, args.id, "logs pod/{0}".format(args.jname).split())
        #print(joblog)
        m = re.match('.*?http://.*(/\?token=.*?)(\s+|$)', " ".join(joblog.split()))
        if m is not None:
            endpt = [e+m.group(1) for e in endpt]
    print(endpt)

if __name__ == "__main__":
    if sys.argv[1]=='kube':
        kubeclient.main(sys.argv[2:])
        exit()
    parser = argparse.ArgumentParser()
    parser.add_argument("verb", choices=['login', 'get', 'create', 'delete', 'checktoken'])
    parser.add_argument("noun", nargs='?', default='')
    parser.add_argument("-s", "--server", default=None)
    parser.add_argument("--id", default=None)
    parser.add_argument("-u", "--user", default=None)
    parser.add_argument("-f", "--file", default=None)
    parser.add_argument("--jobuser", default=None, help="Submit job on behalf of another user (for admins)")
    parser.add_argument("--status", choices=['approved', 'approvednq'], default=None)
    parser.add_argument("--cfg", default=None, help="Configuration to render file for submission")
    parser.add_argument("--endpt", action='store_true', help="Get job endpoint service")
    parser.add_argument("--jendpt", action='store_true', help="Get Jupyter connection endpt")
    parser.add_argument("--jname", help="JobName")
    parser.add_argument("--jsvc", help="ServiceName")
    parser.add_argument("-o", "--output", choices=['yaml'], default=None)
    args = parser.parse_args()
    args.noun = args.noun.lower()
    if args.server is not None:
        args.server = args.server.split(",") # an array of servers
    args.id = getCtxId(args.id, args.server)
    if args.verb != "login":
        args.user = getUser(args.id, args.user)

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
            args.noun = "job"
        if args.verb == "get" and args.endpt:
            svcDesc, _ = kubeclient.doKubeOper(args.user, args.id, "get {0} -o yaml".format(args.noun).split())
            #print(yaml.load(svcDesc))
            port = utils.getVal(yaml.load(svcDesc), 'spec.ports.[0].nodePort')
            if port is not None:
                print(kcapi.serversWithPort(args.id, port, "http"))
        elif args.verb == "get" and args.jendpt:
            getJupyterEndPt(args)
        elif args.file is not None:
            for (queryParams, data, _) in fileIter(args.file, args.user, args.status, args.cfg, args.file, args.jobuser):
                resp = apiOperWithLogin(args.user, args.server, args.id, args.verb, args.noun, queryParams, data)
                printResp(resp, args.output)
        else:
            (queryParams, data) = argsToQuery(user=args.user, jobuser=args.jobuser)
            resp = apiOperWithLogin(args.user, args.server, args.id, args.verb, args.noun, queryParams, data)
            printResp(resp, args.output)
