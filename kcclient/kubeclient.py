import os
import sys
thisPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(thisPath, '..', '..', 'utils'))
sys.path.append(os.path.join(thisPath))
from kcapi import doAPIOper, getUser, getCtxId, argsToQuery, getServers
from subprocess import PIPE
import argparse
import utils
import webutils
import yaml
import subprocess
import atexit
import re
from functools import partial
from subprocess import PIPE

def getKubeStr(user, id, kubeargstr, namespace, server):
    cfgdir = "{0}/.kcluster/{1}".format(utils.getHome(), id)
    base = "{0}/{1}".format(cfgdir, user)
    if namespace is None:
        namespace = utils.loadYaml("{0}/users.yaml".format(cfgdir))[user]['namespace']
    cmd = ("kubectl --server={0} --namespace={1} "
           "--certificate-authority={2}/ca-kube.pem "
           "--client-certificate={3}-kube.pem "
           "--client-key={3}-kube-key.pem {4}".format(
           server, namespace, cfgdir, base, kubeargstr))
    #print(cmd)
    return cmd

def doOper(user, id, kubeargs, namespace, server, capture_stdout=False):
    cmd = getKubeStr(user, id, utils.quoteJoinArgs(kubeargs), namespace, server)
    if capture_stdout:
        out = subprocess.run(cmd, stderr=PIPE, stdout=PIPE)
    else:
        out = subprocess.run(cmd, stderr=PIPE)
    if "Unable to connect to the server" in out.stderr.decode():
        return None
    else:
        if out.stderr.decode() != '':
            print(out.stderr.decode())
        return out

def moveExistConfig():
    home = utils.getHome()
    if os.path.exists("{0}/.kube/config".format(home)):
        os.rename("{0}/.kube/config".format(home), "{0}/.kube/config_temp".format(home))
        atexit.register(os.rename,
                        "{0}/.kube/config_temp".format(home), "{0}/.kube/config".format(home))

def doKubeOper(user, id, kubeargs, namespace=None, servers=None):
    moveExistConfig()
    if servers is None:
        cfgdir = "{0}/.kcluster/{1}".format(utils.getHome(), id)
        serverInfo = utils.loadYaml("{0}/servers.yaml".format(cfgdir))
        servers = serverInfo["Servers"]
        servers = [re.sub('(.*):(.*)', '\g<1>:{0}'.format(serverInfo["k8sport"]), s) for s in servers]
    doOperFn = lambda server : doOper(user, id, kubeargs, namespace, server, True)
    out = webutils.tryServers(servers, doOperFn, None)
    return out.stdout.decode(), out

def main(argv):
    parser = argparse.ArgumentParser("kubectl.py")
    parser.add_argument("--id", default=None, help="Context ID of cluster to operate on")
    parser.add_argument("-u", "--user", default=None)
    parser.add_argument("-n", "--namespace", default=None)
    args, remargs = parser.parse_known_args(argv)

    args.id = getCtxId(args.id, None)
    cfgdir = "{0}/.kcluster/{1}".format(utils.getHome(), args.id)
    args.user = getUser(args.id, args.user)

    # move default config as it may conflict, register to remove
    moveExistConfig()

    serverInfo = utils.loadYaml("{0}/servers.yaml".format(cfgdir))
    servers = serverInfo["Servers"]
    servers = [re.sub('(.*):(.*)', '\g<1>:{0}'.format(serverInfo["k8sport"]), s) for s in servers]
    (queryParams, _) = argsToQuery(user=args.user)
    webutils.tryServers(servers, partial(doOper, args.user, args.id, remargs, args.namespace), partial(getServers, queryParams))
