import os
import threading
from base64 import b64encode, b64decode

import yaml
import copy
import json
import flask
import sys
thisPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(thisPath)
import utils
import dockerutils

import log
import logging
logger = log.start_log("{0}/kubemutate.log".format(utils.getLogDir()), logging.DEBUG, logging.INFO, 'w', 'kubemutatelog')

def setlogger(newlogger):
    global logger
    logger = newlogger
    dockerutils.setlogger(newlogger)

def changeEntryPoint(cont, prefix, suffix):
    entrypoint, cmd = dockerutils.getdockerentrypoint(cont['image'])
    # entrypoint is "command", cmd is "args"
    command = cont.get('command', None)
    # if command is specified, then "args" (cmd) from Dockerfile does not matter
    if command is not None:
        cmd = []
    if command is None:
        command = entrypoint
    if command is None:
        command = ["/bin/sh", "-c"] # default if none specified
    args = cont.get('args', None)
    if args is None:
        args = cmd
    if args is None:
        args = []
    cont['command'] = ['/bin/bash', '-c']
    fullCmd = command + args
    for i, f in enumerate(fullCmd):
        logger.debug("FullCmdBegin: {0}".format(f))
        if type(f)==str:
            fullCmd[i] = fullCmd[i].replace('\\', '\\\\')
            fullCmd[i] = fullCmd[i].replace('"', '\\"')
        if type(f)==str and " " in f:
            fullCmd[i] = '"' + fullCmd[i] + '"'
        if type(f)!=str:
            fullCmd[i] = str(f)
        logger.debug("FullCmdEnd: {0}".format(fullCmd[i]))
    fullCmd = prefix + fullCmd + suffix
    fullCmdStr = " ".join(fullCmd)
    cont['args'] = [fullCmdStr]

class Mutate():
    def __init__(self, port=8000, sslCertKey=None, allowedOper=['CREATE'], allowedObj=['Pod'], cb=None):
        self.server = flask.Flask("Mutate service")
        self.server.add_url_rule("/mutate", None, self.mutate, methods=['GET', 'POST'])
        serverArgs = {'host': '0.0.0.0', 'port': port}
        if sslCertKey is None:
            if os.path.exists('/certs/tls.crt') and os.path.exists('/certs/tls.key'):
                sslCertKey = ('/certs/tls.crt', '/certs/tls.key')
        if sslCertKey is not None:
            serverArgs['ssl_context'] = sslCertKey
        self.allowedOper = allowedOper
        self.allowedObj = allowedObj
        self.cb = cb # callback for mutated object
        t = threading.Thread(target=self.server.run, kwargs=serverArgs)
        t.daemon = True
        t.start()

    def runForever(self):
        e = threading.Event()
        e.wait()

    def mutate(self):
        request = flask.request
        admitRequest = yaml.safe_load(request.data)
        admitResponse = self.mutateObj(admitRequest)
        return flask.jsonify(admitResponse)

    def doMutate(self, obj, objOrig):
        raise NotImplementedError("doMutate not implemented") # implement in subclass
        return False

    def addPatch(self, admitResponse, obj, objOrig):
        # create patch
        patchBody = []
        if utils.getValDef(obj, ['spec'], None, None) != utils.getValDef(objOrig, ['spec'], None, None):
            patchBody.append({"op": "replace", "path": "/spec", "value": obj['spec']})
        if (utils.getValDef(obj, ['metadata', 'annotations'], None, None) != 
            utils.getValDef(objOrig, ['metadata', 'annotations'], None, None)):
            patchBody.append({"op": "replace", "path": "/metadata/annotations", "value": obj['metadata']['annotations']})
        if (utils.getValDef(obj, ['metadata', 'labels'], None, None) != 
            utils.getValDef(objOrig, ['metadata', 'labels'], None, None)):
            patchBody.append({"op": "replace", "path": "/metadata/labels", "value": obj['metadata']['labels']})
        if patchBody==[]:
            return
        patchStr = b64encode(json.dumps(patchBody).encode()).decode()
        if 'name' in obj['metadata']:
            utils.logger.debug("Create Patch {0} for {1}".format(patchStr, obj['metadata']['name']))
        else:
            utils.logger.debug("Create Patch {0} for unknown name".format(patchStr))

        admitResponse['response'].update({
            'patchType': 'JSONPatch',
            'patch': patchStr
        })

    def mutateObj(self, admitRequest):
        admitResponse = {
            'apiVersion': admitRequest['apiVersion'],
            'kind': admitRequest['kind'],
            'response': {
                'uid': admitRequest['request']['uid'],
                'allowed': True,
                'auditAnnotations' : {
                    'mutated': 'true'
                }
            }
        }
        admitRequest = admitRequest['request']

        # check operation - CREATE
        if admitRequest['operation'] not in self.allowedOper:
            admitResponse['response']['allowed'] = False
            return admitResponse # should not happen only register for CREATE

        if admitRequest['object']['kind'] not in self.allowedObj:
            admitResponse['response']['allowed'] = False
            return admitResponse # no patch

        objOrig = copy.deepcopy(admitRequest['object'])

        try:
            mutated = self.doMutate(admitRequest['object'], objOrig) # now object is admitted
            if self.cb is not None: # can be captured in doMutate also
                self.cb(objOrig, admitRequest['object'], mutated)
        except Exception as e:
            logger.error("Mutation error: {0}".format(e))
            admitResponse['response']['allowed'] = False
            return admitResponse

        if mutated:
            self.addPatch(admitResponse, admitRequest['object'], objOrig)

        return admitResponse
