import flask
import yaml
import copy
import json
import utils
from base64 import b64encode

class Mutate():
    def __init__(self, port=8000, sslCertKey=None, allowedOper=['CREATE'], allowedObj=['Pod'], cb=None):
        self.server = flask.Flask("Mutate service")
        self.server.add_url_rule("/mutate", None, self.mutate, methods=['GET', 'POST'])
        serverArgs = {'host': '0.0.0.0', 'port': port}
        if sslCertKey is not None:
            serverArgs['ssl_context'] = sslCertKey
        self.allowedOper = allowedOper
        self.allowedObj = allowedObj
        self.cb = cb # callback for mutated object
        self.server.run()

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
        mutated = self.doMutate(admitRequest['object'], objOrig) # now object is admitted
        if self.cb is not None: # can be captured in doMutate also
            self.cb(objOrig, admitRequest['object'], mutated)

        if mutated:
            self.addPatch(admitResponse, admitRequest['object'], objOrig)

        return admitResponse
