#!/usr/bin/env python3
import os
import subprocess
import kubeutils
from pathlib import Path
import sys
thisPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(thisPath)
import utils
import json
from base64 import b64decode

import log
import logging
logger = log.start_log("{0}/dockerutils.log".format(utils.getLogDir()), logging.DEBUG, logging.INFO, 'w', 'dockerlog')

def setlogger(newlogger):
    global logger
    logger = newlogger

def dockerstoresecrets(c : kubeutils.Cluster, secrets, namespace):
    dockerConfigFile = '{0}/.docker/config.json'.format(os.getenv('HOME'))
    if os.path.exists(dockerConfigFile):
        with open(dockerConfigFile, 'r') as fp:
            existAuths = json.load(fp)
    else:
        existAuths = {'auths': {}}

    for secret in secrets:
        _, _, s = c.call_method('read_namespaced_secret', namespace=namespace, name=secret)
        print(s)
        if s is None or s.data is None or '.dockerconfigjson' not in s.data:
            logger.warning("Secret {0} in namespace {1} not found or has no data".format(secret, namespace))
            continue
        auth = json.loads(b64decode(s.data['.dockerconfigjson']))
        logger.info("Found auth: {0}".format(auth))
        existAuths['auths'].update(auth['auths'])
    Path(os.path.dirname(dockerConfigFile)).mkdir(parents=True, exist_ok=True)

    with open(dockerConfigFile, 'w') as fp:
        json.dump(existAuths, fp)

def dockerpullimage(image):
    logger.info("Pulling docker image: {0}".format(image))
    out = subprocess.check_output('docker pull {0}'.format(image), shell=True, stderr=subprocess.STDOUT)
    logger.info("Docker pull output: {0}".format(out.decode('utf-8')))

def getdockerentrypoint(image):
    dockerpullimage(image) # ensure image is present
    logger.info("Getting docker entrypoint for image: {0}".format(image))
    out = subprocess.check_output('docker inspect {0}'.format(image), shell=True, stderr=subprocess.STDOUT)
    inspect = json.loads(out.decode('utf-8'))
    entrypoint = inspect[0]['Config'].get('Entrypoint', [])
    cmd = inspect[0]['Config'].get('Cmd', [])
    logger.info("Docker entrypoint: {0}, cmd: {1}".format(entrypoint, cmd))
    return entrypoint, cmd

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Docker Utils Test")
    parser.add_argument('--findentrypoint', '-fe', default=None, help="Docker image to find entrypoint for")
    parser.add_argument('--storesecrets', '-ss', nargs='+', default=None, help="Store docker secrets from given secret names (comma separated)")
    kubeutils.Cluster.addCmdArgs(parser)
    args = parser.parse_args()

    if args.findentrypoint:
        dockerpullimage(args.findentrypoint)
        entrypoint, cmd = getdockerentrypoint(args.findentrypoint)
        print("Entrypoint: {0}\nCmd: {1}".format(entrypoint, cmd))
    else:
        c = kubeutils.Cluster.fromCmdArgs(args)
        if args.storesecrets:
            namespace = args.storesecrets[0].split('/')[0] if '/' in args.storesecrets[0] else 'default'
            secrets = [s.split('/')[1] if '/' in s else s for s in args.storesecrets]
            dockerstoresecrets(c, secrets, namespace=namespace)
