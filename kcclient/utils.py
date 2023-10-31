import enum
import time
import random
import string
import uuid
import subprocess
import yaml
import os
import re
import copy
import tempfile
import shutil
import threading
from jinja2 import Environment, FileSystemLoader, Template
import base64
import hashlib
import sys
from datetime import datetime
try:
    import importlib.resources
    importlibmodule = importlib.resources
except Exception:
    import importlib_resources
    importlibmodule = importlib_resources
thisPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(thisPath)

def getHome():
    if 'HOME' in os.environ:
        return os.environ['HOME']
    elif 'USERPROFILE' in os.environ:
        return os.environ['USERPROFILE']
    else:
        return ''

import log
import logging
logger = log.start_log("{0}/logs/utils.log".format(getHome()), logging.DEBUG, logging.INFO, 'w', 'utilslog')

def setLogger(_logger):
    global logger
    logger = _logger

def tryuntil(cmdLambda, stopFn, updateFn, waitPeriod=5):
    while not stopFn():
        try:
            output = cmdLambda() # if exception occurs here, update does not occur
            #print "Output: {0}".format(output)
            updateFn()
            toStop = False
            try:
                toStop = stopFn()
            except Exception as e:
                print("Exception {0} -- stopping anyways".format(e))
                toStop = True
            if toStop:
                return output
        except Exception as e:
            print("Exception in command {0}".format(e))
        if not stopFn():
            print("Not done yet - Sleep for 5 seconds and continue")
            time.sleep(waitPeriod)

def random_string_l(length):
    return ''.join(random.choice(string.ascii_lowercase) for i in range(length))

def random_string(length):
    letters = string.ascii_lowercase + string.digits
    return ''.join(random.choice(letters) for i in range(length))

def random_string_lud(length):
    letters = string.ascii_lowercase + string.ascii_uppercase + string.digits
    return ''.join(random.choice(letters) for i in range(length))  

def getCmd(cmd, machine=None, sshid=None, sudo=False):
    if sudo==False:
        sudo=""
    if sudo==True:
        sudo="sudo "
    if machine is None:
        return '{0}{1}'.format(sudo, cmd)
    elif sshid is None:
        return 'ssh {0} "{1}{2}"'.format(machine, sudo, cmd)
    else:
        return 'ssh -i {0} {1} "{2}{3}"'.format(sshid, machine, sudo, cmd)

def run(cmd, machine=None, sshid=None, sudo=False, verbose=False):
    cmdR = getCmd(cmd, machine, sshid, sudo)
    if verbose:
        print(cmdR)
    os.system(cmdR)

def runOut(cmd, machine=None, sshid=None, sudo=False, verbose=False):
    cmdR = getCmd(cmd, machine, sshid, sudo)
    if verbose:
        print(cmdR)
    return subprocess.check_output(cmdR, shell=True).decode().strip()

def runYaml(cmd, machine=None, sshid=None, sudo=False, verbose=False):
    return yaml.safe_load(runOut(cmd, machine, sshid, sudo, verbose))

def yaml_cmd(cmd):
    try:
        output = subprocess.check_output(cmd, shell=True)
        return yaml.safe_load(output)
    except Exception:
        return None

def var_cmd(cmd):
    try:
        lines = subprocess.check_output(cmd, shell=True).decode('utf-8').splitlines()
        output = {}
        for line in lines:
            line = line.strip()
            match = re.match(r'(.*?)\s*=\s*(.*)', line)
            if match is not None and len(match.groups())==2:
                output[match.group(1).strip()] = match.group(2).strip()
        return output
    except Exception:
        return None

def getoutput(cmd):
    try:
        return subprocess.check_output(cmd, shell=True).decode('utf-8').strip()
    except Exception:
        return None

def render_template(template_file, out_file, config):
    env = Environment(loader=FileSystemLoader("/"))
    try:
        template = env.get_template(os.path.abspath(template_file))
    except Exception:
        # try directly reading file
        with open(os.path.abspath(template_file), "r") as f:
            template = Template(f.read())
    content = template.render(cnf=config)
    out_dir = os.path.dirname(out_file)
    os.system("mkdir -p {0}".format(out_dir))
    with open(out_file, 'w') as f:
        f.write(content)

def render_deploy_script(homedir, codedir, deploydir, script, cfg):
    render_template('{0}/scripts/templates/{1}.template'.format(codedir, script),
                    '{0}/scripts/{1}'.format(deploydir, script),
                    cfg)
    os.system("mkdir -p {0}/bin".format(homedir))
    os.system("cp {0}/scripts/{1} {2}/bin".format(deploydir, script, homedir))
    os.system("chmod +x {0}/bin/{1}".format(homedir, script))
    os.system("sudo ln --symbolic --force {0}/bin/{1} /usr/local/bin/{1}".format(homedir, script))

def deploy_script(homedir, codedir, script):
    os.system("mkdir -p {0}/bin".format(homedir))
    os.system("cp {0}/scripts/{1} {2}/bin".format(codedir, script, homedir))
    os.system("chmod +x {0}/bin/{1}".format(homedir, script))
    os.system("sudo ln --symbolic --force {0}/bin/{1} /usr/local/bin/{1}".format(homedir, script))

def connect_to_remote(host, identityFile=None):
    import paramiko
    if identityFile is None:
        identityFile = "{0}/.ssh/id_rsa".format(os.path.expanduser("~"))
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    [user, host] = host.split("@")
    ssh_client.connect(hostname=host, username=user, key_filename=identityFile)
    return ssh_client

def copyFile2(src, dstArg, homedir, numTry=10, pwd=None, id=None):
    m = re.match("(.*):(.*)", dstArg)
    if len(m.groups())==2:
        loc = m.group(1)
        dst = m.group(2)
        dstDir = os.path.dirname(dst)
        if pwd is not None:
            prefix = "/usr/bin/sshpass -p '{0}' ".format(pwd)
        else:
            prefix = ""
        if id is not None:
            idFile = "-i '{0}'".format(id)
        else:
            idFile = ""
        #mkdir
        cmd = "{0}bash -c \"ssh {1} {2} 'sudo bash -s {3}' < {4}/mkdir.sh\"".format(prefix, idFile, loc, dstDir, thisPath)
        print(cmd)
        for i in range(numTry):
            done = getoutput(cmd)
            #print(done)
            if done=="DONE":
                break
            else:
                time.sleep(5.0) # wait and try again
        # now copy
        tmpname = random_string(64)
        cmd = "{0}bash -c \"sudo scp {1} {2} {3}:{4}/{5}\"".format(prefix, idFile, src, loc, homedir, tmpname)
        print(cmd)
        done = getoutput(cmd)
        print(done)
        cmd = "{0}bash -c \"ssh {1} {2} 'sudo mv {3}/{4} {5}'\"".format(prefix, idFile, loc, homedir, tmpname, dst)
        print(cmd)
        done = getoutput(cmd)
        print(done)

def copyFile(src, dstArg, numTry=20, pwd=None, identity_file=None):
    m = re.match("(.*)@(.*):(.*)", dstArg)
    if len(m.groups())==3:
        username = m.group(1)
        machineName = m.group(2)
        dst = m.group(3)
        dstDir = os.path.dirname(dst)
        if pwd is not None:
            os.system("bash {0}/remotemkdirpwd.sh '{1}' {2}@{3} {4} {5}".format(thisPath, pwd, username, machineName, dstDir, numTry))
            cmd = "/usr/bin/sshpass -p '{0}' scp {1} {2}@{3}:{4}".format(pwd, src, username, machineName, dst)
            os.system(cmd)
        elif identity_file is not None:
            os.system("bash {0}/remotemkdir.sh '-i {1} {2}@{3}' {4} {5}".format(thisPath, identity_file, username, machineName, dstDir, numTry))
            cmd = "scp -i '{0}' {1} {2}@{3}:{4}".format(identity_file, src, username, machineName, dst)
            os.system(cmd)
        else:
            os.system("bash {0}/remotemkdir.sh {1}@{2} {3} {4}".format(thisPath, username, machineName, dstDir, numTry))
            cmd = "scp {0} {1}@{2}:{3}".format(src, username, machineName, dst)
            os.system(cmd)

def waitForFile(file):
    while True:
        if os.path.exists(file):
            break
        time.sleep(5)

def waitForFileSudo(file):
    while True:
        if getoutput('sudo ls {0}'.format(file)) is not None:
            break
        time.sleep(5)

def getKeys(x):
    if x is not None:
        return x.keys()
    else:
        return []

def unionKeys2(x1, x2):
    return list(set(getKeys(x1)).union(getKeys(x2)))

def unionKeys3(x1, x2, x3):
    return list(set(getKeys(x1)).union(getKeys(x2), getKeys(x3)))

def merge2(orig, mod):
    # key in orig and mod
    if isinstance(orig, dict) and isinstance(mod, dict):
        return deepmerge2(orig, mod)
    else:
        return copy.deepcopy(mod)

def deepmerge2(orig, mod):
    keys = unionKeys2(orig, mod)
    output = {}
    for key in keys:
        if key in orig and key in mod:
            output[key] = merge2(orig[key], mod[key])
        elif key in orig:
            output[key] = copy.deepcopy(orig[key])
        elif key in mod:
            output[key] = copy.deepcopy(mod[key])
    #print("OUT: {0}".format(output))
    return output

def merge3(orig, mod1, mod2):
    if isinstance(orig, dict) and isinstance(mod1, dict) and isinstance(mod2, dict):
        return deepmerge3(orig, mod1, mod2)
    elif isinstance(mod1, dict) and isinstance(mod2, dict):
        # orig is not dict
        return deepmerge2(mod1, mod2)
    else:
        if orig==mod2:
            # if mod2 has not changed, use mod1
            return copy.deepcopy(mod1)
        elif isinstance(orig, dict) and isinstance(mod2, dict):
            return deepmerge2(orig, mod2)
        else:
            return copy.deepcopy(mod2)

# overwrites orig with mod1, mod2 (mod2 > mod1 > orig) in terms of precedence on conflict
def deepmerge3(orig, mod1, mod2):
    keys = unionKeys3(orig, mod1, mod2)
    output = {}
    for key in keys:
        if key in orig and key in mod1 and key in mod2: # 111
            output[key] = merge3(orig[key], mod1[key], mod2[key])
        elif key not in orig and key in mod1 and key in mod2: # 011
            output[key] = merge2(mod1[key], mod2[key])
        elif key in orig and key not in mod1 and key in mod2: # 101
            output[key] = merge2(orig[key], mod2[key])
        elif key in orig and key in mod1 and key not in mod2: # 110
            output[key] = merge2(orig[key], mod1[key])
        elif key in orig:
            output[key] = copy.deepcopy(orig[key])
        elif key in mod1:
            output[key] = copy.deepcopy(mod1[key])
        elif key in mod2:
            output[key] = copy.deepcopy(mod2[key])
    return output

# mod has priority for same key
def deepmerge(orig, mod):
    if type(orig) != type(mod):
        return copy.deepcopy(mod)
    if isinstance(orig, list):
        n = copy.deepcopy(orig)
        n.extend(copy.deepcopy(mod))
        return n
    if isinstance(orig, dict):
        n = {}
        for k, v in orig.items():
            if k in mod:
                n[k] = deepmerge(v, mod[k])
            else:
                n[k] = copy.deepcopy(v)
        for k, v in mod.items():
            if k not in orig:
                n[k] = copy.deepcopy(v)
        return n
    return copy.deepcopy(mod) # return mod for anything else

def cmpE(x1, x2):
    if isinstance(x1, dict) and isinstance(x2, dict):
        return True
    if isinstance(x1, dict) != isinstance(x2, dict):
        return False # one is dict, other is not
    return x1 == x2

def cmp(key, x1, x2):
    if (key in x1) and (key in x2):
        return cmpE(x1[key], x2[key])
    elif key not in x1 and key in x2:
        return isinstance(x2[key], dict) # if x2[key] dict, then same, as other is empty dic
    elif key not in x2 and key in x1:
        return isinstance(x1[key], dict)
    else:
        return True # not in either

# convert list to dict using keyToUse
def listToDict(x, keyToUse='name'):
    if isinstance(x, list):
        d = {}
        for i in x:
            if not isinstance(i, dict):
                return x # return original list
            if keyToUse in i and i[keyToUse] not in d:
                d[i[keyToUse]] = i
            else:
                return x # return original list
        return d
    else:
        return x

def dictToList(x, skipEmpty=True, keyToUse='name'):
    if isinstance(x, dict):
        l = []
        for k, v in x.items():
            if skipEmpty and (v is None or v=={}):
                continue
            if isinstance(v, dict):
                c = copy.deepcopy(v)
                v.update({keyToUse: k})
                l.append(v)
            else:
                return x # return original dict
        return l
    else:
        return x

def getNonDictDiff(a, b):
    dFull = {'__add__': a, '__del__': b}
    if a is None:
        return {'__del__': b}, dFull
    else:
        return a, dFull

# returns a - b & "full diff"
def diffA(a, b, keyToUse='name'):
    if not isinstance(a, type(b)):
        return getNonDictDiff(a, b)
    aD = listToDict(a, keyToUse)
    bD = listToDict(b, keyToUse)
    isList = isinstance(a, list)
    if not isinstance(aD, dict) or not isinstance(bD, dict):
        if a==b:
            return None, None
        else:
            return getNonDictDiff(a, b)
    else: # either dict to begin with or convertible
        dPart = {}
        dFull = {}
        keys = set(aD.keys())
        keys.update(bD.keys())
        for k in keys:
            diffP , diffF = diffA(aD.get(k, None), bD.get(k, None), keyToUse)
            #print("k: {0}, diff: {1} diffulll: {2}".format(k, diffP, diffF))
            if diffP is None:
                continue
            dFull[k] = diffF
            if not isinstance(diffP, dict):
                dPart[k] = diffP
            elif '__add__' in diffP and diffP['__add__'] is not None:
                dPart[k] = diffP['__add__']
            elif '__del__' in diffP and diffP['__del__'] is not None:
                dPart[k] = {'__del__': diffP['__del__']}
                # if isinstance(diffP['__del__'], dict):
                #     dPart[k] = diffP['__del__']
                #     dPart[k].update({'__del__': True})
                # else:
                #     dPart[k] = {'__del__': diffP['__del__']}
            else:
                dPart[k] = diffP
        #print(dPart)
        #print(dFull)
        if len(dPart)==0:
            dPart = None
        if len(dFull)==0:
            dFull = None
        if isList:
            return dictToList(dPart, True, keyToUse), dictToList(dFull, True, keyToUse)
        else:
            return dPart, dFull

# if c = a-b, a = b+c
# b is original, c is "patch"
magicVal = uuid.uuid4()
def patchA(b, c, keyToUse='name', removeNoneValue=True, allowNoneValue=False):
    if allowNoneValue:
        patchMagicVal = magicVal
    else:
        patchMagicVal = None
    if c is patchMagicVal:
        return b
    cD = listToDict(c, keyToUse)
    if not isinstance(cD, dict):
        return c
    if '__add__' in cD:
        return c['__add__']
    if '__del__' in cD:
        return patchMagicVal
    isList = isinstance(b, list)
    bD = listToDict(b, keyToUse)
    if bD is patchMagicVal:
        bD = {}
    if not isinstance(bD, dict):
        return c
        #print("b: {0}, c: {1}".format(b, c))
        #raise ValueError("Invalid patch")
    keys = set(bD.keys())
    keys.update(cD.keys())
    n = {}
    for k in keys:
        if removeNoneValue and k in cD and cD[k] is patchMagicVal:
            continue
        patched = patchA(bD.get(k, patchMagicVal), cD.get(k, patchMagicVal), keyToUse, removeNoneValue, allowNoneValue)
        #print("k: {0}, patched: {1}".format(k, patched))
        if patched is not patchMagicVal:
            n[k] = patched
    if isList:
        return dictToList(n, True, keyToUse)
    else:
        return n
    
def updateWithDelete(x, updates, recursive=True):
    keysTotal = set(x.keys())
    keysTotal.update(updates.keys())
    for k in keysTotal:
        if k in updates and updates[k] is None:
            if k in x:
                del x[k]
        elif recursive and (isinstance(x.get(k, None), dict) and isinstance(updates.get(k, None), dict)):
            updateWithDelete(x[k], updates[k])
        elif k in updates:
            x[k] = updates[k]
    return x

def diffList(x1, x2, ignoreOrder=True, keyToUse='name'):
    if x1==x2:
        return True, None

    diffs = []
    if not ignoreOrder:
        for i in range(min(len(x1), len(x2))):
            if x1[i] != x2[i]:
                (same, subDiff) = diff(x1[i], x2[i], ignoreOrder)
                if not same:
                    diffs.append(subDiff)
        if len(x1) > len(x2):
            diffs.extend(x1[len(x2):])
        else:
            diffs.extend(x2[len(x1):])
    else:
        foundA = []
        subDiffA = []
        # array of length x2 with False
        used = [False for i in range(len(x2))]
        for j, x11 in enumerate(x1):
            found = False
            subDiffB = [None for i in range(len(x2))]
            for i, x21 in enumerate(x2):
                if used[i]:
                    continue
                if x11 == x21:
                    found = True
                    used[i] = True
                    break
                (same, subDiff) = diff(x11, x21, ignoreOrder)
                if same:
                    found = True
                    used[i] = True
                    break
                subDiffB[i] = subDiff
            foundA.append(found)
            subDiffA.append(subDiffB)
        for j, x11 in enumerate(x1):
            if foundA[j]:
                continue
            found = False
            for i, subDiff in enumerate(subDiffA[j]):
                if used[i]:
                    continue
                if (isinstance(x11, dict) and isinstance(x2[i], dict) and
                    keyToUse in x11 and keyToUse in x2[i] and x11[keyToUse]==x2[i][keyToUse]):
                    subDiff.update({keyToUse: x11[keyToUse]})
                    diffs.append(subDiff)
                    used[i] = True
                    found = True
                    break
            # try to match index
            if not found and len(x2) >= (j+1) and subDiffA[j][j] is not None and not used[j]:
                diffs.append(subDiffA[j][j])
                found = True
                used[j] = True
            if not found:
                diffs.append(x11)
        for i, x21 in enumerate(x2):
            if not used[i]:
                diffs.append(x21)

    if len(diffs) > 0:
        return False, diffs
    else:
        return True, None

def diffDict(x1, x2, ignoreOrder=True):
    diffs = {}
    for key in x1:
        if key in x2:
            (same, subDiffs) = diff(x1[key], x2[key], ignoreOrder)
            if not same:
                diffs[key] = subDiffs
        else:
            diffs[key] = x1[key]
    for key in x2:
        if key not in x1:
            diffs[key] = x2[key]
    if len(diffs) > 0:
        return False, diffs
    else:
        return True, None

def diff(x1, x2, ignoreOrder=True, keyToUse='name'):
    # if type(x1) != type(x2):
    #     return False, x1

    if isinstance(x1, list) and isinstance(x2, list):
        return diffList(x1, x2, ignoreOrder, keyToUse)

    if isinstance(x1, dict) and isinstance(x2, dict):
        return diffDict(x1, x2, ignoreOrder)

    if x1==x2:
        return True, None
    else:
        return False, x1

# JSON patch to transform xO (old) to xN (new)
def diffJSON(xN, xO):
    diff = {}
    for key, val in xN.items():
        if key in xO:
            if isinstance(val, dict) and isinstance(xO[key], dict):
                subDiff = diffJSON(xN[key], xO[key])
                if subDiff!={}:
                    diff[key] = subDiff
            else:
                if xN[key] != xO[key]:
                    diff[key] = xN[key]
        else:
            diff[key] = xN[key]
    for key, val in xO.items():
        if key not in xN:
            # deleted key
            diff[key] = None
    if diff=={}:
        return {}
    else:
        return diff

def convtToDic(c, commonKeys):
    cN = {}
    if isinstance(c, dict):
        for k, v in c.items():
            if type(v) in [dict, list]:
                cN[k] = convtToDic(v, commonKeys)
            else:
                cN[k] = v
    elif isinstance(c, list):
        for v in c:
            if isinstance(v, list):
                print("Don't know")
                raise Exception("Can't handle {0}".format(c))
            elif isinstance(v, dict):
                found = True
                for k in commonKeys:
                    if k in v:
                        #print("Use key {0}".format(k))
                        cN[v[k]] = convtToDic(v, commonKeys)
                        break
                if not found:
                    raise Exception("Can't find common key in {0}".format(v))
            else:
                cN[v] = v
    else:
        raise Exception("Should be list or dict")
    return cN

def dictUse(key, x):
    if key in x:
        return (isinstance(x[key], dict), x[key])
    else:
        return (False, {})

def dictuse(key, orig, mod1, mod2):
    (isdicto, origUse) = dictUse(key, orig)
    (isdict1, mod1Use) = dictUse(key, mod1)
    (isdict2, mod2Use) = dictUse(key, mod2)
    return (isdicto or isdict1 or isdict2, origUse, mod1Use, mod2Use)

def sync3(orig, mod1, mod2, autoFill2=True):
    keys = unionKeys3(orig, mod1, mod2)
    output = {}
    for key in keys:
        cmp1 = cmp(key, orig, mod1)
        if autoFill2 and (key not in mod2):
            cmp2 = True # auto fill missing data in mod2 from orig
        else:
            cmp2 = cmp(key, orig, mod2)
        if cmp1 and cmp2:
            # both same as before
            (isdict, origUse, mod1Use, mod2Use) = dictuse(key, orig, mod1, mod2)
            if isdict:
                if autoFill2 and (key not in mod2):
                    output[key] = sync3(origUse, mod1Use, origUse, autoFill2)
                else:
                    output[key] = sync3(origUse, mod1Use, mod2Use, autoFill2)
            else:
                output[key] = copy.deepcopy(orig[key])
        elif cmp1: # mod1 is same, mod2 is different
            if key in mod2:
                output[key] = copy.deepcopy(mod2[key])
            # else delete key
        else: # either mod1 is differnt and mod2 same, or both different (in which case second changes rejected)
            if key in mod1:
                output[key] = copy.deepcopy(mod1[key])
    return output

def hostAlive(machine):
    return os.system("ping -c 1 {0} > /dev/null 2>&1".format(machine)) == 0

def timeInMs():
    return int(time.time()*1000)

def getMachineInfo(defInterface=['eth0']):
    config = {}
    config['machine_name'] = subprocess.check_output('cat /etc/hostname', shell=True).decode('utf-8').strip()
    config['dnsname'] = config['machine_name']
    for interface in defInterface:
        try:
            ipinfo = ' '.join(subprocess.check_output('ifconfig {0}'.format(interface), shell=True).decode('utf-8').splitlines())
        except Exception:
            continue # perhaps does not exist, skip
        m=re.match(r'.*(inet addr\s+|inet addr\s*:\s*|inet\s+|inet\s*:\s*)(.*?)\s+', ipinfo)
        if m is not None and len(m.groups())>=2:
            config['private_ip'] = m.group(2).strip()
            break # take first
    return config

def getMachineName():
    try:
        return subprocess.check_output('cat /etc/hostname', shell=True).decode('utf-8').strip()
    except Exception:
        return os.environ["computername"]

# files are src to dst pairs
def copy_from_docker_image(image, files):
    try:
        if os.name != 'nt':
            sudo = 'sudo'
        else:
            sudo = ''
        os.system('{0} docker pull {1}'.format(sudo, image))
        id = subprocess.check_output('{0} docker create {1}'.format(sudo, image), shell=True).decode('utf-8').strip()
        for src in files:
            dst = files[src]
            copyCmd = sudo + " docker cp --follow-link=true " + id + ":" + src + " " + dst
            #print copyCmd
            os.system(copyCmd)
        os.system(sudo + " docker rm -v " + id)
    except Exception:
        pass

# CN is common name
def csrRender(base, cn, size, o, useTemp=False):
    basedir = os.path.dirname(base)
    basefile = os.path.basename(base)
    crt = base+".pem"
    key = base+"-key.pem"
    csrdir = os.path.join(thisPath, "..", "..", "deploy", "csr")
    os.system("mkdir -p {0}".format(basedir))
    if not useTemp:
        csrFile = "{0}/{1}.csr.json".format(csrdir, basefile)
    else:
        (fp, csrFile) = tempfile.mkstemp(suffix='.json')
        fp.close()
    render_template("{0}/../ssh_tls/csr.json.template".format(thisPath), csrFile, {"cn": cn, "size": size, "o": o})
    return crt, key, csrFile

def genCA(base, cn, o="kubernetes", size=2048):
    (crt, key, csrFile) = csrRender(base, cn, size, o)
    if not os.path.exists(crt) or not os.path.exists(key):
        os.system("cfssl gencert -initca {0} | cfssljson -bare {1} -".format(csrFile, base))

def genCert(baseca, base, cn, hostnames, o, size=2048):
    cacrt = baseca + ".pem"
    cakey = baseca + "-key.pem"
    config = "{0}/../ssh_tls/ca-config.json".format(thisPath)
    (crt, key, csrFile) = csrRender(base, cn, size, o)
    if not os.path.exists(crt) or not os.path.exists(key):
        if hostnames is not None:
            hoststr = "-hostname='{0}'".format(",".join(hostnames))
        else:
            hoststr = ""
        os.system("cfssl gencert -ca={0} -ca-key={1} -config={2} "
                  "-profile=default {3} {4} | cfssljson -bare {5}".
                  format(cacrt, cakey, config, hoststr, csrFile, base))

def genCert2(cacrt, cakey, base, cn, hostnames, o, size=2048):
    basedir = os.path.dirname(base)
    config = "{0}/../ssh_tls/ca-config.json".format(thisPath)
    if not os.path.exists(config):
        config = "{0}/ca-config.json".format(basedir)
        with open(config, "w", encoding='utf-8') as f:
            f.write(importlibmodule.read_text("kcclient", "ca-config.json"))
    crt = base + ".pem"
    key = base + "-key.pem"
    csrFile = base + ".csr.json"
    os.system("mkdir -p {0}".format(basedir))
    csrTemplate = "{0}/../ssh_tls/csr.json.template".format(thisPath)
    if not os.path.exists(csrTemplate):
        csrTemplate = "{0}/csr.json.template".format(basedir)
        with open(csrTemplate, "w", encoding='utf-8') as f:
            f.write(importlibmodule.read_text("kcclient", "csr.json.template"))
    render_template(csrTemplate, csrFile, {"cn": cn, "size": size, "o": o})
    if not os.path.exists(crt) or not os.path.exists(key):
        if hostnames is not None:
            hoststr = "-hostname='{0}'".format(",".join(hostnames))
        else:
            hoststr = ""
        os.system("cfssl gencert -ca={0} -ca-key={1} -config={2} "
                  "-profile=default {3} {4} | cfssljson -bare {5}".
                  format(cacrt, cakey, config, hoststr, csrFile, base))

def getCert(baseca, cn, hostnames, o, size=2048, cakey=None):
    tmpdir = tempfile.mkdtemp()
    if cakey is None:
        cacrt = baseca + ".pem"
        cakey = baseca + "-key.pem"
    else:
        cacrt = baseca
    genCert2(cacrt, cakey, '{0}/cert'.format(tmpdir), cn, hostnames, o, size)
    certs = {}
    with open(cacrt) as fp:
        certs['CA'] = fp.read()
    with open('{0}/cert.pem'.format(tmpdir), 'r') as fp:
        certs['Cert'] = fp.read()
    with open('{0}/cert-key.pem'.format(tmpdir), 'r') as fp:
        certs['Key'] = fp.read()
    shutil.rmtree(tmpdir)
    return certs

def updateYaml(infile, updates):
    if os.path.exists(infile):
        with open(infile, 'r') as fp:
            cur = yaml.safe_load(fp)
    else:
        cur = {}
    cur.update(updates)
    with open(infile, 'w') as fp:
        yaml.safe_dump(cur, fp)

def merge2Yaml(infile, updates):
    if os.path.exists(infile):
        with open(infile, 'r') as fp:
            cur = yaml.safe_load(fp)
    else:
        cur = {}
    cur = deepmerge2(cur, updates)
    #print("MERGE: {0} to {1}\nU: {2}".format(cur, infile, updates))
    with open(infile, 'w') as fp:
        yaml.safe_dump(cur, fp)    

def loadYaml(infile):
    try:
        with open(infile, 'r') as fp:
            return yaml.safe_load(fp)
    except Exception:
        return {}

def loadMYamlC(f):
    ysn = []
    try:
        ys = f.split('---')
        for y in ys:
            y = y.strip()
            if y != "":
                yn = yaml.safe_load(y)
                done = False
                if 'kind' in yn and yn['kind'].lower()=='list':
                    if 'items' in yn:
                        for item in yn['items']:
                            ysn.append(item)
                        done = True
                if not done:
                    ysn.append(yn)
    except Exception:
        pass
    return ysn

def loadMYaml(infile):
    try:
        with open(infile, 'r') as fp:
            f = fp.read()
        return loadMYamlC(f)
    except Exception:
        pass
    return []

def dumpYaml(x, outfile):
    with open(outfile, 'w') as fp:
        yaml.dump(x, fp)

def replWithEnvVar(v):
    while True:
        m = re.match(r'(.*?)(\$.*?)([\/\\\$]|$|\s)(.*)', v)
        if m is None:
            break
        v = m.group(1) + os.getenv(m.group(2)[1:]).replace('\\','/') + m.group(3) + m.group(4)
    return v

def replEnvVar(p):
    if type(p)==str:
        return replWithEnvVar(p)
    elif type(p)==list:
        return [replEnvVar(x) for x in p]
    elif type(p)==dict:
        return {replWithEnvVar(k): replEnvVar(v) for k, v in p.items()}
    else:
        return copy.deepcopy(p)

def loadYamlRepl(file):
    with open(file, 'r') as fp:
        return replEnvVar(yaml.safe_load(fp))

from pathlib import Path
def mkdir(dir):
    path = Path(dir)
    path.mkdir(parents=True, exist_ok=True)

# assumes arguments don't have double quotes in them
def quoteJoinArgs(args):
    return " ".join(['"'+arg+'"' for arg in args])

def splitUnquoteArgs(argStr):
    args = argStr.split()
    for i, _ in enumerate(args):
        if args[i][0]=='"' and args[i][-1]=='"':
            args[i] = args[i][1:-1]
    return args

# format of keys: spec.containers.[i].resources.limits.cpu, key is array
def _getValK(x, key):
    if x is None:
        return None
    #print("X: {0}: K: {1}".format(x,key))
    key0 = key.pop(0)
    index = None
    if isinstance(key0, int):
        index = key0
    elif key0[0]=='[' and key0[-1]==']':
        index = int(key0[1:-1])
        key0 = index
    if index is not None and isinstance(x, list):
        if index >= -len(x) and index < len(x):
            v = x[index]
        else:
            return None
    else:
        if key0 in x:
            v = x[key0]
        else:
            return None
    if len(key)==0:
        return v
    else:
        #print("X2: {0} K2: {1}".format(v, key))
        return _getValK(v, key)

def getValK(x, key):
    return _getValK(x, copy.deepcopy(key))

def getVal(x, key, splitChar="."):
    if splitChar is None:
        return _getValK(x, copy.deepcopy(key)) # key is already array of splits
    else:
        return _getValK(x, key.strip().split(splitChar))

def getValDef(x, key, defVal={}, splitChar="."):
    ret = getVal(x, key, splitChar)
    if ret is None:
        return defVal
    else:
        return ret

def _getNextSet(x, key):
    if x is None:
        if isinstance(key[0], int):
            return []
        elif key[0][0]=='[' and key[0][-1]==']':
            return []
        else:
            return {}
    else:
        return x

def _setValK(x, key, v):
    key0 = key.pop(0)
    index = None
    if isinstance(key0, int):
        index = key0
    elif key0[0]=='[' and key0[-1]==']':
        index = int(key0[1:-1])
        key0 = index
    if index is not None and isinstance(x, list):
        if index < -len(x):
            raise Exception("Invalid index")
        elif index >= len(x):
            x.extend([None]*(index-len(x)+1))
        if len(key)==0:
            x[index] = v
        else:
            x[index] = _getNextSet(x[index], key)
            _setValK(x[index], key, v)
    else:
        if len(key)==0:
            x[key0] = v
        else:
            if key0 not in x:
                x[key0] = None
            x[key0] = _getNextSet(x[key0], key)
            _setValK(x[key0], key, v)

def setValK(x, key, v):
    return _setValK(x, copy.deepcopy(key), v)

def setVal(x, key, v, splitChar="."):
    if splitChar is not None:
        key = key.strip().split(splitChar)
    else:
        key = copy.deepcopy(key)
    x = _getNextSet(x, key)
    _setValK(x, key, v)
    return x

def addToVal(x, key, v, splitChar="."):
    curVal = getValDef(x, key, 0, splitChar)
    curVal += v
    return setVal(x, key, curVal, splitChar)

def appendToVal(x, key, v, splitChar="."):
    curVal = getValDef(x, key, [], splitChar)
    curVal.append(v)
    return setVal(x, key, curVal, splitChar)

def extendToVal(x, key, v, splitChar="."):
    curVal = getValDef(x, key, [], splitChar)
    curVal.extend(v)
    return setVal(x, key, curVal, splitChar)

def updateToVal(x, key, v, splitChar="."):
    curVal = getValDef(x, key, {}, splitChar)
    curVal.update(v)
    return setVal(x, key, curVal, splitChar)

def popFromVal(x, key, v, splitChar=".", defVal=[]):
    if isinstance(v, list) and len(v)==0:
        return None
    if not isinstance(v, list):
        v = [v]
        vIsList = False
    else:
        vIsList = True
    curVal = getVal(x, key, splitChar)
    if curVal is None:
        return None
    elif isinstance(curVal, list):    
        if not isinstance(defVal, list):
            defVal = [defVal]
            for _ in (1, range(len(v))):
                defVal.append(defVal[0])
        ret = []
        curValOrig = copy.deepcopy(curVal)
        for i in range(len(v)):
            if i > 0 and v[i] <= v[i-1]:
                setVal(x, key, curValOrig, splitChar)
                raise Exception("Indices must be increasing")
            if len(defVal) > 0 and (v[i]-i) >= len(curVal):
                ret.append(defVal[i])
            else:
                ret.append(curVal.pop(v[i]-i))
        return ret if vIsList else ret[0]
    elif isinstance(curVal, dict):
        ret = []
        for key in v:
            if not isinstance(defVal, list):
                ret.append(curVal.pop(key, defVal))
            else:
                ret.append(curVal.pop(key))
        return ret if vIsList else ret[0]

# oper is "set", "extend", "append", or "update", int key implies array
def setValA(x, keys, val, oper="set", deepcopy=True):
    key = keys.pop(0)
    if x is None:
        if isinstance(key, int):
            x = []
        elif isinstance(key, str):
            x = {}
    if len(keys)==0:
        if oper=='set':
            if deepcopy:
                x[key] = copy.deepcopy(val)
            else:
                x[key] = val
        else:
            if key not in x:
                if oper in ['extend', 'append']:
                    x[key] = []
                elif oper in ['update']:
                    x[key] = {}
            if deepcopy:
                eval('x[key].{0}(copy.deepcopy(val))'.format(oper))
            else:
                eval('x[key].{0}(val)'.format(oper))
        return x
    else:
        x[key] = setValA(x.get(key, None), keys, val, oper, deepcopy)
        return x

def getValA(x, keys, defval=None):
    key = keys.pop(0)
    if ((isinstance(key, int) and isinstance(x, list) and key < len(x)-1) or 
        (isinstance(key, str) and isinstance(x, dict) and key in x)):
        if len(keys)==0:
            return x[key]
        else:
            return getValA(x[key], keys, defval)
    else:
        return defval

class atomicInt():
    def __init__(self, initValue):
        self.val = initValue
        self.lock = threading.Lock()

    # def __add__(self, y) # too confusing
    def incr(self, y):
        self.lock.acquire()
        self.val += y
        self.lock.release()
        return self.val

# string->string (b64encode is bytes->bytes)
def b64e(instr):
    return base64.b64encode(instr.encode()).decode()

# string->string (b64decode is bytes/string->bytes)
def b64d(instr):
    return base64.b64decode(instr).decode()

def b64efile(infile):
    try:
        with open(infile, 'r') as fp:
            return b64e(fp.read().strip())
    except Exception:
        # try reading contents with sudo
        contents = subprocess.check_output('sudo cat {0}'.format(infile), shell=True)
        return b64e(contents.decode().strip())

def msToTimeStr(timeMs, precision=10):
    time = timeMs/1000
    if time < 60:
        return "{0}s".format(round(time, precision))
    elif time < 60*60:
        return "{0}m".format(round(time/60, precision))
    elif time < 60*60*24:
        return "{0}h".format(round(time/3600, precision))
    else:
        return "{0}d".format(round(time/3600/24, precision))

def isGPUMachine():
    try:
        lspci = getoutput('lspci')
        return re.match(r'.*(3D|VGA compatible) controller: NVIDIA Corporation.*', " ".join(lspci.split())) is not None
    except Exception:
        return False

def linuxVer():
    ver = " ".join(getoutput("lsb_release -a").split())
    m = re.match(".*Description:\s+(.* LTS)", ver)
    return m.group(1).strip()

def getContents(user, machine, file):
    return getoutput("ssh -q {0}@{1} 'cat {2}'".format(user, machine, file))

def setContents(user, machine, file, contents):
    dir = os.path.dirname(file)
    return getoutput("ssh {0}@{1} 'mkdir -p {2}; echo {3} > {4}'".format(
        user, machine, dir, contents, file
    ))

def kwargFilter(vars, **kwargs):
    d = {}
    rem = {}
    for var in vars:
        if var in kwargs:
            d[var] = kwargs[var]
    for k in kwargs:
        if k not in vars:
            rem[k] = kwargs[k]
    return d, rem

def kwargHash(**kwargs):
    output = ""
    for key, value in sorted(kwargs.items(), key=lambda x: x[0]): 
        output += "{}:{}".format(key, value)
    return hashlib.md5(output.encode()).hexdigest()

# create a "class"-like object from a dictionary
caseConvtRe1 = re.compile('(.)([A-Z][a-z]+)')
caseConvtRe2 = re.compile('([a-z0-9])([A-Z])')
def convert_to_python_case(name):
    s1 = caseConvtRe1.sub(r'\1_\2', name)
    return caseConvtRe2.sub(r'\1_\2', s1).lower()

def underscore(word):
    word = re.sub(r"([A-Z]+)([A-Z][a-z])", r'\1_\2', word)
    word = re.sub(r"([a-z\d])([A-Z])", r'\1_\2', word)
    #word = word.replace("-", "_") # not good and not needed
    return word.lower()

def _concat(exist, name):
    return exist + "|" + name

RegexpType = type(re.compile(''))
def _convt(exist, name, ignore):
    toConvt = True
    if ignore is not None:
        newExist = _concat(exist, name)
        if type(ignore)==RegexpType: # re.Pattern does not exist < 3.7?
            toConvt = not ignore.match(newExist)
        else:
            toConvt = newExist not in ignore
    return toConvt

def buildIgnorePattern(ignore):
    restr = r"\|("
    for i in range(len(ignore)):
        if i != 0:
            restr += "|"
        restr += ignore[i].replace('.','|').replace('|','\\|').replace('*','.*')
    restr += ")"
    return re.compile(restr)

ToClassIgnore = None
def SetToClassIgnore(ignore):
    global ToClassIgnore
    ToClassIgnore = ignore

def GetClassIgnore():
    return ToClassIgnore

ToDictIgnore = None
def SetToDictIgnore(ignore):
    global ToDictIgnore
    ToDictIgnore = ignore

def GetDictIgnore():
    return ToDictIgnore

from pprint import pformat
import inflection
class ToClass(object):
    def __init__(self, data, convtToPythonCase=False, ignore=None, exist=""):
        if ignore is None:
            ignore = GetClassIgnore()
        #self.original = copy.deepcopy(data)
        for name, value in data.items():
            if convtToPythonCase and _convt(exist, name, ignore):
                newName = underscore(name)
            else:
                newName = name
            setattr(self, newName, self._wrap(value, convtToPythonCase, ignore, _concat(exist, name)))

    def _wrap(self, value, convtToPythonCase, ignore, exist):
        if isinstance(value, (tuple, list, set, frozenset)): 
            return type(value)([self._wrap(v, convtToPythonCase, ignore, exist) for v in value])
        elif isinstance(value, dict):
            return ToClass(value, convtToPythonCase, ignore, exist)
        else:
            return value

    def __getitem__(self, val):
        return self.__dict__[val]

    def __repr__(self):
        return pformat(self.to_dict())

    def toDictString(self):
        return '{%s}' % str(', '.join('%s : %s' % (k, repr(v)) for (k, v) in self.__dict__.items()))

    def _unwrap(self, value, convtToCamelCase, replacements, ignore, exist):
        if isinstance(value, (tuple, list, set, frozenset)):
            return type(value)([self._unwrap(v, convtToCamelCase, replacements, ignore, exist) for v in value])
        elif type(self)==type(value): # was a dictionary before
            return value.to_dict(convtToCamelCase, replacements, ignore, exist)
        else:
            return value

    def to_dict(self, convtToCamelCase=False, replacements={}, ignore=None, exist=""):
        if ignore is None:
            ignore = GetDictIgnore()
        d = {}
        for attr, value in self.__dict__.items():
            if convtToCamelCase and _convt(exist, attr, ignore):
                newName = camelizeWithReplacements(attr, False, replacements)
                #newName = inflection.camelize(attr, False)
            else:
                newName = attr
            d[newName] = self._unwrap(value, convtToCamelCase, replacements, ignore, _concat(exist, attr))
        return d
        #return self.original

def _unwrap(elem, fn, *args):
    if isinstance(elem, (tuple, list, set, frozenset)):
        return [_unwrap(v, fn, *args) for v in elem]
    elif isinstance(elem, dict):
        return fn(elem, *args)
    else:
        return elem

def pythonizeKeys(d, ignore=None, exist=""):
    dNew = {}
    for key, val in d.items():
        if _convt(exist, key, ignore):
            newKey = underscore(key)
        else:
            newKey = key
        dNew[newKey] = _unwrap(val, pythonizeKeys, ignore, _concat(exist, key))
    return dNew

def camelizeWithReplacements(key, upperCaseFirst=False, replacements={}):
    if replacements is not None and len(replacements) > 0:
        parts = key.split('_')
        #print(parts)
        for i, p in enumerate(parts):
            if p in replacements:
                parts[i] = replacements[p]
        #print(parts)
        key = '_'.join(parts)
        #print(key)
    return inflection.camelize(key, upperCaseFirst)

def camelizeKeys(d, upperCaseFirst=False, replacements={}, ignore=None, exist=""):
    if ignore is None:
        ignore = GetDictIgnore() # python->YAML
    dNew = {}
    for key, val in d.items():
        if _convt(exist, key, ignore):
            newKey = camelizeWithReplacements(key, upperCaseFirst, replacements)
        else:
            newKey = key
        dNew[newKey] = _unwrap(val, camelizeKeys, upperCaseFirst, replacements, ignore, _concat(exist, key))
    return dNew

# Text Type:	str
# Numeric Types:	int, float, complex
# Sequence Types:	list, tuple, range
# Mapping Type:	dict
# Set Types:	set, frozenset
# Boolean Type:	bool
# Binary Types:	bytes, bytearray, memoryview
def serialize(x, seenVals=None):
    if seenVals is None:
        seenVals = {}

    if isinstance(x, (str, int, float, complex, bool)) or x is None:
        return x

    idx = id(x)
    if idx in seenVals:
        return {'__ptr__': seenVals[idx]}

    seenVals[idx] = len(seenVals)

    tpName = type(x).__name__
    val = {
        '__type__': tpName,
        '__idx__': seenVals[idx]
    }

    if isinstance(x, (bytes, bytearray)):
        val.update({'__val__': base64.b64encode(x).decode()})
        return val

    if isinstance(x, (tuple, list, set, frozenset)):
        val.update({'__val__': [serialize(v, seenVals) for v in x]})
        return val

    if isinstance(x, dict):
        val.update({'__val__': {k: serialize(v, seenVals) for k, v in sorted(x.items())}})
        return val

    if hasattr(x, '__serialize__'):
        val.update({'__val__': x.__serialize__(seenVals)})
        return val

    if hasattr(x, '__dict__'):
        val.update({'__val__': {k: serialize(v, seenVals) for k, v in sorted(x.__dict__.items())}})
        return val

    raise Exception("Don't know how to serialize {0}".format(x))

def deserialize(o, toDict=False, seenVals=None):
    if seenVals is None:
        seenVals = {}

    if isinstance(o, (str, int, float, complex, bool)) or o is None:
        return o

    # everything else is dict

    if '__ptr__' in o:
        return seenVals[o['__ptr__']]

    tpName = o['__type__']
    ov = o['__val__']
    idx = o['__idx__']
    if tpName in _loadEvals:
        tp = _loadEvals[tpName]
    else:
        tp = eval(tpName)

    val = None

    if tp in [tuple, list, set, frozenset]:
        val = []
    elif tp is dict or (hasattr(tp, '__dict__') and toDict):
        val = {}
    elif hasattr(tp, '__dict__'):
        if tpName in _loadCreate:
            val = _loadCreate[tpName]()
        else:
            val = tp()
    seenVals[idx] = val # for recursive

    if isinstance(val, (bytes, bytearray)):
        val = tp(base64.b64decode(ov.encode()))
        seenVals[idx] = val
        return val

    if isinstance(val, list):
        for v in ov:
            val.append(deserialize(v, toDict, seenVals))
        if tp is not list:
            val = tp(val) # may change 
            seenVals[idx] = val # tuple, set, frozenset are not recursive
        return val

    if isinstance(val, dict):
        for k, v in sorted(ov.items()):
            val[k] = deserialize(v, toDict, seenVals)
        return val

    if hasattr(val, '__deserialize__'):
        val.__deserialize__(ov, toDict, seenVals)
        return val

    if hasattr(val, '__dict__'):
        for k, v in sorted(ov.items()):
            setattr(val, k, deserialize(v, toDict, seenVals))
        return val

    raise Exception("Don't know how to deserialize {0}".format(o))    

def _smartDump(xKey, x, setExToNone, keyMapper, valMapper, seenVals):
    idx = id(x)
    xNew = None
    if idx in seenVals:
        xNew = {'__ptr__': idx} # pointer to something already seen
    elif hasattr(x, '__dump__'):
        seenVals[idx] = True
        xVals = x.__dump__()
    elif hasattr(x, '__dict__'):
        seenVals[idx] = True
        xVals, _ = _smartDump(None, x.__dict__, setExToNone, keyMapper, valMapper, seenVals)
    elif isinstance(x, (tuple, list, set, frozenset)):
        seenVals[idx] = True
        xVals = []
        for v in x:
            vNew, ex = _smartDump(None, v, setExToNone, keyMapper, valMapper, seenVals)
            if ex is None:
                xVals.append(vNew)
            elif setExToNone:
                xVals.append(None)
    elif isinstance(x, dict):
        seenVals[idx] = True
        xVals = {}
        for k, v in x.items():
            try:
                newK = keyMapper(k)
            except Exception:
                continue
            vNew, ex = _smartDump(newK, v, setExToNone, keyMapper, valMapper, seenVals)
            if ex is None:
                xVals[newK] = vNew
            elif setExToNone:
                xVals[newK] = None
    else:
        # shallow copy or numeric type, keep it raw
        try:
            return valMapper(xKey, x), None
        except Exception as ex:
            return None, ex

    if xNew is None:
        xNew = {
            '__idx__': idx,
            '__type__': type(x).__name__, # a string
            '__val__': xVals,
        }
    xNew.update({
        'magicNum': "E94F6C5C-51E6-427D-9345-E00BF14D11E8"
    })

    return xNew, None

def smartDump(x, setExToNone=False):
    dmp, ex = _smartDump(None, x, setExToNone, lambda key : key, lambda key, val : copy.deepcopy(val), {})
    if ex is not None:
        raise ex
    else:
        return dmp

_loadEvals = {} # registered evaluations
_loadCreate = {}
def registerEval(name, tp):
    _loadEvals[name] = tp
def registerCreate(name, fn):
    _loadCreate[name] = fn

def _smartLoad(xKey, x, keyUnmapper, valUnmapper, seenVals, toDict):
    if not isinstance(x, dict) or x.get("magicNum", 0) != "E94F6C5C-51E6-427D-9345-E00BF14D11E8":
        return valUnmapper(xKey, x)

    ptr = x.get('__ptr__', None)
    if ptr in seenVals:
        return seenVals[ptr]

    idx = x['__idx__']
    if x['__type__'] in _loadEvals:
        tp = _loadEvals[x['__type__']]
    else:
        tp = eval(x['__type__']) # convert back to type
    val = x['__val__']

    if hasattr(tp, '__dump__') or hasattr(tp, '__load__'):
        if not toDict:
            # arbitrary class, must have __load__ method to load from dictionary or class with __dump__
            xNew = tp.__load__(val) # static method which loads from value
            seenVals[idx] = xNew
            return xNew
        else:
            tp = dict # change type to dictionary

    if tp in [tuple, list, set, frozenset]:
        xNew = []
        seenVals[idx] = xNew # set up front so reference inside can be used
        for v in val:
            xNew.append(_smartLoad(None, v, keyUnmapper, valUnmapper, seenVals, False)) # set toDict to false
        return xNew

    if tp in [dict]:
        xNew = {}
        seenVals[idx] = xNew
        for k, v in val.items():
            newK = keyUnmapper(k)
            xNew[newK] = _smartLoad(newK, v, keyUnmapper, valUnmapper, seenVals, False)
        return xNew

    raise Exception("Unknown type to unmarshal {0}".format(tp))

def smartLoad(x, toDict=False):
    return _smartLoad(None, x, lambda key : key, lambda key, val : val, {}, toDict)

def replaceSave(old, new):
    dateStr = datetime.utcnow().strftime('%Y_%m_%d_%H_%M_%S')
    a, b = os.path.splitext(old)
    dst = '{0}.{1}{2}'.format(a, dateStr, b)
    #print("DST: {0}".format(dst))
    if os.path.exists(dst):
        raise Exception("{0} already exists".format(dst))
    shutil.move(old, dst)
    shutil.copy(new, old)

def nrun(cmd):
    print(cmd)
    os.system(cmd)

def runScriptRemote(script, user, machine, sshid=None, exe='bash'):
    name = random_string_l(32)
    if sshid is not None:
        id = "-i {0}".format(sshid)
    else:
        id = ""
    loc = "{0}@{1}".format(user, machine)
    nrun("scp {0} {1} {2}:/home/{3}/{4}".format(id, script, loc, user, name))
    nrun("ssh {0} {1} {2} /home/{3}/{4}".format(id, loc, exe, user, name))
    nrun("ssh {0} {1} rm /home/{2}/{3}".format(id, loc, user, name))

# YAML Validation
class Yaml:
    @staticmethod
    def validateVal(x, schema, msgs):
        if isinstance(schema, dict) and ('__validateExpr__' in schema or '__required__' in schema or '__value__' in schema or '__default__' in schema):
            for key in schema:
                if key not in ['__validateExpr__', '__required__', '__value__', '__default__']:
                    msgs.append('Invalid key found {0}'.format(key))
            try:
                if '__validateExpr__' in schema and x is not None:
                    __val__ = x # val used in closure
                    isvalid = eval(schema['__validateExpr__'])
                else:
                    isvalid = True
            except Exception as ex:
                logger.info('validateVal encounters exception {0} eval {1}'.format(ex, schema['__validateExpr__']))
                isvalid = False
            if not isvalid:
                msgs.append('{0} fails eval {1}'.format(x, schema['__validateExpr__']))
            if '__required__' in schema and schema['__required__'] and x is None:
                #print(schema)
                msgs.append('{0} required value missing'.format(schema))
            if '__value__' in schema and x is not None:
                Yaml.validateVal(x, schema['__value__'], msgs)
            if '__default__' in schema and x is None:
                return True
        elif x is not None:
            Yaml.validateVar(x, schema, msgs)

    @staticmethod
    def validateVar(x, schemaX, msgs):
        if isinstance(schemaX, (int, float, complex)):
            if not isinstance(x, (int, float, complex)):
                msgs.append('Type {0} not int, float, complex'.format(x))
        elif isinstance(schemaX, str):
            if not isinstance(x, str):
                msgs.append('Type {0} not str'.format(x))
        elif isinstance(schemaX, list):
            if not isinstance(x, list):
                msgs.append('Type {0} not list'.format(x))
            else:
                # X is list
                for index, xV in enumerate(x):
                    if index >= len(schemaX):
                        schema = schemaX[-1] # use last one
                    else:
                        schema = schemaX[index]
                    Yaml.validateVal(xV, schema, msgs)
        elif isinstance(schemaX, dict):
            if not isinstance(x, dict):
                msgs.append('Type {0} is not dict'.format(x))
            else:
                for key, val in x.items():
                    if key in schemaX:
                        Yaml.validateVal(val, schemaX[key], msgs)
                    elif '__validate__' in schemaX:
                        Yaml.validateVal(key, schemaX['__validate__']['__validateKey__'], msgs)
                        Yaml.validateVal(val, schemaX['__validate__']['__validateVal__'], msgs)
                    else:
                        msgs.append('Key {0} is not a valid key'.format(key))
                toAdd = {}
                for schemaKey, schemaVal in schemaX.items():
                    if schemaKey not in x:
                        toFill = Yaml.validateVal(None, schemaVal, msgs)
                        if toFill:
                            toAdd[schemaKey] = schemaVal['__default__']
                #print("ToAdd: {0}".format(toAdd))
                for addKey, addVal in toAdd.items():
                    x[addKey] = addVal

    @staticmethod
    def validate(x, schema):
        msgs = []
        try:
            Yaml.validateVal(x, schema, msgs)
            return len(msgs)==0, msgs
        except Exception as ex:
            logger.error('Validation fails x: {0} schema: {1} exception: {2}'.format(x, schema, ex))
            return False, "Validation fails with exception {0}".format(ex)

# test cases
# x1={'a':4, 'b':6, 'c':'a'}
# x2={'b':6, 'c': [1, 2], 'd':(3,4)}
# import utils
# utils.unionKeys2(x1, x2)

# x0 = {'a': 4, 'b':10, 'c':11}
# x1 = {'a': 40, 'b':10, 'c':12}
# x2 = {'a':4, 'b':20, 'c':13}
# import utils
# utils.unionKeys3(x0,x1,x2)
# utils.deepmerge3(x0,x1,x2)

# x0 = {'a': 20, 'c': 11, 'b': 10, 'd': 4}
# x1 = {'a': {'a': 17}, 'c': 12, 'b': 10, 'e': (1, 2), 'g': {'a': 4, 'b': 10}}
# x2 = {'a': 20, 'c': 13, 'b': 20, 'g': 7, 'f': (3, 4)}
# import utils
# utils.deepmerge3(x0,x1,x2)

# a = {'a': 3, 'b': {'b': 4, 'c': 5}, 'c': [4, 5]}
# a2 = {'a': 3, 'b' : {'b': 4, 'c': 5,'d': 6}, 'c' : [4,7]}
# a3 = {'a': 3, 'c': [4,3]}
# utils.sync3(a,a2,a3)
# utils.sync3(a,a2,a3,False)

class Heartbeat1():
    def __init__(self, name, interval):
        self.last = time.time()
        self.interval = interval
        self.name = name

    def update(self):
        log.logger.info('Heartbeat from {0} received'.format(self.name))
        self.last = time.time()

class Heartbeat():
    def __init__(self, mainThreadEvent : threading.Event):
        self.registered : list[Heartbeat1] = []
        self.interval = 1000
        self.t = threading.Thread(target=self.run)
        self.t.daemon = True
        self.main = mainThreadEvent
        self.started = False

    def register(self, name, checkinterval):
        assert not self.started, "Heartbeats must be registered before start"
        h = Heartbeat1(name, checkinterval)
        self.registered.append(h)
        self.interval = min(self.interval, checkinterval)
        return h

    def start(self):
        self.started = True
        # update all heartbeats to current time prior to starting
        for h in self.registered:
            h.update()
        self.t.start()

    def run(self):
        while True:
            time.sleep(self.interval)
            now = time.time()
            for h in self.registered:
                time_passed = now - h.last
                if time_passed > h.interval:
                    logger.error('Heartbeat {0} not received for {1} seconds - exiting'.format(h.name, time_passed))
                    self.main.set()
                    exit(1)

