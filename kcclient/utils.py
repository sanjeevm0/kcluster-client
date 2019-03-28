import time
import random
import string
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
thisPath = os.path.dirname(os.path.realpath(__file__))

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

def random_string(length):
  letters = string.ascii_lowercase + string.digits
  return ''.join(random.choice(letters) for i in range(length))

def random_string_lud(length):
  letters = string.ascii_lowercase + string.ascii_uppercase + string.digits
  return ''.join(random.choice(letters) for i in range(length))  

def yaml_cmd(cmd):
    try:
        output = subprocess.check_output(cmd, shell=True)
        return yaml.load(output)
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
        ipinfo = ' '.join(subprocess.check_output('ifconfig {0}'.format(interface), shell=True).decode('utf-8').splitlines())
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
        id = subprocess.check_output('sudo docker create {0}'.format(image), shell=True).decode('utf-8').strip()
        for src in files:
            dst = files[src]
            copyCmd = "sudo docker cp --follow-link=true " + id + ":" + src + " " + dst
            #print copyCmd
            os.system(copyCmd)
        os.system("sudo docker rm -v " + id)
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

def genCert2(baseca, base, cn, hostnames, o, size=2048):
    cacrt = baseca + ".pem"
    cakey = baseca + "-key.pem"
    config = "{0}/../ssh_tls/ca-config.json".format(thisPath)
    crt = base + ".pem"
    key = base + "-key.pem"
    csrFile = base + ".csr.json"
    basedir = os.path.dirname(base)
    os.system("mkdir -p {0}".format(basedir))
    render_template("{0}/../ssh_tls/csr.json.template".format(thisPath), csrFile, {"cn": cn, "size": size, "o": o})
    if not os.path.exists(crt) or not os.path.exists(key):
        if hostnames is not None:
            hoststr = "-hostname='{0}'".format(",".join(hostnames))
        else:
            hoststr = ""
        os.system("cfssl gencert -ca={0} -ca-key={1} -config={2} "
                  "-profile=default {3} {4} | cfssljson -bare {5}".
                  format(cacrt, cakey, config, hoststr, csrFile, base))

def getCert(baseca, cn, hostnames, o, size=2048):
    tmpdir = tempfile.mkdtemp()
    genCert2(baseca, '{0}/cert'.format(tmpdir), cn, hostnames, o, size)
    certs = {}
    with open('{0}.pem'.format(baseca)) as fp:
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
            cur = yaml.load(fp)
    else:
        cur = {}
    cur.update(updates)
    with open(infile, 'w') as fp:
        yaml.safe_dump(cur, fp)

def merge2Yaml(infile, updates):
    if os.path.exists(infile):
        with open(infile, 'r') as fp:
            cur = yaml.load(fp)
    else:
        cur = {}
    cur = deepmerge2(cur, updates)
    #print("MERGE: {0} to {1}\nU: {2}".format(cur, infile, updates))
    with open(infile, 'w') as fp:
        yaml.safe_dump(cur, fp)    

def loadYaml(infile):
    try:
        with open(infile, 'r') as fp:
            return yaml.load(fp)
    except Exception:
        return {}

def loadMYamlC(f):
    ysn = []
    try:
        ys = f.split('---')
        for y in ys:
            y = y.strip()
            if y != "":
                yn = yaml.load(y)
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

def getHome():
    if 'HOME' in os.environ:
        return os.environ['HOME']
    elif 'USERPROFILE' in os.environ:
        return os.environ['USERPROFILE']
    else:
        return ''

from pathlib import Path
def mkdir(dir):
    path = Path(dir)
    path.mkdir(parents=True, exist_ok=True)

# assumes arguments don't have double quotes in them
def quoteJoinArgs(args):
    return " ".join(['"'+arg+'"' for arg in args])

# format of keys: spec.containers.[i].resources.limits.cpu, key is array
def getValK(x, key):
    #print("X: {0}: K: {1}".format(x,key))
    key0 = key.pop(0)
    if key0[0]=='[' and key0[-1]==']':
        index = int(key0[1:-1])
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
        return getValK(v, key)

def getVal(x, key):
    return getValK(x, key.strip().split("."))

def _getNextSet(x, key):
    if x is None:
        if key[0][0]=='[' and key[0][-1]==']':
            return []
        else:
            return {}
    else:
        return x

def setValK(x, key, v):
    key0 = key.pop(0)
    if key0[0]=='[' and key0[-1]==']':
        index = int(key0[1:-1])
        if index < -len(x):
            raise Exception("Invalid index")
        elif index >= len(x):
            x.extend([None]*(index-len(x)+1))
        if len(key)==0:
            x[index] = v
        else:
            x[index] = _getNextSet(x[index], key)
            setValK(x[index], key, v)
    else:
        if len(key)==0:
            x[key0] = v
        else:
            if key0 not in x:
                x[key0] = None
            x[key0] = _getNextSet(x[key0], key)
            setValK(x[key0], key, v)

def setVal(x, key, v):
    x = _getNextSet(x, key)
    setValK(x, key.strip().split("."), v)
    return x

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