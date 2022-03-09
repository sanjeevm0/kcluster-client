import netifaces
import json
import re
import copy

from yaml import safe_dump

names = {
    netifaces.AF_LINK: 'mac',
    netifaces.AF_INET: 'ipv4',
    netifaces.AF_INET6: 'ipv6'
}

namesIfconfig = {
    'ether': 'mac',
    'inet': 'ipv4',
    'inet6': 'ipv6'
}

def getInterfacesRaw():
    ifaces = netifaces.interfaces()
    addr = {}
    for iface in ifaces:
        addr[iface] = netifaces.ifaddresses(iface)
    
    return addr

def getAddr(addr, k, vl, key):
    for vlv in vl:
        if 'addr' in vlv:
            addr[k][key] = vlv
            break

def getInterfacesLocal():
    addr = {}
    addrs = getInterfacesRaw()
    for k, v in addrs.items():
        addr[k] = {}
        for kl, vl in v.items():
            if kl in names:
                getAddr(addr, k, vl, names[kl])
    return addr

def getNameForIpv4(ip, sshid=None, machine=None):
    if sshid is None or machine is None:
        interfaces = getInterfaces()
    else:
        interfaces = getInterfacesRemote(sshid, machine)
    filterInterfaces = {k: v for k, v in interfaces.items() if 'ipv4' in v and v['ipv4']['addr']==ip}
    if len(filterInterfaces) > 0:
        return list(filterInterfaces.keys())[0]
    else:
        return None

import subprocess

def getInterfacesRemote(sshid, machine):
    cmd = 'ssh -i {0} {1} ifconfig'.format(sshid, machine)
    print(cmd)
    ifconfig = subprocess.check_output(cmd, shell=True).decode().split('\n\n')
    addr = {}
    for interface in ifconfig:
        lines = interface.split('\n')
        intName = lines[0].split(':')[0].strip()
        if not intName:
            continue
        addr[intName] = {}
        for i in range(1, len(lines)):
            #print(lines[i])
            vals = lines[i].split()
            #print(vals[0], namesIfconfig)
            if vals[0] in namesIfconfig:
                #print("AA", vals[1])
                addr[intName][namesIfconfig[vals[0]]] = {'addr': vals[1]}
    return addr

def run(sshid, machine, sudo, cmd):
    if sudo==False:
        sudo=""
    if sudo==True:
        sudo="sudo "
    if sshid is None or machine is None:
        cmd = '{0}{1}'.format(sudo, cmd)
    else:
        cmd = 'ssh -i {0} {1} "{2}{3}"'.format(sshid, machine, sudo, cmd)
    print(cmd)
    return subprocess.check_output(cmd, shell=True).decode()

def addPCI(addr, sshid=None, machine=None, sudo=True):
    try:
        infoStr = run(sshid, machine, sudo, "lshw -c network -json")
        infoStr = re.sub(r'\}\s*\{', '},{', infoStr)
        info = json.loads("[{0}]".format(infoStr))
        for interface in info:
            if interface.get("logicalname", None) in addr:
                name = interface["logicalname"]
                if "serial" in interface:
                    addr[name]["serial"] = interface["serial"]
                if "businfo" in interface:
                    addr[name]["businfo"] = interface["businfo"]
                if "product" in interface:
                    addr[name]["product"] = interface["product"]
                if "vendor" in interface:
                    addr[name]["vendor"] = interface["vendor"]
                try:
                    addr[name]["numa_node"] = int(run(sshid, machine, sudo, "cat /sys/class/net/{0}/device/numa_node".format(name)).strip())
                    addr[name]["local_cpus"] = run(sshid, machine, sudo, "cat /sys/class/net/{0}/device/local_cpus".format(name)).strip()
                    addr[name]["local_cpulist"] = run(sshid, machine, sudo, "cat /sys/class/net/{0}/device/local_cpulist".format(name)).strip()
                except Exception:
                    pass
    except Exception as e:
        print("Encounter exception {0} getting lshw to run".format(e))

def getInterfaces(sshid=None, machine=None, sudo=True):
    if sshid is None and machine is None:
        addr = getInterfacesLocal()
    else:
        addr = getInterfacesRemote(sshid, machine)
    addPCI(addr, sshid, machine, sudo)
    return addr

def reorderByPCI(addr):
    addrN = {}
    for k, v in addr.items():
        v['name'] = k
        if 'businfo' in v:
            if '@' in v['businfo']:
                pciAddr = v['businfo'].split('@')[1]
                addrN[pciAddr] = copy.deepcopy(v)
    return addrN

if __name__=="__main__":
    import os
    import yaml
    #print(getInterfacesRaw())
    #print()
    #print(getInterfaces())
    #print()
    #print(list({k: v for k, v in getInterfaces().items() if 'ipv4' in v and v['ipv4']['addr']=='192.168.68.68'}.keys())[0])
    #print()
    #print(getNameForIpv4('192.168.68.68'))
    #print()
    home = os.getenv('HOME')
    print(yaml.safe_dump(getInterfaces()))
    interfaces = getInterfaces('{0}/.ssh/orion'.format(home), 'sanjeevm@roce94')
    print(yaml.safe_dump(interfaces))
    interfaces2 = reorderByPCI(interfaces)
    print(yaml.safe_dump(interfaces2))
    #print(getInterfacesRemote('{0}/.ssh/orion'.format(home), 'sanjeevm@roce94'))
    #print()
    #print(getNameForIpv4('10.196.44.224', '{0}/.ssh/orion'.format(home), 'sanjeevm@roce94'))

