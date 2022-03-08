import netifaces

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

def getInterfaces():
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
        addr[intName] = {}
        for i in range(1, len(lines)):
            #print(lines[i])
            vals = lines[i].split()
            #print(vals[0], namesIfconfig)
            if vals[0] in namesIfconfig:
                #print("AA", vals[1])
                addr[intName][namesIfconfig[vals[0]]] = {'addr': vals[1]}
    return addr

if __name__=="__main__":
    print(getInterfacesRaw())
    print()
    print(getInterfaces())
    print()
    print(list({k: v for k, v in getInterfaces().items() if 'ipv4' in v and v['ipv4']['addr']=='192.168.68.68'}.keys())[0])
    print()
    print(getNameForIpv4('192.168.68.68'))
    print()
    print(getInterfacesRemote('c:/users/sanjeevm/onedrive/sanjeevm/.ssh/orion', 'sanjeevm@roce94'))
    print()
    print(getNameForIpv4('10.196.44.224', 'c:/users/sanjeevm/onedrive/sanjeevm/.ssh/orion', 'sanjeevm@roce94'))

