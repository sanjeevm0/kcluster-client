import yaml
import json
import os
import sys
import utils
thisPath = os.path.dirname(os.path.realpath(__file__))
from urllib.parse import urlencode, urlparse, urlunparse, ParseResult, parse_qs
from http.server import HTTPServer, BaseHTTPRequestHandler
import requests
import random
import copy

oidc = {
    "google" : {
        "client_id": "385176144433-gn2ecc6k246hd8qb6opp90fhli7ng0mm.apps.googleusercontent.com",
        "client_secret": "WBYRGtJZ6VtZXbGHudvQxIke",
        "auth_uri": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_uri": "https://www.googleapis.com/oauth2/v4/token"
    },
    "msft" : {
        "client_id": "96e32135-855d-450b-a3fa-bfca8c952b2c",
        "client_secret": "c2)+]N3FjI0N@sb0@#9uj=",
        "auth_uri": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?prompt=select_account",
        "token_uri": "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    }
}

class HTTPRequestHandler(BaseHTTPRequestHandler):
    def html200(self, html):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(html.encode())

    def json200(self, content):
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(content).encode())

    def html401(self):
        self.send_response(401)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write("<html><body><h1>Invalid</h1></body></html>".encode())

    def htmlHeader200(self, htmlText):
        return self.html200("<html><body><h1>{0}</h1></body></html>".format(htmlText))

    def json(self, code, content):
        self.send_response(code)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(content).encode())

# JWT
import jwt
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend

def validateMSFTJWT(token):
    token_header = jwt.get_unverified_header(token)
    # Get keys
    res = requests.get("https://login.microsoftonline.com/common/discovery/v2.0/keys")
    keys = res.json()
    for key in keys['keys']:
        if key['kid'] == token_header['kid']:
            x5c = key['x5c']
            break
    try:
        # Create cert
        cert = ''.join(['-----BEGIN CERTIFICATE-----\n', x5c[0], '\n-----END CERTIFICATE-----\n'])
        public_key =  load_pem_x509_certificate(cert.encode(), default_backend()).public_key()
        return jwt.decode(token, public_key, 
            algorithms=token_header['alg'], audience=oidc["msft"]["client_id"])
    except Exception:
        return None        

def validateGoogleJWT(token):
    # just use the endpoint for now, look for keys
    req = "https://www.googleapis.com/oauth2/v3/tokeninfo?id_token={0}".format(token)
    #print("Req: {0}".format(req))
    resp = requests.get(req)
    try:
        return json.loads(resp.content.decode())
    except Exception:
        return None

validateJWTFn = {
    "google" : validateGoogleJWT,
    "msft" : validateMSFTJWT
}

def decodeOIDCTokenFromQuery(query):
    if 'provider' in query and 'id_token' in query:
        return validateJWTFn[query['provider']](query['id_token'])
    return None

def decodeOIDCToken(cfgfile, user=None):
    cfg = utils.loadYaml("{0}/.{1}/{1}.users.yaml".format(utils.getHome(), cfgfile))
    if user is None:
        user = list(cfg)[0]
    return validateJWTFn[cfg[user]['provider']](cfg[user]['tokens']['id_token'])

def addQueryParams(req, toAdd):
    parts = urlparse(req)
    query = parse_qs(parts.query)
    query.update(toAdd)
    newParts = ParseResult(scheme=parts.scheme, netloc=parts.netloc, path=parts.path,
        params=parts.params, query=urlencode(query), fragment=parts.fragment)
    return urlunparse(newParts)

def addToken(req, cfg, user=None):
    if user is None:
        user = list(cfg)[0]
    return addQueryParams(req, {
        'provider': cfg[user]['provider'],
        'id_token': cfg[user]['tokens']['id_token']
    })

def addJobToken(req, jobToken):
    return addQueryParams(req, {
        'job_token': jobToken
    })

def dumpServers(resp, configLoc):
    cfgdir = utils.getHome()+"/.{0}".format(configLoc)
    print("Writing {0} to {1}".format(resp.json(), cfgdir))
    utils.mkdir(cfgdir)
    with open('{0}/servers.yaml'.format(cfgdir), 'w') as fp:
        yaml.dump(resp.json(), fp)
    return resp.json()["ClusterID"]

def tryServers(servers, doFn, regetFn):
    sList = copy.deepcopy(list(servers))
    random.shuffle(sList)
    regetServers = False
    success = False
    resp = None
    #print("Servers: {0}".format(sList))
    for server in sList:
        try:
            #print("TryServer:{0}".format(server))
            resp = doFn(server)
            if resp is None: # return of None means failure
                regetServers = True
            success = True
            break
        except Exception as e:
            print("Exception-tryServers: {0}".format(e))
            regetServers = True # at least one failure
    if success and regetServers and regetFn is not None:
        try:
            dumpServers(*regetFn(server))
        except Exception as e:
            print("WARNING: Unable to get servers {0}".format(e))
            pass
    return resp

def tryHttpServers(req, servers, reqFn, regetFn):
    def wrapper(server):
        url = requests.head(server) # exception thrown if not alive
        #if url.status_code != 200 and url.status_code != 302 and url.status_code != 301:
        #    regetServers = True
        #    continue
        reqS = "{0}/{1}".format(server, req)
        #print("Req: {0}".format(reqS))
        return reqFn(reqS)
    return tryServers(servers, wrapper, regetFn)

def tryHttpReqs(servers, doFn):
    for server in servers:
        try:
            requests.head(server) # exception thrown if not alive
            return doFn(server)
        except Exception:
            pass

def parse_qs0(query):
    qs = parse_qs(query)
    return {key: qs[key][0] for key in qs}

# adhoc certs for testing
import ssl

def generate_adhoc_ssl_pair(cn=None, hosts=None):
    from random import random
    from OpenSSL import crypto

    if cn is None:
        cn = '*'

    cert = crypto.X509()
    cert.set_serial_number(int(random() * sys.maxsize))
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(60 * 60 * 24 * 365 * 10) # 10 years

    subject = cert.get_subject()
    subject.CN = cn
    subject.O = 'Dummy Certificate'  # noqa: E741
    if hosts is not None:
        hosts.append('localhost')
        altNames = ", ".join(["DNS:{0}".format(host) for host in hosts])
        cert.add_extensions([crypto.X509Extension(b"subjectAltName", False, altNames.encode())])

    issuer = cert.get_issuer()
    issuer.CN = subject.CN
    issuer.O = subject.O  # noqa: E741

    pkey = crypto.PKey()
    pkey.generate_key(crypto.TYPE_RSA, 2048)
    cert.set_pubkey(pkey)
    cert.sign(pkey, 'sha256')

    return cert, pkey

def make_ssl_devcert(base_path, host=None, cn=None):
    from OpenSSL import crypto
    if host is not None:
        cn = '*.%s/CN=%s' % (host, host)
    cert, pkey = generate_adhoc_ssl_pair(cn=cn)

    cert_file = base_path + '.crt'
    pkey_file = base_path + '.key'

    with open(cert_file, 'wb') as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    with open(pkey_file, 'wb') as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey))

    return cert_file, pkey_file

class SSLContext(object):
    def __init__(self, protocol):
        self._protocol = protocol
        self._certfile = None
        self._keyfile = None
        self._password = None

    def load_cert_chain(self, certfile, keyfile=None, password=None):
        self._certfile = certfile
        self._keyfile = keyfile or certfile
        self._password = password

    def wrap_socket(self, sock, **kwargs):
        return ssl.wrap_socket(sock, keyfile=self._keyfile,
                               certfile=self._certfile,
                               ssl_version=self._protocol, **kwargs)

def load_ssl_context(cert_file, pkey_file=None, protocol=None):
    if protocol is None:
        protocol = ssl.PROTOCOL_SSLv23
    ctx = SSLContext(protocol)
    ctx.load_cert_chain(cert_file, pkey_file)
    return ctx

def generate_adhoc_ssl_context(cn=None, hosts=None):
    """Generates an adhoc SSL context for the development server."""
    from OpenSSL import crypto
    import tempfile
    import atexit

    cert, pkey = generate_adhoc_ssl_pair(cn, hosts)
    cert_handle, cert_file = tempfile.mkstemp()
    pkey_handle, pkey_file = tempfile.mkstemp()
    atexit.register(os.remove, pkey_file)
    atexit.register(os.remove, cert_file)

    os.write(cert_handle, crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    os.write(pkey_handle, crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey))
    os.close(cert_handle)
    os.close(pkey_handle)
    ctx = load_ssl_context(cert_file, pkey_file)
    return ctx
