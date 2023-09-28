import jwt
import random
import requests
import hashlib
import copy
import flask
import os
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlencode, urlparse, urlunparse, ParseResult, parse_qs
import threading
import traceback
import base64
import json
import yaml
import tempfile
import shutil

jwtVer = int(jwt.__version__.split('.')[0])

# OAuth 2 Login

def generate_nonce(length=8):
    """Generate pseudorandom number."""
    return ''.join([str(random.randint(0, 9)) for i in range(length)])

def parse_qs0(query):
    qs = parse_qs(query)
    return {key: qs[key][0] for key in qs}

class OIDCLogin():
    def __init__(self, config, tokenInfo, tokenFound, version):
        self.config = config
        if version=="msftv1":
            self.redirectURL = self.redirectURLv1
            self.getTokenFromCode = self.getTokenFromCodev1
            self.getTokenFromRefreshToken = self.getTokenFromRefreshTokenv1
            self.getTokenFromDeviceCode = None
        elif version=="msftv2" or version=="google":
            self.redirectURL = self.redirectURLv2
            self.getTokenFromCode = self.getTokenFromCodev2
            self.getTokenFromRefreshToken = self.getTokenFromRefreshTokenv2
            self.getTokenFromDeviceCode = self.getTokenFromDeviceCodeV2
        self.auth = urlparse(self.config['auth_uri'])
        self.authQueryParams = parse_qs0(self.auth.query)
        self.tokenInfo = tokenInfo
        self.tokenFound = tokenFound
        self.tokenInfo['resp'] = None
        self.tokenInfo['tokens'] = None
        self.tokenInfo['user'] = None
        self.version = version

    # For webbrowser based login
    def start(self):
        self.server = flask.Flask("oidclogin")
        self.server.secret_key = hashlib.sha256(os.urandom(1024)).hexdigest()
        self.server.add_url_rule('/', None, self.home, methods=['GET'])
        self.server.add_url_rule('/login', None, self.login, methods=['GET'])
        self.server.add_url_rule('/getAToken', None, self.token, methods=['GET'])
        self.server.run()

    def getScope(self):
        scope = 'openid email offline_access'
        if 'scope' in self.config: # additional scope
            scope += " " + self.config["scope"]
        return scope

    def redirectURLv2(self):
        state = hashlib.sha256(os.urandom(1024)).hexdigest()
        queryParams = copy.deepcopy(self.authQueryParams)
        queryParams.update({
            'client_id': self.config['client_id'],
            'response_type': 'code',
            'scope': self.getScope(),
            'state': state,
            'nonce': generate_nonce(),
            'access_type': 'offline',
            'redirect_uri': self.config['redirect_uri']
        })
        return (state, urlunparse((self.auth.scheme, self.auth.netloc, self.auth.path, self.auth.params, 
                                   urlencode(queryParams), self.auth.fragment)))

    def redirectURLv1(self):
        state = hashlib.sha256(os.urandom(1024)).hexdigest()
        queryParams = copy.deepcopy(self.authQueryParams)
        queryParams.update({
            'client_id': self.config['client_id'],
            'response_type': 'code',
            'redirect_uri': self.config['redirect_uri'],
            'resource': self.config['resource'],
            'state': state
        })
        return (state, urlunparse((self.auth.scheme, self.auth.netloc, self.auth.path, self.auth.params, 
                                   urlencode(queryParams), self.auth.fragment)))

    def getTokenV2(self, postReq, prtErr=True):
        #print("TokenURI: {0} Data: {1}".format(self.config['token_uri'], postReq))
        resp = requests.post(self.config['token_uri'], data = postReq,
                             headers={'Content-Type': 'application/x-www-form-urlencoded'})
        if resp.ok:
            tokens = resp.json()
            if jwtVer < 2:
                user = jwt.decode(tokens['id_token'], verify=False)['email']
            else:
                user = jwt.decode(tokens['id_token'], options={'verify_signature': False})['email']
            return resp, tokens, user
        else:
            if prtErr:
                print("ERROR: {0}".format(resp.json()))
            return None, None, None

    def getTokenFromCodev2(self, code):
        postReq = {
            'code': code,
            'client_id': self.config['client_id'],
            'client_secret': self.config['client_secret'],
            'redirect_uri': self.config['redirect_uri'],
            'grant_type': 'authorization_code'
        }
        return self.getTokenV2(postReq)

    def getTokenFromRefreshTokenv2(self, refreshToken, public):
        postReq = {
            'refresh_token': refreshToken,
            'client_id': self.config['client_id'],
            'grant_type': 'refresh_token'
        }
        if not public:
            postReq['client_secret'] = self.config['client_secret']
        return self.getTokenV2(postReq)

    def getTokenFromDeviceCodeV2(self, deviceCode):
        postReq = {
            'device_code': deviceCode,
            'client_id': self.config['client_id'],
            'grant_type': 'device_code'            
        }
        return self.getTokenV2(postReq, prtErr=False)

    def getTokenFromCodev1(self, code):
        import adal
        auth_context = adal.AuthenticationContext(self.config['token_uri'])
        token_response = auth_context.acquire_token_with_authorization_code(code,
            self.config['redirect_uri'], self.config['resource'], self.config['client_id'], self.config['client_secret'])
        return None, token_response, token_response['userId']

    def getTokenFromRefreshTokenv1(self, refreshToken):
        import adal
        auth_context = adal.AuthenticationContext(self.config['token_uri'])
        token_response = auth_context.acquire_token_with_refresh_token(refreshToken,
            self.config['client_id'], self.config['resource'], self.config['client_secret'])
        #print(token_response)
        return None, token_response, None

    def home(self):
        login_url = 'http://localhost:{0}/login'.format(self.config['port'])
        resp = flask.Response(status=307)
        resp.headers['location'] = login_url
        return resp

    def login(self):
        state, auth_uri = self.redirectURL()
        resp = flask.Response(status=307) # temporary redirect
        flask.session['state'] = state
        resp.headers['location'] = auth_uri
        print("REDIRECT TO: {0}".format(auth_uri))
        return resp

    def token(self):
        try:
            code = flask.request.args['code']
            state = flask.request.args['state']
            if state != flask.session['state']:
                return flask.jsonify({'Login': 'State does not match'}), 401
            resp, tokens, user = self.getTokenFromCode(code)
            self.tokenInfo['resp'] = resp
            self.tokenInfo['tokens'] = tokens
            self.tokenInfo['user'] = user
            threading.Timer(2.0, lambda : self.tokenFound.set()).start()
            return flask.jsonify({'Login': 'Successful'}), 200
        except Exception as ex:
            print("{0}\n{1}".format(ex, traceback.format_exc()))
            self.tokenInfo = None
            return flask.jsonify({'Login': 'Failed'}), 401

    def getFromDeviceCode(self):
        if 'devicecode_uri' not in self.config:
            raise Exception("Not supported")
        postReq = {
            "client_id": self.config["client_id"],
            "scope": self.getScope()
        }
        print("Post to {0} Data={1}".format(self.config['devicecode_uri'], postReq))
        resp = requests.post(self.config['devicecode_uri'], data = postReq)
        if not resp.ok:
            print("Resp {0}".format(resp))
            exit(-1)
        resp = resp.json()
        print(resp['message'])

        start = time.time()
        while time.time() - start < resp['expires_in']:
            time.sleep(resp['interval'])
            tokenResp, tokens, user = self.getTokenFromDeviceCode(resp['device_code'])
            if tokenResp is not None:
                self.tokenInfo['resp'] = tokenResp
                self.tokenInfo['tokens'] = tokens
                self.tokenInfo['user'] = user
                return resp, tokens, user
            else:
                #print(tokenResp)
                print("Waiting for authentication")

        return None, None, None

    # ===============================
    # Token validation
    MSFTKeys = {}
    AllMSFTKeys = None
    @staticmethod
    def getMSFTKey(token):
        token_header = jwt.get_unverified_header(token)
        if token_header['kid'] in OIDCLogin.MSFTKeys:
            return OIDCLogin.MSFTKeys[token_header['kid']]
        else:
            if OIDCLogin.AllMSFTKeys is None:
                res = requests.get("https://login.microsoftonline.com/common/discovery/v2.0/keys")
                OIDCLogin.AllMSFTKeys = res.json()
            x5c = None
            for key in OIDCLogin.AllMSFTKeys['keys']:
                if key['kid'] == token_header['kid']:
                    x5c = key['x5c']
                    break
            if x5c is None:
                return None
            # Create cert
            try:
                from cryptography.x509 import load_pem_x509_certificate
                from cryptography.hazmat.backends import default_backend
                cert = ''.join(['-----BEGIN CERTIFICATE-----\n', x5c[0], '\n-----END CERTIFICATE-----\n'])
                public_key =  load_pem_x509_certificate(cert.encode(), default_backend()).public_key()
                OIDCLogin.MSFTKeys[token_header['kid']] = public_key
                return public_key
            except Exception:
                return None

    @staticmethod
    def ValidateMSFTJWT(token, audience=None, options=None):
        from cryptography.x509 import load_pem_x509_certificate
        from cryptography.hazmat.backends import default_backend
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
            # audience is client id only for id_token, for access_token it is resoure being accessed or some location
            return jwt.decode(token, public_key, algorithms=[token_header['alg']], audience=audience, options=options)
            #return jwt.decode(token, public_key, algorithms=[token_header['alg']], options={'verify_aud': False}) # audience=self.config['client_id'])
        except Exception:
            return None

    def validateMSFTJWT(self, token, audience=None, options=None):
        if audience is None:
            audience = self.config['client_id']
        return OIDCLogin.ValidateMSFTJWT(token, audience=audience, options=options)

    @staticmethod
    def ValidateGoogleJWT(token):
        # just use the endpoint for now, look for keys
        req = "https://www.googleapis.com/oauth2/v3/tokeninfo?id_token={0}".format(token)
        #print("Req: {0}".format(req))
        resp = requests.get(req)
        try:
            return json.loads(resp.content.decode())
        except Exception:
            return None

    def validateGoogleJWT(self, token):
        return OIDCLogin.ValidateGoogleJWT(token)

    @staticmethod
    def VerifyAndDecode(token, audience=None, verify=True, options=None):
        # find issuer
        decoded = None
        if verify and audience is None:
            raise ValueError('Invalid audience')
        try:
            token_header = jwt.get_unverified_header(token)
            decoded = jwt.decode(token, options={'verify_signature': False})
            if not verify:
                return False, decoded
            if decoded['iss'].startswith("https://login.microsoftonline.com/"):
                publickey = OIDCLogin.getMSFTKey(token)
                if publickey is None:
                    return False, decoded
                decodedT = jwt.decode(token, publickey, algorithms=[token_header['alg']], audience=audience, options=options)
                decoded = decodedT
                if (time.time() > decoded['exp']) or (audience is not None and audience != decoded['aud']):
                    return False, decoded
                return True, decoded
            elif decoded['iss'] == "https://accounts.google.com":
                resp = OIDCLogin.ValidateGoogleJWT(token)
                verified = resp is not None
                return verified, decoded
            else:
                return False, decoded
        except Exception:
            return False, decoded

    def decodeToken(self, token, verify=True, useProvider=True, audience=None, options=None):
        if not useProvider:
            # verify must be False if provider not being used
            if jwtVer < 2:
                return jwt.decode(token, verify=verify)
            else:
                return jwt.decode(token, options={'verify_signature': verify})
        elif self.version in ["msftv1", "msftv2"]:
            return self.validateMSFTJWT(token, audience=audience, options=options)
        elif self.version == "google":
            return self.validateGoogleJWT(token)

# Write URIs using version
def getLoginConfig(loginConfig, version):
    #print(loginConfig, version)
    loginInfo = copy.deepcopy(loginConfig)
    loginInfo["redirect_uri"] = "http://localhost:{0}/getAToken".format(loginInfo['port'])
    #loginInfo['port'] = loginInfo['redirect_uri'].split('/')[2].split(':')[1]    
    # Common for MSFT login providers - use "tenant" = "common" for standard MSFT properties
    t = loginInfo.get('tenant', 'common')
    if version=="msftv2":
        loginInfo.update({
            "auth_uri": "https://login.microsoftonline.com/{}/oauth2/v2.0/authorize?prompt=select_account".format(t),
            "token_uri": "https://login.microsoftonline.com/{}/oauth2/v2.0/token".format(t),
            "devicecode_uri": "https://login.microsoftonline.com/{}/oauth2/v2.0/devicecode".format(t),
        })
    elif version=="msftv1":
        loginInfo.update({
            "auth_uri": "https://login.microsoftonline.com/{}/oauth2/authorize?prompt=select_account".format(t),
            "token_uri": "https://login.microsoftonline.com/{}".format(t),
        })
    elif version=="google":
        loginInfo.update({
            "auth_uri": "https://accounts.google.com/o/oauth2/v2/auth?prompt=select_account",
            "token_uri": "https://www.googleapis.com/oauth2/v4/token",
        })
    loginInfo.update({
        "client_id": loginConfig[version]["client_id"],
        "client_secret": loginConfig[version]["client_secret"]
    })
    # further overwrite with existing uri's
    loginInfo.update(loginConfig)
    return loginInfo

# use multiproc
def loginProc(loginConfig, tokenInfo, tokenFound, version):
    loginInfo = getLoginConfig(loginConfig, version)
    login = OIDCLogin(loginInfo, tokenInfo, tokenFound, version)
    login.start()

def e64(d):
    e = {}
    for k, v in d.items():
        e[k] = base64.b64encode(yaml.safe_dump(v).encode()).decode()
    return e

def d64(e):
    d = {}
    for k, v in e.items():
        d[k] = yaml.safe_load(base64.b64decode(str(v)).decode())
    return d

def getExistTokensFromCluster(cluster, namespace, secret):
    _, _, tokenSecret = cluster.call_method('read_namespaced_secret', namespace=namespace, name=secret)
    return d64(tokenSecret.data) # k/v base64-decode of value

def getExistTokensFromFile(file):
    with open(file, 'r') as fp:
        return yaml.safe_load(fp)

def refreshTokenToCluster(cluster, namespace, secret, newTokens):
    cluster.call_method('patch_namespaced_secret', namespace=namespace, name=secret, body={'data': e64(newTokens)})

def createTokenToCluster(cluster, namespace, secret, tokens):
    secretYaml = {
        'apiVersion': 'v1',
        'kind': 'Secret',
        'metadata': {
            'name': secret,
            'namespace': namespace,
        },
        'type': 'Opaque',
        'data': e64(tokens)
    }
    #cluster.call_method('delete_namespaced_secret', namespace=namepace, name=secret)
    cluster.call_method('create_namespaced_secret', namespace=namespace, body=secretYaml)    

def refreshTokenToFile(file, newTokens):
    (fd, tmp) = tempfile.mkstemp(suffix=".yaml")
    with open(tmp, 'w') as fp:
        yaml.dump(newTokens, fp)
    shutil.copy(tmp, file)
    os.close(fd)
    os.remove(tmp)

def getCluster(args, cluster):
    from kcclient import kubeutils, utils
    if cluster is None:
        return kubeutils.Cluster.fromCmdArgs(args)
    else:
        return cluster

def refreshToken(loginConfig, cluster, ns, secret):
    existTokens = getExistTokensFromCluster(cluster, ns, secret)
    version = existTokens['oauth_version']
    public = existTokens['oauth_publicclient']
    login = OIDCLogin(getLoginConfig(loginConfig, version), {}, None, version)
    _, tokens, _ = login.getTokenFromRefreshToken(existTokens['refresh_token'], public)
    refreshTokenToCluster(cluster, ns, secret, tokens)
    return tokens

def authLoginMain(argv, loginConfig, existTokens=None):
    from kcclient import kubeutils, utils
    import argparse, sys
    from multiprocessing import Process, Manager, Event

    cluster = None

    parser = argparse.ArgumentParser(description="Login and store token in secret")
    kstore = not ('--nostore' in argv or '-nostore' in argv or '--file' in argv or '-file' in argv)
    parser.add_argument('--secret', '-secret', required=kstore, help="Name of secret")
    parser.add_argument('--namespace', '-ns', required=kstore, help="Namespace of secret")
    parser.add_argument('--nostore', '-nostore', action='store_true', help="Don't store, only print")
    parser.add_argument('--version', '-v', default="msftv2", help='OAuth version, 1, 2, or google')
    parser.add_argument('--refresh', '-refresh', action='store_true', help='Refresh token')
    parser.add_argument('--browser', '-browser', action='store_true', help='Auto open webbrowser to complete login')
    parser.add_argument('--device', '-device', action='store_true', help="Use device code login")
    parser.add_argument('--file', '-file', default=None, help="Token file")
    parser.add_argument('--noprint', '-noprint', action='store_true', help="Don't print, just return")
    parser.add_argument('--validate', '-validate', default=None, help="Validate token - use 'provider' or 'yes' to validate")
    kubeutils.Cluster.addCmdArgs(parser)
    args = parser.parse_args(argv)

    if args.validate is not None:
        if existTokens is not None:
            pass
        elif args.file:
            existTokens = getExistTokensFromFile(args.file)
        else:
            cluster = getCluster(args, cluster)
            existTokens = getExistTokensFromCluster(cluster, args.namespace, args.secret)
        version = existTokens['oauth_version']
        login = OIDCLogin(getLoginConfig(loginConfig, version), {}, None, version)
        useProvider = (args.validate.lower() in ['provider', 'yes'])
        print("Validated Signature: {0}".format(useProvider))
        print(login.decodeToken(existTokens['id_token'], verify=False, useProvider=useProvider))
        exit(0)

    if args.refresh:
        # Refresh
        if existTokens is not None:
            pass
        elif args.file:
            existTokens = getExistTokensFromFile(args.file)
        else:
            cluster = getCluster(args, cluster)
            existTokens = getExistTokensFromCluster(cluster, args.namespace, args.secret)
        user = existTokens['oauth_user']
        version = existTokens['oauth_version']
        public = existTokens['oauth_publicclient']
        login = OIDCLogin(getLoginConfig(loginConfig, version), {}, None, version)
        _, tokens, _ = login.getTokenFromRefreshToken(existTokens['refresh_token'], public)
    elif args.device:
        # Device code
        version = args.version
        public = True # public client can't include client secret
        login = OIDCLogin(getLoginConfig(loginConfig, args.version), {}, None, version)
        _, tokens, user = login.getFromDeviceCode()
    else:
        # From webserver
        m = Manager()
        tokenInfo = m.dict()
        tokenFound = m.Event()
        version = args.version
        public = False # must include client secret
        p = Process(target=loginProc, args=(loginConfig, tokenInfo, tokenFound, version))
        p.start()
        if args.browser:
            time.sleep(2) # wait for server to start
            import webbrowser
            webbrowser.open("http://localhost:{0}".format(loginConfig['port']), new=2) # open in new tab
        tokenFound.wait()
        p.terminate()
        p.join()
        tokens = copy.deepcopy(tokenInfo['tokens'])
        user = tokenInfo['user']

    tokens['oauth_version'] = version
    tokens['oauth_user'] = user
    tokens['oauth_publicclient'] = public

    if not args.noprint and args.nostore:
        print(tokens)
    elif args.file:
        refreshTokenToFile(args.file, tokens)
    elif not args.nostore:
        cluster = getCluster(args, cluster)
        if args.refresh:
            refreshTokenToCluster(cluster, args.namespace, args.secret, tokens)
        else:
            createTokenToCluster(cluster, args.namespace, args.secret, tokens)

    return tokens
