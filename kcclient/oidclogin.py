import webbrowser
import urllib
import urllib.parse
import hashlib
import requests
import copy
import yaml
import os
import sys
thisPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(thisPath)
import json
import pathlib
from urllib.parse import urlencode, urlparse, urlunparse, ParseResult, parse_qs
from http.server import HTTPServer, BaseHTTPRequestHandler
import webutils
import utils
import jwt
import random

def generate_nonce(length=8):
    """Generate pseudorandom number."""
    return ''.join([str(random.randint(0, 9)) for i in range(length)])

class WebServer(HTTPServer):
    def __init__(self, config, hostport, *args, **kwargs):
        self.session = {}
        self.config = config
        self.hostport = hostport
        super(WebServer, self).__init__(hostport, *args, **kwargs)

    def getSession0(self):
        if len(self.session) > 0:
            key0 = list(self.session.keys())[0]
            return self.session[key0]
        else:
            return None

class ClientRedirectHandler(webutils.HTTPRequestHandler):
    def exchangeCodeForToken(self, state):
        postReq = {
            'code': self.server.session[state]['code'],
            'client_id': self.server.config['client_id'],
            'client_secret': self.server.config['client_secret'],
            'redirect_uri': self.server.session[state]['redirect_uri'],
            'grant_type': 'authorization_code'
        }
        resp = requests.post(self.server.config['token_uri'], data = postReq,
                             headers={'Content-Type': 'application/x-www-form-urlencoded'})
        self.server.session[state]['tokens'] = resp.json()
        return resp

    def oidc(self):
        try:
            parts = urlparse(self.path)
            ret = parse_qs(parts.query)
            getState = ret['state'][0]
            getCode = ret['code'][0]
            if getState not in self.server.session:
                self.html401()
            self.server.session[getState].update({'code': getCode})
            self.exchangeCodeForToken(getState)
            self.html200("<html><body><h1>Successfully logged in!</h1></body></html>")
        except Exception as e:
            print("Exception {0}".format(e))
            self.html401()

    def do_GET(self):
        parts = urlparse(self.path)
        if parts.path == '/oidc':
            self.oidc()

def login_url(config, server):
    (host, port) = server.hostport
    state = hashlib.sha256(os.urandom(1024)).hexdigest()
    redirect_uri = "http://{0}:{1}/oidc".format(host, port)
    server.session[state] = {'redirect_uri' : redirect_uri}
    auth = urlparse(config["auth_uri"])
    queryParams = webutils.parse_qs0(auth.query)
    queryParams.update({
        'client_id': config['client_id'],
        'response_type': 'code',
        'scope': 'openid email',
        'state': state,
        'nonce': generate_nonce(),
        'access_type': 'offline',
        'redirect_uri': redirect_uri
    })
    loc = ParseResult(
        scheme=auth.scheme,
        netloc=auth.netloc,
        path=auth.path,
        params='',
        query=urlencode(queryParams),
        fragment=''
    )
    location = urlunparse(loc)
    #print("Redirect: {0}".format(location))
    return location

def get_code(provider, config, useReqs):
    port = 5000
    web_server = WebServer(config, ('localhost', port), ClientRedirectHandler)
    url = login_url(config, web_server)
    if useReqs:
        requests.get(url)
    else:
        webbrowser.open(url, new=2)

    while True:
        web_server.handle_request()
        session0 = web_server.getSession0()
        #print("Session0: {0}".format(session0))
        if session0 is not None and 'tokens' in session0:
            break

    tokens = copy.deepcopy(web_server.getSession0()['tokens'])
    user = jwt.decode(tokens['id_token'], verify=False)['email'] # verify only needed on server side
    sessionState = {user: {'provider' : provider, 'tokens': tokens}}
    web_server.server_close()
 
    return sessionState, user

def login(provider, cfgfile, useReqs=False):
    (sessionState, user) = get_code(provider, webutils.oidc[provider], useReqs)
    configdir = "{0}/.{1}".format(utils.getHome(), cfgfile)
    pathlib.Path(configdir).mkdir(parents=True, exist_ok=True)
    utils.updateYaml("{0}/{1}.users.yaml".format(configdir, cfgfile), sessionState)
    return sessionState, user

if __name__ == "__main__":
    login("msft", "kcluster")
