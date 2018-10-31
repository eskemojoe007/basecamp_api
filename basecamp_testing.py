#!/usr/bin/env python
from flask import Flask, abort, request
from uuid import uuid4
import requests
import six
import configparser
CLIENT_ID = None
CLIENT_SECRET = None
REDIRECT_URI = None
USER_AGENT = None
PORT = None


def set_config():
    def read_config(fn='config.ini', key='basecamp'):
        config = configparser.ConfigParser()

        dataset = config.read(fn)

        if len(dataset) < 1:
            raise ValueError('Could not read in file: %s' % fn)

        try:
            return config[key]
        except KeyError:
            raise KeyError(
                'Section "%s" was not found in the init file: %s' % (key, fn))

    config = read_config()

    global CLIENT_ID
    global CLIENT_SECRET
    global USER_AGENT
    global REDIRECT_URI
    global PORT

    CLIENT_ID = config['CLIENT_ID']
    CLIENT_SECRET = config['CLIENT_SECRET']
    USER_AGENT = config['USER_AGENT']
    PORT = config['PORT']
    REDIRECT_URI = config['REDIRECT_URI_BASE'] + \
        ":" + PORT + "/" + config['callback_adder']


def user_agent():
    return USER_AGENT


def base_headers():
    return {"User-Agent": user_agent()}


app = Flask(__name__)


@app.route('/')
def homepage():
    text = '<a href="%s">Authenticate with Basecamp 3</a>'
    return text % make_authorization_url()


def make_authorization_url():
    # Generate a random string for the state parameter
    # Save it for use later to prevent xsrf attacks
    state = str(uuid4())
    save_created_state(state)
    # type=web_server&client_id=your-client-id&redirect_uri=your-redirect-uri
    params = {
        "type": "web_server",
        "client_id": CLIENT_ID,
        "state": state,
        "redirect_uri": REDIRECT_URI}
    url = "https://launchpad.37signals.com/authorization/new?" + \
        six.moves.urllib.parse.urlencode(params)
    return url


# Left as an exercise to the reader.
# You may want to store valid states in a database or memcache.
def save_created_state(state):
    pass


def is_valid_state(state):
    return True


@app.route('/basecamp_callback')
def basecamp_callback():
    error = request.args.get('error', '')
    if error:
        return "Error: " + error
    state = request.args.get('state', '')
    if not is_valid_state(state):
        # Uh-oh, this request wasn't started by us!
        abort(403)
    code = request.args.get('code')
    print(code)
    access_token = get_token(code)
    # Note: In most cases, you'll want to store the access token, in, say,
    # a session for use in other parts of your web app.
    return "Your first name is: %s" % get_username(access_token)


def get_token(code):
    # client_auth = requests.auth.HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET)
    post_data = {"type": "web_server",
                 'client_id': CLIENT_ID,
                 'client_secret': CLIENT_SECRET,
                 "code": code,
                 "redirect_uri": REDIRECT_URI}
    headers = base_headers()
    # response = requests.post("https://launchpad.37signals.com/authorization/token?",
    #                          auth=client_auth,
    #                          headers=headers,
    #                          data=post_data)
    response = requests.post("https://launchpad.37signals.com/authorization/token?",
                             # auth=client_auth,
                             headers=headers,
                             data=post_data)
    token_json = response.json()
    print(token_json)
    return token_json["access_token"]


def get_username(access_token):
    headers = base_headers()
    headers.update({"Authorization": "bearer " + access_token})
    response = requests.get(
        "https://launchpad.37signals.com/authorization.json", headers=headers)
    me_json = response.json()
    print(me_json)
    return me_json['identity']['first_name']


if __name__ == '__main__':
    set_config()
    app.run(debug=True, port=int(PORT))
    basecamp_callback()
