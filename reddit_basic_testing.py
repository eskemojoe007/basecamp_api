# %% Import Packages
import requests
import configparser
# end%%


# %% Read Config File
def read_config(fn='config.ini',key='reddit_script'):
    config = configparser.ConfigParser()

    dataset = config.read(fn)

    if len(dataset)<1:
        raise ValueError('Could not read in file: %s'%fn)

    try:
        return config[key]
    except KeyError:
        raise KeyError('Section "%s" was not found in the init file: %s'%(key,fn))

config = read_config()

CLIENT_ID = config['CLIENT_ID']
CLIENT_SECRET = config['CLIENT_SECRET']
USERNAME = config['USERNAME']
PASSWORD = config['PASSWORD']
USER_AGENT = config['USER_AGENT']
TOKEN_URI = config['TOKEN_URI']
# end%%

# %%  Get Token
def get_token():
    client_auth = requests.auth.HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET)
    post_data = {"grant_type": "password", "username": USERNAME, "password":PASSWORD}
    headers = {"User-Agent": USER_AGENT}

    token_response = requests.post(TOKEN_URI, auth=client_auth, data=post_data, headers=headers)

    return token_response.json()

def get_token_str(token_json=None):
    if token_json is None:
        token_json = get_token()

    return token_json['token_type'] + ' ' + token_json['access_token']

token_str = get_token_str()
# end%%

# %% Now perform query about user based on token
headers = {"Authorization": token_str, "User-Agent": USER_AGENT}
response = requests.get("https://oauth.reddit.com/api/v1/me", headers=headers)
print(response.json())
# end%%
