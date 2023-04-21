

import os

from tendril.config import AUTH0_NAMESPACE
os.environ['AUTH0_RULE_NAMESPACE'] = AUTH0_NAMESPACE

from fastapi import Security
from fastapi_auth0 import Auth0, Auth0User

from auth0.exceptions import Auth0Error
from auth0.authentication import GetToken
from auth0.management import Auth0 as Auth0PythonClient

from tendril.authz import scopes

from tendril.config import AUTH0_DOMAIN
from tendril.config import AUTH0_AUDIENCE
from tendril.config import AUTH0_USER_MANAGEMENT_API_CLIENTID
from tendril.config import AUTH0_USER_MANAGEMENT_API_CLIENTSECRET
from tendril.config import AUTH0_USERINFO_CACHING
from tendril.config import AUTH0_M2M_CLIENTS
from tendril.config import AUTH0_MECHANIZED_CONNECTION
from tendril.config import AUTH0_MECHANIZED_USER_DOMAIN


from tendril.utils import log
logger = log.get_logger(__name__, log.DEBUG)


logger.info("Using Auth0 parameters:\n"
            "  - domain    {} \n"
            "  - audience  {} \n"
            "  - namespace {} ".format(AUTH0_DOMAIN, AUTH0_AUDIENCE, AUTH0_NAMESPACE))


if AUTH0_USERINFO_CACHING == 'platform':
    logger.info("Using platform level caching for Auth0 UserInfo")
    from tendril.caching import platform_cache as cache
else:
    logger.info("Not caching Auth0 UserInfo")
    from tendril.caching import no_cache as cache


auth = Auth0(domain=AUTH0_DOMAIN,
             api_audience=AUTH0_AUDIENCE,
             scopes=scopes.scopes)


authn_dependency = auth.implicit_scheme
AuthUserModel = Auth0User

management_api_token = None


def auth_spec(scopes=None):
    kwargs = {}
    if scopes:
        kwargs['scopes'] = scopes
    return Security(auth.get_user, **kwargs)


def get_management_api_token():
    global management_api_token
    logger.debug("Attempting to get the management API token using:\n"
                 "  - domain          {}\n"
                 "  - client id       {}\n"
                 "  - client secret   ending with {}".format(
        AUTH0_DOMAIN, AUTH0_USER_MANAGEMENT_API_CLIENTID,
        AUTH0_USER_MANAGEMENT_API_CLIENTSECRET[-5:0])
    )
    get_token = GetToken(AUTH0_DOMAIN, AUTH0_USER_MANAGEMENT_API_CLIENTID,
                         client_secret=AUTH0_USER_MANAGEMENT_API_CLIENTSECRET)
    token = get_token.client_credentials('https://{}/api/v2/'.format(AUTH0_DOMAIN))
    management_api_token = token['access_token']
    logger.info("Successfully received Management API token ending in {}".format(management_api_token[-5:]))


def management_api(func):
    def _wrapper(*args, **kwargs):
        global management_api_token
        if management_api_token is None:
            get_management_api_token()
        try:
            auth0 = Auth0PythonClient(AUTH0_DOMAIN, management_api_token)
            return func(*args, auth0=auth0, **kwargs)
        except Auth0Error as error:
            if error.status_code == 401:
                get_management_api_token()
                auth0 = Auth0PythonClient(AUTH0_DOMAIN, management_api_token)
                return func(*args, auth0=auth0, **kwargs)
            if error.status_code == 400:
                # this may be an M2M client
                raise
            else:
                raise
    return _wrapper


@management_api
def get_user_object(user_id, auth0=None):
    logger.debug("Attempting to fetch user information for {} from Auth0".format(user_id))
    user_profile = auth0.users.get(user_id)
    logger.info("Got user details for {} from Auth0 Management API".format(user_id))
    return user_profile


_m2m_clients = {}


def _key_func(user_id):
    return user_id


@cache(namespace='userinfo', ttl=86400, key=_key_func)
def get_user_profile(user_id):
    if user_id in _m2m_clients.keys():
        return _m2m_clients[user_id]
    global management_api_token
    if management_api_token is None:
        get_management_api_token()
    try:
        return get_user_object(user_id)
    except Auth0Error as error:
        if error.status_code == 401:
            get_management_api_token()
            return get_user_object(user_id)
        if error.status_code == 400:
            # this may be an M2M client
            raise
        else:
            raise


@cache(namespace='userstub', ttl=86400, key=_key_func)
def get_user_stub(user_id):
    profile = get_user_profile(user_id)
    if 'description' in profile.keys():
        return profile
    return {
        'name': profile['name'],
        'nickname': profile['nickname'],
        'picture': profile['picture'],
        'user_id': profile['user_id'],
    }


@management_api
def get_connections(auth0: Auth0PythonClient = None):
    return auth0


def get_mechanized_user_email(username, prefix):
    return f'{username}@{prefix}.{AUTH0_MECHANIZED_USER_DOMAIN}'


def get_mechanized_user_username(username, prefix):
    return f'{prefix}-{username}'


@management_api
def create_mechanized_user(username, prefix, password=None,
                           auth0: Auth0PythonClient = None):
    if not AUTH0_MECHANIZED_CONNECTION:
        raise (ValueError('AUTH0_MECHANIZED_CONNECTION needs to be '
                          'provided to enable mechanized user creation'))
    auth0.users.create(body={
        'email': get_mechanized_user_email(username, prefix),
        'name': f'{prefix} {username}',
        'username': get_mechanized_user_username(username, prefix),
        'connection': AUTH0_MECHANIZED_CONNECTION,
        'password': password,
    })


@management_api
def find_user_by_email(email, mechanized=True, auth0: Auth0PythonClient = None):
    results = auth0.users_by_email.search_users_by_email(email, fields=['user_id', 'identities'])
    if mechanized:
        return [x['user_id'] for x in results if
                x['identities'][0]['connection'] == AUTH0_MECHANIZED_CONNECTION]
    else:
        return [x['user_id'] for x in results]


@management_api
def set_user_password(user_id, password, auth0: Auth0PythonClient = None):
    auth0.users.update(user_id, {'password': password})


def init():
    global _m2m_clients
    _m2m_clients = AUTH0_M2M_CLIENTS
