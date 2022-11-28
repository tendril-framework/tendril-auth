import os
import json

from tendril.config import AUTH0_NAMESPACE
os.environ['AUTH0_RULE_NAMESPACE'] = AUTH0_NAMESPACE

from fastapi import Security
from fastapi_auth0 import Auth0, Auth0User

from auth0.v3.exceptions import Auth0Error
from auth0.v3.authentication import GetToken
from auth0.v3.management import Auth0 as Auth0PythonClient

from tendril.config import AUTH0_DOMAIN
from tendril.config import AUTH0_AUDIENCE
from tendril.config import AUTH0_USER_MANAGEMENT_API_CLIENTID
from tendril.config import AUTH0_USER_MANAGEMENT_API_CLIENTSECRET

from tendril.utils import log
from tendril.authz import scopes

logger = log.get_logger(__name__, log.DEBUG)

logger.info("Using auth0 parameters:\n"
            "  - domain    {} \n"
            "  - audience  {} \n"
            "  - namespace {} ".format(AUTH0_DOMAIN, AUTH0_AUDIENCE, AUTH0_NAMESPACE))

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
    logger.debug("Attempting to get the management API token using:")
    logger.debug("Domain: {}".format(AUTH0_DOMAIN))
    logger.debug("Client ID: {}".format(AUTH0_USER_MANAGEMENT_API_CLIENTID))
    logger.debug("Client Secret ending in {}".format(AUTH0_USER_MANAGEMENT_API_CLIENTSECRET[-5:]))
    get_token = GetToken(AUTH0_DOMAIN)
    token = get_token.client_credentials(AUTH0_USER_MANAGEMENT_API_CLIENTID,
                                         AUTH0_USER_MANAGEMENT_API_CLIENTSECRET,
                                         'https://{}/api/v2/'.format(AUTH0_DOMAIN))
    management_api_token = token['access_token']
    logger.info("Successfully received Management API token ending in {}".format(management_api_token[-5:]))


def _get_user_profile(user: AuthUserModel):
    global management_api_token
    logger.debug("Attempting to fetch user information for {} from Auth0".format(user.id))
    auth0 = Auth0PythonClient(AUTH0_DOMAIN, management_api_token)
    user_profile = auth0.users.get(user.id)
    logger.info("Got user details for {} from Auth0 Management API".format(user.id))
    return user_profile


def get_user_profile(user: AuthUserModel):
    global management_api_token
    if management_api_token is None:
        get_management_api_token()
    try:
        return _get_user_profile(user)
    except Auth0Error as error:
        if error.status_code == 401:
            get_management_api_token()
            return _get_user_profile(user)
        else:
            raise
