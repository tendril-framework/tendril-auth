

from tendril.config import AUTHZ_PROVIDER
from tendril.utils import log
logger = log.get_logger(__name__, log.DEFAULT)


if AUTHZ_PROVIDER == "auth0":
    logger.info("Using the auth0 authz provider")
    from tendril.authz.providers import auth0 as AuthZProvider
    provider_name = 'auth0'
if AUTHZ_PROVIDER == "stytch":
    logger.error("Stytch is not an AUTHZ_PROVIDER but is configured to be one. "
                 "AuthZ and all dependent features will not be available until "
                 "a suitable AUTHZ_PROVIDER is configured.")
else:
    raise ImportError("AUTHZ_PROVIDER {} not recognized".format(AUTHZ_PROVIDER))


def get_current_scopes():
    return AuthZProvider.get_current_scopes()


def commit_scopes(scopes):
    return AuthZProvider.commit_scopes(scopes)


def get_user_scopes(user_id):
    return AuthZProvider.get_user_scopes(user_id)


def add_user_scopes(user_id, scopes):
    return AuthZProvider.add_user_scopes(user_id, scopes)


def remove_user_scopes(user_id, scopes):
    return AuthZProvider.remove_user_scopes(user_id, scopes)
