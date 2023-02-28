

from tendril.config import AUTH_PROVIDER
from tendril.utils import log
logger = log.get_logger(__name__, log.DEFAULT)


if AUTH_PROVIDER == "auth0":
    logger.info("Using the auth0 authz provider")
    from tendril.authz import auth0 as AuthProvider
    provider_name = 'auth0'
else:
    raise ImportError("AUTH_PROVIDER {} not recognized".format(AUTH_PROVIDER))


def get_current_scopes():
    return AuthProvider.get_current_scopes()


def commit_scopes(scopes):
    return AuthProvider.commit_scopes(scopes)


def get_user_scopes(user_id):
    return AuthProvider.get_user_scopes(user_id)


def add_user_scopes(user_id, scopes):
    return AuthProvider.add_user_scopes(user_id, scopes)


def remove_user_scopes(user_id, scopes):
    return AuthProvider.remove_user_scopes(user_id, scopes)
