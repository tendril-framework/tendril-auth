

from tendril.config import AUTH_PROVIDER

from .db.controller import register_provider
from .db.controller import register_user

from tendril.utils import log
logger = log.get_logger(__name__, log.DEBUG)


if AUTH_PROVIDER == "auth0":
    logger.info("Using the auth0 auth provider")
    from . import auth0 as AuthProvider
    provider_name = 'auth0'
else:
    raise ImportError("AUTH_PROVIDER {} not recognized".format(AUTH_PROVIDER))


authn_dependency = AuthProvider.authn_dependency
AuthUserModel = AuthProvider.AuthUserModel
auth_spec = AuthProvider.auth_spec
get_provider_user_profile = AuthProvider.get_user_profile


def get_user_profile(user):
    if isinstance(user, AuthUserModel):
        user = user.id
    profile = {}
    profile[provider_name] = get_provider_user_profile(user)
    return profile


def get_user_stub(user):
    if isinstance(user, AuthUserModel):
        user = user.id
    return AuthProvider.get_user_stub(user)


def verify_user_registration(user):
    if isinstance(user, AuthUserModel):
        user = user.id
    return register_user(user, provider_name)


def init():
    AuthProvider.init()
    register_provider(provider_name)


init()
