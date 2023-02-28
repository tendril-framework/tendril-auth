

from tendril.config import AUTH_PROVIDER
from tendril.utils.pydantic import TendrilTBaseModel
from tendril.authn.pydantic import UserStubTModel

from .db.model import User
from .db.controller import register_provider
from .db.controller import register_user
from .db.controller import get_user_by_id


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


def preprocess_user(user):
    if isinstance(user, AuthUserModel):
        user = user.id
    elif isinstance(user, User):
        user = user.id
    elif isinstance(user, int):
        user = get_user_by_id(user).puid
    return user


def get_user_profile(user):
    user = preprocess_user(user)
    profile = {}
    profile[provider_name] = get_provider_user_profile(user)
    return profile


def expand_user_stub(cls, v):
    if isinstance(v, str):
        return get_user_stub(v)
    return v


def get_user_stub(user):
    user = preprocess_user(user)
    return AuthProvider.get_user_stub(user)


def verify_user_registration(user):
    user_id = preprocess_user(user)
    user, first_login = register_user(user_id, provider_name)
    if first_login:
        from tendril.authz.connector import add_user_scopes
        from tendril.authz.scopes import default_user_scopes
        add_user_scopes(user.puid, default_user_scopes)


def init():
    AuthProvider.init()
    register_provider(provider_name)


init()
