

from tendril.config import AUTH_PROVIDER
from tendril.authz import domains

from .db.model import User
from .db.controller import register_provider
from .db.controller import register_user
from .db.controller import get_user_by_id


from tendril.utils import log
logger = log.get_logger(__name__, log.DEBUG)


if AUTH_PROVIDER == "auth0":
    logger.info("Using the auth0 auth provider")
    from .providers import auth0 as AuthProvider
    provider_name = 'auth0'
if AUTH_PROVIDER == "stytch":
    logger.info("Using the stytch auth provider")
    from .providers import stytch as AuthProvider
    provider_name = 'stytch'
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


def expand_user_stub(v, **kwargs):
    if isinstance(v, str):
        return get_user_stub(v)
    return v


def get_user_stub(user):
    user = preprocess_user(user)
    return AuthProvider.get_user_stub(user)


def get_user_email(user):
    profile = get_user_profile(user)
    try:
        return profile[provider_name]['email']
    except KeyError:
        raise AttributeError(f"Could not find an email for user {user}")


def verify_user_registration(user, background_tasks=None):
    user_id = preprocess_user(user)
    user, first_login = register_user(user_id, provider_name)
    if background_tasks:
        background_tasks.add_task(domains.upsert,
                                  user=user,
                                  first_login=first_login)


def init():
    AuthProvider.init()
    register_provider(provider_name)


init()
