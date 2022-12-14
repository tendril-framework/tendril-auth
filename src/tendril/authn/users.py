

from pydantic import Field
from pydantic import BaseModel
from pydantic import HttpUrl
from pydantic import validator
from pydantic import create_model

from tendril.config import AUTH_PROVIDER
from tendril.utils.pydantic import TendrilTBaseModel

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


class UserStubTModel(TendrilTBaseModel):
    name: str = Field(..., example="User Full Name")
    nickname: str = Field(..., example="nickname")
    picture: HttpUrl = Field(..., example='https://s.gravatar.com/avatar/...')
    user_id: str = Field(..., example='auth0|...')


def expand_user_stub(cls, v):
    if isinstance(v, str):
        return get_user_stub(v)
    return v



def UserStubTMixin(inp='puid', out='user'):
    validators = {
        'expand_user_stub':
        validator('puid', pre=True)(expand_user_stub)
    }
    kwargs = {
        inp : (UserStubTModel, Field(..., alias=out)),
        '__base__': TendrilTBaseModel,
        '__validators__': validators
    }
    _inner = create_model(
        f'UserStubTModel_{inp}_{out}',
        **kwargs
    )
    return _inner


def get_user_stub(user):
    user = preprocess_user(user)
    return AuthProvider.get_user_stub(user)


def verify_user_registration(user):
    user = preprocess_user(user)
    return register_user(user, provider_name)


def init():
    AuthProvider.init()
    register_provider(provider_name)


init()
