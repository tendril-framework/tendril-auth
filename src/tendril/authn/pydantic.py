

from pydantic import Field
from pydantic import HttpUrl
from pydantic import validator
from pydantic import create_model

from tendril.utils.pydantic import TendrilTBaseModel


class UserStubTModel(TendrilTBaseModel):
    name: str = Field(..., example="User Full Name")
    nickname: str = Field(..., example="nickname")
    picture: HttpUrl = Field(..., example='https://s.gravatar.com/avatar/...')
    user_id: str = Field(..., example='auth0|...')


def _expand_user_stub(*args, **kwargs):
    # This strangeness is here to (hopefully)
    # break a circular import issue
    from tendril.authn.users import expand_user_stub
    return expand_user_stub(*args, **kwargs)


def UserStubTMixin(inp='puid', out='user'):
    validators = {
        'expand_user_stub':
        validator('puid', pre=True)(_expand_user_stub)
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
