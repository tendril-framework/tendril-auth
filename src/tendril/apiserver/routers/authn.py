

from fastapi import APIRouter
from fastapi import Depends

from tendril.authn.users import authn_dependency
from tendril.authn.users import AuthUserModel
from tendril.authn.users import auth_spec
from tendril.authn.users import verify_user_registration
from tendril.authn.users import get_user_profile
from tendril.authn.users import get_user_stub


user_services = APIRouter(prefix='/user',
                          tags=["User Authentication Services"],
                          dependencies=[Depends(authn_dependency),
                                        auth_spec()])


@user_services.get("/verify")
async def verify(user: AuthUserModel = auth_spec()):
    verify_user_registration(user)
    return {"message": "Logged in User Verified."}


@user_services.get("/profile/me")
async def my_profile(user: AuthUserModel = auth_spec()):
    return get_user_profile(user)


@user_services.get("/stub")
async def user_stub(user_id: str):
    # TODO change this to use the nickname or something instead
    return get_user_stub(user_id)


routers = [
    user_services
]
