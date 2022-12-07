

from fastapi import APIRouter
from fastapi import Depends

from tendril.authn.users import authn_dependency
from tendril.authn.users import AuthUserModel
from tendril.authn.users import auth_spec
from tendril.authn.users import verify_user_registration


user_services = APIRouter(prefix='/user',
                          tags=["User Authentication Services"],
                          dependencies=[Depends(authn_dependency),
                                        auth_spec()])


@user_services.get("/verify")
async def verify(user: AuthUserModel = auth_spec()):
    verify_user_registration(user)
    return {"message": "Logged in User Verified."}


routers = [
    user_services
]
