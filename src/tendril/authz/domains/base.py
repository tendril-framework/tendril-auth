

from tendril.utils.log import get_logger
logger = get_logger(__name__)


class AuthzDomainBase:
    jwt_spec = None

    def get_user_profile(self, user):
        from tendril.authn.users import get_user_profile
        return get_user_profile(user)

    def get_user_email(self, user):
        from tendril.authn.users import get_user_email
        return get_user_email(user)

    async def upsert(self, user, first_login):
        pass


domains = {}
