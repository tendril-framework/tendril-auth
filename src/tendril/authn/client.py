

from httpx import Auth
from tendril.utils.www import async_client

from tendril.config import AUTH0_DOMAIN
from tendril.utils import log
logger = log.get_logger(__name__, log.DEBUG)


class IntramuralAuthenticator(Auth):
    requires_response_body = True

    def __init__(self, audience, client_id, client_secret):
        self._audience = audience
        self._client_id = client_id
        self._client_secret = client_secret
        self._access_token = None

    def sync_auth_flow(self, request):
        raise NotImplementedError

    async def async_auth_flow(self, request):
        if self._access_token:
            request.headers["Authorization"] = "Bearer " + self._access_token
            response = yield request

        if not self._access_token or response.status_code == 401:
            # If the server issues a 401 response, then issue a request to
            # refresh tokens, and resend the request.
            await self.async_get_access_token()
            request.headers["Authorization"] = "Bearer " + self._access_token
            yield request

    async def async_get_access_token(self):
        logger.info(f"Requesting intramural access token for {self._audience}")
        async with async_client() as auth_client:
            response = await auth_client.post(
                f"https://{AUTH0_DOMAIN}/oauth/token",
                json={"audience": self._audience,
                      "grant_type": "client_credentials",
                      "client_id": self._client_id,
                      "client_secret": self._client_secret},
                headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()
            logger.info(f"Got intramural access token for {self._audience}")
            self._access_token = response.json()['access_token']
