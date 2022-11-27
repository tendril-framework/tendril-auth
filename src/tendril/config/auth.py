

from tendril.utils.config import ConfigOption
from tendril.utils import log
logger = log.get_logger(__name__, log.DEFAULT)

depends = ['tendril.config.core']


config_elements_auth = [
    ConfigOption(
        'AUTH_PROVIDER',
        "'auth0'",
        "Auth Provider"
    ),
]


config_elements_auth0 = [
    ConfigOption(
        'AUTH0_DOMAIN',
        "None",
        "Auth0 Domain"
    ),
    ConfigOption(
        'AUTH0_AUDIENCE',
        "None",
        "Auth0 Audience"
    )
]


def load(manager):
    logger.debug("Loading {0}".format(__name__))
    manager.load_elements(config_elements_auth,
                          doc="Authentication Configuration")
    if manager.AUTH_PROVIDER == "auth0":
        manager.load_elements(config_elements_auth0,
                              doc="Auth0 Configuration")

