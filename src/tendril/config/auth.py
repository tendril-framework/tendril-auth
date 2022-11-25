

from tendril.utils.config import ConfigOption
from tendril.utils import log
logger = log.get_logger(__name__, log.DEFAULT)

depends = ['tendril.config.core']


config_elements_auth = [
    ConfigOption(
        'AUTH_SECRET_KEY',
        "None",
        "A secret key to be used for user authentication. Ideally, this should "
        "be provided as an environment variable in the authenticating host or "
        "something of the sort. At present, it should be atleast stored in the "
        "local config instead of the instance config."
    ),
]


def load(manager):
    logger.debug("Loading {0}".format(__name__))
    manager.load_elements(config_elements_auth,
                          doc="Authentication Configuration")
