from tendril.utils.config import ConfigOption
from tendril.utils import log
logger = log.get_logger(__name__, log.DEFAULT)

depends = ['tendril.config.core',
           'tendril.config.auth']


config_elements_stytch = [
    ConfigOption(
        'AUTH_STYTCH_PROJECT_ID',
        'None',
        'Stytch Project ID'
    ),
    ConfigOption(
        'AUTH_STYTCH_SECRET',
        'None',
        'Stytch Secret',
        masked=True,
    ),
    ConfigOption(
        'AUTH_STYTCH_ENVIRONMENT',
        'None',
        'Stytch Environment'
    ),
    ConfigOption(
        'AUTH_STYTCH_MECHANIZED_PROJECT_ID',
        'None',
        'Stytch Project ID for Mechanized Users'
    ),
    ConfigOption(
        'AUTH_STYTCH_MECHANIZED_SECRET',
        'None',
        'Stytch Secret for Mechanized Users',
        masked=True,
    ),
    ConfigOption(
        'AUTH_STYTCH_MECHANIZED_ENVIRONMENT',
        'None',
        'Stytch Environment for Mechanized Users'
    ),
]


def load(manager):
    if manager.AUTH_PROVIDER == "stytch":
        logger.debug("Loading {0}".format(__name__))
        manager.load_elements(config_elements_stytch,
                              doc="Stytch Configuration")
