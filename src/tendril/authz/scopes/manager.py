

import importlib
from tendril.utils.versions import get_namespace_package_names
from tendril.utils import log
logger = log.get_logger(__name__, log.DEFAULT)


class ScopesManager(object):
    def __init__(self, prefix):
        self._prefix = prefix
        self._scopes = {}
        self._find_scopes()

    def _find_scopes(self):
        logger.debug("Loading authn scopes from {0}".format(self._prefix))
        modules = list(get_namespace_package_names(self._prefix))
        for m_name in modules:
            if m_name == __name__:
                continue
            m = importlib.import_module(m_name)
            logger.debug("Loading scopes from {0}".format(m_name))
            self._scopes.update(m.scopes)

    @property
    def scopes(self):
        return self._scopes
