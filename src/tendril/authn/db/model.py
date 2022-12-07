

from sqlalchemy import Column
from sqlalchemy import String
from sqlalchemy import Integer
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.orm import backref

from tendril.utils.db import DeclBase
from tendril.utils.db import BaseMixin

from tendril.utils import log
logger = log.get_logger(__name__, log.DEFAULT)


class Provider(DeclBase, BaseMixin):
    name = Column(String(50), unique=True)


class UserRoles(DeclBase, BaseMixin):
    user_id = Column(Integer(),
                     ForeignKey('User.id', ondelete='CASCADE'))
    role_id = Column(Integer(),
                     ForeignKey('Role.id', ondelete='CASCADE'))


class User(DeclBase, BaseMixin):
    puid = Column(String(255), nullable=False)

    roles = relationship('Role', secondary=UserRoles.__table__,
                         backref=backref('users', lazy='dynamic'))

    provider_id = Column(Integer(),
                         ForeignKey('Provider.id'), nullable=False)
    provider = relationship(
        "Provider", backref="users",
        primary_join=(Provider.id == provider_id)
    )

    __table_args__ = (
        UniqueConstraint('puid', 'provider_id'),
    )


class Role(DeclBase, BaseMixin):
    name = Column(String(50), unique=True)
    description = Column(String(255))
