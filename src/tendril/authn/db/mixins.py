

from sqlalchemy import Column
from sqlalchemy import Integer
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship

# from .model import User


class UserMixin(object):
    user_id = Column(Integer(),
                     ForeignKey('User.id'), nullable=False)
    user = relationship("User", back_populates="user")
