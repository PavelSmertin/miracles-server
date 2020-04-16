
from sqlalchemy import Table, Column, ForeignKey, String, Integer, Numeric, DateTime
from sqlalchemy.orm import relationship
from connexion_sql_utils import to_json, event_func, dump_method
from models import DbModel, DbModelClear
from sqlalchemy.dialects.postgresql import ARRAY
from datetime import datetime

from sqlalchemy_serializer import SerializerMixin

import logging


class User(DbModel, SerializerMixin):

    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)

    name                            = Column(String(40), nullable=False)
    email                           = Column(String(80), unique=True)
    avatar                          = Column(String(512))
    social_id                       = Column(String(128), nullable=False, unique=True)
    facebook_authorization_code     = Column(String(512))
    facebook_access_token           = Column(String(512))
    auth_token                      = Column(String(512))
    #karma                           = Column(Numeric, nullable=True)

    @dump_method
    def remove_meta(self, vals):
        logging.debug('remove meta')

        vals.pop('facebook_authorization_code', None)
        vals.pop('facebook_access_token', None)
        vals.pop('auth_token', None)

        return vals

    # a method to be called to help in the conversion to json.
    @to_json('karma')
    def convert_decimal(self, val):
        if val is not None:
            logging.debug('Converting karma...')
            return float(val)
        return val


message_tag = Table('messagetag', DbModel.metadata,
    Column('message_id', Integer, ForeignKey('messages.id')),
    Column('tag_id', Integer, ForeignKey('tags.id'))
)


class Message(DbModel, SerializerMixin):
    __tablename__ = 'messages'
    id = Column(Integer, primary_key=True)
    uid = Column(Integer, ForeignKey("users.id"))
    content = Column(String(360), nullable=True)
    temp = Column(Numeric, nullable=True)
    visitors = Column(ARRAY(Integer))
    tms = Column(DateTime, index=True, default=datetime.utcnow)

    user = relationship("User", foreign_keys=[uid])

    #tags = relationship('tags', secondary = message_tag, back_populates="messages")

class Tag(DbModel, SerializerMixin):
    __tablename__ = 'tags'
    id = Column(Integer, primary_key=True)
    name = Column(String(128), nullable=True)
    #messages = relationship('messages', secondary = message_tag, back_populates="tags")



# class MessageTag(DbModel):
#     __tablename__ = 'messagetag'
#     message_id = Column(Integer, ForeignKey('messages.id'), primary_key=True)
#     tag_id = Column(Integer, ForeignKey('tags.id'), primary_key=True)

class Visits(DbModel, SerializerMixin):
    __tablename__ = 'visits'
    id = Column(Integer, primary_key=True)
    message_id = Column(Integer, index=True)
    uid = Column(Integer, index=True)
    tms = Column(DateTime, index=True, default=datetime.utcnow)

class Socials(DbModel, SerializerMixin):
    __tablename__ = 'socials'
    uid1 = Column(Integer, primary_key=True)
    uid2 = Column(Integer, primary_key=True)
