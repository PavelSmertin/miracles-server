
from sqlalchemy import Column, ForeignKey, String, Numeric, DateTime
from sqlalchemy.orm import relationship
from connexion_sql_utils import to_json, event_func, dump_method
from models import DbModel, DbModelClear
from sqlalchemy.dialects.postgresql import UUID, ARRAY
from datetime import datetime
import uuid


class User(DbModel):

    __tablename__ = 'users'

    id = Column(UUID(), primary_key=True, default=uuid.uuid4)

    name                            = Column(String(40), nullable=False)
    email                           = Column(String(80), unique=True)
    avatar                          = Column(String(512))
    social_id                       = Column(String(128), nullable=False, unique=True)
    facebook_authorization_code     = Column(String(512))
    facebook_access_token           = Column(String(512))
    auth_token                      = Column(String(512))
    karma                           = Column(Numeric, nullable=True)

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

class Post(DbModel):
    __tablename__ = 'posts'
    id = Column(UUID(), primary_key=True, default=uuid.uuid4)
    uid = Column(UUID())
    message = Column(String(512), nullable=True)
    temp = Column(Numeric, nullable=True)
    visitors = Column(ARRAY(UUID()))
    tags = relationship('tags', secondary = 'posttag')

class Tag(DbModel):
    __tablename__ = 'tags'
    id = Column(UUID(), primary_key=True, default=uuid.uuid4)
    name = Column(String(128), nullable=True)
    posts = relationship('posts', secondary = 'posttag')


class PostTag(DbModel):
    __tablename__ = 'posttag'
    post_id = Column(UUID(), ForeignKey('posts.id'), primary_key=True)
    tag_id = Column(UUID(), ForeignKey('tags.id'), primary_key=True)

class Visits(DbModel):
    __tablename__ = 'visits'
    id = Column(UUID(), primary_key=True, default=uuid.uuid4)
    post_id = Column(UUID(), index=True)
    uid = Column(UUID(), index=True)
    tms = Column(DateTime, index=True, default=datetime.utcnow)

class Socials(DbModel):
    __tablename__ = 'socials'
    uid1 = Column(UUID(), primary_key=True)
    uid2 = Column(UUID(), primary_key=True)
