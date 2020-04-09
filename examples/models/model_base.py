import os

from connexion_sql_utils import BaseMixin

from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base


DB_USER = os.environ.get('DB_USER', 'postgres')
DB_PASSWORD = os.environ.get('DB_PASSWORD', 'postgres')
DB_HOST = os.environ.get('DB_HOST', 'localhost')
DB_PORT = os.environ.get('DB_PORT', 5432)
DB_NAME = os.environ.get('DB_NAME', 'postgres')

#DB_URI = 'postgres+psycopg2://{user}:{password}@{host}:{port}/{db}'.format(
DB_URI = 'postgres://{user}:{password}@{host}:{port}/{db}'.format(
    user=DB_USER,
    password=DB_PASSWORD,
    host=DB_HOST,
    port=DB_PORT,
    db=DB_NAME
)

engine = create_engine(DB_URI)


Session = scoped_session(
    sessionmaker(autocommit=False, autoflush=False, bind=engine,
                 expire_on_commit=False)
)


# The only method required to complete the mixin is to add a staticmethod
# that should return a session.  This is used in the queries.
class ModelBase(BaseMixin):

    # give the models an access to a session.
    @staticmethod
    def session_maker():
        return Session()


# By attaching the ``session_maker`` method to the class we now create a
# ``declarative_base`` to be used.  The ``BaseMixin`` class declares an
# ``id`` column, that is ``postgresql.UUID``.  It also has an declared attr
# for the __tablename__.  If you would to override these, they can be declared
# when create your database model
DbModel = declarative_base(cls=ModelBase)
DbModelClear = declarative_base()

