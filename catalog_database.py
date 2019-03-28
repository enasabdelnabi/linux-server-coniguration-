from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()

   

   """
    Registered user information is stored in db
    """
class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)

    @property
    def serialize(self):
        return {
            'name': self.name,
            'email': self.email,
            'id': self.id
            'category_id' :self.category_id 
            'user_id':self.user_id
        }


class Category(Base):
    __tablename__ = "category"

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    description = Column(String)
    # relationship
    user_id = Column(Integer, ForeignKey(User.id))
    user = relationship(User)

    @property
    def serialize(self):
        return {
            'id': self.id,
            'name': self.name
            'category_id' :self.category_id 
            'user_id':self.user_id
        }


class Item(Base):
    __tablename__ = 'item'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    description = Column(String)
    # relationships
    user_id = Column(Integer, ForeignKey(User.id))
    user = relationship(User)
    category_id = Column(Integer, ForeignKey(Category.id))
    category = relationship(Category)

    @property
    def serialize(self):
        return {
            'id': self.id,
            'name': self.name
            'category_id' :self.category_id 
            'user_id':self.user_id
        }


# create DB
#engine = create_engine('sqlite:///itemcatalog.db')
engine = create_engine('postgresql://catalog:password@localhost/catalog')
Base.metadata.create_all(engine)
