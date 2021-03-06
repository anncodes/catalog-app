import sys
import os
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, backref
from sqlalchemy import create_engine

Base = declarative_base()


class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))


class Category(Base):
    __tablename__ = 'category'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User, backref="category")

    @property
    def serialize(self):
        return {
            'name': self.name,
            'id': self.id,
            }


class ItemPlace(Base):
    __tablename__ = 'item_place'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    address = Column(String(250), nullable=False)
    description = Column(String(250))
    photo = Column(String(250))
    category_id = Column(Integer, ForeignKey('category.id'))
    category = relationship(Category, backref=backref(
        'item_place', cascade='all, delete'))
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User, backref="item_place")

    @property
    def serialize(self):
        return {
            'name': self.name,
            'address': self.address,
            'description': self.description,
            'id': self.id,
            'photo': self.photo,
            'category': self.category.name
            }

engine = create_engine('sqlite:///catalogplaces.db')
Base.metadata.create_all(engine)
