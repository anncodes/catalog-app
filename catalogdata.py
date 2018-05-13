from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import datetime
from database_setup import *

# To create engine function, let program know what
# database to connect to and bind the engine
# to the database
engine = create_engine('sqlite:///catalogplaces.db')
Base.metadata.bind = engine

# Create session maker
DBsession = sessionmaker(bind=engine)
session = DBsession()

session.query(Category).delete()
session.query(ItemPlace).delete()
session.query(User).delete()

# Add users
User1 = User(
    name="Sophie Durand",
    email="sdurand512@gmail.com",
    picture="https://placeimg.com/200/200/animals")
session.add(User1)
session.commit()

User2 = User(
    name="Ann Gepulle",
    email="annm.gepulle@gmail.com",
    picture="https://placeimg.com/200/200/animals")
session.add(User2)
session.commit()

# Create categories
Category1 = Category(
    name="Cultural",
    user_id=2)
session.add(Category1)
session.commit()

Category2 = Category(
    name="Food",
    user_id=2)
session.add(Category2)
session.commit()

Category3 = Category(
    name="Sports",
    user_id=2)
session.add(Category3)
session.commit()

# Add item places to categories
ItemPlace1 = ItemPlace(
    name="Shuri Castle",
    address="Shuri, Okinawa",
    description="Shuri Castle is a Ryukyuan gusuku \
    in Shuri, Okinawa.",
    photo="http://bit.ly/2EhVDZK",
    category_id=1,
    user_id=2)
session.add(ItemPlace1)
session.commit()

ItemPlace2 = ItemPlace(
    name="Makishi Market",
    address="Naha, Okinawa",
    description="An excellent place for visitors to go to learn \
    about everyday life in Okinawa",
    photo="http://bit.ly/2EhGDeg",
    category_id=1,
    user_id=2)
session.add(ItemPlace2)
session.commit()

ItemPlace3 = ItemPlace(
    name="Sefa Utaki",
    address="Naha, Okinawa",
    description=" Sefa Utaki is an historical sacred space, \
    overlooking Kudaka Island, that served as one of the key  \
    locations of worship in the native religion of the \
    Ryukyuan people for millennia.",
    photo="http://bit.ly/2D6WJs5",
    category_id=1,
    user_id=2)
session.add(ItemPlace3)
session.commit()

ItemPlace4 = ItemPlace(
    name="Ugan",
    address="Zamami, Kerama",
    description="There are a current around Ugan that \
    standing on the ocean, a dynamic drop off \
    and schools of fish.",
    photo="http://bit.ly/2D53Jpf",
    category_id=2,
    user_id=2)
session.add(ItemPlace4)
session.commit()

print 'Database has been populated'
