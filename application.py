from flask import Flask, render_template, url_for, request, redirect, jsonify, flash
from flask import session as login_session
from functools import wraps
import random
import string
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker, relationship
from database_setup import Base, Category, User, ItemPlace

#imports for oauth2client
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "catalog-app"
engine = create_engine('sqlite:///catalogplaces.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

def login_required(f):
    @wraps(f)
    def x(*args, **kwargs):
        if 'username' not in login_session:
            return redirect('/login')
        return f(*args, **kwargs)
    return x

#Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)

# GConnect
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code, now compatible with Python3
    request.get_data()
    code = request.data.decode('utf-8')

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    # Submit request, parse response - Python3 compatible
    h = httplib2.Http()
    response = h.request(url, 'GET')[1]
    str_response = response.decode('utf-8')
    result = json.loads(str_response)

    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    return output

# User Helper Functions


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

# DISCONNECT - Revoke a current user's token and reset their login_session


@app.route('/gdisconnect')
def gdisconnect():
        # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        # Reset the user's sesson.
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        # response = make_response(json.dumps('Successfully disconnected.'), 200)
        # response.headers['Content-Type'] = 'application/json'
        response = redirect(url_for('showCatalog'))
        flash("You are now logged out.")
        return response
    else:
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response
#Flask routes
#Show 
@app.route('/')
@app.route('/catalog/')
def showAllCategories():
    categories = session.query(Category).order_by(asc(Category.name))
    categoryPlaces =session.query(ItemPlace).all()

    return render_template('categories.html', categories = categories, categoryPlaces = categoryPlaces)

#Show items in a category
@app.route('/catalog/<path:catalog_name>')
def showCategory(catalog_name):
    categories = session.query(Category).order_by(asc(Category.name))
    category = session.query(Category).filter_by(name=catalog_name).one()
    categoryName = category.name
    categoryPlaces = session.query(ItemPlace).filter_by(category=category).all()
    count = session.query(ItemPlace).filter_by(category=category).count()
    creator = getUserInfo(category.user_id)
    if 'username' not in login_session or creator.id != login_session['user_id']:
        return render_template('publiccategory.html', 
                                category=category, 
                                categories=categories,
                                categoryName=categoryName,
                                count=count,
                                categoryPlaces =categoryPlaces)
    else:
        user = getUserInfo(login_session['user_id'])
        return render_template('category.html',
                                categories=categories, 
                                categoryName=categoryName, 
                                categoryPlaces=categoryPlaces,
                                count=count,
                                creator = creator)

#Show a place with its details
@app.route('/catalog/<path:catalog_name>/<path:place_name>')
def showPlace(catalog_name, place_name):
    # Get category item
    place = session.query(ItemPlace).filter_by(name = place_name).first()
    categories = session.query(Category).all()
    creator = getUserInfo(place.user_id)
    if 'username' not in login_session or creator.id != login_session['user_id']:
        return render_template('publicplace.html', 
                               place = place,
                               category = catalog_name,
                               categories=categories,
                               creator=creator)
    else:
        return render_template('place.html', 
                               place = place,
                               category = catalog_name,
                               categories=categories,
                               creator=creator)

# Add new category
@app.route('/catalog/newcategory', methods=['GET','POST'])
@login_required
def newCategory():
    
    if request.method == 'POST':
        newCategory = Category( 
            name=request.form['name'],
            user_id=login_session['user_id'])
        session.add(newCategory)
        flash('New Category %s Successfully created' % newCategory.name)
        session.commit()
        return redirect(url_for('showCategory'))
    else:
        return render_template('newCategory.html')

#Edit a category
@app.route('/catalog/<path:catalog_name>/edit', methods=['GET', 'POST'])
@login_required
def editCategory(catalog_name):
    
    # Get category to edit
    editedCategory = session.query(Category).filter_by(name=catalog_name).one()

    # Get all categories
    categories = session.query(Category).all()

    # Get creator of category
    creator =getUserInfo(editCategory.user_id)

    # Check if user logged is the creator
    if creator.id != login_session['user_id']:
        flash ("You do not have a permission to edit this Category. This belongs to %s" 
            % creator.name)
        return redirect('/login')

    # POST method
    if request.method == 'POST':
        if request.form['name']:
            editCategory.name = request.form['name']
        session.add(editCategory)
        session.commit()
        flash('Category successfully edited.')
        return redirect(url_for('showCategory'))
    else:
        return render_template('editcategory.html',
                                categories=editedCategory,
                                catalog = catalog)

#Delete a category
@app.route('/catalog/<path:catalog_name>/delete', methods=['GET','POST'])
@login_required
def deleteCategory(catalog_name):
    deleteCategory = session.query(Category).filter_by(name=catalog_name).one()
    creator = getUserInfo(deleteCategory.user_id)
    user = getUserInfo(login_session['user_id'])

    #if logged in user is the catalog owner
    if creator.id != login_session['user_id']:
        flash('No permission to deleted this category. This belongs to %s' % creator.name)
        return redirect(url_for('showCategory'))
    if request.method == 'POST':
        session.delete(deleteCategory)
        session.commit()
        flash('Category successfully deleted.')
        return redirect(url_for(showCategory))
    else:
        return render_template('deletecategory.html', category=categoryDelete)

#Add an item
@app.route('/catalog/add', methods=['GET', 'POST'])
@login_required
def addItemPlace():
     
    categories = session.query(Category).all()
    if request.method == 'POST':
        newItemPlace = ItemPlace(
            name=request.form['name'],
            address=request.form['address'],
            description=request.form['description'],
            photo=request.form['photo'],
            category=request.session[Category].filter_by(name=request.form['category']).one(),
            user_id=login_session['user_id'])
        session.add(newItemPlace)
        session.commit()
        flash('Place successfully added.')
        return redirect(url_for(showCategory))
    else:
        return render_template('newitemplace.html', categories=categories)

# Edit an item place in a category
@app.route('/catalog/<path:catalog_name>/<path:place_name>/edit', methods=['GET', 'POST'])
@login_required
def editPlace(catalog_name, place_name):
    
     # Get category to edit
    editedPlace = session.query(ItemPlace).filter_by(name=place_name).one()

    # Get all categories
    categories = session.query(Category).all()

    # Get creator of category
    creator =getUserInfo(editCategory.user_id)

    # Check if user logged is the creator
    if creator.id != login_session['user_id']:
        flash ("You do not have a permission to edit this Category. This belongs to %s" 
            % creator.name)
        return redirect('/login')

    # POST method
    if request.method == 'POST':
        if request.form['name']:
            editedPlace.name = request.form['name']
        if request.form['description']:
            editedPlace.description = request.form['description']
        if request.form['photo']:
            editedPlace.photo = request.form['photo']
        if request.form['category']:
            category = session.query(Category).filter_by(name=request.form['category']).one()
            editedPlace.category = request.form['category']
        session.add(editedPlace)
        session.commit()
        flash('Item successfully edited.')
        return redirect(url_for('showCategory', catalog_name=editedPlace.category.name))
    else:
        return render_template('edititemplace.html',
                                editedItem=editedItem,
                                categories = categories)

#Delete item place
@app.route('/catalog/<path:catalog_name>/<path:place_name>/delete', methods=['GET','POST'])
@login_required
def deleteItemPlace(catalog_name, place_name):

     category = session.query(Category).filter_by(name=catalog_name).one()
     placetoDelete = session.query(ItemPlace).filter_by(name=place_name).one()
     categories = session.query(Category).all()
     
     # Check if user logged is the creator
     if creator.id != login_session['user_id']:
        flash ("You do not have a permission to delete this item. This belongs to %s" 
            % creator.name)
        return redirect('/login')
     if request.method == 'POST':
        session.delete(placetoDelete)
        session.commit()
        flash('Item successfully deleted!')
        return redirect(url_for('showCategory', catalog_name=cataeory.name))
     else:
        return render_template('deleteplace.html', place_name=placetoDelete)

# JSON APIs 



if __name__ == '__main__':
    app.debug = True
    app.secret_key = "altered_secret_key"
    app.run(host = '0.0.0.0', port = 5020)