from flask import Flask, render_template, url_for, request, redirect, jsonify, flash
from flask import session as login_session
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

#Create anti-forgery state token
@app.route('/login')
def showLogin():
	state = ''.join(random.choice(string.ascii_uppercase + string.digits)
	for x in xrange(32))
	login_session['state'] = state
	return render_template('login.html', STATE=state)

@app.route('/gconnect', methods=['POST'])
def gconnect():
	#Validate state token
	if request.args.get('state') != login_session['state']:
		response = make_response(json.dumps('Invalid state parameter.'), 401)
		response.headers['Content-Type'] = 'application/json'
		return response
	# Obtain authorization code
	code = request.data()
	code = request.data.decode('utf-8')

	try:
		#Upgrade the authorization code into credentials object
		oauth_flow = flow_from_clientsecrets('clients_secrets.json', scope='')
		oauth_flow.redirect_uri = 'postmessage'
		credentials = oauth_flow.step2_excahnge(code)
	except FlowExchangeError:
		response = make_response(
			json.dumps('Failed to upgrade the authorization code.'), 401)
		response.header['Content-Type'] = 'application/json'
		return response

 # Check that the access token is valid.
	access_token = credentials.access_token
	url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
		   % access_token)
	h = httplib2.Http()
	result = json.loads(h.request(url, 'GET')[1])
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
		print "Token's client ID does not match app's."
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
	login_session['access_token'] = credentials.access_token
	login_session['gplus_id'] = gplus_id

	# Get user info
	userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
	params = {'access_token': credentials.access_token, 'alt': 'json'}
	answer = requests.get(userinfo_url, params=params)

	data = answer.json()

	login_session['username'] = data['name']
	login_session['picture'] = data['picture']
	login_session['email'] = data['email']

	# Check if user exists
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
		response = make_response(json.dumps('Successfully disconnected.'), 200)
		response.headers['Content-Type'] = 'application/json'
		return response
	else:
		response = make_response(json.dumps('Failed to revoke token for given user.', 400))
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
								categoryPlaces=categoryPlaces)
	else:
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
	place = session.query(ItemPlace).filter_by(name = place_name).one()
	category = session.query(Category).filter_by(name=catalog_name).one()
	categories = session.query(Category).all()
	creator = getUserInfo(place.user_id)
	if 'username' not in login_session or creator.id != login_session['user_id']:
		return render_template('publicplace.html', 
							   place = place,
							   category = category,
							   categories=categories,
							   creator=creator)
	else:
		return render_template('place.html', 
							   place = place,
							   category = catalog_name,
							   categories=categories,
							   creator=creator)

#

if __name__ == '__main__':
	app.debug = True
	app.run(host = '0.0.0.0', port = 5030)