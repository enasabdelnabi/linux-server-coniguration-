from flask import Flask,render_template, request, redirect, url_for,flash
,jsonify
# import CRUD Operations 
from catalog-database import Base, Category, item,User
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker,

# IMPORTS FOR G-connect
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "catalog App"

# Create session and connect to DB ##
engine = create_engine('sqlite:///catalog-database.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


## fuction which show categories && items
@app.route('/')
@app.route('/category/<int:category_id/>items')
def showcategory( category_id):
category=session.quary(Category).filter_by(id=category_id).one()
items=session.quary(item).filter_by(category_id=category_id)
return render_template (category.html,category=category,items=item)




@app.route('/del')
def deleteCat():
    session = DBSession()
    items = session.query(Category).all()
    for item in items:
        if 'test' in item.name:
            session.delete(item)
            session.commit()
    return redirect('/categories')


# function which show item        

@app.route('/categories/<int:category_id>/items/<int:item_id>')
def showItems(category_id, item_id):
    item = session.query(Item).filter_by(
        category_id=category_id, id=item_id).one()
    return render_template('showitem.html', item=item)
      

    # functio to add new item 
@app.route('/item/<int:item_id>/add/', methods=['GET', 'POST'])
def Addnewitem( category_id ):
	if not login_session['username']:
        flash('You have to login first.')
        return redirect('/')
if request.method=='POST':
	newItem=Item(name=request.form['name'],
		description = request.form['description'],
        category_id = request.form['category_id']
    session.add(newItem)
    session.commit()
    flash("new item created!")
    return redirect (url_for ('showcategory',category_id=category_id)
  else:
     return render_template('Additem.html',category_id=category_id
     	)

     

@app.route('/category/<int:category_id>/<int:item_id>/delete',
           methods=['GET', 'POST'])
def deleteItem(category_id, item_id):
	if 'username' not in login_session:
        flash('You have to login first.')
        return redirect('/')
    deleteitem = session.query(item).filter_by(id=item_id).one()
    if request.method == 'POST':
        session.delete(deleteitem)
        session.commit()
        return redirect(url_for('category', category_id=category_id))
    else:
        return render_template('deleteitem.html', item=deleteitem)




@app.route('/category/<int:category_id>/<int:item_id>/edit',
           methods=['GET', 'POST'])
def EditItem():
	if 'username' not in login_session:
        flash('You have to login first.')
        return redirect('/')
 edititem=session.quary(item).filter_by(id=item.id).one()
 if request.method=='POST':
     if request.form['name']:
   	     edititem.name=request.form['name']
   	 if request.form['description']:
   	     edititem.name=request.form['description']
   	 if request.form['category_id']:
   	     edititem.name=request.form['category_id']
     session.add(edititem)
     session.commit()
     return redirect(url_for('category_id', 
	restaurant_id=category_id))
else
return render_template(edititem.html,category_id=category_id,
	                     item_id=item_id)



#jsoin API
@app.route('/category'/<int:category_id>/menu/json)
def categoryjson(category_id):
	category=session.quary(category).filter_by(id=category_id)
    .one()
    item=session.quary(item).filter_by(category_id
    	 =category_id).all()
    return  jsonify(item=[item.serialize for item in items])


@app.route('/json/category/<int:category_id>/items/<int:item_id>')
def Itemjson(category_id, item_id):
    item = session.query(item).filter_by(id=item_id).first()
    return jsonify(item=[item.serialize])


# Create anti-forgery state token

@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase +
                    string.digits) for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)



 CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "catalog App"

# Googele+ SIGN
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

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

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output

# DISCONNECT - Revoke a current user's token and reset their login_session


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response
  #facebook 


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token


    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]


    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
        Due to the formatting for the result from the server token exchange we have to
        split the token first on commas and select the first index which gives us the key : value
        for the server access token then we split it on colons to pull out the actual token value
        and replace the remaining quotes with nothing so that it can be used directly in the graph
        api calls
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
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

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"

 # User Heper fuctions 
def createUser(login_session):
    newUser = User(name=login_session['username'],
                   email=login_session['email'])
    session = DBSession()
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).first()
    return user.id


def getUserInfo(user_id):
    session = DBSession()
    user = session.query(User).filter_by(id=user_id).first()
    return user



def getUserID(email):
    session = DBSession()
    try:
        user = session.query(User).filter_by(email=email).first()
        if user:
            return user.id
        else:
            return None
    except 'error':
        return None



if __name__ == '__main__':
	app.secret_key='super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)