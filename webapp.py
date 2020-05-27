from flask import Flask, redirect, url_for, session, request, jsonify, Markup
from flask_oauthlib.client import OAuth
from flask import render_template
from profanityfilter import ProfanityFilter

import pprint
import os
import pymongo


# This code originally from https://github.com/lepture/flask-oauthlib/blob/master/example/github.py
# Edited by P. Conrad for SPIS 2016 to add getting Client Id and Secret from
# environment variables, so that this will work on Heroku.
# Edited by S. Adams for Designing Software for the Web to add comments and remove flash messaging

app = Flask(__name__)

app.debug = True #Change this to False for production

connection_string = os.environ["MONGO_CONNECTION_STRING"]
db_name = os.environ["MONGO_DBNAME"]
    
client = pymongo.MongoClient(connection_string)
db = client[db_name]

collection = db['Forum-PostsCol'] 

app.secret_key = os.environ['SECRET_KEY'] 
oauth = OAuth(app)


#Set up Github as the OAuth provider
github = oauth.remote_app(
    'github',
    consumer_key=os.environ['GITHUB_CLIENT_ID'], 
    consumer_secret=os.environ['GITHUB_CLIENT_SECRET'],
    request_token_params={'scope': 'user:email'}, #request read-only access to the user's email.  For a list of possible scopes, see developer.github.com/apps/building-oauth-apps/scopes-for-oauth-apps
    base_url='https://api.github.com/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://github.com/login/oauth/access_token',  
    authorize_url='https://github.com/login/oauth/authorize' #URL for github's OAuth login
)


@app.context_processor
def inject_logged_in():
    return {"logged_in":('github_token' in session)}

user_valid = []
user_not_valid = []

@app.route('/')
def home():
    super_secret_data = ''
    super_secret_data2 = ''
    global user_valid
    global user_not_valid
    
    post_info = ''
    for a in collection.find():
        print('hi')
        post_info += Markup('<div class=\"eachPost\">'+'<h3>' + a['fname'] + ' ' + a['lname'] + '</h3><br>' + '<p class=\"paragraphPost\">' + a['message'] + '</p>' + '</div>')
    
    if 'user_data' in session and session['user_data']['public_repos'] > 10:
        user_check = True#pprint.pformat(session['user_data'])#format the user data nicely
        user_valid.append(session['user_data']['login'])
        if session['user_data']['login'] == 'LucaCC':
            for x in user_valid:
                try:
                    super_secret_data.index(x) #checking for error
                except Exception as inst:
                    super_secret_data += x + ' '
            for y in user_not_valid:
                try:
                    super_secret_data2.index(y)
                except Exception as inst:
                    super_secret_data2 += y + ' '
            admin_check = 'Admin Privileges'
        else:
            super_secret_data = ''
            super_secret_data2 = ''
            admin_check = ''
    else:
        user_check = False
        super_secret_data = ''
        super_secret_data2 = ''
        admin_check = ''
        if 'user_data' in session:
            user_not_valid.append(session['user_data']['login'])
    return render_template('home.html',post=post_info, valid_user=user_check, admin_secret_data=super_secret_data, admin_secret_data2=super_secret_data2, Admin=admin_check)

@app.route('/login')
def login():   
    return github.authorize(callback=url_for('authorized', _external=True, _scheme='https'))

@app.route('/logout')
def logout():
    session.clear()
    return render_template('message.html', message='You were logged out')
@app.route('/postcheck', methods=['POST'])
def post_check():
    pf = ProfanityFilter()
    if 'user_data' in session and len(request.form['message'].split(' '))/session['user_data']['public_repos'] <= 5:
        doc = {'fname': request.form['fname'],'lname': request.form['lname'],'message': pf.censor(request.form['message'])}
        collection.insert_one(doc)
        return render_template('message.html', message='You successfully posted')
    return render_template('message.html', message='You failed to post due to too many words for your repository count')

@app.route('/login/authorized')#the route should match the callback URL registered with the OAuth provider
def authorized():
    resp = github.authorized_response()
    if resp is None:
        session.clear()
        message = 'Access denied: reason=' + request.args['error'] + ' error=' + request.args['error_description'] + ' full=' + pprint.pformat(request.args)      
    else:
        try:
            #save user data and set log in message
            session['github_token'] = (resp['access_token'], '')
            session['user_data'] = github.get('user').data
            message = 'You were successfully logged in as ' + session['user_data']['login']
        except Exception as inst:
            #clear the session and give error message
            session.clear()
            print(inst)
            message = 'Unable to login. Please Try again'
    return render_template('message.html', message=message)



@github.tokengetter
def get_github_oauth_token():
    return session['github_token']


if __name__ == '__main__':
    app.run()
