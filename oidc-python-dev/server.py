import json
from functools import wraps
import pandas as pd
from os import environ as env
from werkzeug.exceptions import HTTPException

from dotenv import load_dotenv, find_dotenv
from flask import Flask, request, flash
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import session
from flask import url_for
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode

import constants
import socket
import requests

import ssl
context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
context.verify_mode = ssl.CERT_NONE
context.load_cert_chain("certificate.crt", "privateKey.key")

import pymysql
hostname = 'localhost'
username = 'root'
password = ''
database = 'gluu_server'


#ssl._create_default_https_context = ssl._create_unverified_context
#from OpenSSL import SSL
#context = SSL.Context(SSL.TLSv1_2_METHOD)
#context.use_privatekey_file('privateKey.key')
#context.use_certificate_file('certificate.crt')


#ENV_FILE = find_dotenv()
#if ENV_FILE:
#    load_dotenv(ENV_FILE)

AUTH0_CLIENT_ID = "1ec69aaa-95fd-4644-b4a8-a7b243b64a6e"
AUTH0_CLIENT_SECRET = "iTCBqTfF8iNa3iqhDoXyrRMn"
AUTH0_DOMAIN = "iam4.centroxy.com"

AUTH0_CALLBACK_URL = "http://client.example.com:3000/callback"
# AUTH0_CLIENT_ID = "@!476B.F204.1952.447C!0001!F388.20DD!0008!B6EB.F5AE.4CA0.279C"
# AUTH0_CLIENT_SECRET = "centroxy1234"
# AUTH0_DOMAIN = "iam.centroxy.com"
AUTH0_BASE_URL = 'https://' + AUTH0_DOMAIN
AUTH0_AUDIENCE = ""
if AUTH0_AUDIENCE == '':
    AUTH0_AUDIENCE = AUTH0_BASE_URL + '/oxauth/restv1/userinfo'

app = Flask(__name__, static_url_path='/public', static_folder='./public')
app.secret_key = constants.SECRET_KEY
app.debug = True
#app.config['SERVER_NAME'] = 'client.example.com'


@app.errorhandler(Exception)
def handle_auth_error(ex):
    response = jsonify(message=str(ex))
    response.status_code = (ex.code if isinstance(ex, HTTPException) else 500)
    return response


oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=AUTH0_CLIENT_ID,
    client_secret=AUTH0_CLIENT_SECRET,
    api_base_url=AUTH0_BASE_URL,
    access_token_url=AUTH0_BASE_URL + '/oxauth/restv1/token',
    authorize_url=AUTH0_BASE_URL + '/oxauth/restv1/authorize',
    client_kwargs={
        'scope': 'openid profile email permission',
    },
)


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if constants.PROFILE_KEY not in session:
            return redirect('/login')
        return f(*args, **kwargs)

    return decorated

def only_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if  'role' in session:
            if session['role'] == 'admin':
                return f(*args, **kwargs)
        flash("Access Denied")
        return redirect(url_for('dashboard'))
    return decorated
      


# Controllers API
@app.route('/')
def home():
    return render_template('home.html')


@app.route('/callback')
def callback_handling():
    print(0)
    auth0.authorize_access_token(verify=False)
    print(1)
    print(auth0)
    print(auth0.get)
    resp = auth0.get('oxauth/restv1/userinfo',verify=False)
    print(2)
    userinfo = resp.json()
    

    session[constants.JWT_PAYLOAD] = userinfo
    session[constants.PROFILE_KEY] = {
        'user_id': userinfo['sub'],
        'name': userinfo['name'],
        'family_name' : userinfo['family_name'],
        'givenName' : userinfo['given_name'],
        'email' : userinfo['email'],
        'role' : userinfo['role']
    }
    session['role'] = userinfo['role']
    return redirect('/dash')


# @app.route('/callback')
# def callback_handling():
#     auth0.authorize_access_token()
#     resp = auth0.get('userinfo')
#     userinfo = resp.json()
 
#     session[constants.JWT_PAYLOAD] = userinfo
#     session[constants.PROFILE_KEY] = {
#         'user_id': userinfo['sub'],
#         'name': userinfo['name'],
#         'picture': userinfo['picture'],
#         'family_name' : userinfo['family_name'],
#         'givenName' : userinfo['given_name']
#     }
#     return redirect('/info')


@app.route('/login')
def login():
    return auth0.authorize_redirect(redirect_uri=AUTH0_CALLBACK_URL, audience=AUTH0_AUDIENCE)


@app.route('/logout')
def logout():
    session.clear()
    params = {'post_logout_redirect_uri':"https://client.example.com:3000", 'client_id': AUTH0_CLIENT_ID}
    print(auth0.api_base_url)
    return redirect(auth0.api_base_url + '/oxauth/restv1/end_session?' + urlencode(params))


@app.route('/dash')
@requires_auth
def dashboard():
    return render_template('dash.html',
                           userinfo=session[constants.PROFILE_KEY],
                           userinfo_pretty=json.dumps(session[constants.JWT_PAYLOAD], indent=4))

@app.route('/profile')
@requires_auth
@only_admin
def profile():
    return render_template('user.html')


@app.route('/', methods = ['POST','GET'])
# Simple routine to run a query on a database and print the results:
def doQuery() :
    if request.method == "POST":
        myConnection = pymysql.connect( host=hostname, user=username, passwd=password, db=database )
        # doQuery( myConnection )
        cur = myConnection.cursor()
        role = request.form['role']
        name = request.form['name']
        givenName = request.form['firstname']
        familyName = request.form['lastname']
        email = request.form['email']
        sub = request.form['Sub']
        sql = "INSERT INTO `user_details`(`role`,`name`, `given_name`, `family_name`, `email`, `sub`) VALUES ('{}','{}','{}','{}','{}','{}')".format(role,name,givenName,familyName,email,sub)
        # val = (name, givenName, familyname, email, user_id)
        cur.execute(sql)
        myConnection.commit()

        myConnection.close()
        return 'Success'
    return render_template('dash.html')




if __name__ == "__main__":
    app.jinja_env.auto_reload = True
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    #context = ('minica.pem', 'minica-key.pem')
    app.run(debug=True, host='client.example.com',port=3000)
