# standard library
from flask import Flask, session, abort, redirect, request, render_template, session, send_file
from google_auth_oauthlib.flow import Flow
import os
from datetime import timedelta, datetime
import requests
import pathlib
import flask
import pandas as pd
# from flask_mysqldb import MySQL
# flask_mysqldb is used for mysql connectivity and doing queries using mysql workbench
from flask import jsonify
# jsonify library used for converting result comes from mysql queries into json format
import json

# third party library
from pip._vendor import cachecontrol
from google.oauth2 import id_token
import google.auth.transport.requests
import requests_oauthlib
from requests_oauthlib.compliance_fixes import facebook_compliance_fix

# local files
global data
data = pd.read_csv("data_csv.csv")
detail = pd.read_csv("details.csv")

# creating flask app objects
app = Flask(__name__)

# generating random secret key
app.secret_key = "secret key"

# --------------------------using database as a mysql workbench ----------------------------------

# this is used when we have multiple environment to run the code
# calling config file as per requirement
# if app.config["ENV"] == "production":
#     app.config.from_object("config.ProductionConfig")
# elif app.config["ENV"] == "development":
#     app.config.from_object("config.DevelopmentConfig")
# else:
#     app.config.from_object("config.TestingConfig")


# reading config.json file which contain database connectivity details
# path = os.getcwd()+"\config.json"
# conf = open("config.json")
# conf_data = conf.read()

# json parsing
# conf_data = json.loads(conf_data)


# initializing mysql object
# mysql = MySQL()
# app.config['MYSQL_HOST'] = conf_data["MYSQL_HOST"]
# app.config['MYSQL_USER'] = conf_data["MYSQL_USER"]
# app.config['MYSQL_PASSWORD'] = conf_data["MYSQL_PASSWORD"]
# app.config['MYSQL_DB'] = conf_data["MYSQL_DB"]
# mysql.init_app(app)


# @app.route('/')
# def home():
#     # print(app.config["MYSQL_USER"])
#     return render_template("home.html")

# @app.route("/signin")
# def signin():
#     return render_template("signin.html")

# @app.route("/login")
# def login():
#     return render_template("login.html")

# @app.route("/signin_success", methods=['POST'])
# def success():
#     if request.method=='POST':
#         cur = mysql.connection.cursor()
#         email = request.form['email']
#         password = request.form['password']
#         # cur.execute("select email from login where email LIKE %s",[email])
#         try:
#             cur.execute("INSERT INTO LOGIN VALUES(%s,%s)",(email,password))
#             mysql.connection.commit()
#             cur.close()
#             # result = jsonify(data)
#             signin = True
#             return render_template("main.html", signin=signin,email=email)
#         except:
#             signin=False
#             return render_template("signin.html",signin=signin)

# @app.route('/login_success',methods=['POST'])
# def login_success():
#     if request.method=='POST':
#         cur = mysql.connection.cursor()
#         email = request.form['email']
#         password = request.form['password']
#         cur.execute("SELECT password,email FROM login WHERE email LIKE %s",[email])
#         data = cur.fetchall()

#         if not data:
#             fail = "email_wrong"
#             return render_template('login.html', fail=fail)
#         else:
#             # return str(data[0][0])
#             if data[0][0] == password:
#                 login=True
#                 return render_template("main.html",login=login,email=email)
#             else:
#                 fail = "password_wrong"
#                 return render_template("login.html", fail=fail)
                

# -------------------------------------using database as a csv file --------------------------------------

# return all unique user name
def get_user():
    a = set()
    data = pd.read_csv("data_csv.csv")
    for i in data['username']:
        a.add(i)
    return a
    
# return password for login authentication
def get_pass(user):
    data = pd.read_csv("data_csv.csv")
    pwd = data["password"].loc[data["username"] == user].iloc[0]
    print("password from get_pass",pwd)
    return pwd

# home page for an app
@app.route("/")
def home():
    return render_template("home.html")

# signin page of the app
@app.route("/signin")
def signin():
    return render_template("signin.html")

# check signin successfull or not, if successfull then insert the record into csv file
@app.route("/signin_success", methods=["POST"])
def signin_success():
    data = pd.read_csv("data_csv.csv")
    if request.method == "POST":
        user = request.form["user"]
        password = request.form["pass"]
        email = request.form["email"]
        get_user_data = get_user()
        if user in get_user_data:
            user = True
            return render_template("/signin.html", user = user)
        else:
            data1 =data.append({"username":user, "password":password,"email":email }, ignore_index=True)
            data1.to_csv("data_csv.csv", index=False)
            user=user
            return render_template("/main.html",user=user)
        

# login page for an app
@app.route("/login")
def login():
    return render_template("login.html")

global dictionary 
dictionary = {}
# checking login authentication if login successfull then redirect to main page else throws error
@app.route("/login_success", methods=["POST"])
def login_success():
    if request.method=="POST":
        user = request.form["user"]
        pwd  = request.form["pass"]
        print(user, pwd)
        
        user_data = get_user()
        if user in user_data:
            password = get_pass(user)
        # print("password from login",str(password))
        # print("password from user", str(pwd))
            if pwd == password:
                dictionary["username"] = user
                dictionary["password"] = pwd
                #  {"username":user, "password":pwd}
                return render_template("details.html", user=user)
            else:
                return render_template("login.html", login=True)
        else:
            return render_template("login.html",user=True)

@app.route("/details_success",methods=["POST"])
def detail_success():
    if request.method == "POST":
        data = pd.read_csv("data_csv.csv")
        detail = pd.read_csv("details.csv")
        print("dictionary=",dictionary["username"],dictionary["password"])
        json_data = request.form
        
        json_data = json_data.to_dict()
        
        if not json_data["num2"]:
            del json_data["num2"]
            
        json_data["username"] = dictionary["username"]
        json_data["email"] = data["email"].loc[data["username"] == json_data["username"]].iloc[0]


        row = detail.append(json_data, ignore_index=True)
        row.to_csv("details.csv",index = False)
        
        with open(dictionary["username"]+'_details.json',"w") as file_:
            json.dump(json_data, file_, indent=4)

        if request.form["action"] == "submit":
            return render_template("main.html",user = json_data["username"], save = True)
        else:
            return send_file(dictionary["username"]+'_details.json',as_attachment=True)



# ------------------------------ google social login------------------------------------------

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
google_client_id = "600548504659-9uapv9g0cfhjsht48nh70oufji0e5q10.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent,"client_secret.json")


# add client secret file into google flow
flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/userinfo.email",
    "openid"],
    redirect_uri="https://flask-social-app-csv.herokuapp.com/callback"
)

# create decorator
def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401) # authentication required
        else:
            return function()
    return wrapper


# google login page
@app.route("/google_login")
def google_login():
    authorization_url, state = flow.authorization_url()
    session['state']=state
    return redirect(authorization_url)

@app.route("/callback")
def authorize():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args['state']:
        abort(500) # state does not match

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token = credentials._id_token,
        request=token_request,
        audience=google_client_id
    )

    
    session['google_id'] = id_info.get("sub")        
    session["name"] = id_info.get("name")
    return redirect("/protected_area")

# trying to implement google session timeout for google login user

    # if 'google_id' in session:
    #     app.permanent_session_lifetime = timedelta(seconds=5)
        # return redirect("/")
    #     start_time = datetime.datetime.now()
    #     end_time = start_time + datetime.timedelta(0,10)
    #     if start_time > end_time :
    #         print("time matched")
    #         session.pop("google_id",None)
        # print("session_id=",session['google_id'])
        # print("current_time=",start_time)
        # print("end _time =",end_time)

@app.route("/logout")
def logout():
    session.pop("google_id",None)
    return redirect("/")

# @app.route("/")
# def index():
#     return "hello world <a href='/google_login'><button>Click here to Google Login</button></a>"

@app.route("/protected_area")
@login_is_required 
def pretected_area():
    
    # app.permanent_session_lifetime = timedelta(seconds=5)
    # session.pop("google_id",None)
    return "Protected <a href='/logout'><button>Logout</button></a>"



# --------------------------------------facebook social login page-----------------------------------------


# Your ngrok url, obtained after running "ngrok http 5000"
# URL = "https://679e4c83.ngrok.io"
# URL = "http://localhost:5000"
URL = "https://flask-social-app-csv.herokuapp.com"

FB_CLIENT_ID = "259762062401630"
FB_CLIENT_SECRET = "6b8a4fc54a76d6005fc742b4ace0ba5e"

fb_authorization_base_url = "https://www.facebook.com/dialog/oauth"
FB_TOKEN_URL = "https://graph.facebook.com/oauth/access_token"

FB_SCOPE = ["email"]

# This allows us to use a plain HTTP callback
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

# facebook Login route page    
# @app.route('/facebook_login')
# def facebook_login():
#     return redirect(url_for("/fb_login"))
@app.route("/fb-login")
def fb_login():
    facebook = requests_oauthlib.OAuth2Session(
        FB_CLIENT_ID, redirect_uri=URL + "/fb-callback", scope=FB_SCOPE
    )
    authorization_url, _ = facebook.authorization_url(fb_authorization_base_url)

    return flask.redirect(authorization_url)

@app.route("/fb-callback")
def callback():
    facebook = requests_oauthlib.OAuth2Session(
        FB_CLIENT_ID, scope=FB_SCOPE, redirect_uri=URL + "/fb-callback"
    )

    # we need to apply a fix for Facebook here
    facebook = facebook_compliance_fix(facebook)

    facebook.fetch_token(
        FB_TOKEN_URL,
        client_secret=FB_CLIENT_SECRET,
        authorization_response=flask.request.url,
    )

    # Fetch a protected resource, i.e. user profile, via Graph API

    facebook_user_data = facebook.get(
        "https://graph.facebook.com/me?fields=id,name,email,picture{url}"
    ).json()

    # Fb user data 
    email = facebook_user_data["email"]
    name = facebook_user_data["name"]
    picture_url = facebook_user_data.get("picture", {}).get("data", {}).get("url")
  

    #login details
    return f"""
        User information: <br>
        Name: {name} <br>
        Email: {email} <br>
        Avatar <img src="{picture_url}"> <br>
        <a href="/">Home</a>
        """

# running flask app
if __name__ == "__main__":
    app.run(debug=True)