import os
import re
from flask import Flask, render_template, request, redirect, session, url_for, escape, flash, abort, Blueprint
from flask_wtf import FlaskForm
from flask_login import LoginManager,current_user, login_user, UserMixin
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask.ext.bcrypt import Bcrypt
from wtforms import StringField, PasswordField, BooleanField, SubmitField, validators,Form
from wtforms.validators import DataRequired
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import validates, relationship
from sqlalchemy import Integer, ForeignKey, String, Column
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.hybrid import hybrid_property, hybrid_method

app = Flask(__name__)
SECRET_KEY = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = "postgres://localhost:5432/instagram"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db=SQLAlchemy(app)
bcrypt= Bcrypt(app)
login = LoginManager(app)
Migrate(app,db)    
app.secret_key=os.urandom(32)

@app.route("/")
def signup():
     return render_template('signup.html')

class User(db.Model, UserMixin):
     __tablename__= 'users'
     def __init__(self, username, password):
          self.username = username
          self.password = password
          
     id = db.Column(db.Integer,primary_key = True)
     username = db.Column(db.String,unique = True ) 
     password = db.Column(db.String(16),unique = True ) 
     
     @validates('username')
     def validate_username(self, key, username):
          if not username:
               raise AssertionError('Username field is empty')
          
          if User.query.filter(User.username == username).first():
               raise AssertionError('Username is taken')
               # return """<body><script>alert('That username is taken')</script></body>"""

          if len(username) < 5 or len(username) > 16:
               raise AssertionError('Username must be between 5 and 16 characters')
          
          return username
          
     def validate_password(self, password):
          if not password:
               raise AssertionError('Password field is empty')
          
          if not re.match('\d.*[A-Z]|[A-Z].*\d', password):
               raise AssertionError('Password must have 1 number and 1 capital letter ')
          
          if len(password) < 8 or len(password) > 20:
               raise AssertionError('Username must be between 8 and 20 charatcers')
         
          self.password = generate_password_hash(password)
          

     def check_password(self, password):
          return check_password_hash(self.password, password)

     
@app.route("/", methods=["GET","POST"])
def attempt_sign_up():
     user = User(request.form['username'], request.form['password'])
     db.session.add(user)
     db.session.commit()
     return render_template('userprofile.html')


@app.route("/<username>",methods=['GET','POST'])
def userprofile():
     return render_template('userprofile.html')

@app.route("/signin")
def signin():
     return render_template('signin.html')

@app.route("/signin",methods=['POST','GET'])
def attempt_sign_in():   
     user = User.query.filter_by(request.form['user_username'], request.form['user_password'])
     if user and 
     
@app.route("/failedsignup")
def failedsignup():
     return render_template('signupfail.html')

@app.errorhandler(500)
def handle_internal_error(e):
    return """<body><script>alert('That didn\'t work please try again')</script></body>""", 500

@app.errorhandler(400)
def handle_bad_request(e):
    return """<body><script>alert('The password and username don\'t match')</script></body>""", 400

if __name__ == '__main__': 
    app.run(debug=True)

