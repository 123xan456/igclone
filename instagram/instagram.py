import os
import re
from flask import Flask, render_template, request, redirect, session, url_for, escape, flash, abort, Blueprint
from flask_login import LoginManager,current_user, login_user, UserMixin, confirm_login, login_manager, login_required,logout_user
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
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
login = LoginManager(app)
Migrate(app,db)   
login_manager = LoginManager(app)
login_manager.login_view = 'attempt_sign_in'
app.secret_key=os.urandom(32)


@login_manager.user_loader
def load_user(user_id):
    return None

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
     password = db.Column(db.String(255),unique = True ) 
     
     @validates('username')
     def validate_username(self, key, username):
          if not username:
               raise AssertionError('Username field is empty')
          
          if User.query.filter(User.username == username).first():
               raise AssertionError('Username is taken')

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
          
     
@app.route("/", methods=["GET","POST"])
def attempt_sign_up():
     pw_hash = generate_password_hash(request.form['password'])
     user = User(request.form['username'], pw_hash)
     db.session.add(user)
     db.session.commit()
     login_user(user, remember=False)
     confirm_login()
     return redirect(url_for('profile'))

@app.route("/signin",methods=["GET","POST"])
def signin():
     return render_template('signin.html')

@app.route("/signin",methods=['POST','GET'])
def attempt_sign_in():   
     user = User.query.filter_by(username = request.form['user_username']).first()
     if user and check_password_hash(user.password,request.form['user_password']):
          login_user(user, remember=False)
          confirm_login()
          return render_template('userprofile.html')
     else:
          return render_template('signin.html')

@app.route("/profile", methods=['GET','POST'])
@login_required
def profile():
     return render_template('userprofile.html')

# @app.route("/hi", methods=['GET','POST'])
# @login_required
# def edit_info():
#      pw_hash = generate_password_hash(request.form['edit_password'])
#      user = User(request.form['username'], pw_hash)
#      current_user.
#      db.session.commit()
#      return render_template('userprofile.html')
    
@app.route("/logout")
def logout():
     logout_user()
     return redirect(url_for('signup'))

@app.route("/failedsignup")
def failedsignup():
     return render_template('signupfail.html')

if __name__ == '__main__': 
    app.run(debug=True)

