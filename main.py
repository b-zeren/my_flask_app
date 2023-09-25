from flask import Flask, flash, render_template,redirect, url_for, request
from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from flask_mail import Mail, Message

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean

from datetime import datetime, date
import logging

from os import urandom
from hashlib import pbkdf2_hmac
import hmac
from socket import gethostname, gethostbyname
from random import randint
import re
from itsdangerous import URLSafeSerializer


### CONFIG VARIABLES ###

#  will be used to make sure passwords contain only letters and numbers and has at least 8 chars
pass_pattern = re.compile(r"[A-Za-z0-9]{8,}")

app = Flask(__name__)

# database config
# postgresql://[YOUR_USERNAME]:[YOUR_PASSWORD]@[YOUR_HOST_NAME]:[YOUR_PORT]/[DATABASE_NAME]
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://USER_NAME:PASSWORD@localhost:5432/DB_NAME"
app.secret_key = 'super secret key'
db = SQLAlchemy(app)

# flask-login initialization
login_manager = LoginManager(app)
login_manager.init_app(app)

# which file to store the logs
logging.basicConfig(filename = 'records.log')


# mail server configuration, check flask-mail module docs for more info
sender_mail = 'user@gmail.com'
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = sender_mail
app.config['MAIL_PASSWORD'] = 'password' 
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

# mail instance initialized
mail = Mail(app)

# serializer to securely sending password reset token
password_protector = URLSafeSerializer('smtverysecret')



### UTIL FUNCTIONS ###

# Encode new password with sha256, return hashed password and random salt to store in database
def hash_new_password(password):
    salt = urandom(32)
    pw_hash = pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    pw_hash = pw_hash.hex()
    salt = salt.hex() 
    return salt, pw_hash

# Takes salt and pw_hash from database, password from user input, compare pw_hash and password to check correctness
def is_correct_password(salt, pw_hash, password):
    salt = bytes.fromhex(salt)
    pw_hash = bytes.fromhex(pw_hash)
    return hmac.compare_digest(
        pw_hash,
        pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    )

# Log various activities by ip and time, also update related fields on the database
def add_user_activity(user):
    app.logger.info(f'{user.username} activity on {user.ip_address} on {user.lastactivity}')
    user.ip_address = gethostbyname(gethostname())
    user.lastactivity = datetime.now()
    db.session.commit()

# Log login for user, change related fields on the database
def log_login(user):
    app.logger.info(f'{user.username} logged in on {user.ip_address} on {user.lastactivity}')
    user.ip_address = gethostbyname(gethostname())
    user.lastactivity = datetime.now()
    user.logintime = datetime.now()
    user.is_loggedout = False
    db.session.commit()


# Log logout for user, change related fields on the database
def log_logout(user):
    app.logger.info(f'{user.username} logged out on {user.ip_address} on {user.lastactivity}')
    user.ip_address = gethostbyname(gethostname())
    user.lastactivity = datetime.now()
    user.is_loggedout = True
    db.session.commit()

### USER CLASS DEFINITON ###

class User(db.Model):
    __tablename__ = 'users'

    # General info
    id = Column(Integer(), primary_key=True)
    username = Column(String(20))
    firstname = Column(String(20))
    middlename = Column(String(20))
    lastname = Column(String(20))
    birthdate = Column(DateTime(), default=datetime.now)
    email = Column(String(40))

    # Hashed password and salt
    password = Column(String(64))
    salt = Column(String(64))

    # For log purposes
    ip_address = Column(String(20))
    logintime = Column(DateTime(), default=datetime.now)
    lastactivity = Column(DateTime(),default=datetime.now)
    is_loggedout = Column(Boolean)

    # To prevent brute force attacks for guessing the password
    attempt_count = Column(Integer())

    def __init__(self,id, username, password,firstname, middlename, lastname, birthdate,email):
        self.username = username
        tp_salt, tp_passw = hash_new_password(password)
        self.salt = tp_salt
        self.password = tp_passw
        self.email = email
        self.firstname = firstname
        self.middlename = middlename
        self.lastname = lastname
        if birthdate is None or birthdate=='':
            self.birthdate = datetime.now().strftime("%Y-%m-%d")
        else:
            self.birthdate = birthdate
        self.id = id
        self.ip_address = gethostbyname(gethostname())
        self.is_loggedout = True
        self.attempt_count = 0

    # These functions are required by flask-login
    def __repr__(self):
        return f"<User {self.username}>"
    
    def is_active(self):
        return True

    def get_id(self):
        # Primary key is user_name for this app
        return self.username

    def is_authenticated(self):
        return self.authenticated

    def is_anonymous(self):
        return False



# This function is required by flask-login
@login_manager.user_loader
def user_loader(user_id):
    return User.query.filter_by(username=user_id).first()


### APP ROUTES ###

# Nothing to do, just static links
@app.route('/')
def index():
   return render_template('index.html')


# User creation endpoint
@app.route('/user/create',methods=['POST', 'GET'])
def create_user():
    error = ""
    if request.method == 'POST':
        # Get entered values
        username = request.form['usern']
        firstname = request.form['firstn']
        middlename = request.form['middlen']
        lastname = request.form['lastn']
        dob = request.form['bdate']
        password = request.form['passw']
        email = request.form['email']

        # If no user with same username and email exists, then accept signup
        if not db.session.query(User).filter(User.username == username).count():
            if not db.session.query(User).filter(User.email == email).count():
                    # Check is password is valid
                    if re.fullmatch(pass_pattern, password):
                        # Save user with a randomly assigned password
                        user = User(randint(1,1000), username, password, firstname, middlename, lastname, dob,email)
                        db.session.add(user)
                        db.session.commit()
                        print("User created successfully")
                        app.logger.info(f"User with username {user.username} is created.")
                        # Go back to the main screen
                        return redirect("/")
                    else:
                        error = "Make sure your password contains only letters and numbers and has at least 8 characters."
            else:
                error = "This mail address already has an account."
        
        #This username exists
        else:
            # This username exists with a different email
            if not db.session.query(User).filter(User.email == email).count():
                error = "This username is taken."
            else:
                error = "You already have an account."

    return render_template('signup.html',error = error)
    
 
# Login a previously created user, if successful go to /loginsuccess, else show the same page with some error message
@app.route('/login', methods=['POST', 'GET'])
def login():
    error = ""
    if request.method =='POST':
        # Get entered info 
        username = request.form['usern']
        password = request.form['passw']
        user = User.query.filter_by(username=username).first()

        # If user exists
        if user:

            # If password is correct, reset attempt_count
            if is_correct_password(user.salt, user.password, password):
                user.attempt_count = 0
                user.authenticated = True
                db.session.add(user)
                db.session.commit()
                login_user(user, remember=True)
                log_login(user)
                return redirect("/loginsuccess")
            
            # More than 3 unsuccessful attempts, lock the account
            elif user.attempt_count >= 3:
                user.is_active = False
                db.session.add(user)
                db.session.commit()
                error = "You have tried to login with wrong password three times. This account is deactivated, please talk to your administrator."
            
            # Wrong password is entered, increase attempt count
            else:
                user.attempt_count += 1
                db.session.add(user)
                db.session.commit()
                error = "Wrong password"
        else:
            error = "User cannot be found"
    return render_template("login.html",error=error)


# Display account that are logged in and had an activity in the last 30 mins
@app.route("/onlineusers")
def display_online():
    # Get logged in accounts
    user_list=User.query.filter(User.is_loggedout == False)
    # Filter accounts by checking last activity time and current time
    for check_user in user_list:
        time_since_last_activity = datetime.now() - check_user.lastactivity
        if  time_since_last_activity.total_seconds() > 60 *30:
            check_user.is_loggedout = True
            check_user.is_authenticated = False
            db.session.add(check_user)
            app.logger.info(f"User {check_user.username}'s session is terminated")
    db.session.commit()
    app.logger.info("Online users are listed.")
    return render_template('online.html',users = user_list)


# Show this page if login is successful a.k.a "my home" page
@app.route("/loginsuccess")
def log_success():
    # If an anonymous user tries to access this page, redirect to login screen
    if current_user.is_authenticated == False:
        return redirect("/login")
    return render_template('loginsuccess.html')


# Show this page if login fails, note: current login logic doesn't redirect to this page ever
@app.route("/loginfailed")
def log_fail():
    return render_template('loginfailed.html')

# Show all registered users, this page has the links for delete and update
@app.route("/user/list")
@login_required
def list_users():
    mgs = None
    user=current_user
    add_user_activity(user)
    user_list=User.query.all()
    app.logger.info("All users are listed.")
    return render_template("list.html",mgs = mgs, users=user_list)


# Delete user endpoint, a user cannot delete others, can only delete themselves
@app.route('/user/delete/<id>',methods=['POST','GET'])
@login_required
def delete(id):
    message=""
    user=current_user
    add_user_activity(user)
    delete_user = User.query.filter_by(id=id).first()
    message = "User cannot be found"
    # Check if user to be deleted is the currently logged in one
    if delete_user.id != user.id:
        return render_template("delete.html", mgs = "Sorry, you are not allowed to delete this user")
    if delete_user:
        db.session.delete(delete_user)
        db.session.commit()
        message = f"User with username {delete_user.username} is deleted"
        app.logger.info(f"User with username {delete_user.username} is deleted")
        return render_template("list.html", mgs = message)
    
    return redirect("/user/list")


# Update user endpoint, a user cannot Update others, can only Update themselves
@app.route('/user/update/<id>',methods=['POST','GET'])
def update(id):
    user=current_user
    add_user_activity(user)
    error = None
    update_user = User.query.filter_by(id=id).first()
    # If update_user is valid
    if update_user:
        # If the current user is the one to be updated
        if update_user.id != user.id:
            return render_template("list.html", mgs = "Sorry, you are not allowed to update this user.")
        if request.method == 'POST':
            # Check if new password is valid
            if re.fullmatch(pass_pattern, request.form['passw']):
                update_user.username = request.form['usern']
                update_user.firstname = request.form['firstn']
                update_user.middlename = request.form['middlen']
                update_user.lastname = request.form['lastn']
                update_user.dob = request.form['bdate']
                update_user.email = request.form['email']
                update_user.salt, update_user.passw = hash_new_password(request.form['passw'])
                
                db.session.commit()

                error = "User is updated"
                app.logger.info(f"User with username {update_user.username} is updated")
            else:
                error = "Make sure new password is valid."
        else:
            return render_template('update.html',error = error, data=update_user)
    else:
        error = "User with id = {id} does not exist"
 
    return redirect('/user/list')


# Logout the current user
@app.route("/logout")
@login_required
def logout():
    user = current_user #current_user is a flask-login variable
    # If user was not logged in at the first, go to main page without any change
    if user.is_authenticated == False:
        return render_template("index.html")
    user.authenticated = False
    log_logout(user)
    db.session.add(user)
    db.session.commit()
    logout_user() # flask-login function to end session
    return render_template("index.html")

# If user forgot their password, grab their email from database and send a token to redirect them to reset password screen
@app.route("/forgotpassword",methods=['POST','GET'])
def forgot():
    mgs=""
    if request.method == 'POST':
        #Check if user exists and grab mail address
        user_name = request.form['usern']
        update_user = User.query.filter_by(username=user_name).first()

        if update_user:
            dest_mail = update_user.email
            mgs = f"Reset token is sent to your email at {dest_mail}"
            # Unique url using username, old password and current day
            reset_url = request.base_url + '/reset/' + password_protector.dumps([update_user.username, update_user.password, str(date.today())])
            # Send mail
            reset_msg = Message('Reset Password', sender = sender_mail, recipients = [dest_mail])
            reset_msg.body = f"Follow this link to reset your password: \n {reset_url}"
            mail.send(reset_msg)

        else:
            mgs = "User not found"
    return render_template("forgot_pass.html",mgs=mgs)
 
# Verify token and let user change their password
@app.route("/forgotpassword/reset/<token>",methods=['POST','GET'])
def reset(token):
    mgs = ""
    is_valid = True
    # Read serialized info
    user_name, old_pass, day_of_reset = password_protector.loads(token)
    update_user = User.query.filter_by(username=user_name).first()

    # Make sure token was sent at the same day
    if str(date.today()) == day_of_reset:
        # Make sure token is not used before to change password
        if update_user.password != old_pass:
            mgs = "This token is used already"
            is_valid = False
        else:
            pass
    else:
        mgs = "This token is expired, please request a new one"
        is_valid = False

    if request.method == 'POST':
        if is_valid:
            new_pass = request.form['passw']
            # If new password is valid, hash it and store with the new salt
            if re.fullmatch(pass_pattern, new_pass):
                tp_salt, tp_passw = hash_new_password(new_pass)
                update_user.salt = tp_salt
                update_user.password = tp_passw
                db.session.commit()
                add_user_activity(update_user)
                mgs = 'Password is updated successfully'
            else:
                mgs = "Please make sure your new password contains only letters and numbers and has at least 8 characters"

    return render_template("reset.html",mgs=mgs)


### RUN APP ###
if __name__ == '__main__':
   app.run(debug=True)
