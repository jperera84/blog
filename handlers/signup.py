""" SignUp Handler """
import re
import random
import string
import hashlib
import webapp2
import jinja2
from handlers.handler import Handler
from models.user import User
from google.appengine.ext import ndb

def validate_username(username):
    """ Method validate username """
    match = re.match(r"^[a-zA-Z0-9_-]{3,20}$", username)
    if match:
        return ""
    else:
        return "Username invalid!"

def validate_password(password):
    """ Method validate username """
    match = re.match(r"^.{3,20}$", password)
    if match:
        return ""
    else:
        return "Password invalid!"

def validate_verify(password, verify):
    """ Method validate username """
    if password:
        if password == verify:
            return ""
        else:
            return "Password didn't match!"
    else:
        return ""

def validate_email(email):
    """ Method validate username """
    if email:
        match = re.match(r"^[\S]+@[\S]+.[\S]+$", email)
        if match:
            return ""
        else:
            return "Email invalid!"
    else:
        return ""

def make_salt():
    """ Generate a salt string """
    return ''.join(random.choice(string.letters) for x in range(5))

def make_pw_hash(name, password, salt=None):
    """ Generate the hash password """
    if not salt:
        salt = make_salt()
    hash_pass = hashlib.sha256(name + password + salt).hexdigest()
    return '%s|%s' % (hash_pass, salt)

class SignUp(Handler):
    """ Main Program class"""
    def get(self):
        """ Default get method"""
        self.render("signup.html")
    def post(self):
        """ Post method to register a new user """
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')
        if username:
            query = User.query(User.username == username).fetch(1)
            user = None
            if query:
                user = query[0]
            if user:
                self.render("signup.html", emailError="The user already exist.")
            else:
                username_error = validate_username(username)
                password_error = validate_password(password)
                verify_error = validate_verify(password, verify)
                email_error = validate_email(email)
                if username_error or password_error or verify_error or email_error:
                    self.render("signup.html", username=username, usernameError=username_error,
                                passwordError=password_error, verifyError=verify_error, email=email,
                                emailError=email_error)
                else:
                    user = User(username=username, password=make_pw_hash(username, password),
                                email=email)
                    user_key = user.put()
                    user_url = user_key.urlsafe()
                    self.response.headers.add_header('Set-Cookie', 'user_key = %s' % user_url,
                                                     path='/')
                    self.redirect("/blog/welcome")
        else:
            self.render("signup.html", usernameError="The username can't be empty")
