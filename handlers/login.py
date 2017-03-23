""" Login Handler """
import random
import string
import hashlib
import webapp2
import jinja2
from handlers.handler import Handler
from models.user import User
from google.appengine.ext import ndb

def make_salt():
    """ Generate a salt string """
    return ''.join(random.choice(string.letters) for x in range(5))

def make_pw_hash(name, password, salt=None):
    """ Generate the hash password """
    if not salt:
        salt = make_salt()
    hash_pass = hashlib.sha256(name + password + salt).hexdigest()
    return '%s|%s' % (hash_pass, salt)

class Login(Handler):
    """ Login handler class """
    def get(self):
        """ Default get method """
        user_url = self.request.cookies.get('user_key', None)
        if user_url:
            self.redirect("/blog")
        else:
            self.render("login.html", login="Login")
    def post(self):
        """ Post method to verify username and password"""
        username = self.request.get('username')
        password = self.request.get('password')
        query = User.query(User.username == username).fetch(1)
        user = None
        if query:
            user = query[0]
        if user:
            salt = user.password.split('|')[1]
            if user.password == make_pw_hash(username, password, salt):
                user_url = user.key.urlsafe()
                self.response.headers.add_header('Set-Cookie', 'user_key = %s' % user_url, path='/')
                self.redirect("/blog")
            else:
                error = "The username or password is incorrect!"
                self.render("login.html", login="Login", username=username, error=error)
        else:
            error = "The username not exists!"
            self.render("login.html", login="Login", username=username, error=error)
