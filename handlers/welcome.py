""" Comment Handler """
import webapp2
import jinja2
from handlers.handler import Handler
from models.user import User
from google.appengine.ext import ndb

class Welcome(Handler):
    """ Welcome handler class """
    def get(self):
        """ Default get method"""
        user_url = self.request.cookies.get('user_key', None)
        if user_url:
            user = ndb.Key(urlsafe=user_url).get()
            self.render("welcome.html", login="Login", username=user.username)
        else:
            self.redirect("/blog/signup")
