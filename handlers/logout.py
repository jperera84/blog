""" Comment Handler """
import webapp2
import jinja2
from handlers.handler import Handler
from google.appengine.ext import ndb

class Logout(Handler):
    """ Logout handler class """
    def get(self):
        """ Default get method"""
        user_url = self.request.cookies.get('user_key', None)
        if user_url:
            self.response.delete_cookie('user_key', path='/blog')
            self.redirect("/blog/login")
        else:
            self.redirect("/blog/login")
